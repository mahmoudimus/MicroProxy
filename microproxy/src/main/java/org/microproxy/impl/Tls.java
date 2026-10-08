package org.microproxy.impl;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/** Layers TLS over already-connected sockets. */
final class Tls {

    private Tls() {}

    /**
     * Starts a client handshake over {@code plain}.
     *
     * @param verifyHostname enable HTTPS endpoint identification against {@code host}
     */
    static SSLSocket clientHandshake(
            SSLContext context,
            Socket plain,
            String host,
            int port,
            boolean verifyHostname,
            Consumer<SSLSocket> configurer,
            Duration deadline)
            throws IOException {
        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(plain, host, port, true);
        try {
            socket.setUseClientMode(true);
            SSLParameters params = socket.getSSLParameters();
            if (!isIpLiteral(host)) {
                try {
                    params.setServerNames(List.of(new SNIHostName(host)));
                } catch (IllegalArgumentException ignored) {
                    // Not a valid SNI name (e.g. contains an underscore); send no SNI.
                }
            }
            if (verifyHostname) {
                params.setEndpointIdentificationAlgorithm("HTTPS");
            }
            socket.setSSLParameters(params);
            if (configurer != null) {
                configurer.accept(socket);
            }
            handshake(socket, plain, deadline);
            return socket;
        } catch (IOException | RuntimeException e) {
            closeQuietly(socket);
            throw e;
        }
    }

    /**
     * Starts a server handshake over {@code plain}.
     *
     * @param consumed bytes already read from {@code plain} that belong to the TLS stream
     */
    static SSLSocket serverHandshake(
            SSLContext context,
            Socket plain,
            byte[] consumed,
            boolean needClientAuth,
            Consumer<SSLSocket> configurer,
            Duration deadline)
            throws IOException {
        SSLSocket socket =
                (SSLSocket) context.getSocketFactory()
                        .createSocket(plain, consumed.length == 0 ? null : new ByteArrayInputStream(consumed), true);
        try {
            socket.setUseClientMode(false);
            if (needClientAuth) {
                socket.setNeedClientAuth(true);
            }
            if (configurer != null) {
                configurer.accept(socket);
            }
            handshake(socket, plain, deadline);
            return socket;
        } catch (IOException | RuntimeException e) {
            closeQuietly(socket);
            throw e;
        }
    }

    static boolean isIpLiteral(String host) {
        if (host.indexOf(':') >= 0) return true;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        return true;
    }

    /** Closes sockets whose handshake overran its deadline. One daemon thread serves the whole JVM. */
    private static final ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "microproxy-tls-deadline");
        t.setDaemon(true);
        return t;
    });

    /**
     * Runs the handshake, closing the underlying socket if it has not finished within {@code
     * deadline}. The read timeout alone does not bound a handshake: a peer sending a byte now and
     * then keeps it alive indefinitely.
     */
    private static void handshake(SSLSocket socket, Socket plain, Duration deadline) throws IOException {
        if (deadline == null || deadline.isZero() || deadline.isNegative()) {
            socket.startHandshake();
            return;
        }
        AtomicBoolean expired = new AtomicBoolean();
        // Closing the plain socket, not the SSLSocket, avoids contending for the handshake's locks.
        ScheduledFuture<?> timer = DEADLINES.schedule(() -> {
            expired.set(true);
            closeQuietly(plain);
        }, deadline.toMillis(), TimeUnit.MILLISECONDS);
        try {
            socket.startHandshake();
        } catch (IOException e) {
            if (expired.get()) throw timedOut(deadline, e);
            throw e;
        } finally {
            timer.cancel(false);
        }
        if (expired.get()) throw timedOut(deadline, null);
    }

    private static SocketTimeoutException timedOut(Duration deadline, Throwable cause) {
        SocketTimeoutException e = new SocketTimeoutException("TLS handshake not finished within " + deadline.toMillis() + " ms");
        if (cause != null) e.initCause(cause);
        return e;
    }

    static void closeQuietly(Closeable c) {
        if (c == null) return;
        try {
            c.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }
}
