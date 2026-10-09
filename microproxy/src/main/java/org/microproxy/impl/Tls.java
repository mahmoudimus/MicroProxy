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
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/** Layers TLS over already-connected sockets. */
final class Tls {

    private Tls() {}

    /**
     * Starts a client handshake over {@code plain}.
     *
     * @param verifyHostname enable HTTPS endpoint identification against {@code host}
     * @param protocols the TLS versions to enable before {@code configurer} runs, or null for the
     *     context's defaults (see {@link #pinProtocols})
     * @param peer who the handshake is with, for the log lines ({@link TlsLog})
     */
    static SSLSocket clientHandshake(
            SSLContext context,
            Socket plain,
            String host,
            int port,
            boolean verifyHostname,
            String[] protocols,
            Consumer<SSLSocket> configurer,
            Duration deadline,
            TlsLog.Peer peer)
            throws IOException {
        long start = System.nanoTime();
        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(plain, host, port, true);
        try {
            socket.setUseClientMode(true);
            pinProtocols(socket, protocols);
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
            TlsLog.started(peer, plain, true, false);
            handshake(socket, plain, deadline);
            TlsLog.succeeded(peer, plain, socket, true, start);
            return socket;
        } catch (IOException e) {
            closeQuietly(socket);
            TlsLog.failed(peer, plain, socket, true, e);
            throw e;
        } catch (RuntimeException e) {
            closeQuietly(socket);
            throw e;
        }
    }

    /**
     * Starts a server handshake over {@code plain}.
     *
     * @param consumed bytes already read from {@code plain} that belong to the TLS stream
     * @param protocols the TLS versions to enable before {@code configurer} runs, or null for the
     *     context's defaults (see {@link #pinProtocols})
     * @param peer who the handshake is with, for the log lines ({@link TlsLog})
     */
    static SSLSocket serverHandshake(
            SSLContext context,
            Socket plain,
            byte[] consumed,
            boolean needClientAuth,
            String[] protocols,
            Consumer<SSLSocket> configurer,
            Duration deadline,
            TlsLog.Peer peer)
            throws IOException {
        long start = System.nanoTime();
        SSLSocket socket =
                (SSLSocket) context.getSocketFactory()
                        .createSocket(plain, consumed.length == 0 ? null : new ByteArrayInputStream(consumed), true);
        try {
            socket.setUseClientMode(false);
            pinProtocols(socket, protocols);
            if (needClientAuth) {
                socket.setNeedClientAuth(true);
            }
            if (configurer != null) {
                configurer.accept(socket);
            }
            TlsLog.started(peer, plain, false, socket.getNeedClientAuth());
            handshake(socket, plain, deadline);
            TlsLog.succeeded(peer, plain, socket, false, start);
            return socket;
        } catch (IOException e) {
            closeQuietly(socket);
            TlsLog.failed(peer, plain, socket, false, e);
            throw e;
        } catch (RuntimeException e) {
            closeQuietly(socket);
            throw e;
        }
    }

    /**
     * Enables exactly those of {@code pinned} that {@code socket}'s context supports, in the order
     * given. Configuration hooks run afterwards and may change them again.
     *
     * @throws SSLHandshakeException if the context supports none of them
     */
    static void pinProtocols(SSLSocket socket, String[] pinned) throws SSLHandshakeException {
        if (pinned == null) return;
        String[] supportedProtocols = socket.getSupportedProtocols();
        java.util.Set<String> supported = java.util.Set.of(supportedProtocols);
        String[] usable = java.util.Arrays.stream(pinned).filter(supported::contains).toArray(String[]::new);
        if (usable.length == 0) {
            throw new SSLHandshakeException("none of the TLS protocols " + String.join(", ", pinned)
                    + " allowed by withTlsProtocols (tls_protocols) is supported by this SSLContext, which supports "
                    + String.join(", ", supportedProtocols));
        }
        socket.setEnabledProtocols(usable);
    }

    /**
     * Whether a failed client handshake means the peer is not a TLS server at all, the same
     * signs LittleProxy's {@code shouldRetryWithoutSsl} looks for: plaintext where a TLS record
     * was expected, or the peer closing or resetting the connection on the ClientHello.
     * Certificate and protocol-version failures come from real TLS servers and do not count.
     */
    static boolean looksLikePlaintextPeer(SSLException e) {
        String message = String.valueOf(e.getMessage()).toLowerCase(java.util.Locale.ROOT);
        return message.contains("unrecognized ssl message")
                || message.contains("not an ssl")
                || message.contains("remote host terminated")
                || message.contains("connection reset")
                || e.getCause() instanceof java.io.EOFException
                || e.getCause() instanceof java.net.SocketException;
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
