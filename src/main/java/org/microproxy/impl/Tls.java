package org.microproxy.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.List;
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
            Consumer<SSLSocket> configurer)
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
            socket.startHandshake();
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
            Consumer<SSLSocket> configurer)
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
            socket.startHandshake();
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

    static void closeQuietly(java.io.Closeable c) {
        if (c == null) return;
        try {
            c.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }
}
