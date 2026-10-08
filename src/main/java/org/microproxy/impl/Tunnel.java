package org.microproxy.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLSocket;

/**
 * Relays bytes in both directions between two sockets until both directions finish, using one
 * extra virtual thread. End-of-stream on one side is propagated as a half-close to the other.
 * With an idle timeout, the tunnel closes only when neither direction has moved data for that
 * long.
 */
final class Tunnel {

    private Tunnel() {}

    static void relay(
            Socket clientSocket, InputStream clientIn, OutputStream clientOut,
            Socket serverSocket, InputStream serverIn, OutputStream serverOut,
            Duration idleTimeout, String name) {
        AtomicLong lastActivity = new AtomicLong(System.nanoTime());
        long idleNanos = idleTimeout == null ? 0 : idleTimeout.toNanos();
        Runnable closeAll = () -> {
            Tls.closeQuietly(clientSocket);
            Tls.closeQuietly(serverSocket);
        };
        Thread upstream = Thread.ofVirtual().name(name + "-up").start(
                () -> pump(clientIn, serverOut, serverSocket, lastActivity, idleNanos, closeAll));
        pump(serverIn, clientOut, clientSocket, lastActivity, idleNanos, closeAll);
        try {
            upstream.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeAll.run();
        }
    }

    private static void pump(
            InputStream in, OutputStream out, Socket destination,
            AtomicLong lastActivity, long idleNanos, Runnable closeAll) {
        byte[] buf = new byte[16384];
        try {
            while (true) {
                int n;
                try {
                    n = in.read(buf);
                } catch (SocketTimeoutException e) {
                    if (idleNanos > 0 && System.nanoTime() - lastActivity.get() < idleNanos) {
                        continue;
                    }
                    closeAll.run();
                    return;
                }
                if (n < 0) {
                    halfClose(destination, out);
                    return;
                }
                out.write(buf, 0, n);
                out.flush();
                lastActivity.set(System.nanoTime());
            }
        } catch (IOException e) {
            closeAll.run();
        }
    }

    private static void halfClose(Socket destination, OutputStream out) {
        try {
            out.flush();
            if (destination instanceof SSLSocket) {
                // TLS half-close support varies by peer; closing is the safe choice.
                destination.close();
            } else if (!destination.isClosed() && !destination.isOutputShutdown()) {
                destination.shutdownOutput();
            }
        } catch (IOException | UnsupportedOperationException e) {
            Tls.closeQuietly(destination);
        }
    }
}
