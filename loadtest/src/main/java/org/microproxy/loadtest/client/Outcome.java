package org.microproxy.loadtest.client;

import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;

/** How one exchange (or connection attempt) ended, from the load generator's side. */
public enum Outcome {
    /** The expected status and body length. */
    OK,
    /** A complete response with another status. */
    BAD_STATUS,
    /** A complete response with the expected status but another body length. */
    BAD_LENGTH,
    /** The connection ended inside the body. */
    TRUNCATED,
    /** The connection ended before a status line. */
    CLOSED,
    /** A TCP reset (or broken pipe). */
    RESET,
    /** No response within the read timeout. */
    TIMEOUT,
    /** The connection was refused. */
    CONNECT_REFUSED,
    /** The connection was not accepted within the connect timeout. */
    CONNECT_TIMEOUT,
    /** The load generator ran out of file descriptors: its own limit, not the proxy's. */
    CLIENT_FDS,
    /** The load generator ran out of ephemeral ports: its own limit, not the proxy's. */
    CLIENT_PORTS,
    /** Anything else. */
    IO_ERROR;

    /** Whether this outcome is a limit of the load generator's process rather than the proxy. */
    public boolean clientLimit() {
        return this == CLIENT_FDS || this == CLIENT_PORTS;
    }

    /** Classifies an exception; {@code connecting} tells a connect timeout from a read timeout. */
    public static Outcome of(IOException e, boolean connecting, boolean inBody) {
        String msg = String.valueOf(e.getMessage());
        if (msg.contains("Too many open files")) return CLIENT_FDS;
        if (msg.contains("Cannot assign requested address") || msg.contains("Address already in use")) return CLIENT_PORTS;
        if (e instanceof SocketTimeoutException) return connecting ? CONNECT_TIMEOUT : TIMEOUT;
        if (e instanceof ConnectException) {
            return msg.contains("timed out") ? CONNECT_TIMEOUT : CONNECT_REFUSED;
        }
        if (e instanceof NoRouteToHostException) return CONNECT_REFUSED;
        if (msg.contains("Connection reset") || msg.contains("Broken pipe")) return inBody ? TRUNCATED : RESET;
        if (e instanceof EOFException) return inBody ? TRUNCATED : CLOSED;
        return IO_ERROR;
    }
}
