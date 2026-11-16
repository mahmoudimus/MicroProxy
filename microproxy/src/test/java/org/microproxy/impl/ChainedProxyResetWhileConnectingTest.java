package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketException;
import org.junit.jupiter.api.Test;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.ChainedProxyConnectException;
import org.microproxy.ChainedProxyType;

/**
 * Which failures on the connection to an HTTP chained proxy, to send it a {@code CONNECT}, are its
 * reset: on the connect ({@link ClientConnection#resetWhileConnecting}), and after it accepted the
 * connection ({@link ClientConnection#afterAccept}). When the reset lands is a race (on the
 * connect, on setting the socket's options, on writing the {@code CONNECT}, on reading its answer),
 * so each case is checked here directly; {@code ChainedProxyConnectFailureTest} has the race.
 */
class ChainedProxyResetWhileConnectingTest {

    private static final SocketException RESET = new SocketException("Connection reset by peer (connect failed)");

    private static ChainedProxy proxy(ChainedProxyType type) {
        return new ChainedProxyAdapter() {
            @Override
            public ChainedProxyType getChainedProxyType() {
                return type;
            }
        };
    }

    @Test
    void aResetWhileConnectingToAnHttpChainedProxyForACONNECTIsItsReset() {
        assertTrue(ClientConnection.resetWhileConnecting(proxy(ChainedProxyType.HTTP), ClientConnection.Mode.TLS, RESET));
        assertTrue(ClientConnection.resetWhileConnecting(proxy(ChainedProxyType.HTTP), ClientConnection.Mode.TLS,
                new SocketException("Connection reset")));
    }

    @Test
    void aProxyThatAnsweredNothingIsNoReset() {
        ChainedProxy http = proxy(ChainedProxyType.HTTP);
        assertFalse(ClientConnection.resetWhileConnecting(http, ClientConnection.Mode.TLS,
                new ConnectException("Connection refused")));
        assertFalse(ClientConnection.resetWhileConnecting(http, ClientConnection.Mode.TLS,
                new NoRouteToHostException("No route to host")));
        assertFalse(ClientConnection.resetWhileConnecting(http, ClientConnection.Mode.TLS,
                new SocketException("Socket closed")));
    }

    @Test
    void onlyAnHttpChainedProxyAskedForACONNECT() {
        assertFalse(ClientConnection.resetWhileConnecting(null, ClientConnection.Mode.TLS, RESET), "a direct connection");
        assertFalse(ClientConnection.resetWhileConnecting(proxy(ChainedProxyType.SOCKS5), ClientConnection.Mode.TLS, RESET));
        assertFalse(ClientConnection.resetWhileConnecting(proxy(ChainedProxyType.HTTP), ClientConnection.Mode.PLAIN, RESET),
                "requests forwarded to it, no CONNECT");
    }

    @Test
    void afterTheProxyAcceptedAnySocketFailureIsItsReset() throws Exception {
        ChainedProxy http = proxy(ChainedProxyType.HTTP);
        try (Socket open = new Socket()) {
            // macOS fails setsockopt on a connection already reset with EINVAL.
            SocketException invalid = new SocketException("Invalid argument");
            ChainedProxyConnectException reset = assertInstanceOf(ChainedProxyConnectException.class,
                    ClientConnection.afterAccept(http, ClientConnection.Mode.TLS, open, open, invalid));
            assertSame(ChainedProxyConnectException.Outcome.RESET, reset.outcome());
            assertSame(invalid, reset.getCause());
            assertInstanceOf(ChainedProxyConnectException.class,
                    ClientConnection.afterAccept(http, ClientConnection.Mode.TLS, open, open, new SocketException("Broken pipe")));
        }
    }

    @Test
    void afterTheProxyAcceptedItsOwnCloseAndTypedFailuresStayWhatTheyAre() throws Exception {
        ChainedProxy http = proxy(ChainedProxyType.HTTP);
        SocketException closed = new SocketException("Socket closed");
        try (Socket open = new Socket(); Socket shut = new Socket()) {
            shut.close();
            assertSame(closed, ClientConnection.afterAccept(http, ClientConnection.Mode.TLS, shut, shut, closed));
            // A TLS chained proxy: the socket under the TLS one closed.
            assertSame(closed, ClientConnection.afterAccept(http, ClientConnection.Mode.TLS, shut, open, closed));
            assertSame(closed, ClientConnection.afterAccept(http, ClientConnection.Mode.TLS, open, shut, closed));
            ChainedProxyConnectException typed = ChainedProxyConnectException.closed(null);
            assertSame(typed, ClientConnection.afterAccept(http, ClientConnection.Mode.TLS, open, open, typed));
            assertSame(closed, ClientConnection.afterAccept(proxy(ChainedProxyType.SOCKS5), ClientConnection.Mode.TLS,
                    open, open, closed));
            assertSame(closed, ClientConnection.afterAccept(http, ClientConnection.Mode.PLAIN, open, open, closed));
            assertSame(closed, ClientConnection.afterAccept(null, ClientConnection.Mode.TLS, open, open, closed));
        }
    }
}
