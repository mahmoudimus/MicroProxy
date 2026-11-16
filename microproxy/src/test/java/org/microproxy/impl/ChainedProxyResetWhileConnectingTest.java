package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import org.junit.jupiter.api.Test;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.ChainedProxyType;

/**
 * Which failed connects to a chained proxy are its reset ({@link
 * ClientConnection#resetWhileConnecting}): an HTTP chained proxy that accepted the connection and
 * reset it before the {@code CONNECT} went out. When the reset lands is a race (on the connect, on
 * writing the {@code CONNECT}, on reading its answer), so the connect's case is checked here
 * directly; the others are in {@code ChainedProxyConnectFailureTest}.
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
}
