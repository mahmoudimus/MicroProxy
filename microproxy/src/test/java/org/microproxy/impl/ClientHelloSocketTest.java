package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ClientHelloNotSentException;
import org.microproxy.ProxyFailure.TlsFailed.Reason;

/**
 * Which failed first writes {@link ClientHelloSocket} takes for a ClientHello that did not reach the
 * connection: a peer's reset (as {@code MitmHandshakeClosedTest} has), not a socket the proxy
 * closed itself (an abort, a client that left).
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class ClientHelloSocketTest {

    @Test
    void aSocketTheProxyClosedIsNoClientHelloNotSent() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                Socket plain = new Socket(listener.getInetAddress(), listener.getLocalPort());
                Socket peer = listener.accept()) {
            ClientHelloSocket socket = new ClientHelloSocket(plain);
            OutputStream out = socket.getOutputStream();
            plain.close();
            IOException e = assertThrows(IOException.class, () -> out.write(new byte[] {0x16, 3, 1}));
            assertFalse(e instanceof ClientHelloNotSentException, "the proxy's own close: " + e);
            assertEquals(Reason.OTHER, Reason.of(e));
        }
    }
}
