package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.packet.Packet;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A QUIC client shaped as Chrome 156's (its QUIC ClientHello, transport parameters, connection IDs
 * and Initial packets) against the module's server: the connection works, and its first Initials
 * look as Chrome's captured ones do (quic/src/test/resources/fingerprints/chrome-156-quic).
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ChromeQuicClientTest {

    static ClientConfig chromeClient() {
        QuicClientProfile chrome = QuicClientProfile.chrome156();
        TlsConfig tls = chrome.applyTo(TlsConfig.builder()
                .serverName("localhost")
                .trustManager(TestCerts.CA.trustManager())
                .alpnProtocols(LoopbackTest.ALPN), io.github.mahmoudimus.quic.tls.CertificateDecompressor.ZLIB).build();
        return chrome.applyTo(ClientConfig.builder(tls).transport(chrome.applyTo(TransportConfig.builder()).build())).build();
    }

    @Test
    void theConnectionWorksAndItsInitialsLookLikeChromes() throws Exception {
        List<ByteBuffer> seen = new CopyOnWriteArrayList<>();
        try (EchoServer echo = new EchoServer(LoopbackTest.serverConfig(LoopbackTest.fastTransport()));
                Relay relay = new Relay(echo.address(), seen);
                QuicClient client = QuicClient.create(chromeClient(), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                        QuicClientProfile.chrome156().endpointConfig())) {
            QuicConnection c = client.connect(relay.address(), "localhost", Duration.ofSeconds(10));
            byte[] data = LoopbackTest.data(11, 200_000);
            assertArrayEquals(LoopbackTest.sha256().digest(data), LoopbackTest.echo(c, data));
            c.close(0, "done");
            assertTrue(echo.errors().isEmpty(), echo.errors().toString());
        }

        ByteBuffer first = seen.getFirst();
        // a long header: 8-byte destination, empty source connection ID (Chrome's)
        assertEquals(8, first.get(5));
        assertEquals(0, first.get(6 + 8));
        List<ByteBuffer> initials = new ArrayList<>();
        for (ByteBuffer d : seen) {
            if (ProtectedPacket.parse(d.duplicate(), 0).type() == PacketType.INITIAL) initials.add(d);
        }
        // the hello, with a hybrid share, takes two full-size datagrams, as Chrome's does
        assertEquals(1250, initials.get(0).remaining());
        assertEquals(1250, initials.get(1).remaining());

        ProtectedPacket p0 = ProtectedPacket.parse(first.duplicate(), 0);
        DirectionalKeys keys = Keys.initial(p0.version(), p0.destinationId(), true).remote();
        long expectedPn = 1;
        int cryptoFrames = 0;
        int pings = 0;
        for (ByteBuffer d : initials.subList(0, 2)) {
            Packet packet = ProtectedPacket.splitDatagram(ByteBuffer.wrap(copy(d)), 0, false).getFirst().unprotect(keys, -1);
            assertEquals(expectedPn++, packet.header().packetNumber());
            for (Frame f : FrameDecoder.decodeAll(packet.payload(), PacketType.INITIAL)) {
                if (f instanceof Frame.Crypto) cryptoFrames++;
                if (f instanceof Frame.Ping) pings++;
            }
        }
        // chaos protection: the hello in several CRYPTO frames, with PINGs among them
        assertTrue(cryptoFrames >= 4, "CRYPTO frames " + cryptoFrames);
        assertTrue(pings >= 2, "PING frames " + pings);
    }

    /** Forwards datagrams between one client and the server, keeping a copy of each the client sends. */
    static final class Relay implements AutoCloseable {
        private final java.net.DatagramSocket socket;
        private volatile java.net.SocketAddress clientAddress;

        Relay(InetSocketAddress server, List<ByteBuffer> fromClient) throws java.io.IOException {
            socket = new java.net.DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            Thread.ofVirtual().start(() -> {
                byte[] buf = new byte[65_535];
                while (!socket.isClosed()) {
                    try {
                        java.net.DatagramPacket p = new java.net.DatagramPacket(buf, buf.length);
                        socket.receive(p);
                        byte[] d = java.util.Arrays.copyOf(buf, p.getLength());
                        if (p.getSocketAddress().equals(server)) {
                            if (clientAddress != null) socket.send(new java.net.DatagramPacket(d, d.length, clientAddress));
                        } else {
                            clientAddress = p.getSocketAddress();
                            fromClient.add(ByteBuffer.wrap(d));
                            socket.send(new java.net.DatagramPacket(d, d.length, server));
                        }
                    } catch (java.io.IOException e) {
                        return;
                    }
                }
            });
        }

        InetSocketAddress address() {
            return (InetSocketAddress) socket.getLocalSocketAddress();
        }

        @Override
        public void close() {
            socket.close();
        }
    }

    private static byte[] copy(ByteBuffer b) {
        byte[] out = new byte[b.remaining()];
        b.duplicate().get(out);
        return out;
    }
}
