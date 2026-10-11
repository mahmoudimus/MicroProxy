package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.packet.PacketBuilder;
import io.github.mahmoudimus.quic.packet.PacketHeader;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.microproxy.ClientHello;
import org.microproxy.TlsHellos;

/**
 * Reading a QUIC client's ClientHello from its Initial packets: the RFC 9001 and RFC 9369 sample
 * Initials, a real one from the Java QUIC client, large ClientHellos over several packets and
 * datagrams with their CRYPTO frames out of order, and Initials that cannot be read.
 */
class QuicClientHelloTest {

    private static final Properties VECTORS = vectors();
    private static final ConnectionId DCID = ConnectionId.of(HexFormat.of().parseHex("8394c8f03e515708"));
    private static final ConnectionId SCID = ConnectionId.of(HexFormat.of().parseHex("c0ffee00"));

    private static Properties vectors() {
        Properties p = new Properties();
        try (InputStream in = QuicClientHelloTest.class.getResourceAsStream("quic-initial-vectors.properties")) {
            p.load(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return p;
    }

    private static ByteBuffer vector(QuicVersion v) {
        String key = (v == QuicVersion.V1 ? "rfc9001" : "rfc9369") + ".client-initial.protected";
        return ByteBuffer.wrap(HexFormat.of().parseHex(VECTORS.getProperty(key)));
    }

    /** Reads {@code datagrams} in order; the ClientHello the last one completes. */
    private static ClientHello read(List<ByteBuffer> datagrams) throws Exception {
        QuicClientHello reader = QuicClientHello.start(datagrams.getFirst());
        ClientHello hello = null;
        for (int i = 0; i < datagrams.size(); i++) {
            assertNull(hello, "complete before datagram " + i);
            hello = reader.offer(datagrams.get(i));
        }
        return hello;
    }

    /** RFC 9001 A.2 and RFC 9369 A.2: the sample client Initial, a ClientHello for example.com. */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void readsTheRfcSampleInitial(QuicVersion v) throws Exception {
        ByteBuffer datagram = vector(v);
        byte[] before = datagram.array().clone();
        QuicClientHello reader = QuicClientHello.start(datagram);
        assertEquals(v, reader.version());
        assertEquals(DCID, reader.destinationId());
        assertEquals(ConnectionId.EMPTY, reader.sourceId());
        ClientHello hello = reader.offer(datagram);
        assertNotNull(hello);
        assertEquals("example.com", hello.sni());
        assertEquals(List.of("alpn"), hello.alpnProtocols());
        assertEquals(List.of(0x0304), hello.versions());
        assertEquals(List.of(0x1301, 0x1302), hello.cipherSuites());
        assertEquals(241, hello.raw().length);
        assertArrayEquals(before, datagram.array(), "the datagram is left as it was, to be relayed");
    }

    /** The first Initial the Java QUIC client sends, to a socket that never answers. */
    @Test
    void readsTheJavaQuicClientsInitial() throws Exception {
        try (DatagramSocket sink = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            sink.setSoTimeout(10_000);
            ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                    .alpnProtocols("h3")
                    .serverName("origin.test")
                    .trustAllCertificates(true)
                    .build()).build();
            try (QuicClient client = QuicClient.create(config)) {
                Thread.ofVirtual().start(() -> {
                    try {
                        client.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), sink.getLocalPort()),
                                "origin.test", Duration.ofSeconds(5));
                    } catch (IOException expected) {
                        // nobody answers
                    }
                });
                DatagramPacket p = new DatagramPacket(new byte[2048], 2048);
                sink.receive(p);
                ByteBuffer datagram = ByteBuffer.wrap(Arrays.copyOf(p.getData(), p.getLength()));
                assertTrue(datagram.remaining() >= 1200, "a client's Initial datagram is padded");
                ClientHello hello = read(List.of(datagram));
                assertNotNull(hello);
                assertEquals("origin.test", hello.sni());
                assertEquals(List.of("h3"), hello.alpnProtocols());
                assertTrue(hello.versions().contains(0x0304), hello.versions().toString());
                assertTrue(hello.extensionTypes().contains(0x39), "quic_transport_parameters");
            }
        }
    }

    /**
     * A ClientHello as large as a post-quantum one, over three Initial packets in three datagrams,
     * its CRYPTO frames shuffled and mixed with PING (as Chrome sends them).
     */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void readsALargeClientHelloOverSeveralDatagramsOutOfOrder(QuicVersion v) throws Exception {
        byte[] message = large("pq.example", 3000);
        List<byte[]> pieces = split(message, 6);
        List<ByteBuffer> datagrams = List.of(
                initial(v, 0, List.of(crypto(pieces, message, 3), new Frame.Ping(), crypto(pieces, message, 1))),
                initial(v, 1, List.of(crypto(pieces, message, 5), crypto(pieces, message, 4))),
                initial(v, 2, List.of(new Frame.Ping(), crypto(pieces, message, 2), crypto(pieces, message, 0))));
        ClientHello hello = read(datagrams);
        assertNotNull(hello);
        assertEquals("pq.example", hello.sni());
        assertEquals(List.of("h3"), hello.alpnProtocols());
        assertArrayEquals(message, hello.raw());
    }

    /** Two packets coalesced in one datagram, the second one finishing the message. */
    @Test
    void readsCoalescedInitials() throws Exception {
        byte[] message = large("coalesced.example", 1500);
        List<byte[]> pieces = split(message, 2);
        ByteBuffer buf = ByteBuffer.allocate(4000);
        PacketBuilder b = new PacketBuilder(buf, 4000);
        Keys keys = Keys.initial(QuicVersion.V1, DCID, false);
        ByteBuffer frames = b.begin(new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, new byte[0], 0, 2), keys.local());
        crypto(pieces, message, 1).encode(frames);
        b.finish(0);
        frames = b.begin(new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, new byte[0], 1, 2), keys.local());
        crypto(pieces, message, 0).encode(frames);
        b.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);
        ClientHello hello = read(List.of(b.datagram()));
        assertNotNull(hello);
        assertEquals("coalesced.example", hello.sni());
    }

    /** A retransmission repeats data already read; an Initial that fails authentication later is skipped. */
    @Test
    void skipsRetransmissionsAndForgedLaterInitials() throws Exception {
        byte[] message = large("retransmit.example", 2000);
        List<byte[]> pieces = split(message, 2);
        ByteBuffer first = initial(QuicVersion.V1, 0, List.of(crypto(pieces, message, 0)));
        ByteBuffer forged = initial(QuicVersion.V1, 1, List.of(crypto(pieces, message, 1)));
        forged.put(forged.limit() - 1, (byte) (forged.get(forged.limit() - 1) ^ 1));
        QuicClientHello reader = QuicClientHello.start(first);
        assertNull(reader.offer(first));
        assertNull(reader.offer(first.duplicate()));
        assertNull(reader.offer(forged));
        ClientHello hello = reader.offer(initial(QuicVersion.V1, 2, List.of(crypto(pieces, message, 1))));
        assertNotNull(hello);
        assertArrayEquals(message, hello.raw());
    }

    // ---------------------------------------------------------------------------------------
    // What cannot be read

    @Test
    void refusesATamperedInitial() throws Exception {
        ByteBuffer datagram = vector(QuicVersion.V1);
        datagram.put(600, (byte) (datagram.get(600) ^ 0x40));
        QuicClientHello reader = QuicClientHello.start(datagram);
        assertThrows(TlsClientHello.Malformed.class, () -> reader.offer(datagram));
    }

    @Test
    void refusesPacketsThatAreNotInitials() {
        // A short header packet.
        byte[] shortHeader = new byte[1200];
        shortHeader[0] = 0x40;
        assertThrows(TlsClientHello.Malformed.class, () -> QuicClientHello.start(ByteBuffer.wrap(shortHeader)));
        // A Handshake packet.
        ByteBuffer buf = ByteBuffer.allocate(1500);
        PacketBuilder b = new PacketBuilder(buf, 1500);
        ByteBuffer frames = b.begin(new PacketHeader.Handshake(QuicVersion.V1, DCID, SCID, 0, 1),
                Keys.initial(QuicVersion.V1, DCID, false).local());
        new Frame.Ping().encode(frames);
        b.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);
        assertThrows(TlsClientHello.Malformed.class, () -> QuicClientHello.start(b.datagram()));
        // Not QUIC at all.
        assertThrows(TlsClientHello.Malformed.class, () -> QuicClientHello.start(ByteBuffer.wrap(new byte[] {(byte) 0xc0, 0, 0})));
    }

    @Test
    void tellsUnknownVersions() {
        byte[] datagram = new byte[1200];
        ByteBuffer.wrap(datagram).put((byte) 0xc0).putInt(0x6b3343ce).put((byte) 8).put(DCID.toByteArray()).put((byte) 0);
        QuicClientHello.UnknownVersion e = assertThrows(QuicClientHello.UnknownVersion.class,
                () -> QuicClientHello.start(ByteBuffer.wrap(datagram)));
        assertEquals(0x6b3343ce, e.version);
    }

    @Test
    void refusesCryptoDataThatIsNotAClientHello() throws Exception {
        byte[] serverHello = large("x.example", 100);
        serverHello[0] = 2;
        ByteBuffer datagram = initial(QuicVersion.V1, 0, List.of(new Frame.Crypto(0, ByteBuffer.wrap(serverHello))));
        QuicClientHello reader = QuicClientHello.start(datagram);
        assertThrows(TlsClientHello.Malformed.class, () -> reader.offer(datagram));
    }

    @Test
    void refusesAClientHelloThatEndsEarly() throws Exception {
        byte[] message = large("short.example", 100);
        // The length says the message ends right after the cipher suites' length.
        byte[] cut = Arrays.copyOf(message, 4 + 2 + 32 + 1 + 2);
        cut[1] = 0;
        cut[2] = 0;
        cut[3] = (byte) (cut.length - 4);
        ByteBuffer datagram = initial(QuicVersion.V1, 0, List.of(new Frame.Crypto(0, ByteBuffer.wrap(cut))));
        QuicClientHello reader = QuicClientHello.start(datagram);
        assertThrows(TlsClientHello.Malformed.class, () -> reader.offer(datagram));
    }

    @Test
    void refusesFramesAnInitialMayNotCarry() throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(1500);
        PacketBuilder b = new PacketBuilder(buf, 1500);
        ByteBuffer frames = b.begin(new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, new byte[0], 0, 1),
                Keys.initial(QuicVersion.V1, DCID, false).local());
        Frame.Stream.encode(frames, 0, 0, ByteBuffer.wrap(new byte[10]), true, frames.remaining());
        b.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);
        ByteBuffer datagram = b.datagram();
        QuicClientHello reader = QuicClientHello.start(datagram);
        assertThrows(TlsClientHello.Malformed.class, () -> reader.offer(datagram));
    }

    @Test
    void refusesClientHellosThatAreTooLarge() throws Exception {
        // One that says it is larger than the limit.
        byte[] header = {1, 0x02, 0, 0}; // 128 KiB
        ByteBuffer datagram = initial(QuicVersion.V1, 0, List.of(new Frame.Crypto(0, ByteBuffer.wrap(header))));
        QuicClientHello reader = QuicClientHello.start(datagram);
        assertThrows(TlsClientHello.TooLarge.class, () -> reader.offer(datagram));
        // CRYPTO data far past the limit.
        ByteBuffer far = initial(QuicVersion.V1, 0, List.of(new Frame.Crypto(1 << 20, ByteBuffer.wrap(new byte[10]))));
        QuicClientHello farReader = QuicClientHello.start(far);
        assertThrows(TlsClientHello.TooLarge.class, () -> farReader.offer(far));
    }

    @Test
    void givesUpOnAClientHelloThatNeverCompletes() throws Exception {
        byte[] message = large("endless.example", 20_000);
        List<byte[]> pieces = split(message, 40);
        // Everything but the first piece, and then the first piece too late.
        ByteBuffer first = initial(QuicVersion.V1, 0, List.of(crypto(pieces, message, 1)));
        QuicClientHello reader = QuicClientHello.start(first);
        assertNull(reader.offer(first));
        for (int i = 1; i < QuicClientHello.MAX_DATAGRAMS; i++) {
            assertNull(reader.offer(initial(QuicVersion.V1, i, List.of(crypto(pieces, message, 1 + i)))));
        }
        assertThrows(TlsClientHello.TooLarge.class,
                () -> reader.offer(initial(QuicVersion.V1, 99, List.of(crypto(pieces, message, 0)))));
    }

    // ---------------------------------------------------------------------------------------
    // Building Initials

    /** A ClientHello for {@code sni} offering {@code h3}, with an extension of {@code extra} bytes (a large key share, say). */
    static byte[] large(String sni, int extra) {
        byte[] small = TlsHellos.build(List.of(sni), List.of("h3"), 0x0304);
        // The extensions are last: append one, and fix the lengths of the extensions and the message.
        int extensionsAt = 4 + 2 + 32 + 1 + 2 + 6 + 2;
        int extensionsLength = (small[extensionsAt] & 0xff) << 8 | (small[extensionsAt + 1] & 0xff);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(small, 0, small.length);
        out.write(0xfe);
        out.write(0x0d);
        out.write(extra >> 8);
        out.write(extra);
        out.writeBytes(new byte[extra]);
        byte[] m = out.toByteArray();
        int newExtensions = extensionsLength + 4 + extra;
        m[extensionsAt] = (byte) (newExtensions >> 8);
        m[extensionsAt + 1] = (byte) newExtensions;
        int body = m.length - 4;
        m[1] = (byte) (body >> 16);
        m[2] = (byte) (body >> 8);
        m[3] = (byte) body;
        return m;
    }

    private static List<byte[]> split(byte[] message, int n) {
        List<byte[]> pieces = new ArrayList<>();
        int size = (message.length + n - 1) / n;
        for (int at = 0; at < message.length; at += size) {
            pieces.add(Arrays.copyOfRange(message, at, Math.min(message.length, at + size)));
        }
        assertEquals(n, pieces.size());
        return pieces;
    }

    /** The CRYPTO frame of piece {@code i}, at its offset in {@code message}. */
    private static Frame.Crypto crypto(List<byte[]> pieces, byte[] message, int i) {
        int offset = 0;
        for (int j = 0; j < i; j++) offset += pieces.get(j).length;
        return new Frame.Crypto(offset, ByteBuffer.wrap(pieces.get(i)));
    }

    /** A client Initial datagram, padded to 1200 bytes, with packet number {@code pn} and these frames. */
    private static ByteBuffer initial(QuicVersion v, long pn, List<Frame> frameList) {
        ByteBuffer buf = ByteBuffer.allocate(1500);
        PacketBuilder b = new PacketBuilder(buf, 1500);
        ByteBuffer frames = b.begin(new PacketHeader.Initial(v, DCID, SCID, new byte[0], pn, 2),
                Keys.initial(v, DCID, false).local());
        for (Frame f : frameList) f.encode(frames);
        b.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);
        ByteBuffer datagram = b.datagram();
        return ByteBuffer.wrap(Arrays.copyOfRange(datagram.array(), datagram.position(), datagram.limit()));
    }
}
