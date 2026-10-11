package io.github.mahmoudimus.quic.packet;

import static io.github.mahmoudimus.quic.TestVectors.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.Secrets;
import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class PacketHeaderTest {

    private static final ConnectionId DCID = ConnectionId.of(hex("06b858ec6f80452b"));
    private static final ConnectionId SCID = ConnectionId.of(hex("a1a2a3a4"));
    private static final byte[] NO_TOKEN = new byte[0];

    private static Keys handshakeKeys(boolean isServer) {
        return Keys.fromSecrets(new Secrets(EncryptionLevel.HANDSHAKE, CipherSuite.TLS_AES_128_GCM_SHA256,
                hex("b8767708f8772358a6ea9fc43e4add2c961b3f5287a6d1467ee0aeab33724dbf"),
                hex("42dc972140e0f2e39845b767613439dc6758ca43259b878506824eb1e438d855")), isServer);
    }

    /** quinn {@code packet::tests::header_encoding}. */
    @Test
    void quinnHeaderEncoding() throws Exception {
        Keys client = Keys.initial(QuicVersion.V1, DCID, false);
        PacketHeader.Initial header = new PacketHeader.Initial(QuicVersion.V1, DCID, ConnectionId.EMPTY, NO_TOKEN, 0, 1);
        ByteBuffer buf = ByteBuffer.allocate(128);
        HeaderLayout layout = header.encode(buf);
        int end = PacketProtection.protect(buf, layout, layout.payloadOffset() + 16, 0, client.local());
        assertArrayEquals(hex("c8000000010806b858ec6f80452b00004021be"
                + "3ef50807b84191a196f760a6dad1e9d1c430c48952cba0148250c21c0a6a70e1"), Arrays.copyOf(buf.array(), end));

        Keys server = Keys.initial(QuicVersion.V1, DCID, true);
        ProtectedPacket p = ProtectedPacket.parse(ByteBuffer.wrap(Arrays.copyOf(buf.array(), end)), 0);
        Packet packet = p.unprotect(server.remote(), -1);
        assertArrayEquals(hex("c0000000010806b858ec6f80452b0000402100"), Arrays.copyOf(bytes(p.bytes()), 19));
        assertEquals(header, packet.header());
        assertArrayEquals(new byte[16], bytes(packet.payload()));
    }

    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void longHeaderRoundTrips(QuicVersion v) throws Exception {
        Keys initialClient = Keys.initial(v, DCID, false);
        Keys initialServer = Keys.initial(v, DCID, true);
        List<PacketHeader.Numbered> headers = List.of(
                new PacketHeader.Initial(v, DCID, SCID, hex("deadbeef"), 0x1234, 2),
                new PacketHeader.ZeroRtt(v, DCID, SCID, 7, 1),
                new PacketHeader.Handshake(v, DCID, SCID, 0x01020304L, 4));
        for (PacketHeader.Numbered h : headers) {
            DirectionalKeys send = h.type() == PacketType.HANDSHAKE ? handshakeKeys(false).local() : initialClient.local();
            DirectionalKeys recv = h.type() == PacketType.HANDSHAKE ? handshakeKeys(true).remote() : initialServer.remote();
            ByteBuffer buf = ByteBuffer.allocate(256);
            HeaderLayout layout = h.encode(buf);
            int typeBits = (buf.get(0) >> 4) & 0x03;
            assertEquals(h.type().longTypeBits(v), typeBits);
            buf.put(new byte[] {0x01, 0x00, 0x00, 0x00, 0x00});
            int end = PacketProtection.protect(buf, layout, buf.position(), h.packetNumber(), send);

            ProtectedPacket p = ProtectedPacket.parse(buf.duplicate().position(0).limit(end), 0);
            assertEquals(h.type(), p.type());
            assertEquals(v, p.version());
            assertEquals(SCID, p.sourceId());
            assertEquals(layout.packetNumberOffset(), p.packetNumberOffset());
            Packet packet = p.unprotect(recv, h.packetNumber() - 1);
            assertEquals(h, packet.header());
            assertEquals(List.of(new Frame.Ping(), new Frame.Padding(4)),
                    FrameDecoder.decodeAll(packet.payload(), h.type()));
        }
    }

    @Test
    void versionTwoTypeBitsDiffer() {
        assertEquals(1, PacketType.INITIAL.longTypeBits(QuicVersion.V2));
        assertEquals(2, PacketType.ZERO_RTT.longTypeBits(QuicVersion.V2));
        assertEquals(3, PacketType.HANDSHAKE.longTypeBits(QuicVersion.V2));
        assertEquals(0, PacketType.RETRY.longTypeBits(QuicVersion.V2));
        for (PacketType t : List.of(PacketType.INITIAL, PacketType.ZERO_RTT, PacketType.HANDSHAKE, PacketType.RETRY)) {
            for (QuicVersion v : QuicVersion.values()) {
                assertEquals(t, PacketType.fromLongTypeBits(v, t.longTypeBits(v)));
            }
        }
        assertThrows(IllegalStateException.class, () -> PacketType.ONE_RTT.longTypeBits(QuicVersion.V1));
    }

    @Test
    void shortHeaderSpinAndKeyPhase() throws Exception {
        Keys client = handshakeKeys(false);
        Keys server = handshakeKeys(true);
        long pn = 1_000_000;
        for (boolean spin : new boolean[] {false, true}) {
            for (boolean keyPhase : new boolean[] {false, true}) {
                // Every packet gets its own number: the JDK refuses to seal one twice with a key.
                PacketHeader.Short h = new PacketHeader.Short(spin, keyPhase, DCID, ++pn, 3);
                ByteBuffer buf = ByteBuffer.allocate(64);
                HeaderLayout layout = h.encode(buf);
                assertEquals(-1, layout.lengthOffset());
                assertEquals(1 + 8, layout.packetNumberOffset());
                buf.put((byte) 0x01);
                int end = PacketProtection.protect(buf, layout, buf.position(), h.packetNumber(), client.local());
                ProtectedPacket p = ProtectedPacket.parse(buf.duplicate().position(0).limit(end), 8);
                assertNull(p.version());
                assertNull(p.header());
                assertEquals(DCID, p.destinationId());
                PacketHeader.Numbered decoded = p.removeHeaderProtection(server.remote().header(), pn - 1);
                assertEquals(h, decoded);
                assertNotNull(p.decrypt(server.remote().packet()));
            }
        }
    }

    @Test
    void minimumPayloadIsPaddedForTheSample() {
        assertEquals(3, PacketProtection.minPayloadLength(1));
        assertEquals(0, PacketProtection.minPayloadLength(4));
        Keys client = handshakeKeys(false);
        ByteBuffer buf = ByteBuffer.allocate(64);
        HeaderLayout layout = new PacketHeader.Short(false, false, DCID, 0, 1).encode(buf);
        buf.put((byte) 0x01);
        assertThrows(IllegalArgumentException.class,
                () -> PacketProtection.protect(buf, layout, buf.position(), 0, client.local()));

        PacketBuilder b = new PacketBuilder(ByteBuffer.allocate(64), 64);
        b.begin(new PacketHeader.Short(false, false, DCID, 0, 1), client.local()).put((byte) 0x01);
        int end = b.finish();
        assertEquals(1 + 8 + 1 + 3 + 16, end);
    }

    @Test
    void reservedBitsAreAProtocolViolation() throws Exception {
        Keys client = handshakeKeys(false);
        Keys server = handshakeKeys(true);
        ByteBuffer buf = ByteBuffer.allocate(64);
        HeaderLayout layout = new PacketHeader.Short(false, false, DCID, 5, 2).encode(buf);
        buf.put(0, (byte) (buf.get(0) | PacketHeader.SHORT_RESERVED_BITS));
        buf.put(new byte[] {0x01, 0x00, 0x00});
        int end = PacketProtection.protect(buf, layout, buf.position(), 5, client.local());
        ProtectedPacket p = ProtectedPacket.parse(buf.duplicate().position(0).limit(end), 8);
        p.removeHeaderProtection(server.remote().header(), 4);
        QuicException e = assertThrows(QuicException.class, () -> p.decrypt(server.remote().packet()));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());

        ByteBuffer longBuf = ByteBuffer.allocate(64);
        HeaderLayout longLayout = new PacketHeader.Handshake(QuicVersion.V1, DCID, SCID, 6, 2).encode(longBuf);
        longBuf.put(0, (byte) (longBuf.get(0) | PacketHeader.LONG_RESERVED_BITS));
        longBuf.put(new byte[] {0x01, 0x00, 0x00});
        int longEnd = PacketProtection.protect(longBuf, longLayout, longBuf.position(), 6, client.local());
        ProtectedPacket lp = ProtectedPacket.parse(longBuf.duplicate().position(0).limit(longEnd), 8);
        lp.removeHeaderProtection(server.remote().header(), 4);
        assertEquals(QuicException.PROTOCOL_VIOLATION,
                assertThrows(QuicException.class, () -> lp.decrypt(server.remote().packet())).code());
    }

    @Test
    void fixedBitMustBeSetUnlessGreased() throws Exception {
        byte[] shortPacket = new byte[30];
        shortPacket[0] = 0x01; // short header, fixed bit clear
        assertThrows(PacketDecodeException.class, () -> ProtectedPacket.parse(ByteBuffer.wrap(shortPacket), 4));
        assertEquals(PacketType.ONE_RTT, ProtectedPacket.parse(ByteBuffer.wrap(shortPacket), 4, true).type());

        byte[] longPacket = hex("80 00000001 00 00 00 15" + "00".repeat(21));
        assertThrows(PacketDecodeException.class, () -> ProtectedPacket.parse(ByteBuffer.wrap(longPacket), 0));
        assertEquals(PacketType.INITIAL, ProtectedPacket.parse(ByteBuffer.wrap(longPacket), 0, true).type());
    }

    @Test
    void authenticationFailureReturnsNull() throws Exception {
        Keys client = Keys.initial(QuicVersion.V1, DCID, false);
        ByteBuffer buf = ByteBuffer.allocate(64);
        HeaderLayout layout = new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, NO_TOKEN, 3, 1).encode(buf);
        buf.put(new byte[] {0x01, 0x00, 0x00, 0x00});
        int end = PacketProtection.protect(buf, layout, buf.position(), 3, client.local());
        buf.put(end - 1, (byte) (buf.get(end - 1) ^ 0x80));
        ProtectedPacket p = ProtectedPacket.parse(buf.duplicate().position(0).limit(end), 0);
        assertNull(p.unprotect(Keys.initial(QuicVersion.V1, DCID, true).remote(), -1));
        assertThrows(IllegalStateException.class, () -> p.removeHeaderProtection(client.remote().header(), -1));
    }

    @Test
    void coalescedDatagram() throws Exception {
        Keys initialClient = Keys.initial(QuicVersion.V1, DCID, false);
        Keys hsClient = handshakeKeys(false);
        PacketBuilder b = new PacketBuilder(ByteBuffer.allocate(1500), 1500);
        ByteBuffer f = b.begin(new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, NO_TOKEN, 0, 1), initialClient.local());
        Frame.Ack.of(0, null, 0).encode(f);
        int first = b.finish();
        f = b.begin(new PacketHeader.Handshake(QuicVersion.V1, DCID, SCID, 0, 1), hsClient.local());
        new Frame.Crypto(0, ByteBuffer.wrap(new byte[100])).encode(f);
        int second = b.finish();
        f = b.begin(new PacketHeader.Short(false, false, DCID, 1, 1), hsClient.local());
        new Frame.Ping().encode(f);
        b.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);
        ByteBuffer datagram = b.datagram();
        assertEquals(1200, datagram.remaining());

        List<ProtectedPacket> packets = ProtectedPacket.splitDatagram(datagram, 8, false);
        assertEquals(3, packets.size());
        assertEquals(List.of(PacketType.INITIAL, PacketType.HANDSHAKE, PacketType.ONE_RTT),
                packets.stream().map(ProtectedPacket::type).toList());
        assertEquals(0, packets.get(0).start());
        assertEquals(first, packets.get(0).end());
        assertEquals(second, packets.get(1).end());
        assertEquals(1200, packets.get(2).end());
        assertNotNull(packets.get(0).unprotect(Keys.initial(QuicVersion.V1, DCID, true).remote(), -1));
        Packet hs = packets.get(1).unprotect(handshakeKeys(true).remote(), -1);
        assertInstanceOf(Frame.Crypto.class, FrameDecoder.decodeAll(hs.payload(), PacketType.HANDSHAKE).get(0));
        Packet oneRtt = packets.get(2).unprotect(handshakeKeys(true).remote(), -1);
        List<Frame> frames = FrameDecoder.decodeAll(oneRtt.payload(), PacketType.ONE_RTT);
        assertEquals(new Frame.Ping(), frames.get(0));
        assertInstanceOf(Frame.Padding.class, frames.get(1));
    }

    @Test
    void coalescedStopsAtADifferentConnectionIdOrGarbage() throws Exception {
        Keys k = Keys.initial(QuicVersion.V1, DCID, false);
        ByteBuffer buf = ByteBuffer.allocate(512);
        PacketBuilder b = new PacketBuilder(buf, 512);
        b.begin(new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, NO_TOKEN, 0, 1), k.local()).put((byte) 1);
        b.finish();
        ConnectionId other = ConnectionId.of(hex("0000000000000001"));
        b.begin(new PacketHeader.Initial(QuicVersion.V1, other, SCID, NO_TOKEN, 1, 1), k.local()).put((byte) 1);
        b.finish();
        assertEquals(1, ProtectedPacket.splitDatagram(b.datagram(), 8, false).size());

        ByteBuffer padded = ByteBuffer.allocate(300);
        PacketBuilder b2 = new PacketBuilder(padded, 300);
        b2.begin(new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, NO_TOKEN, 0, 1), k.local()).put((byte) 1);
        int end = b2.finish();
        // Zero bytes after the packet, as some stacks pad datagrams, are ignored.
        assertEquals(1, ProtectedPacket.splitDatagram(padded.duplicate().position(0).limit(end + 50), 8, false).size());
    }

    /** quinn {@code tests::version_negotiate_server}: a reserved version in a long header. */
    @Test
    void unsupportedVersion() {
        byte[] header = hex("80 0a1a2a3a 04 00000000 04 00000000 00");
        UnsupportedVersionException e = assertThrows(UnsupportedVersionException.class,
                () -> ProtectedPacket.parse(ByteBuffer.wrap(header), 8));
        assertEquals(0x0a1a2a3a, e.version());
        byte[] vn = e.versionNegotiation(QuicVersion.V1.wireValue(), QuicVersion.V2.wireValue(), 0x1a2a3a4a);
        assertTrue((vn[0] & 0x80) != 0);
        assertArrayEquals(hex("00000000 04 00000000 04 00000000"), Arrays.copyOfRange(vn, 1, 15));
        assertArrayEquals(hex("00000001 6b3343cf 1a2a3a4a"), Arrays.copyOfRange(vn, 15, vn.length));

        // Unknown versions may carry connection IDs longer than 20 bytes (RFC 8999).
        byte[] longIds = new byte[1 + 4 + 1 + 40 + 1 + 30];
        longIds[0] = (byte) 0xc0;
        longIds[4] = 0x02;
        longIds[5] = 40;
        longIds[46] = 30;
        UnsupportedVersionException e2 = assertThrows(UnsupportedVersionException.class,
                () -> ProtectedPacket.parse(ByteBuffer.wrap(longIds), 8));
        assertEquals(40, e2.destinationId().length);
        assertEquals(30, e2.sourceId().length);
        assertEquals(1 + 4 + 1 + 30 + 1 + 40, e2.versionNegotiation().length);
    }

    /** quinn {@code tests::version_negotiate_client}, and an encode round trip. */
    @Test
    void versionNegotiation() throws Exception {
        ProtectedPacket p = ProtectedPacket.parse(ByteBuffer.wrap(hex("80 00000000 00 04 00000000 0a1a2a3a")), 0);
        assertEquals(PacketType.VERSION_NEGOTIATION, p.type());
        PacketHeader.VersionNegotiation vn = assertInstanceOf(PacketHeader.VersionNegotiation.class, p.header());
        assertEquals(ConnectionId.EMPTY, vn.destinationId());
        assertEquals(ConnectionId.of(new byte[4]), vn.sourceId());
        assertEquals(List.of(0x0a1a2a3a), vn.versions());

        PacketHeader.VersionNegotiation out = new PacketHeader.VersionNegotiation(DCID, SCID, List.of(1, 0x6b3343cf));
        ByteBuffer buf = ByteBuffer.allocate(64);
        out.encode(buf);
        assertEquals(out, ProtectedPacket.parse(buf.flip(), 0).header());

        // The fixed bit does not matter in Version Negotiation; a ragged version list does.
        assertEquals(PacketType.VERSION_NEGOTIATION,
                ProtectedPacket.parse(ByteBuffer.wrap(hex("80 00000000 00 00 00000001")), 0).type());
        assertThrows(PacketDecodeException.class,
                () -> ProtectedPacket.parse(ByteBuffer.wrap(hex("80 00000000 00 00 000001")), 0));
    }

    @Test
    void retryParsing() throws Exception {
        PacketHeader.Retry retry = PacketHeader.Retry.create(QuicVersion.V2, SCID, DCID, hex("0102030405"), ConnectionId.of(hex("99")));
        ByteBuffer buf = ByteBuffer.allocate(64);
        retry.encode(buf);
        ProtectedPacket p = ProtectedPacket.parse(buf.flip(), 0);
        assertEquals(PacketType.RETRY, p.type());
        assertEquals(retry, p.header());
        assertEquals(-1, p.sampleOffset());
        assertTrue(p.verifyRetry(ConnectionId.of(hex("99"))));
        assertThrows(IllegalStateException.class, () -> p.removeHeaderProtection(null, 0));
        // Shorter than the integrity tag.
        assertThrows(PacketDecodeException.class,
                () -> ProtectedPacket.parse(ByteBuffer.wrap(hex("f0 00000001 00 00 0102030405")), 0));
    }

    /** quinn {@code tests::malformed_token_len}, {@code tests::reject_short_idcid} and other bad headers. */
    @Test
    void malformedHeaders() throws Exception {
        assertThrows(PacketDecodeException.class,
                () -> ProtectedPacket.parse(ByteBuffer.wrap(hex("8900 0000 0101 0000 1b1b 841b 0000 0000 3f00")), 8));
        // An empty DCID still parses; the server decides whether it is long enough.
        byte[] emptyDcid = Arrays.copyOf(hex("c4 00000001 00 00 00 3f"), 1200);
        assertEquals(ConnectionId.EMPTY, ProtectedPacket.parse(ByteBuffer.wrap(emptyDcid), 8).destinationId());
        // Length beyond the datagram.
        assertThrows(PacketDecodeException.class,
                () -> ProtectedPacket.parse(ByteBuffer.wrap(Arrays.copyOf(hex("c0 00000001 00 00 00 4400"), 100)), 0));
        // Too short to sample.
        assertThrows(PacketDecodeException.class,
                () -> ProtectedPacket.parse(ByteBuffer.wrap(Arrays.copyOf(hex("c0 00000001 00 00 00 13"), 30)), 0));
        assertThrows(PacketDecodeException.class, () -> ProtectedPacket.parse(ByteBuffer.wrap(new byte[] {0x40, 1, 2}), 0));
        // A connection ID over 20 bytes in version 1.
        byte[] longId = new byte[100];
        longId[0] = (byte) 0xc0;
        longId[4] = 1;
        longId[5] = 21;
        assertThrows(PacketDecodeException.class, () -> ProtectedPacket.parse(ByteBuffer.wrap(longId), 0));
        // Truncated inside the version.
        ByteBuffer truncated = ByteBuffer.wrap(hex("c0 0000"));
        assertThrows(PacketDecodeException.class, () -> ProtectedPacket.parse(truncated, 0));
        assertEquals(0, truncated.position());
    }

    @Test
    void initialTokenSurvives() throws Exception {
        Keys k = Keys.initial(QuicVersion.V2, DCID, false);
        PacketBuilder b = new PacketBuilder(ByteBuffer.allocate(1500), 1350);
        byte[] token = new byte[300];
        Arrays.fill(token, (byte) 0x5a);
        ByteBuffer f = b.begin(new PacketHeader.Initial(QuicVersion.V2, DCID, SCID, token, 9, 2), k.local());
        assertEquals(1350 - (1 + 4 + 1 + 8 + 1 + 4 + 2 + 300 + 2 + 2) - 16, b.remaining());
        new Frame.Ping().encode(f);
        b.finish(1200);
        ProtectedPacket p = ProtectedPacket.parse(b.datagram(), 0);
        assertArrayEquals(token, p.token());
        PacketHeader.Initial h = (PacketHeader.Initial) p.unprotect(Keys.initial(QuicVersion.V2, DCID, true).remote(), 8).header();
        assertArrayEquals(token, h.token());
        assertEquals(9, h.packetNumber());
    }

    @Test
    void builderRejectsAHeaderThatDoesNotFit() {
        Keys k = handshakeKeys(false);
        PacketBuilder b = new PacketBuilder(ByteBuffer.allocate(100), 30);
        assertThrows(java.nio.BufferOverflowException.class,
                () -> b.begin(new PacketHeader.Initial(QuicVersion.V1, DCID, SCID, new byte[20], 0, 1), k.local()));
        assertEquals(0, b.remaining());
        assertThrows(IllegalStateException.class, b::finish);
        b.begin(new PacketHeader.Short(false, false, DCID, 0, 1), k.local());
        assertEquals(30 - 10 - 16, b.remaining());
        assertThrows(IllegalStateException.class,
                () -> b.begin(new PacketHeader.Short(false, false, DCID, 1, 1), k.local()));
        assertThrows(IllegalStateException.class, () -> b.finish(1200));
        assertEquals(29, b.finish());
    }

    private static byte[] bytes(ByteBuffer b) {
        byte[] out = new byte[b.remaining()];
        b.duplicate().get(out);
        return out;
    }
}
