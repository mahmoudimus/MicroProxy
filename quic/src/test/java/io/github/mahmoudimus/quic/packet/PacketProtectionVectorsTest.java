package io.github.mahmoudimus.quic.packet;

import static io.github.mahmoudimus.quic.TestVectors.hex;
import static io.github.mahmoudimus.quic.TestVectors.vector;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.Hkdf;
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

/** The sample packets of RFC 9001 appendix A and RFC 9369 appendix A, byte for byte. */
class PacketProtectionVectorsTest {

    private static final ConnectionId CLIENT_DCID = ConnectionId.of(hex("8394c8f03e515708"));
    private static final ConnectionId SERVER_SCID = ConnectionId.of(hex("f067a5502a4262b5"));
    private static final byte[] CHACHA_SECRET = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    private static final byte[] EMPTY = new byte[0];

    private static String rfc(QuicVersion v) {
        return v == QuicVersion.V1 ? "rfc9001" : "rfc9369";
    }

    /** RFC 9001 A.1 and RFC 9369 A.1. */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void initialKeys(QuicVersion v) {
        Secrets s = Keys.initialSecrets(v, CLIENT_DCID);
        Hkdf h = Hkdf.SHA256;
        boolean v1 = v == QuicVersion.V1;
        assertArrayEquals(hex(v1 ? "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
                : "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"), s.client());
        assertArrayEquals(hex(v1 ? "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
                : "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"), s.server());
        assertArrayEquals(hex(v1 ? "1f369613dd76d5467730efcbe3b1a22d" : "8b1a0bc121284290a29e0971b5cd045d"),
                h.expandLabel(s.client(), v.keyLabel(), EMPTY, 16));
        assertArrayEquals(hex(v1 ? "9f50449e04a0e810283a1e9933adedd2" : "45b95e15235d6f45a6b19cbcb0294ba9"),
                h.expandLabel(s.client(), v.headerProtectionLabel(), EMPTY, 16));
        assertArrayEquals(hex(v1 ? "cf3a5331653c364c88f0f379b6067e37" : "82db637861d55e1d011f19ea71d5d2a7"),
                h.expandLabel(s.server(), v.keyLabel(), EMPTY, 16));
        assertArrayEquals(hex(v1 ? "c206b8d9b9f0f37644430b490eeaa314" : "edf6d05c83121201b436e16877593c3a"),
                h.expandLabel(s.server(), v.headerProtectionLabel(), EMPTY, 16));

        Keys client = Keys.initial(v, CLIENT_DCID, false);
        Keys server = Keys.initial(v, CLIENT_DCID, true);
        // The IV is the nonce of packet number 0.
        assertArrayEquals(hex(v1 ? "fa044b2f42a3fd3b46fb255c" : "91f73e2351d8fa91660e909f"), client.local().packet().nonce(0));
        assertArrayEquals(hex(v1 ? "fa044b2f42a3fd3b46fb255c" : "91f73e2351d8fa91660e909f"), server.remote().packet().nonce(0));
        assertArrayEquals(hex(v1 ? "0ac1493ca1905853b0bba03e" : "dd13c276499c0249d3310652"), server.local().packet().nonce(0));
        assertEquals(CipherSuite.TLS_AES_128_GCM_SHA256, s.suite());
    }

    /** RFC 9001 A.2: the header protection mask of the client Initial. */
    @Test
    void clientInitialMask() {
        Keys client = Keys.initial(QuicVersion.V1, CLIENT_DCID, false);
        assertArrayEquals(hex("437b9aec36"), client.local().header().mask(hex("d1b1c98dd7689fb8ec11d242b123dc9b")));
        assertArrayEquals(hex("2ec0d8356a"),
                Keys.initial(QuicVersion.V1, CLIENT_DCID, true).local().header().mask(hex("2cd0991cd25b0aac406a5816b6394100")));
    }

    /** RFC 9001 A.2 and RFC 9369 A.2: the whole protected client Initial from its payload. */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void clientInitial(QuicVersion v) throws Exception {
        byte[] crypto = vector(rfc(v) + ".client-initial.payload");
        PacketHeader.Initial header = new PacketHeader.Initial(v, CLIENT_DCID, ConnectionId.EMPTY, EMPTY, 2, 4);

        ByteBuffer buf = ByteBuffer.allocate(1500);
        HeaderLayout layout = header.encode(buf);
        buf.put(crypto);
        int payloadEnd = layout.payloadOffset() + 1162;
        int end = PacketProtection.protect(buf, layout, payloadEnd, 2, Keys.initial(v, CLIENT_DCID, false).local());
        assertEquals(1200, end);
        assertArrayEquals(vector(rfc(v) + ".client-initial.protected"), Arrays.copyOf(buf.array(), end));

        // The unprotected header, as RFC 9001 shows it.
        ByteBuffer plain = ByteBuffer.allocate(64);
        HeaderLayout l2 = header.encode(plain);
        plain.putShort(l2.lengthOffset(), (short) (0x4000 | 1182));
        assertArrayEquals(vector(rfc(v) + ".client-initial.header"), Arrays.copyOf(plain.array(), l2.payloadOffset()));

        // The server removes protection.
        ByteBuffer datagram = ByteBuffer.wrap(vector(rfc(v) + ".client-initial.protected"));
        ProtectedPacket p = ProtectedPacket.parse(datagram, 8);
        assertEquals(PacketType.INITIAL, p.type());
        assertEquals(v, p.version());
        assertEquals(CLIENT_DCID, p.destinationId());
        assertEquals(ConnectionId.EMPTY, p.sourceId());
        assertEquals(18, p.packetNumberOffset());
        assertEquals(22, p.sampleOffset());
        assertEquals(1200, p.length());
        assertFalse(datagram.hasRemaining());
        Packet packet = p.unprotect(Keys.initial(p.version(), p.destinationId(), true).remote(), -1);
        assertNotNull(packet);
        assertEquals(header, packet.header());
        assertArrayEquals(vector(rfc(v) + ".client-initial.header"), Arrays.copyOf(datagram.array(), 22));
        assertEquals(1162, packet.payload().remaining());
        List<Frame> frames = FrameDecoder.decodeAll(packet.payload(), PacketType.INITIAL);
        assertEquals(2, frames.size());
        Frame.Crypto c = assertInstanceOf(Frame.Crypto.class, frames.get(0));
        assertEquals(0, c.offset());
        assertEquals(241, c.data().remaining());
        assertEquals(new Frame.Padding(1162 - crypto.length), frames.get(1));
    }

    /** The client Initial again, built by {@link PacketBuilder} with a CRYPTO frame and padding. */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void clientInitialFromBuilder(QuicVersion v) {
        byte[] crypto = vector(rfc(v) + ".client-initial.payload");
        PacketBuilder b = new PacketBuilder(ByteBuffer.allocate(1500), 1500);
        ByteBuffer frames = b.begin(new PacketHeader.Initial(v, CLIENT_DCID, ConnectionId.EMPTY, EMPTY, 2, 4),
                Keys.initial(v, CLIENT_DCID, false).local());
        ByteBuffer data = ByteBuffer.wrap(crypto, 4, crypto.length - 4); // past the frame header
        assertEquals(241, Frame.Crypto.encode(frames, 0, data, frames.remaining()));
        // quinn's two-byte length reservation is not needed: the CRYPTO frame matches the RFC.
        b.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);
        ByteBuffer datagram = b.datagram();
        byte[] out = new byte[datagram.remaining()];
        datagram.get(out);
        assertArrayEquals(vector(rfc(v) + ".client-initial.protected"), out);
    }

    /** RFC 9001 A.3 and RFC 9369 A.3: the server Initial. */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void serverInitial(QuicVersion v) throws Exception {
        byte[] payload = vector(rfc(v) + ".server-initial.payload");
        PacketHeader.Initial header = new PacketHeader.Initial(v, ConnectionId.EMPTY, SERVER_SCID, EMPTY, 1, 2);
        ByteBuffer buf = ByteBuffer.allocate(256);
        HeaderLayout layout = header.encode(buf);
        buf.put(payload);
        int end = PacketProtection.protect(buf, layout, buf.position(), 1, Keys.initial(v, CLIENT_DCID, true).local());
        assertArrayEquals(vector(rfc(v) + ".server-initial.protected"), Arrays.copyOf(buf.array(), end));

        ProtectedPacket p = ProtectedPacket.parse(ByteBuffer.wrap(vector(rfc(v) + ".server-initial.protected")), 0);
        assertEquals(SERVER_SCID, p.sourceId());
        assertEquals(22, p.sampleOffset());
        Packet packet = p.unprotect(Keys.initial(v, CLIENT_DCID, false).remote(), -1);
        assertEquals(header, packet.header());
        byte[] plain = new byte[packet.payload().remaining()];
        packet.payload().get(plain);
        assertArrayEquals(payload, plain);
        List<Frame> frames = FrameDecoder.decodeAll(packet.payload(), PacketType.INITIAL);
        assertEquals(Frame.Ack.of(0, null, 0), frames.get(0));
        assertInstanceOf(Frame.Crypto.class, frames.get(1));
    }

    /** RFC 9001 A.4 and RFC 9369 A.4: the Retry packet and its integrity tag. */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void retry(QuicVersion v) throws Exception {
        byte[] bytes = vector(rfc(v) + ".retry");
        PacketHeader.Retry built = PacketHeader.Retry.create(v, ConnectionId.EMPTY, SERVER_SCID,
                "token".getBytes(java.nio.charset.StandardCharsets.US_ASCII), CLIENT_DCID);
        ByteBuffer buf = ByteBuffer.allocate(64);
        built.encode(buf);
        assertArrayEquals(bytes, Arrays.copyOf(buf.array(), buf.position()));

        ProtectedPacket p = ProtectedPacket.parse(ByteBuffer.wrap(bytes), 8);
        assertEquals(PacketType.RETRY, p.type());
        assertEquals(built, p.header());
        assertEquals("token", new String(p.token(), java.nio.charset.StandardCharsets.US_ASCII));
        assertTrue(p.verifyRetry(CLIENT_DCID));
        assertFalse(p.verifyRetry(ConnectionId.of(hex("8394c8f03e515709"))));
        bytes[bytes.length - 1] ^= 1;
        assertFalse(ProtectedPacket.parse(ByteBuffer.wrap(bytes), 8).verifyRetry(CLIENT_DCID));
    }

    /** RFC 9001 A.5 and RFC 9369 A.5: a ChaCha20-Poly1305 short header packet. */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void chaCha20ShortHeader(QuicVersion v) throws Exception {
        boolean v1 = v == QuicVersion.V1;
        CipherSuite suite = CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
        assertArrayEquals(hex(v1 ? "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"
                : "3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2"),
                suite.hkdf().expandLabel(CHACHA_SECRET, v.keyLabel(), EMPTY, 32));
        assertArrayEquals(hex(v1 ? "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"
                : "d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2"),
                suite.hkdf().expandLabel(CHACHA_SECRET, v.headerProtectionLabel(), EMPTY, 32));
        DirectionalKeys keys = DirectionalKeys.fromSecret(suite, CHACHA_SECRET, v);
        long pn = 654360564;
        assertArrayEquals(hex(v1 ? "e0459b3474bdd0e46d417eb0" : "a6b5bc6ab7dafce328ff4a29"), keys.packet().nonce(pn));
        assertArrayEquals(hex(v1 ? "aefefe7d03" : "97580e32bf"),
                keys.header().mask(hex(v1 ? "5e5cd55c41f69080575d7999c25a5bfb" : "e7b6b932bc27d786f4bc2bb20f2162ba")));

        PacketHeader.Short header = new PacketHeader.Short(false, false, ConnectionId.EMPTY, pn, 3);
        ByteBuffer buf = ByteBuffer.allocate(64);
        HeaderLayout layout = header.encode(buf);
        assertArrayEquals(hex("4200bff4"), Arrays.copyOf(buf.array(), 4));
        buf.put((byte) 0x01);
        int end = PacketProtection.protect(buf, layout, buf.position(), pn, keys);
        byte[] expected = hex(v1 ? "4cfe4189655e5cd55c41f69080575d7999c25a5bfb" : "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba");
        assertArrayEquals(expected, Arrays.copyOf(buf.array(), end));

        ProtectedPacket p = ProtectedPacket.parse(ByteBuffer.wrap(expected.clone()), 0);
        assertEquals(PacketType.ONE_RTT, p.type());
        PacketHeader.Numbered h = p.removeHeaderProtection(DirectionalKeys.fromSecret(suite, CHACHA_SECRET, v).header(), pn - 1);
        assertEquals(header, h);
        Packet packet = p.decrypt(DirectionalKeys.fromSecret(suite, CHACHA_SECRET, v).packet());
        assertEquals(List.of(new Frame.Ping()), FrameDecoder.decodeAll(packet.payload(), PacketType.ONE_RTT));
    }

    /** RFC 9001 A.5 and RFC 9369 A.5: the key update secret ({@code "quic ku"}). */
    @ParameterizedTest
    @EnumSource(QuicVersion.class)
    void chaCha20KeyUpdateSecret(QuicVersion v) {
        assertArrayEquals(hex(v == QuicVersion.V1
                        ? "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"
                        : "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88"),
                Keys.nextSecret(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CHACHA_SECRET, v));
    }

    /** rustls {@code quic::tests::key_update_test_vector}. */
    @Test
    void keyUpdateVector() {
        Secrets secrets = new Secrets(io.github.mahmoudimus.quic.EncryptionLevel.ONE_RTT, CipherSuite.TLS_AES_128_GCM_SHA256,
                hex("b8767708f8772358a6ea9fc43e4add2c961b3f5287a6d1467ee0aeab33724dbf"),
                hex("42dc972140e0f2e39845b767613439dc6758ca43259b878506824eb1e438d855"));
        Secrets next = Keys.nextSecrets(secrets, QuicVersion.V1);
        assertArrayEquals(hex("42cac8c91cd5eb40682e432edf2d2be9f41a52ca6b22d8e6cdb1e8aca9061fce"), next.client());
        assertArrayEquals(hex("eb7f5e2a123f407db499e361cae590d4d992e14b7ace03c244e0422115b6d38a"), next.server());
    }

    /** Packets sealed after a key update open only with the updated keys; header keys stay. */
    @Test
    void keyUpdateKeepsHeaderKeys() throws Exception {
        Secrets secrets = new Secrets(io.github.mahmoudimus.quic.EncryptionLevel.ONE_RTT, CipherSuite.TLS_AES_256_GCM_SHA384,
                hex("b8767708f8772358a6ea9fc43e4add2c961b3f5287a6d1467ee0aeab33724dbf8f3e4a5c6d7e8f90a1b2c3d4e5f60718"),
                hex("42dc972140e0f2e39845b767613439dc6758ca43259b878506824eb1e438d8551122334455667788990011223344aabb"));
        Keys client = Keys.fromSecrets(secrets, false);
        Keys server = Keys.fromSecrets(secrets, true);
        Secrets next = Keys.nextSecrets(secrets, QuicVersion.V1);
        Keys client2 = client.update(next, false, QuicVersion.V1);
        Keys server2 = server.update(next, true, QuicVersion.V1);
        assertEquals(client.local().header(), client2.local().header());
        assertEquals(client.remote().header(), client2.remote().header());

        ConnectionId dcid = ConnectionId.of(hex("0102030405060708"));
        ByteBuffer buf = ByteBuffer.allocate(128);
        PacketHeader.Short header = new PacketHeader.Short(true, true, dcid, 77, 2);
        HeaderLayout layout = header.encode(buf);
        buf.put(new byte[] {0x01, 0x00, 0x00, 0x00});
        int end = PacketProtection.protect(buf, layout, buf.position(), 77, client2.local());
        byte[] wire = Arrays.copyOf(buf.array(), end);

        ProtectedPacket stale = ProtectedPacket.parse(ByteBuffer.wrap(wire.clone()), 8);
        PacketHeader.Numbered h = stale.removeHeaderProtection(server.remote().header(), 70);
        assertTrue(((PacketHeader.Short) h).keyPhase());
        assertTrue(((PacketHeader.Short) h).spin());
        assertEquals(77, h.packetNumber());
        assertEquals(null, stale.decrypt(server.remote().packet()));

        ProtectedPacket fresh = ProtectedPacket.parse(ByteBuffer.wrap(wire.clone()), 8);
        fresh.removeHeaderProtection(server2.remote().header(), 70);
        assertNotNull(fresh.decrypt(server2.remote().packet()));
    }
}
