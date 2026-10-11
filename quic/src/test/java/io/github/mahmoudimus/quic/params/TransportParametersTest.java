package io.github.mahmoudimus.quic.params;

import static io.github.mahmoudimus.quic.TestVectors.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.VarInt;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Random;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

class TransportParametersTest {

    private static final StatelessResetToken TOKEN = StatelessResetToken.of(hex("abababababababababababababababab"));

    private static PreferredAddress preferredAddress(ConnectionId cid) throws Exception {
        return new PreferredAddress(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 42),
                new InetSocketAddress(InetAddress.getByName("::1"), 24), cid, TOKEN);
    }

    private static void assertRejected(byte[] encoded, boolean sentByServer) {
        QuicException e = assertThrows(QuicException.class, () -> TransportParameters.decode(encoded, sentByServer));
        assertEquals(QuicException.TRANSPORT_PARAMETER_ERROR, e.code());
    }

    private static byte[] param(long id, byte[] value) {
        ByteBuffer out = ByteBuffer.allocate(16 + value.length);
        VarInt.write(out, id);
        VarInt.write(out, value.length);
        out.put(value);
        byte[] b = new byte[out.position()];
        out.flip().get(b);
        return b;
    }

    private static byte[] concat(byte[]... parts) {
        ByteBuffer out = ByteBuffer.allocate(1024);
        for (byte[] p : parts) out.put(p);
        byte[] b = new byte[out.position()];
        out.flip().get(b);
        return b;
    }

    /** quinn {@code transport_parameters::test::coding}, with every parameter set. */
    @Test
    void coding() throws Exception {
        TransportParameters params = TransportParameters.builder()
                .initialSourceConnectionId(ConnectionId.EMPTY)
                .originalDestinationConnectionId(ConnectionId.EMPTY)
                .initialMaxStreamsBidi(16)
                .initialMaxStreamsUni(16)
                .ackDelayExponent(2)
                .maxUdpPayloadSize(1200)
                .preferredAddress(preferredAddress(ConnectionId.of(hex("42"))))
                .greaseQuicBit(true)
                .minAckDelay(2_000)
                .build();
        byte[] encoded = params.encode();
        assertEquals(encoded.length, params.encodedLength());
        assertEquals(params, TransportParameters.decode(encoded, true));
    }

    @Test
    void everyParameterRoundTrips() throws Exception {
        TransportParameters params = TransportParameters.builder()
                .originalDestinationConnectionId(ConnectionId.of(hex("0102030405060708")))
                .maxIdleTimeout(30_000)
                .statelessResetToken(TOKEN)
                .maxUdpPayloadSize(1452)
                .initialMaxData(VarInt.MAX)
                .initialMaxStreamDataBidiLocal(1 << 20)
                .initialMaxStreamDataBidiRemote(1 << 21)
                .initialMaxStreamDataUni(63)
                .initialMaxStreamsBidi(TransportParameters.MAX_STREAM_COUNT)
                .initialMaxStreamsUni(64)
                .ackDelayExponent(20)
                .maxAckDelay((1 << 14) - 1)
                .disableActiveMigration(true)
                .preferredAddress(new PreferredAddress(null, new InetSocketAddress(InetAddress.getByName("2001:db8::1"), 443),
                        ConnectionId.of(new byte[20]), TOKEN))
                .activeConnectionIdLimit(8)
                .initialSourceConnectionId(ConnectionId.of(hex("aa")))
                .retrySourceConnectionId(ConnectionId.of(hex("bb")))
                .maxDatagramFrameSize(65535)
                .greaseQuicBit(true)
                .minAckDelay(1000)
                .versionInformation(new VersionInformation(0x6b3343cf, List.of(0x6b3343cf, 1, 0x1a2a3a4a)))
                .addUnknownParameter(UnknownParameter.grease(new Random(5)))
                .addUnknownParameter(new UnknownParameter(0x7fff, hex("cafe")))
                .build();
        byte[] encoded = params.encode();
        assertEquals(encoded.length, params.encodedLength());
        TransportParameters decoded = TransportParameters.decode(encoded, true);
        assertEquals(params, decoded);
        assertEquals(params, params.toBuilder().build());
    }

    @Test
    void defaults() throws QuicException {
        TransportParameters d = TransportParameters.decode(new byte[0], false);
        assertEquals(TransportParameters.defaults(), d);
        assertEquals(65527, d.maxUdpPayloadSize());
        assertEquals(3, d.ackDelayExponent());
        assertEquals(25, d.maxAckDelay());
        assertEquals(2, d.activeConnectionIdLimit());
        assertEquals(-1, d.minAckDelay());
        assertEquals(0, d.maxDatagramFrameSize());
        assertEquals(0, TransportParameters.defaults().encode().length, "defaults are not encoded");
        // An explicit default value decodes the same.
        assertEquals(d, TransportParameters.decode(param(0x0a, hex("03")), false));
    }

    /** quinn {@code reserved_transport_parameter_ignored_when_read}, preserved here instead. */
    @Test
    void greaseParametersArePreserved() throws QuicException {
        Random r = new Random(1);
        for (int i = 0; i < 100; i++) {
            UnknownParameter g = UnknownParameter.grease(r);
            assertTrue(UnknownParameter.isReserved(g.id()));
            assertTrue(g.value().length < UnknownParameter.MAX_GREASE_LENGTH);
            TransportParameters p = TransportParameters.decode(param(g.id(), g.value()), false);
            assertEquals(List.of(g), p.unknownParameters());
            assertEquals(TransportParameters.defaults(), TransportParameters.builder().build());
            assertArrayEquals(param(g.id(), g.value()), p.encode(), "re-encoded as received");
        }
    }

    @Test
    void serverOnlyParametersFromAClient() throws Exception {
        List<UnaryOperator<TransportParameters.Builder>> serverOnly = List.of(
                b -> b.originalDestinationConnectionId(ConnectionId.of(hex("01"))),
                b -> b.statelessResetToken(TOKEN),
                b -> b.retrySourceConnectionId(ConnectionId.of(hex("01"))),
                b -> {
                    try {
                        return b.preferredAddress(preferredAddress(ConnectionId.of(hex("01"))));
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
        for (UnaryOperator<TransportParameters.Builder> f : serverOnly) {
            byte[] encoded = f.apply(TransportParameters.builder()).build().encode();
            assertDoesNotThrow(() -> TransportParameters.decode(encoded, true));
            assertRejected(encoded, false);
        }
    }

    /** quinn {@code read_semantic_validation} and RFC 9000 section 18.2 limits. */
    @Test
    void limits() throws Exception {
        List<UnaryOperator<TransportParameters.Builder>> illegal = List.of(
                b -> b.maxUdpPayloadSize(1199),
                b -> b.ackDelayExponent(21),
                b -> b.maxAckDelay(1 << 14),
                b -> b.activeConnectionIdLimit(1),
                b -> b.activeConnectionIdLimit(0),
                b -> b.initialMaxStreamsBidi(TransportParameters.MAX_STREAM_COUNT + 1),
                b -> b.initialMaxStreamsUni(TransportParameters.MAX_STREAM_COUNT + 1),
                b -> b.minAckDelay(25 * 1000 + 1),
                b -> {
                    try {
                        return b.preferredAddress(preferredAddress(ConnectionId.EMPTY));
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
        for (UnaryOperator<TransportParameters.Builder> f : illegal) {
            assertRejected(f.apply(TransportParameters.builder()).build().encode(), true);
        }
        assertDoesNotThrow(() -> TransportParameters.decode(TransportParameters.builder().maxUdpPayloadSize(1200)
                .ackDelayExponent(20).maxAckDelay((1 << 14) - 1).minAckDelay(25_000).build().encode(), true));
    }

    @Test
    void duplicates() {
        byte[] p = param(0x04, hex("4064"));
        assertRejected(concat(p, p), false);
        byte[] g = param(27, hex("01"));
        assertRejected(concat(g, g), false);
        byte[] flag = param(0x0c, new byte[0]);
        assertRejected(concat(flag, flag), false);
    }

    /** quinn {@code read_length_mismatch}, {@code read_min_ack_delay_length_mismatch} and others. */
    @Test
    void malformed() throws Exception {
        // max_datagram_frame_size claims three bytes but holds a one-byte varint.
        assertRejected(concat(param(0x20, hex("000c00")), param(0x0c, new byte[0])), false);
        // min_ack_delay claims no value.
        assertRejected(concat(param(0xff04de1bL, new byte[0]), param(0x04, hex("07"))), false);
        // preferred_address has a fixed size, so a parameter inside its declared length is trailing.
        PreferredAddress address = preferredAddress(ConnectionId.of(hex("42")));
        ByteBuffer pa = ByteBuffer.allocate(address.encodedLength() + 2);
        address.encode(pa);
        pa.put(hex("0c00"));
        assertRejected(param(0x0d, pa.array()), true);
        assertDoesNotThrow(() -> TransportParameters.decode(
                param(0x0d, java.util.Arrays.copyOf(pa.array(), address.encodedLength())), true));
        assertRejected(param(0x0d, new byte[10]), true); // truncated
        assertRejected(param(0x0d, new byte[41]), true); // neither address
        assertRejected(param(0x02, new byte[15]), true); // short reset token
        assertRejected(param(0x0f, new byte[21]), false); // connection ID too long
        assertRejected(param(0x0c, hex("00")), false); // flag with a value
        assertRejected(param(0x2ab2, hex("01")), false);
        assertRejected(hex("04 05 01"), false); // length beyond the extension
        assertRejected(hex("04"), false); // truncated
        // Integer values need not be minimally encoded (RFC 9000 section 16), but must fill the length.
        assertDoesNotThrow(() -> TransportParameters.decode(param(0x04, hex("4001")), false));
        assertRejected(param(0x04, hex("400100")), false);
    }

    @Test
    void versionInformation() throws QuicException {
        assertRejected(param(0x11, hex("000001")), false); // not a multiple of 4
        assertRejected(param(0x11, new byte[0]), false); // empty
        assertRejected(param(0x11, hex("00000000 00000001")), true); // chosen version 0
        assertRejected(param(0x11, hex("00000001 00000000")), true); // available version 0
        // A client must list its chosen version; a server need not.
        assertRejected(param(0x11, hex("00000001 6b3343cf")), false);
        VersionInformation server = TransportParameters.decode(param(0x11, hex("00000001 6b3343cf")), true).versionInformation();
        assertEquals(new VersionInformation(1, List.of(0x6b3343cf)), server);
        assertEquals(new VersionInformation(1, List.of()),
                TransportParameters.decode(param(0x11, hex("00000001")), true).versionInformation());
    }

    @Test
    void connectionIdAuthentication() throws QuicException {
        ConnectionId clientScid = ConnectionId.of(hex("c1"));
        ConnectionId serverScid = ConnectionId.of(hex("5e"));
        ConnectionId odcid = ConnectionId.of(hex("0d"));
        ConnectionId retryScid = ConnectionId.of(hex("7e"));
        TransportParameters client = TransportParameters.builder().initialSourceConnectionId(clientScid).build();
        client.authenticateConnectionIds(false, clientScid, null, null);
        assertThrows(QuicException.class, () -> client.authenticateConnectionIds(false, serverScid, null, null));
        assertThrows(QuicException.class,
                () -> TransportParameters.defaults().authenticateConnectionIds(false, clientScid, null, null));

        TransportParameters server = TransportParameters.builder().initialSourceConnectionId(serverScid)
                .originalDestinationConnectionId(odcid).build();
        server.authenticateConnectionIds(true, serverScid, odcid, null);
        assertThrows(QuicException.class, () -> server.authenticateConnectionIds(true, serverScid, odcid, retryScid));
        assertThrows(QuicException.class, () -> server.authenticateConnectionIds(true, serverScid, clientScid, null));
        TransportParameters retried = server.toBuilder().retrySourceConnectionId(retryScid).build();
        retried.authenticateConnectionIds(true, serverScid, odcid, retryScid);
        QuicException e = assertThrows(QuicException.class, () -> retried.authenticateConnectionIds(true, serverScid, odcid, null));
        assertEquals(QuicException.TRANSPORT_PARAMETER_ERROR, e.code());
    }

    @Test
    void unknownParameterValueSemantics() {
        UnknownParameter a = new UnknownParameter(99, hex("0102"));
        assertEquals(a, new UnknownParameter(99, hex("0102")));
        assertEquals(a.hashCode(), new UnknownParameter(99, hex("0102")).hashCode());
        byte[] v = a.value();
        v[0] = 9;
        assertArrayEquals(hex("0102"), a.value());
        assertThrows(IllegalArgumentException.class, () -> new UnknownParameter(-1, new byte[0]));
    }
}
