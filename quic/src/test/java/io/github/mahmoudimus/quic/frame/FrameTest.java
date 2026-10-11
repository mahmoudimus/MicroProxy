package io.github.mahmoudimus.quic.frame;

import static io.github.mahmoudimus.quic.TestVectors.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.packet.PacketType;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.LongStream;
import org.junit.jupiter.api.Test;

class FrameTest {

    private static final long[] EDGES = {0, 1, 63, 64, 16383, 16384, (1L << 30) - 1, 1L << 30, VarInt.MAX};
    private static final StatelessResetToken TOKEN = StatelessResetToken.of(hex("00112233445566778899aabbccddeeff"));

    private static ByteBuffer bytes(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (i * 7 + 1);
        return ByteBuffer.wrap(b);
    }

    private static byte[] encode(Frame f) {
        ByteBuffer out = ByteBuffer.allocate(f.encodedLength());
        f.encode(out);
        assertFalse(out.hasRemaining(), "encodedLength matches for " + f);
        return out.array();
    }

    private static Frame roundTrip(Frame f) throws FrameException {
        ByteBuffer in = ByteBuffer.wrap(encode(f));
        Frame decoded = FrameDecoder.decode(in);
        assertFalse(in.hasRemaining());
        assertEquals(f, decoded);
        assertEquals(f.typeCode(), decoded.typeCode());
        return decoded;
    }

    private static List<Frame> allFrames() {
        List<Frame> frames = new ArrayList<>();
        frames.add(new Frame.Padding(1));
        frames.add(new Frame.Padding(17));
        frames.add(new Frame.Ping());
        frames.add(new Frame.HandshakeDone());
        frames.add(new Frame.ImmediateAck());
        for (long v : EDGES) {
            frames.add(new Frame.ResetStream(v, VarInt.MAX - v, v));
            frames.add(new Frame.StopSending(v, v));
            frames.add(new Frame.Crypto(v == VarInt.MAX ? v - 5 : v, bytes(5)));
            frames.add(new Frame.MaxData(v));
            frames.add(new Frame.MaxStreamData(v, VarInt.MAX - v));
            frames.add(new Frame.DataBlocked(v));
            frames.add(new Frame.StreamDataBlocked(v, v));
            frames.add(new Frame.RetireConnectionId(v));
            frames.add(new Frame.AckFrequency(v, v, v, v));
            frames.add(new Frame.ConnectionClose(v, v, bytes(3)));
            frames.add(new Frame.ApplicationClose(v, bytes(0)));
            if (v <= Frame.MAX_STREAM_COUNT) {
                frames.add(new Frame.MaxStreams(true, v));
                frames.add(new Frame.MaxStreams(false, v));
                frames.add(new Frame.StreamsBlocked(true, v));
                frames.add(new Frame.StreamsBlocked(false, v));
            }
            for (boolean fin : new boolean[] {false, true}) {
                frames.add(new Frame.Stream(v, v == VarInt.MAX ? v - 100 : v, bytes(100), fin));
                frames.add(new Frame.Stream(v, 0, bytes(0), fin));
            }
        }
        frames.add(new Frame.MaxStreams(true, Frame.MAX_STREAM_COUNT));
        frames.add(new Frame.Crypto(0, bytes(0)));
        frames.add(new Frame.Crypto(1000, bytes(20_000)));
        frames.add(new Frame.NewToken(bytes(1)));
        frames.add(new Frame.NewToken(bytes(300)));
        frames.add(new Frame.NewConnectionId(5, 3, ConnectionId.of(hex("01")), TOKEN));
        frames.add(new Frame.NewConnectionId(VarInt.MAX, VarInt.MAX, ConnectionId.of(new byte[20]), TOKEN));
        frames.add(new Frame.PathChallenge(0x0102030405060708L));
        frames.add(new Frame.PathResponse(-1L));
        frames.add(new Frame.Datagram(bytes(0)));
        frames.add(new Frame.Datagram(bytes(1000)));
        frames.add(Frame.ConnectionClose.of(QuicException.PROTOCOL_VIOLATION, 0x08, "bad stream"));
        frames.add(Frame.ApplicationClose.of(0x101, "goodbye é"));
        frames.add(Frame.Ack.of(0, null, 0));
        frames.add(Frame.Ack.of(VarInt.MAX, null, VarInt.MAX));
        frames.add(Frame.Ack.of(25, new Frame.EcnCounts(0, VarInt.MAX, 64), 1, 2, 3, 5, 10, 11, 14));
        frames.add(new Frame.Ack(List.of(new Frame.AckRange(VarInt.MAX - 10, VarInt.MAX), new Frame.AckRange(0, 0)), 3, null));
        return frames;
    }

    @Test
    void everyFrameRoundTrips() throws FrameException {
        List<Frame> frames = allFrames();
        assertEquals(FrameType.values().length, frames.stream().map(Frame::type).distinct().count(), "every type covered");
        for (Frame f : frames) {
            roundTrip(f);
        }
    }

    @Test
    void framesRoundTripTogether() throws FrameException {
        List<Frame> frames = allFrames().stream().filter(f -> !(f instanceof Frame.Padding)).toList();
        int total = frames.stream().mapToInt(Frame::encodedLength).sum();
        ByteBuffer out = ByteBuffer.allocate(total);
        frames.forEach(f -> f.encode(out));
        assertEquals(frames, FrameDecoder.decodeAll(out.flip(), PacketType.ONE_RTT));
    }

    /** quinn {@code frame::test::ack_coding}. */
    @Test
    void quinnAckCoding() throws FrameException {
        long[] packets = {1, 2, 3, 5, 10, 11, 14};
        Frame.EcnCounts ecn = new Frame.EcnCounts(42, 24, 12);
        Frame.Ack ack = Frame.Ack.of(42, ecn, packets);
        // quinn's ArrayRangeSet encoding: largest 14, delay 42, 3 more ranges, first range 0, then
        // (gap, length) pairs (1, 1), (3, 0), (0, 2).
        assertArrayEquals(hex("03 0e 2a 03 00 01 01 03 00 00 02 2a 18 0c"), encode(ack));
        Frame.Ack decoded = (Frame.Ack) FrameDecoder.decodeAll(ByteBuffer.wrap(encode(ack)), PacketType.ONE_RTT).get(0);
        long[] acked = LongStream.range(0, 20).filter(decoded::contains).toArray();
        assertArrayEquals(packets, acked);
        assertEquals(ecn, decoded.ecn());
        assertEquals(14, decoded.largest());
    }

    /** quinn {@code frame::test::ack_frequency_coding} and {@code immediate_ack_coding}. */
    @Test
    void quinnAckFrequencyCoding() throws FrameException {
        Frame.AckFrequency f = new Frame.AckFrequency(42, 20, 50_000, 1);
        assertEquals(f, roundTrip(f));
        assertArrayEquals(hex("40af"), Arrays.copyOf(encode(f), 2));
        assertEquals(List.of(new Frame.ImmediateAck()), FrameDecoder.decodeAll(ByteBuffer.wrap(hex("1f")), PacketType.ONE_RTT));
    }

    @Test
    void streamFlagCombinations() throws FrameException {
        // Every STREAM type code decodes; without LEN the data runs to the end of the payload.
        for (int type = 0x08; type <= 0x0f; type++) {
            ByteBuffer out = ByteBuffer.allocate(32);
            out.put((byte) type);
            VarInt.write(out, 4);
            if ((type & 0x04) != 0) VarInt.write(out, 1000);
            if ((type & 0x02) != 0) VarInt.write(out, 3);
            out.put(new byte[] {7, 8, 9});
            Frame.Stream s = (Frame.Stream) FrameDecoder.decode(out.flip());
            assertEquals(4, s.streamId());
            assertEquals((type & 0x04) != 0 ? 1000 : 0, s.offset());
            assertEquals((type & 0x01) != 0, s.fin());
            assertEquals(ByteBuffer.wrap(new byte[] {7, 8, 9}), s.data());
            assertFalse(out.hasRemaining());
        }
        assertEquals(0x0b, new Frame.Stream(0, 0, bytes(1), true).typeCode());
        assertEquals(0x0e, new Frame.Stream(0, 9, bytes(1), false).typeCode());
    }

    @Test
    void streamBudget() throws FrameException {
        // Everything fits with a Length field.
        ByteBuffer out = ByteBuffer.allocate(100);
        ByteBuffer data = bytes(20);
        assertEquals(20, Frame.Stream.encode(out, 4, 0, data, true, 100));
        assertFalse(data.hasRemaining());
        assertEquals(1 + 1 + 1 + 20, out.position());
        Frame.Stream s = (Frame.Stream) FrameDecoder.decode(out.flip());
        assertTrue(s.fin());
        assertEquals(bytes(20), s.data());

        // The budget cuts the data: no Length field, no FIN, the frame fills the budget exactly.
        out = ByteBuffer.allocate(100);
        data = bytes(200);
        // 1 type + 1 stream ID + 2 offset bytes leave 46 bytes of data.
        assertEquals(46, Frame.Stream.encode(out, 4, 64, data, true, 50));
        assertEquals(50, out.position());
        assertEquals(46, data.position());
        assertEquals(0x0c, out.get(0));
        s = (Frame.Stream) FrameDecoder.decode(out.flip());
        assertFalse(s.fin());
        assertEquals(64, s.offset());
        assertEquals(46, s.data().remaining());

        // Exactly the data plus its Length field fits.
        out = ByteBuffer.allocate(100);
        assertEquals(10, Frame.Stream.encode(out, 0, 0, bytes(10), false, 13));
        assertEquals(13, out.position());
        // One byte less: the Length field is dropped instead.
        out = ByteBuffer.allocate(100);
        assertEquals(10, Frame.Stream.encode(out, 0, 0, bytes(10), true, 12));
        assertEquals(0x09, out.get(0));
        // FIN-only and no room at all.
        out = ByteBuffer.allocate(100);
        assertEquals(0, Frame.Stream.encode(out, 0, 5, bytes(0), true, 100));
        assertEquals(new Frame.Stream(0, 5, bytes(0), true), FrameDecoder.decode(out.flip()));
        assertEquals(-1, Frame.Stream.encode(ByteBuffer.allocate(100), 1L << 40, 1L << 40, bytes(5), false, 16));
        // The buffer bounds the budget too.
        out = ByteBuffer.allocate(10);
        assertEquals(8, Frame.Stream.encode(out, 0, 0, bytes(100), false, 1000));
    }

    @Test
    void cryptoBudget() throws FrameException {
        ByteBuffer out = ByteBuffer.allocate(2000);
        ByteBuffer data = bytes(5000);
        // 1 type + 2 offset + 2 length leaves 995 bytes of data in a 1000-byte budget.
        assertEquals(995, Frame.Crypto.encode(out, 100, data, 1000));
        assertEquals(1000, out.position());
        assertEquals(995, data.position());
        Frame.Crypto c = (Frame.Crypto) FrameDecoder.decode(out.flip());
        assertEquals(100, c.offset());
        assertEquals(995, c.data().remaining());
        // At the one-byte length boundary the length field shrinks with the data.
        out = ByteBuffer.allocate(100);
        assertEquals(63, Frame.Crypto.encode(out, 0, bytes(100), 66));
        assertEquals(66, out.position());
        out = ByteBuffer.allocate(100);
        assertEquals(63, Frame.Crypto.encode(out, 0, bytes(100), 67));
        assertEquals(66, out.position());
        out = ByteBuffer.allocate(100);
        assertEquals(64, Frame.Crypto.encode(out, 0, bytes(100), 68));
        assertEquals(68, out.position());
        assertEquals(-1, Frame.Crypto.encode(ByteBuffer.allocate(100), 0, bytes(10), 2));
        assertEquals(0, Frame.Crypto.encode(ByteBuffer.allocate(100), 0, bytes(0), 100));
    }

    @Test
    void closeReasonTruncation() throws FrameException {
        Frame.ConnectionClose close = Frame.ConnectionClose.of(0x0a, 0x06, "x".repeat(100));
        ByteBuffer out = ByteBuffer.allocate(200);
        assertTrue(close.encode(out, 20));
        assertEquals(20, out.position());
        Frame.ConnectionClose decoded = (Frame.ConnectionClose) FrameDecoder.decode(out.flip());
        assertEquals("x".repeat(16), decoded.reasonPhrase());
        assertFalse(close.encode(ByteBuffer.allocate(200), 3));
        Frame.ApplicationClose app = Frame.ApplicationClose.of(7, "y".repeat(100));
        out = ByteBuffer.allocate(200);
        assertTrue(app.encode(out, 10));
        assertEquals("y".repeat(7), ((Frame.ApplicationClose) FrameDecoder.decode(out.flip())).reasonPhrase());
    }

    @Test
    void datagramWithoutLength() throws FrameException {
        Frame.Datagram d = new Frame.Datagram(bytes(10));
        ByteBuffer out = ByteBuffer.allocate(11);
        d.encode(out, false);
        Frame decoded = FrameDecoder.decode(out.flip());
        assertEquals(d, decoded);
        assertEquals(11, d.encodedLength(false));
        assertThrows(BufferOverflowException.class, () -> d.encode(ByteBuffer.allocate(11), true));
    }

    @Test
    void paddingRunsCollapse() throws FrameException {
        List<Frame> frames = FrameDecoder.decodeAll(ByteBuffer.wrap(hex("0000000100000000")), PacketType.INITIAL);
        assertEquals(List.of(new Frame.Padding(3), new Frame.Ping(), new Frame.Padding(4)), frames);
    }

    @Test
    void ackEliciting() {
        assertFalse(new Frame.Padding(1).isAckEliciting());
        assertFalse(Frame.Ack.of(0, null, 1).isAckEliciting());
        assertFalse(Frame.ConnectionClose.of(0, 0, "").isAckEliciting());
        assertFalse(Frame.ApplicationClose.of(0, "").isAckEliciting());
        assertTrue(new Frame.Ping().isAckEliciting());
        assertTrue(new Frame.Stream(0, 0, bytes(1), false).isAckEliciting());
    }

    /** RFC 9000 Table 3. */
    @Test
    void packetTypeRules() throws FrameException {
        String[][] table = {
            {"PADDING", "IH01"}, {"PING", "IH01"}, {"ACK", "IH_1"}, {"RESET_STREAM", "__01"},
            {"STOP_SENDING", "__01"}, {"CRYPTO", "IH_1"}, {"NEW_TOKEN", "___1"}, {"STREAM", "__01"},
            {"MAX_DATA", "__01"}, {"MAX_STREAM_DATA", "__01"}, {"MAX_STREAMS", "__01"}, {"DATA_BLOCKED", "__01"},
            {"STREAM_DATA_BLOCKED", "__01"}, {"STREAMS_BLOCKED", "__01"}, {"NEW_CONNECTION_ID", "__01"},
            {"RETIRE_CONNECTION_ID", "__01"}, {"PATH_CHALLENGE", "__01"}, {"PATH_RESPONSE", "___1"},
            {"CONNECTION_CLOSE", "IH01"}, {"APPLICATION_CLOSE", "__01"}, {"HANDSHAKE_DONE", "___1"},
            {"DATAGRAM", "__01"},
        };
        PacketType[] order = {PacketType.INITIAL, PacketType.HANDSHAKE, PacketType.ZERO_RTT, PacketType.ONE_RTT};
        for (String[] row : table) {
            FrameType t = FrameType.valueOf(row[0]);
            for (int i = 0; i < 4; i++) {
                assertEquals(row[1].charAt(i) != '_', t.isAllowedIn(order[i]), t + " in " + order[i]);
            }
            assertFalse(t.isAllowedIn(PacketType.RETRY));
            assertFalse(t.isAllowedIn(PacketType.VERSION_NEGOTIATION));
        }
        // No STREAM in Initial, no CRYPTO in 0-RTT, no application close in Handshake.
        assertViolation(new Frame.Stream(0, 0, bytes(3), false), PacketType.INITIAL);
        assertViolation(new Frame.Crypto(0, bytes(3)), PacketType.ZERO_RTT);
        assertViolation(Frame.ApplicationClose.of(1, ""), PacketType.HANDSHAKE);
        assertViolation(new Frame.HandshakeDone(), PacketType.ZERO_RTT);
        assertViolation(Frame.Ack.of(0, null, 1), PacketType.ZERO_RTT);
        FrameException empty = assertThrows(FrameException.class,
                () -> FrameDecoder.decodeAll(ByteBuffer.allocate(0), PacketType.ONE_RTT));
        assertEquals(QuicException.PROTOCOL_VIOLATION, empty.code());
    }

    private static void assertViolation(Frame f, PacketType packetType) {
        FrameException e = assertThrows(FrameException.class,
                () -> FrameDecoder.decodeAll(ByteBuffer.wrap(encode(f)), packetType));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
        assertEquals(f.typeCode(), e.frameType());
    }

    private static void assertMalformed(String hex, long frameType) {
        FrameException e = assertThrows(FrameException.class, () -> FrameDecoder.decode(ByteBuffer.wrap(hex(hex))));
        assertEquals(QuicException.FRAME_ENCODING_ERROR, e.code(), hex);
        assertEquals(frameType, e.frameType(), hex);
    }

    @Test
    void malformedFrames() {
        assertMalformed("21", 0x21); // unknown type
        assertMalformed("4040", 0x40);
        assertMalformed("40", 0); // truncated type
        assertMalformed("02 05 00 00 06", 0x02); // first range below zero
        assertMalformed("02 05 00 01 01 03 00", 0x02); // gap below zero
        assertMalformed("02 05 00 01 00 00 05", 0x02); // second range below zero
        assertMalformed("02 05 00 3f 00", 0x02); // range count beyond the frame
        assertMalformed("03 05 00 00 00 01 02", 0x03); // truncated ECN counts
        assertMalformed("04 00 00", 0x04);
        assertMalformed("06 00 05 0102", 0x06); // CRYPTO length beyond the frame
        assertMalformed("06 ffffffffffffffff 01 00", 0x06); // CRYPTO past 2^62-1
        assertMalformed("07 00", 0x07); // empty NEW_TOKEN
        assertMalformed("0e 00 ffffffffffffffff 01 00", 0x0e); // STREAM past 2^62-1
        assertMalformed("0a 00 05 01", 0x0a);
        assertMalformed("12 d000000000000001", 0x12); // MAX_STREAMS above 2^60
        assertMalformed("17 d000000000000001", 0x17);
        assertMalformed("18 01 02 08 0102030405060708" + "00".repeat(16), 0x18); // retire prior to > sequence
        assertMalformed("18 01 00 00" + "00".repeat(16), 0x18); // empty connection ID
        assertMalformed("18 01 00 15" + "00".repeat(37), 0x18); // 21-byte connection ID
        assertMalformed("18 01 00 01 01" + "00".repeat(15), 0x18); // short reset token
        assertMalformed("1a 01020304", 0x1a);
        assertMalformed("1c 0a 00 05 00", 0x1c);
        assertMalformed("1d 0a", 0x1d);
        assertMalformed("31 05 0102", 0x31);
        assertMalformed("40af 01 02 03", 0xaf);
        // A frame type in a longer encoding than necessary.
        FrameException e = assertThrows(FrameException.class, () -> FrameDecoder.decode(ByteBuffer.wrap(hex("4001"))));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
    }

    @Test
    void constructorsRejectBadValues() {
        assertThrows(IllegalArgumentException.class, () -> new Frame.Padding(0));
        assertThrows(IllegalArgumentException.class, () -> new Frame.MaxData(-1));
        assertThrows(IllegalArgumentException.class, () -> new Frame.MaxData(VarInt.MAX + 1));
        assertThrows(IllegalArgumentException.class, () -> new Frame.MaxStreams(true, Frame.MAX_STREAM_COUNT + 1));
        assertThrows(IllegalArgumentException.class, () -> new Frame.NewToken(bytes(0)));
        assertThrows(IllegalArgumentException.class, () -> new Frame.NewConnectionId(1, 2, ConnectionId.of(hex("01")), TOKEN));
        assertThrows(IllegalArgumentException.class, () -> new Frame.NewConnectionId(1, 0, ConnectionId.EMPTY, TOKEN));
        assertThrows(IllegalArgumentException.class, () -> new Frame.Ack(List.of(), 0, null));
        assertThrows(IllegalArgumentException.class, () -> new Frame.Ack(
                List.of(new Frame.AckRange(5, 6), new Frame.AckRange(4, 4)), 0, null)); // adjacent ranges
        assertThrows(IllegalArgumentException.class, () -> new Frame.AckRange(3, 2));
        assertThrows(IllegalArgumentException.class, () -> new Frame.Stream(0, VarInt.MAX, bytes(1), false));
        assertThrows(BufferOverflowException.class, () -> new Frame.Ping().encode(ByteBuffer.allocate(0)));
        ByteBuffer small = ByteBuffer.allocate(3);
        assertThrows(BufferOverflowException.class, () -> new Frame.ResetStream(1000, 1000, 1000).encode(small));
        assertEquals(0, small.position(), "nothing written on overflow");
    }

    @Test
    void decodedDataIsAViewOfThePayload() throws FrameException {
        byte[] payload = encode(new Frame.Crypto(0, bytes(8)));
        Frame.Crypto c = (Frame.Crypto) FrameDecoder.decode(ByteBuffer.wrap(payload));
        payload[payload.length - 1] = 0x55;
        ByteBuffer data = c.data();
        assertEquals(0x55, data.get(7));
        data.position(8);
        assertEquals(8, c.data().remaining(), "accessors return independent views");
        assertInstanceOf(Frame.Crypto.class, c);
    }
}
