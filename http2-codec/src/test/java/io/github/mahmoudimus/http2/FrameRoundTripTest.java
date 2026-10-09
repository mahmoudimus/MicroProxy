package io.github.mahmoudimus.http2;

import static io.github.mahmoudimus.http2.TestBytes.assertFrameEquals;
import static io.github.mahmoudimus.http2.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

class FrameRoundTripTest {

    private static Frame roundTrip(Frame frame) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameWriter w = new FrameWriter(out);
        w.setMaxFrameSize(1 << 20);
        w.writeFrame(frame);
        FrameReader r = new FrameReader(new ByteArrayInputStream(out.toByteArray()));
        r.setMaxFrameSize(1 << 20);
        r.setDeliverUnknownFrames(true);
        Frame read = r.readFrame();
        assertNull(r.readFrame(), "one frame only");
        return read;
    }

    private static void assertRoundTrips(Frame frame) throws IOException {
        assertFrameEquals(frame, roundTrip(frame));
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    void data() throws IOException {
        assertRoundTrips(new Frame.Data(1, bytes("hello"), false));
        assertRoundTrips(new Frame.Data(3, bytes("bye"), true));
        assertRoundTrips(new Frame.Data(5, new byte[0], true));
        assertRoundTrips(new Frame.Data(Frame.MAX_STREAM_ID, new byte[70_000], false));
    }

    @Test
    void paddedData() throws IOException {
        Frame.Data d = new Frame.Data(7, bytes("padded"), true, 11);
        assertRoundTrips(d);
        assertEquals(17, d.flowControlledLength());
        assertRoundTrips(new Frame.Data(7, bytes("x"), false, 1)); // pad length 0
        assertRoundTrips(new Frame.Data(7, new byte[0], false, 256)); // all padding
    }

    @Test
    void headers() throws IOException {
        assertRoundTrips(new Frame.Headers(1, hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"), true));
        assertRoundTrips(new Frame.Headers(3, new byte[0], false));
        assertRoundTrips(new Frame.Headers(5, bytes("block"), false, true, new Frame.PrioritySpec(3, true, 256), 0));
        assertRoundTrips(new Frame.Headers(5, bytes("block"), true, true, new Frame.PrioritySpec(0, false, 1), 9));
        assertRoundTrips(new Frame.Headers(5, bytes("block"), true, true, null, 4));
    }

    @Test
    void priority() throws IOException {
        assertRoundTrips(new Frame.Priority(3, new Frame.PrioritySpec(1, false, 16)));
        assertRoundTrips(new Frame.Priority(3, new Frame.PrioritySpec(Frame.MAX_STREAM_ID, true, 200)));
    }

    @Test
    void rstStream() throws IOException {
        Frame.RstStream r = (Frame.RstStream) roundTrip(new Frame.RstStream(9, ErrorCode.CANCEL));
        assertEquals(9, r.streamId());
        assertEquals(ErrorCode.CANCEL, r.error());
        // Unknown codes survive as values and read as INTERNAL_ERROR.
        Frame.RstStream odd = (Frame.RstStream) roundTrip(new Frame.RstStream(9, 0xdeadbeef));
        assertEquals(0xdeadbeef, odd.errorCode());
        assertEquals(ErrorCode.INTERNAL_ERROR, odd.error());
    }

    @Test
    void settings() throws IOException {
        Map<Integer, Long> values = new LinkedHashMap<>();
        values.put(Http2Settings.ENABLE_PUSH, 0L);
        values.put(Http2Settings.MAX_CONCURRENT_STREAMS, 100L);
        values.put(Http2Settings.INITIAL_WINDOW_SIZE, (long) Integer.MAX_VALUE);
        values.put(Http2Settings.MAX_FRAME_SIZE, (long) Http2Settings.MAX_MAX_FRAME_SIZE);
        values.put(Http2Settings.MAX_HEADER_LIST_SIZE, 0xffffffffL);
        values.put(0xabcd, 42L); // unknown: kept, to be ignored
        Frame.Settings s = (Frame.Settings) roundTrip(new Frame.Settings(false, values));
        assertEquals(values, s.values());
        assertEquals(List.copyOf(values.keySet()), List.copyOf(s.values().keySet()), "order is kept");
        assertRoundTrips(new Frame.Settings(false, Map.of()));
        assertRoundTrips(Frame.Settings.acknowledgement());
    }

    @Test
    void settingsAckBytes() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new FrameWriter(out).writeSettingsAck();
        assertEquals("000000040100000000", hex(out.toByteArray()));
    }

    @Test
    void repeatedSettingKeepsTheLastValue() throws IOException {
        byte[] payload = hex("0004 00000100 0003 00000005 0004 00000200");
        Frame.Settings s = (Frame.Settings) TestBytes.reader(TestBytes.frame(FrameType.SETTINGS, 0, 0, payload)).readFrame();
        assertEquals(Map.of(3, 5L, 4, 0x200L), s.values());
        assertEquals(List.of(3, 4), List.copyOf(s.values().keySet()));
        Http2Settings applied = Http2Settings.DEFAULT.apply(s);
        assertEquals(0x200, applied.initialWindowSize());
        assertEquals(5, applied.maxConcurrentStreams());
    }

    @Test
    void pushPromise() throws IOException {
        assertRoundTrips(new Frame.PushPromise(1, 2, bytes("promised block"), true, 0));
        assertRoundTrips(new Frame.PushPromise(1, Frame.MAX_STREAM_ID - 1, bytes("x"), true, 33));
    }

    @Test
    void ping() throws IOException {
        assertRoundTrips(new Frame.Ping(false, 0x0102030405060708L));
        assertRoundTrips(new Frame.Ping(true, -1L));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new FrameWriter(out).writePing(true, 0x0102030405060708L);
        assertEquals("000008060100000000" + "0102030405060708", hex(out.toByteArray()));
    }

    @Test
    void goAway() throws IOException {
        assertRoundTrips(new Frame.GoAway(0, ErrorCode.NO_ERROR, new byte[0]));
        Frame.GoAway g = (Frame.GoAway) roundTrip(new Frame.GoAway(Frame.MAX_STREAM_ID, ErrorCode.ENHANCE_YOUR_CALM, bytes("slow down")));
        assertEquals(ErrorCode.ENHANCE_YOUR_CALM, g.error());
        assertArrayEquals(bytes("slow down"), g.debugData());
    }

    @Test
    void windowUpdate() throws IOException {
        assertRoundTrips(new Frame.WindowUpdate(0, 1));
        assertRoundTrips(new Frame.WindowUpdate(11, Integer.MAX_VALUE));
    }

    @Test
    void unknownFramesAreSkippedOrDelivered() throws IOException {
        byte[] unknown = TestBytes.frame(0xfa, 0x5a, 3, bytes("extension"));
        byte[] ping = TestBytes.frame(FrameType.PING, 0, 0, new byte[8]);
        FrameReader skipping = TestBytes.reader(unknown, ping);
        assertInstanceOf(Frame.Ping.class, skipping.readFrame());
        assertNull(skipping.readFrame());

        assertRoundTrips(new Frame.Unknown(0xfa, 0x5a, 3, bytes("extension")));
        assertRoundTrips(new Frame.Unknown(0x10, 0, 0, new byte[0]));
    }

    @Test
    void reservedBitIsIgnored() throws IOException {
        byte[] f = TestBytes.frame(FrameType.WINDOW_UPDATE, 0, 0x80000005, hex("80000010"));
        Frame.WindowUpdate w = (Frame.WindowUpdate) TestBytes.reader(f).readFrame();
        assertEquals(5, w.streamId());
        assertEquals(16, w.increment());
    }

    @Test
    void longFieldBlocksAreSplitIntoContinuationsAndJoinedAgain() throws IOException {
        byte[] block = new byte[16_384 * 3 + 100];
        new Random(1).nextBytes(block);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameWriter w = new FrameWriter(out);
        w.writeHeaders(3, block, true);
        w.writePushPromise(3, 4, block);
        w.writeData(3, bytes("after"), 0, 5, true);
        byte[] wire = out.toByteArray();
        // HEADERS (no END_HEADERS) + 3 CONTINUATION, the last with END_HEADERS.
        assertEquals(FrameType.HEADERS, wire[3]);
        assertEquals(FrameType.FLAG_END_STREAM, wire[4]);
        assertEquals(16_384, ((wire[0] & 0xff) << 16) | ((wire[1] & 0xff) << 8) | (wire[2] & 0xff));

        FrameReader r = new FrameReader(new ByteArrayInputStream(wire));
        Frame.Headers h = (Frame.Headers) r.readFrame();
        assertArrayEquals(block, h.fieldBlock());
        assertTrue(h.endStream());
        assertTrue(h.endHeaders());
        Frame.PushPromise p = (Frame.PushPromise) r.readFrame();
        assertEquals(4, p.promisedStreamId());
        assertArrayEquals(block, p.fieldBlock());
        assertArrayEquals(bytes("after"), ((Frame.Data) r.readFrame()).data());
        assertNull(r.readFrame());
    }

    @Test
    void manualContinuationFramesAreJoined() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameWriter w = new FrameWriter(out);
        w.writeFrame(new Frame.Headers(1, bytes("ab"), true, false, new Frame.PrioritySpec(0, false, 16), 3));
        w.writeFrame(new Frame.Continuation(1, bytes("cd"), false));
        w.writeFrame(new Frame.Continuation(1, new byte[0], false));
        w.writeFrame(new Frame.Continuation(1, bytes("ef"), true));
        Frame.Headers h = (Frame.Headers) new FrameReader(new ByteArrayInputStream(out.toByteArray())).readFrame();
        assertArrayEquals(bytes("abcdef"), h.fieldBlock());
        assertEquals(new Frame.PrioritySpec(0, false, 16), h.priority());
        assertEquals(3, h.padding());
        assertTrue(h.endStream());
    }

    @Test
    void exactlyMaxFrameSizeIsAccepted() throws IOException {
        byte[] data = new byte[Http2Settings.DEFAULT_MAX_FRAME_SIZE];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new FrameWriter(out).writeData(1, data, 0, data.length, false);
        assertEquals(data.length, ((Frame.Data) TestBytes.reader(out.toByteArray()).readFrame()).data().length);
    }

    @Test
    void clientPreface() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameWriter w = new FrameWriter(out);
        w.writeClientPreface();
        w.writeSettings(Http2Settings.builder().enablePush(false).maxConcurrentStreams(100).build());
        assertEquals(FrameReader.CLIENT_PREFACE, new String(Arrays.copyOf(out.toByteArray(), 24), StandardCharsets.US_ASCII));
        FrameReader r = new FrameReader(new ByteArrayInputStream(out.toByteArray()));
        r.readClientPreface();
        Frame.Settings s = (Frame.Settings) r.readFrame();
        assertEquals(Map.of(Http2Settings.ENABLE_PUSH, 0L, Http2Settings.MAX_CONCURRENT_STREAMS, 100L), s.values());
        assertFalse(s.ack());
    }

    @Test
    void badClientPrefaceFailsAtTheFirstWrongByte() {
        // An HTTP/1.1 request shorter than the preface must not block waiting for 24 bytes.
        FrameReader r = new FrameReader(new ByteArrayInputStream(bytes("GET / HTTP/1.1\r\n")));
        Http2Exception e = assertThrows(Http2Exception.class, r::readClientPreface);
        assertEquals(ErrorCode.PROTOCOL_ERROR, e.errorCode());
        assertTrue(e.isConnectionError());
        assertThrows(EOFException.class, () -> new FrameReader(new ByteArrayInputStream(bytes("PRI * HTTP/2.0"))).readClientPreface());
    }

    @Test
    void cleanEndOfStreamIsNullAndTruncationIsEof() throws IOException {
        assertNull(TestBytes.reader().readFrame());
        byte[] ping = TestBytes.frame(FrameType.PING, 0, 0, new byte[8]);
        for (int cut = 1; cut < ping.length; cut++) {
            FrameReader r = TestBytes.reader(Arrays.copyOf(ping, cut));
            assertThrows(EOFException.class, r::readFrame, "cut at " + cut);
        }
        // Inside a field block.
        byte[] headers = TestBytes.frame(FrameType.HEADERS, 0, 1, bytes("ab"));
        assertThrows(EOFException.class, TestBytes.reader(headers)::readFrame);
        // Inside a skipped unknown frame.
        assertThrows(EOFException.class, TestBytes.reader(TestBytes.frame(100, 0xee, 0, 0, new byte[10]))::readFrame);
    }

    @Test
    void writerRejectsFramesThePeerWouldRefuse() {
        FrameWriter w = new FrameWriter(new ByteArrayOutputStream());
        byte[] big = new byte[Http2Settings.DEFAULT_MAX_FRAME_SIZE + 1];
        assertThrows(IllegalArgumentException.class, () -> w.writeData(1, big, 0, big.length, false));
        assertThrows(IllegalArgumentException.class, () -> w.writeFrame(new Frame.Data(1, big, false)));
        assertThrows(IllegalArgumentException.class, () -> w.writeFrame(new Frame.Data(1, new byte[16_384], false, 1)));
        assertThrows(IllegalArgumentException.class, () -> w.writeData(0, new byte[1], 0, 1, false));
        assertThrows(IllegalArgumentException.class, () -> w.writeHeaders(0, new byte[1], false));
        assertThrows(IllegalArgumentException.class, () -> w.writeSettings(Map.of(Http2Settings.ENABLE_PUSH, 2L)));
        assertThrows(IllegalArgumentException.class, () -> w.writeSettings(Map.of(Http2Settings.MAX_FRAME_SIZE, 100L)));
        assertThrows(IllegalArgumentException.class, () -> new Frame.WindowUpdate(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new Frame.Data(0, new byte[0], false));
        assertThrows(IllegalArgumentException.class, () -> new Frame.Data(1, new byte[0], false, 257));
        assertThrows(IllegalArgumentException.class, () -> new Frame.Settings(true, Map.of(1, 1L)));
        assertThrows(IllegalArgumentException.class, () -> new Frame.Unknown(FrameType.DATA, 0, 1, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new Frame.PrioritySpec(1, false, 0));
        assertThrows(IllegalArgumentException.class, () -> w.setMaxFrameSize(1000));
    }
}
