package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.assertFrameEquals;
import static io.github.mahmoudimus.http3.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Every frame type written and read back, through streams and buffers. */
class FrameRoundTripTest {

    private static final long MAX = QuicVarInt.MAX_VALUE;

    static List<Http3Frame> allFrames() {
        Map<Long, Long> settings = new LinkedHashMap<>();
        settings.put(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 4096L);
        settings.put(Http3Settings.MAX_FIELD_SECTION_SIZE, 1L << 20);
        settings.put(Http3Settings.QPACK_BLOCKED_STREAMS, 16L);
        settings.put(Http3Settings.ENABLE_CONNECT_PROTOCOL, 1L);
        settings.put(Http3Settings.H3_DATAGRAM, 1L);
        settings.put(Http3FrameType.reserved(7), 1234L); // grease
        settings.put(0x2a2aL, MAX); // an extension
        return List.of(
                new Http3Frame.Data(new byte[0]),
                new Http3Frame.Data("hello".getBytes()),
                new Http3Frame.Data(new byte[20_000]),
                new Http3Frame.Headers(hex("0000d1d7")),
                new Http3Frame.Headers(new byte[0]),
                new Http3Frame.CancelPush(0),
                new Http3Frame.CancelPush(MAX),
                new Http3Frame.Settings(Map.of()),
                new Http3Frame.Settings(settings),
                new Http3Frame.PushPromise(3, hex("0000d1")),
                new Http3Frame.PushPromise(MAX, new byte[0]),
                new Http3Frame.GoAway(0),
                new Http3Frame.GoAway(1L << 30),
                new Http3Frame.MaxPushId(16383),
                new Http3Frame.MaxPushId(16384),
                new Http3Frame.Unknown(0x21, new byte[0]), // the first reserved type
                new Http3Frame.Unknown(Http3FrameType.reserved(1000), "grease".getBytes()),
                new Http3Frame.Unknown(0x0f, new byte[] {1, 2, 3}), // ORIGIN-like extension
                new Http3Frame.Unknown(MAX, new byte[] {9}));
    }

    @Test
    void everyFrameTypeRoundTripsThroughAStream() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FrameWriter writer = new Http3FrameWriter(out);
        for (Http3Frame f : allFrames()) writer.writeFrame(f);
        writer.flush();
        Http3FrameReader reader = new Http3FrameReader(new ByteArrayInputStream(out.toByteArray()));
        for (Http3Frame expected : allFrames()) assertFrameEquals(expected, reader.readFrame());
        assertNull(reader.readFrame());
    }

    @Test
    void everyFrameTypeRoundTripsThroughABuffer() throws Http3Exception {
        ByteBuffer buf = ByteBuffer.allocate(64 * 1024);
        for (Http3Frame f : allFrames()) Http3FrameWriter.encode(f, buf);
        buf.flip();
        for (Http3Frame expected : allFrames()) {
            assertFrameEquals(expected, Http3FrameReader.parse(buf, 32 * 1024));
        }
        assertEquals(0, buf.remaining());
        assertNull(Http3FrameReader.parse(buf, 32 * 1024));

        buf.rewind();
        Http3FrameReader reader = Http3FrameReader.of(buf);
        try {
            for (Http3Frame expected : allFrames()) assertFrameEquals(expected, reader.readFrame());
            assertNull(reader.readFrame());
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void parsingAPartialFrameLeavesTheBufferAlone() throws Http3Exception {
        for (Http3Frame f : allFrames()) {
            byte[] whole = Http3FrameWriter.encode(f);
            for (int cut = 0; cut < Math.min(whole.length, 40); cut++) {
                ByteBuffer partial = ByteBuffer.wrap(whole, 0, cut);
                assertNull(Http3FrameReader.parse(partial, 32 * 1024), "cut at " + cut);
                assertEquals(0, partial.position());
            }
        }
    }

    @Test
    void wireFormatIsExact() {
        assertEquals("0005" + hex("hello".getBytes()), hex(Http3FrameWriter.encode(new Http3Frame.Data("hello".getBytes()))));
        assertEquals("0104" + "0000d1d7", hex(Http3FrameWriter.encode(new Http3Frame.Headers(hex("0000d1d7")))));
        assertEquals("030103", hex(Http3FrameWriter.encode(new Http3Frame.CancelPush(3))));
        assertEquals("0400", hex(Http3FrameWriter.encode(new Http3Frame.Settings(Map.of()))));
        assertEquals("04030140" + "64", hex(Http3FrameWriter.encode(new Http3Frame.Settings(Map.of(1L, 100L)))));
        assertEquals("050302" + "0000", hex(Http3FrameWriter.encode(new Http3Frame.PushPromise(2, hex("0000")))));
        assertEquals("070100", hex(Http3FrameWriter.encode(new Http3Frame.GoAway(0))));
        assertEquals("07024040", hex(Http3FrameWriter.encode(new Http3Frame.GoAway(64))));
        assertEquals("0d0108", hex(Http3FrameWriter.encode(new Http3Frame.MaxPushId(8))));
        // A frame type above 63 takes two bytes.
        assertEquals("405c00", hex(Http3FrameWriter.encode(new Http3Frame.Unknown(0x5c, new byte[0]))));
    }

    @Test
    void writerConvenienceMethods() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(out);
        w.writeStreamType(Http3StreamType.CONTROL);
        w.writeSettings(Http3Settings.builder().qpackMaxTableCapacity(4096).qpackBlockedStreams(8).grease(3, 7).build());
        w.writeMaxPushId(10);
        w.writeCancelPush(4);
        w.writeGoAway(8);
        byte[] data = "0123456789".getBytes();
        w.writeData(data, 2, 5);
        w.writeData(new byte[0]);
        w.writeHeaders(hex("0000"));
        w.writePushPromise(1, hex("0000"));

        Http3FrameReader r = new Http3FrameReader(new ByteArrayInputStream(out.toByteArray()));
        assertEquals(Http3StreamType.CONTROL, r.readStreamType());
        Http3Settings s = Http3Settings.fromFrame((Http3Frame.Settings) r.readFrame());
        assertEquals(4096, s.qpackMaxTableCapacity());
        assertEquals(8, s.qpackBlockedStreams());
        assertEquals(Map.of(Http3FrameType.reserved(3), 7L), s.extensions());
        assertEquals(10, ((Http3Frame.MaxPushId) r.readFrame()).pushId());
        assertEquals(4, ((Http3Frame.CancelPush) r.readFrame()).pushId());
        assertEquals(8, ((Http3Frame.GoAway) r.readFrame()).id());
        assertArrayEquals("23456".getBytes(), ((Http3Frame.Data) r.readFrame()).data());
        assertEquals(0, ((Http3Frame.Data) r.readFrame()).data().length);
        assertArrayEquals(hex("0000"), ((Http3Frame.Headers) r.readFrame()).fieldSection());
        Http3Frame.PushPromise p = (Http3Frame.PushPromise) r.readFrame();
        assertEquals(1, p.pushId());
        assertArrayEquals(hex("0000"), p.fieldSection());
        assertNull(r.readFrame());
    }

    @Test
    void longDataFramesComeBackInPiecesOfTheLimit() throws IOException {
        byte[] body = new byte[100_000];
        new Random(1).nextBytes(body);
        byte[] wire = Http3FrameWriter.encode(new Http3Frame.Data(body));
        Http3FrameReader r = new Http3FrameReader(new ByteArrayInputStream(TestBytes.concat(wire,
                Http3FrameWriter.encode(new Http3Frame.Headers(hex("0000"))))));
        r.setMaxFramePayloadSize(30_000);
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        List<Integer> sizes = new ArrayList<>();
        Http3Frame f;
        while ((f = r.readFrame()) instanceof Http3Frame.Data d) {
            sizes.add(d.data().length);
            joined.writeBytes(d.data());
        }
        assertEquals(List.of(30_000, 30_000, 30_000, 10_000), sizes);
        assertArrayEquals(body, joined.toByteArray());
        assertInstanceOf(Http3Frame.Headers.class, f);
    }

    @Test
    void unknownFramesCanBeSkipped() throws IOException {
        byte[] wire = TestBytes.concat(
                Http3FrameWriter.encode(new Http3Frame.Unknown(Http3FrameType.reserved(2), new byte[100_000])),
                Http3FrameWriter.encode(new Http3Frame.GoAway(4)));
        Http3FrameReader r = new Http3FrameReader(new ByteArrayInputStream(wire));
        r.setDeliverUnknownFrames(false);
        // Skipped without allocating, so not subject to the payload limit.
        assertEquals(new Http3Frame.GoAway(4), r.readFrame());
        assertNull(r.readFrame());
    }

    @Test
    void frameRecordsRejectImpossibleValues() {
        assertThrows(IllegalArgumentException.class, () -> new Http3Frame.CancelPush(-1));
        assertThrows(IllegalArgumentException.class, () -> new Http3Frame.GoAway(MAX + 1));
        assertThrows(IllegalArgumentException.class, () -> new Http3Frame.MaxPushId(-5));
        assertThrows(IllegalArgumentException.class, () -> new Http3Frame.PushPromise(-1, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new Http3Frame.Settings(Map.of(-1L, 0L)));
        assertThrows(IllegalArgumentException.class, () -> new Http3Frame.Settings(Map.of(1L, MAX + 1)));
        for (long known : new long[] {0x0, 0x1, 0x3, 0x4, 0x5, 0x7, 0xd, 0x2, 0x6, 0x8, 0x9}) {
            assertThrows(IllegalArgumentException.class, () -> new Http3Frame.Unknown(known, new byte[0]), "type " + known);
        }
        assertTrue(new Http3Frame.Unknown(0x21, new byte[0]).isReserved());
        assertTrue(!new Http3Frame.Unknown(0x22, new byte[0]).isReserved());
    }

    @Test
    void writerRejectsHttp2OnlySettings() {
        for (long id : new long[] {0x0, 0x2, 0x3, 0x4, 0x5}) {
            Http3Frame.Settings s = new Http3Frame.Settings(Map.of(id, 1L));
            assertThrows(IllegalArgumentException.class, () -> Http3FrameWriter.encode(s), "id " + id);
        }
        assertThrows(IllegalArgumentException.class,
                () -> Http3FrameWriter.encode(new Http3Frame.Settings(Map.of(Http3Settings.H3_DATAGRAM, 2L))));
        assertThrows(BufferOverflowException.class,
                () -> Http3FrameWriter.encode(new Http3Frame.Data(new byte[10]), ByteBuffer.allocate(5)));
    }

    @Test
    void reservedValuesFollowTheGreasePattern() {
        assertEquals(0x21, Http3FrameType.reserved(0));
        assertEquals(0x40, Http3FrameType.reserved(1));
        assertTrue(Http3FrameType.isReserved(0x1f * 12345L + 0x21));
        assertTrue(!Http3FrameType.isReserved(0x20));
        assertTrue(!Http3FrameType.isReserved(0x22));
        assertTrue(Http3StreamType.isReserved(0x21));
        assertTrue(Http3ErrorCode.isReserved(0x5f));
        assertEquals(Http3ErrorCode.H3_NO_ERROR, Http3ErrorCode.forCode(0x5f));
        assertEquals(Http3ErrorCode.QPACK_DECODER_STREAM_ERROR, Http3ErrorCode.forCode(0x202));
        assertEquals(0x10e, Http3ErrorCode.H3_MESSAGE_ERROR.code());
    }
}
