package org.microproxy.frames;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3FrameType;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.http3.QpackEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * {@link Http3FramePipeline}: request and control streams written with the codec, run through an
 * interceptor, and read back with the codec; edits, drops, added frames, grease, illegal results
 * and malformed input.
 */
class Http3FramePipelineTest {

    private static final long GREASE = Http3FrameType.reserved(3);

    private static List<HeaderField> request() {
        return List.of(new HeaderField(":method", "POST"), new HeaderField(":scheme", "https"),
                new HeaderField(":authority", "example.com"), new HeaderField(":path", "/upload"),
                new HeaderField("content-type", "text/plain"));
    }

    /** A request stream: HEADERS, a grease frame, two DATA frames, and trailers. */
    private static byte[] requestStream() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(out);
        QpackEncoder qpack = new QpackEncoder();
        w.writeHeaders(qpack.encode(0, request()));
        w.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(GREASE, "grease".getBytes(StandardCharsets.UTF_8)));
        w.writeData("password=hunter2&".getBytes(StandardCharsets.UTF_8));
        w.writeData("more".getBytes(StandardCharsets.UTF_8));
        w.writeHeaders(qpack.encode(0, List.of(new HeaderField("x-checksum", "1"))));
        return out.toByteArray();
    }

    /** A client's control stream: the stream type, SETTINGS with a grease setting, a grease frame, MAX_PUSH_ID. */
    private static byte[] controlStream() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(out);
        w.writeStreamType(Http3StreamType.CONTROL);
        w.writeSettings(Http3Settings.builder().maxFieldSectionSize(16_384).qpackMaxTableCapacity(0).grease(5, 7).build());
        w.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(GREASE, new byte[] {1}));
        w.writeMaxPushId(8);
        return out.toByteArray();
    }

    /** A frame read back, with field sections decoded. */
    record Out(io.github.mahmoudimus.http3.Http3Frame frame, List<HeaderField> fields) {
        String text() {
            return frame instanceof io.github.mahmoudimus.http3.Http3Frame.Data d ? new String(d.data(), StandardCharsets.UTF_8) : null;
        }

        String field(String name) {
            for (HeaderField f : fields) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }
    }

    /** Reads the pipeline's output, decoding field sections with a static-only decoder, as anyone could. */
    private static List<Out> read(byte[] bytes, boolean control) throws IOException {
        Http3FrameReader r = new Http3FrameReader(new ByteArrayInputStream(bytes));
        if (control) assertEquals(Http3StreamType.CONTROL, r.readStreamType());
        QpackDecoder qpack = new QpackDecoder();
        List<Out> out = new ArrayList<>();
        for (io.github.mahmoudimus.http3.Http3Frame f; (f = r.readFrame()) != null; ) {
            List<HeaderField> fields = f instanceof io.github.mahmoudimus.http3.Http3Frame.Headers h ? qpack.decode(0, h.fieldSection())
                    : List.of();
            out.add(new Out(f, fields));
        }
        return out;
    }

    private static List<Out> runRequest(FrameInterceptor interceptor, byte[] stream) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FramePipeline.builder(interceptor).build().requestStream(0, new ByteArrayInputStream(stream), out);
        return read(out.toByteArray(), false);
    }

    private static List<String> types(List<Out> frames) {
        return frames.stream().map(o -> o.frame instanceof io.github.mahmoudimus.http3.Http3Frame.Unknown u
                ? "0x" + Long.toHexString(u.type()) : Http3FrameType.name(o.frame.type())).toList();
    }

    @Test
    void theCodecIsHere() {
        assertTrue(Http3FramePipeline.available());
    }

    @Test
    void aRequestStreamRoundTripsThroughAPassThroughInterceptor() throws Exception {
        List<HttpFrame> seen = new CopyOnWriteArrayList<>();
        List<Out> out = runRequest((f, d, c) -> {
            seen.add(f);
            return f;
        }, requestStream());
        assertEquals(List.of("HEADERS", "DATA", "DATA", "HEADERS"),
                types(out).stream().filter(t -> !t.startsWith("0x")).toList());
        assertEquals(5, out.size());
        assertEquals("/upload", out.get(0).field(":path"));
        assertEquals("POST", out.get(0).field(":method"));
        // Grease passes through as it was.
        io.github.mahmoudimus.http3.Http3Frame.Unknown grease = (io.github.mahmoudimus.http3.Http3Frame.Unknown) out.get(1).frame;
        assertEquals(GREASE, grease.type());
        assertArrayEquals("grease".getBytes(StandardCharsets.UTF_8), grease.payload());
        assertEquals("password=hunter2&", out.get(2).text());
        assertEquals("1", out.get(4).field("x-checksum"));
        // What the interceptor saw: decoded fields, grease as Unknown.
        Http3Frame.Headers head = (Http3Frame.Headers) seen.getFirst();
        assertEquals("example.com", head.get(":authority"));
        Http3Frame.Unknown unknown = assertInstanceOf(Http3Frame.Unknown.class, seen.get(1));
        assertTrue(unknown.isReserved());
        assertEquals("UNKNOWN", unknown.typeName());
    }

    @Test
    void framesAreEditedDroppedAndAdded() throws Exception {
        List<Out> out = runRequest((f, d, c) -> switch (f) {
            case Http3Frame.Headers h when h.get(":method") != null -> h.withHeader("x-seen", "h3").withoutHeader("content-type");
            case Http3Frame.Data data when data.text().contains("hunter2") -> {
                c.send(Http3Frame.unknown(0x2a2a, "ext".getBytes(StandardCharsets.UTF_8)));
                c.send(Http3Frame.data("[added]".getBytes(StandardCharsets.UTF_8)));
                yield data.withText(data.text().replace("hunter2", "*******"));
            }
            case Http3Frame.Unknown u when u.isReserved() -> null;
            default -> f;
        }, requestStream());
        assertEquals(List.of("HEADERS", "DATA", "0x2a2a", "DATA", "DATA", "HEADERS"), types(out));
        assertEquals("h3", out.get(0).field("x-seen"));
        assertNull(out.get(0).field("content-type"));
        assertEquals("password=*******&", out.get(1).text());
        assertEquals("[added]", out.get(3).text());
        assertEquals("more", out.get(4).text());
    }

    @Test
    void trailersCanBeAddedAfterTheLastData() throws Exception {
        ByteArrayOutputStream in = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(in);
        w.writeHeaders(new QpackEncoder().encode(0, request()));
        w.writeData("body".getBytes(StandardCharsets.UTF_8));
        List<Out> out = runRequest((f, d, c) -> {
            if (f instanceof Http3Frame.Data) c.send(Http3Frame.headers(List.of(new Field("x-digest", "abc"))));
            return f;
        }, in.toByteArray());
        assertEquals(List.of("HEADERS", "DATA", "HEADERS"), types(out));
        assertEquals("abc", out.get(2).field("x-digest"));
    }

    @Test
    void dataAfterAddedTrailersFailsTheStream() {
        Http3Exception e = assertThrows(Http3Exception.class, () -> runRequest((f, d, c) -> {
            if (f instanceof Http3Frame.Data data && data.text().contains("hunter2")) {
                c.send(Http3Frame.headers(List.of(new Field("x-early", "1"))));
            }
            return f;
        }, requestStream()));
        assertEquals(Http3ErrorCode.H3_FRAME_UNEXPECTED, e.errorCode());
    }

    @Test
    void aResponseMayStartWithInterimHeaders() throws Exception {
        ByteArrayOutputStream in = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(in);
        QpackEncoder qpack = new QpackEncoder();
        w.writeHeaders(qpack.encode(0, List.of(new HeaderField(":status", "103"), new HeaderField("link", "</a.css>"))));
        w.writeHeaders(qpack.encode(0, List.of(new HeaderField(":status", "200"))));
        w.writeData("ok".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FramePipeline.builder((f, d, c) -> f instanceof Http3Frame.Headers h && "200".equals(h.get(":status"))
                        ? h.withHeader("x-direction", d.name()) : f)
                .direction(FrameDirection.FROM_SERVER).build()
                .requestStream(4, new ByteArrayInputStream(in.toByteArray()), out);
        List<Out> frames = read(out.toByteArray(), false);
        assertEquals(List.of("HEADERS", "HEADERS", "DATA"), types(frames));
        assertEquals("103", frames.get(0).field(":status"));
        assertEquals("FROM_SERVER", frames.get(1).field("x-direction"));
    }

    @Test
    void aControlStreamRoundTripsAndItsSettingsCanBeEdited() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        AtomicReference<FrameContext> context = new AtomicReference<>();
        Http3FramePipeline.builder((f, d, c) -> {
            context.compareAndSet(null, c);
            return f instanceof Http3Frame.Settings s
                    ? s.withValue(Http3Frame.SETTINGS_MAX_FIELD_SECTION_SIZE, 4096).withoutValue(Http3FrameType.reserved(5))
                    : f;
        }).connectionId(7).server("example.com:443").build().controlStream(2, new ByteArrayInputStream(controlStream()), out);
        List<Out> frames = read(out.toByteArray(), true);
        assertEquals(3, frames.size());
        io.github.mahmoudimus.http3.Http3Frame.Settings settings = (io.github.mahmoudimus.http3.Http3Frame.Settings) frames.get(0).frame;
        assertEquals(4096L, settings.values().get(Http3Settings.MAX_FIELD_SECTION_SIZE));
        assertEquals(Map.of(Http3Settings.MAX_FIELD_SECTION_SIZE, 4096L), settings.values());
        assertInstanceOf(io.github.mahmoudimus.http3.Http3Frame.Unknown.class, frames.get(1).frame);
        assertEquals(8, ((io.github.mahmoudimus.http3.Http3Frame.MaxPushId) frames.get(2).frame).pushId());
        FrameContext c = context.get();
        assertEquals(FrameProtocol.HTTP_3, c.protocol());
        assertEquals(2, c.streamId());
        assertEquals(7, c.connectionId());
        assertEquals("example.com:443", c.server());
        assertNull(c.flowContext());
        assertNull(c.clientAddress());
        assertThrows(IllegalStateException.class, () -> c.send(Http3Frame.data(new byte[0])));
    }

    /** Results that break a rule: the original is written instead. */
    @Test
    void illegalResultsAreReplacedByTheOriginal() throws Exception {
        List<FrameInterceptor> illegal = List.of(
                (f, d, c) -> f instanceof Http3Frame.Headers ? null : f,
                (f, d, c) -> f instanceof Http3Frame.Headers h ? h.withHeader("Upper", "x") : f,
                (f, d, c) -> f instanceof Http3Frame.Headers h ? h.withHeader("connection", "close") : f,
                (f, d, c) -> f instanceof Http3Frame.Headers ? Http3Frame.data(new byte[1]) : f,
                (f, d, c) -> f instanceof Http3Frame.Data ? new Http3Frame.Settings(Map.of()) : f,
                (f, d, c) -> f instanceof Http3Frame.Data ? org.microproxy.frames.Http2Frame.data(1, new byte[0], false) : f,
                (f, d, c) -> {
                    if (f instanceof Http3Frame.Headers h && h.get(":method") != null) c.send(Http3Frame.data(new byte[1]));
                    return f;
                },
                (f, d, c) -> {
                    throw new IllegalStateException("interceptor bug");
                });
        List<Out> expected = runRequest((f, d, c) -> f, requestStream());
        for (FrameInterceptor i : illegal) {
            List<Out> out = runRequest(i, requestStream());
            assertEquals(types(expected), types(out));
            assertEquals(expected.get(0).fields, out.get(0).fields);
            assertEquals(expected.get(2).text(), out.get(2).text());
        }
        // Control frames: SETTINGS that HTTP/3 forbids, SETTINGS dropped, MAX_PUSH_ID edited.
        List<FrameInterceptor> control = List.of(
                (f, d, c) -> f instanceof Http3Frame.Settings s ? s.withValue(0x02, 1) : f,
                (f, d, c) -> f instanceof Http3Frame.Settings s ? s.withValue(Http3Frame.SETTINGS_ENABLE_CONNECT_PROTOCOL, 2) : f,
                (f, d, c) -> f instanceof Http3Frame.Settings ? null : f,
                (f, d, c) -> f instanceof Http3Frame.MaxPushId ? new Http3Frame.MaxPushId(9) : f);
        for (FrameInterceptor i : control) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Http3FramePipeline.builder(i).build().controlStream(2, new ByteArrayInputStream(controlStream()), out);
            assertArrayEquals(controlStream(), out.toByteArray());
        }
    }

    @Test
    void dynamicTableSectionsNeedTheEncoderStreamAndComeOutStaticOnly() throws Exception {
        QpackEncoder qpack = new QpackEncoder(4096);
        qpack.setPeerSettings(4096, 1);
        ByteArrayOutputStream in = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(in);
        List<HeaderField> fields = new ArrayList<>(request());
        fields.add(new HeaderField("x-long-custom-header", "a value worth a table entry"));
        qpack.insert("x-long-custom-header", "a value worth a table entry");
        w.writeHeaders(qpack.encode(0, fields));
        byte[] encoderStream = concat(Http3StreamType.encode(Http3StreamType.QPACK_ENCODER), qpack.encoderStreamBytes());
        assertTrue(encoderStream.length > 1);

        // Without the encoder stream the section cannot be decoded.
        Http3FramePipeline unfed = Http3FramePipeline.builder((f, d, c) -> f).qpack(4096, 1).build();
        IOException e = assertThrows(IOException.class,
                () -> unfed.requestStream(0, new ByteArrayInputStream(in.toByteArray()), new ByteArrayOutputStream()));
        assertTrue(e.getMessage().contains("encoder stream"), e.getMessage());

        Http3FramePipeline pipeline = Http3FramePipeline.builder((f, d, c) -> f).qpack(4096, 1).build();
        pipeline.encoderStream(new ByteArrayInputStream(encoderStream));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        pipeline.requestStream(0, new ByteArrayInputStream(in.toByteArray()), out);
        // A static-only decoder reads the result.
        List<Out> frames = read(out.toByteArray(), false);
        assertEquals("a value worth a table entry", frames.getFirst().field("x-long-custom-header"));
    }

    @Test
    void malformedInputFailsTheStream() throws Exception {
        byte[] good = requestStream();
        // Cut short in the middle of a frame.
        assertThrows(Http3Exception.class, () -> runRequest((f, d, c) -> f, Arrays.copyOf(good, good.length - 2)));
        // DATA before HEADERS.
        ByteArrayOutputStream dataFirst = new ByteArrayOutputStream();
        new Http3FrameWriter(dataFirst).writeData(new byte[] {1});
        Http3Exception e = assertThrows(Http3Exception.class, () -> runRequest((f, d, c) -> f, dataFirst.toByteArray()));
        assertEquals(Http3ErrorCode.H3_FRAME_UNEXPECTED, e.errorCode());
        // A type HTTP/3 forbids (HTTP/2's PRIORITY).
        assertThrows(Http3Exception.class, () -> runRequest((f, d, c) -> f, new byte[] {0x02, 0x01, 0x00}));
        // A request stream that ends before its header section.
        e = assertThrows(Http3Exception.class, () -> runRequest((f, d, c) -> f, new byte[0]));
        assertEquals(Http3ErrorCode.H3_REQUEST_INCOMPLETE, e.errorCode());
        // A field section that is not QPACK.
        assertThrows(Http3Exception.class, () -> runRequest((f, d, c) -> f, new byte[] {0x01, 0x02, (byte) 0xff, (byte) 0xff}));
        // A control stream that does not start with SETTINGS, and a stream that is not a control stream.
        ByteArrayOutputStream noSettings = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(noSettings);
        w.writeStreamType(Http3StreamType.CONTROL);
        w.writeGoAway(0);
        Http3FramePipeline pipeline = Http3FramePipeline.builder((f, d, c) -> f).build();
        e = assertThrows(Http3Exception.class, () -> pipeline.controlStream(2,
                new ByteArrayInputStream(noSettings.toByteArray()), new ByteArrayOutputStream()));
        assertEquals(Http3ErrorCode.H3_MISSING_SETTINGS, e.errorCode());
        e = assertThrows(Http3Exception.class, () -> pipeline.controlStream(2,
                new ByteArrayInputStream(new byte[] {0x02}), new ByteArrayOutputStream()));
        assertEquals(Http3ErrorCode.H3_STREAM_CREATION_ERROR, e.errorCode());
        assertThrows(IllegalArgumentException.class, () -> pipeline.requestStream(-1, new ByteArrayInputStream(good),
                new ByteArrayOutputStream()));
    }

    @Test
    void longDataIsShownInPieces() throws Exception {
        ByteArrayOutputStream in = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(in);
        w.writeHeaders(new QpackEncoder().encode(0, request()));
        w.writeData(new byte[10_000]);
        List<Integer> sizes = new CopyOnWriteArrayList<>();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FramePipeline.builder((f, d, c) -> {
            if (f instanceof Http3Frame.Data data) sizes.add(data.data().length);
            return f;
        }).maxFramePayloadSize(4096).build().requestStream(0, new ByteArrayInputStream(in.toByteArray()), out);
        assertEquals(List.of(4096, 4096, 1808), sizes);
        Map<String, Integer> total = new LinkedHashMap<>();
        for (Out o : read(out.toByteArray(), false)) {
            if (o.text() != null) total.merge("data", ((io.github.mahmoudimus.http3.Http3Frame.Data) o.frame).data().length, Integer::sum);
        }
        assertEquals(10_000, total.get("data"));
    }

    @Test
    void frameHelpers() {
        assertEquals("QPACK_MAX_TABLE_CAPACITY", Http3Frame.settingName(1));
        assertEquals(0x33, Http3Frame.settingId("SETTINGS_H3_DATAGRAM"));
        assertEquals(0x21, Http3Frame.settingId("0x21"));
        assertThrows(IllegalArgumentException.class, () -> Http3Frame.settingId("NOPE"));
        Http3Frame.Headers h = Http3Frame.headers(List.of(new Field(":status", "200"))).withHeader("a", "1");
        assertEquals("1", h.get("a"));
        assertEquals(Http3Frame.data("x".getBytes(StandardCharsets.UTF_8)), new Http3Frame.Data("x".getBytes(StandardCharsets.UTF_8)));
        assertEquals("h3", FrameProtocol.HTTP_3.alpn());
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
