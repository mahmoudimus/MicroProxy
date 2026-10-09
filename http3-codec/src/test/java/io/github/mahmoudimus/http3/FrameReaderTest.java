package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.assertConnectionError;
import static io.github.mahmoudimus.http3.TestBytes.assertContains;
import static io.github.mahmoudimus.http3.TestBytes.concat;
import static io.github.mahmoudimus.http3.TestBytes.frame;
import static io.github.mahmoudimus.http3.TestBytes.hex;
import static io.github.mahmoudimus.http3.TestBytes.reader;
import static io.github.mahmoudimus.http3.TestBytes.settingsPayload;
import static io.github.mahmoudimus.http3.TestBytes.varint;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Frames that break RFC 9114 §7 are rejected with the right error code. */
class FrameReaderTest {

    private static final Http3ErrorCode FRAME_ERROR = Http3ErrorCode.H3_FRAME_ERROR;
    private static final Http3ErrorCode SETTINGS_ERROR = Http3ErrorCode.H3_SETTINGS_ERROR;

    @Test
    void http2OnlyFrameTypesAreUnexpected() {
        for (long type : new long[] {0x02, 0x06, 0x08, 0x09}) {
            Http3Exception e = assertConnectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED, reader(frame(type, new byte[4])));
            assertContains(e.getMessage(), "HTTP/2");
            // Rejected on the type alone, before the length or payload arrive.
            assertConnectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED, reader(varint(type)));
            assertConnectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED,
                    () -> Http3FrameReader.parse(ByteBuffer.wrap(varint(type)), 100));
        }
    }

    @Test
    void framesCutShortByTheEndOfTheStream() {
        byte[] settings = Http3FrameWriter.encode(Http3Settings.builder().qpackMaxTableCapacity(4096).qpackBlockedStreams(100).build().toFrame());
        byte[] whole = concat(settings, Http3FrameWriter.encode(new Http3Frame.Data(new byte[300])));
        // Every cut that is not on a frame boundary is a truncated frame.
        int boundary = settings.length;
        for (int cut = 1; cut < whole.length; cut++) {
            if (cut == boundary) continue;
            assertConnectionError(FRAME_ERROR, reader(Arrays.copyOf(whole, cut)));
        }
        // Truncated inside a two-byte type, inside the length, inside a skipped unknown frame.
        assertConnectionError(FRAME_ERROR, reader(hex("40")));
        assertConnectionError(FRAME_ERROR, reader(hex("0040")));
        Http3FrameReader skipping = reader(frame(0x21, 50, new byte[10]));
        skipping.setDeliverUnknownFrames(false);
        assertConnectionError(FRAME_ERROR, skipping);
    }

    @Test
    void cleanEndOfStreamBetweenFrames() throws IOException {
        assertNull(reader().readFrame());
        Http3FrameReader r = reader(frame(Http3FrameType.GOAWAY, varint(0)));
        assertEquals(new Http3Frame.GoAway(0), r.readFrame());
        assertNull(r.readFrame());
    }

    @Test
    void singleIntegerFramesMustHoldExactlyOneInteger() {
        for (long type : new long[] {Http3FrameType.CANCEL_PUSH, Http3FrameType.GOAWAY, Http3FrameType.MAX_PUSH_ID}) {
            assertConnectionError(FRAME_ERROR, reader(frame(type))); // empty
            assertConnectionError(FRAME_ERROR, reader(frame(type, hex("0405")))); // extra byte
            assertConnectionError(FRAME_ERROR, reader(frame(type, hex("40")))); // integer cut short
            assertConnectionError(FRAME_ERROR, reader(frame(type, hex("80000001ff"))));
        }
        assertConnectionError(FRAME_ERROR, reader(frame(Http3FrameType.PUSH_PROMISE)));
        assertConnectionError(FRAME_ERROR, reader(frame(Http3FrameType.PUSH_PROMISE, hex("c0"))));
    }

    @Test
    void payloadLimitIsCheckedBeforeReading() {
        // Declares a megabyte but carries nothing: the reader must fail on the header alone.
        for (long type : new long[] {Http3FrameType.HEADERS, Http3FrameType.SETTINGS, Http3FrameType.PUSH_PROMISE, 0x21}) {
            InputStream noMore = new ByteArrayInputStream(frame(type, 1 << 20, new byte[0])) {
                @Override
                public byte[] readNBytes(int len) {
                    throw new AssertionError("payload read despite the limit");
                }
            };
            assertConnectionError(Http3ErrorCode.H3_EXCESSIVE_LOAD, new Http3FrameReader(noMore));
        }
        Http3FrameReader r = reader(frame(Http3FrameType.HEADERS, new byte[200]));
        r.setMaxFramePayloadSize(100);
        assertConnectionError(Http3ErrorCode.H3_EXCESSIVE_LOAD, r);
        assertConnectionError(Http3ErrorCode.H3_EXCESSIVE_LOAD,
                () -> Http3FrameReader.parse(ByteBuffer.wrap(frame(Http3FrameType.DATA, new byte[200])), 100));
        assertThrows(IllegalArgumentException.class, () -> reader().setMaxFramePayloadSize(0));
    }

    @Test
    void settingsMayNotRepeatAnIdentifier() {
        Http3Exception e = assertConnectionError(SETTINGS_ERROR, reader(frame(Http3FrameType.SETTINGS, settingsPayload(1, 100, 7, 1, 1, 100))));
        assertContains(e.getMessage(), "more than once");
        // Even reserved and unknown ones.
        assertConnectionError(SETTINGS_ERROR, reader(frame(Http3FrameType.SETTINGS, settingsPayload(0x21, 1, 0x21, 2))));
        // The same identifier with a non-minimal encoding is still the same identifier.
        assertConnectionError(SETTINGS_ERROR, reader(frame(Http3FrameType.SETTINGS, concat(hex("06 01"), hex("4006 02")))));
    }

    @Test
    void http2OnlySettingsAreRejected() {
        for (long id : new long[] {0x00, 0x02, 0x03, 0x04, 0x05}) {
            Http3Exception e = assertConnectionError(SETTINGS_ERROR, reader(frame(Http3FrameType.SETTINGS, settingsPayload(id, 0))));
            assertContains(e.getMessage(), "reserved");
        }
    }

    @Test
    void booleanSettingsMustBeZeroOrOne() throws IOException {
        for (long id : new long[] {Http3Settings.ENABLE_CONNECT_PROTOCOL, Http3Settings.H3_DATAGRAM}) {
            assertConnectionError(SETTINGS_ERROR, reader(frame(Http3FrameType.SETTINGS, settingsPayload(id, 2))));
            assertEquals(1L, ((Http3Frame.Settings) reader(frame(Http3FrameType.SETTINGS, settingsPayload(id, 1))).readFrame())
                    .values().get(id));
        }
    }

    @Test
    void settingsPayloadMustEndOnAPair() {
        assertConnectionError(FRAME_ERROR, reader(frame(Http3FrameType.SETTINGS, settingsPayload(1))));
        assertConnectionError(FRAME_ERROR, reader(frame(Http3FrameType.SETTINGS, hex("0140"))));
        assertConnectionError(FRAME_ERROR, reader(frame(Http3FrameType.SETTINGS, hex("4001"))));
    }

    @Test
    void settingsKeepUnknownAndReservedIdentifiersInOrder() throws IOException {
        Http3Frame.Settings s = (Http3Frame.Settings) reader(frame(Http3FrameType.SETTINGS,
                settingsPayload(0x40, 9, 6, 1000, 0x1234, 5, 1, 0))).readFrame();
        assertEquals(List.of(0x40L, 6L, 0x1234L, 1L), List.copyOf(s.values().keySet()));
    }

    @Test
    void streamTypeIsReadBeforeTheFrames() throws IOException {
        Http3FrameReader r = reader(varint(Http3StreamType.QPACK_DECODER));
        assertEquals(Http3StreamType.QPACK_DECODER, r.readStreamType());
        assertEquals(Http3FrameType.reserved(5), reader(varint(Http3FrameType.reserved(5))).readStreamType());
        // A stream that ends before or inside its type is tolerated.
        assertEquals(-1, reader().readStreamType());
        assertEquals(-1, reader(hex("80 00")).readStreamType());
        assertEquals("QPACK encoder", Http3StreamType.name(Http3StreamType.QPACK_ENCODER));
        assertContains(Http3StreamType.name(0x21), "reserved");
    }
}
