package io.github.mahmoudimus.http2;

import static io.github.mahmoudimus.http2.TestBytes.assertContains;
import static io.github.mahmoudimus.http2.TestBytes.assertError;
import static io.github.mahmoudimus.http2.TestBytes.frame;
import static io.github.mahmoudimus.http2.TestBytes.hex;
import static io.github.mahmoudimus.http2.TestBytes.reader;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;

/** Frames that break RFC 9113 are rejected with the right error code and scope. */
class FrameReaderTest {

    private static final ErrorCode PROTOCOL = ErrorCode.PROTOCOL_ERROR;
    private static final ErrorCode FRAME_SIZE = ErrorCode.FRAME_SIZE_ERROR;

    private static byte[] ping() {
        return frame(FrameType.PING, 0, 0, new byte[8]);
    }

    // --- lengths -------------------------------------------------------------------------------

    @Test
    void frameLargerThanMaxFrameSizeIsRejectedBeforeItsPayloadIsRead() throws IOException {
        // Declares 16385 bytes but carries none: the reader must fail on the header alone.
        assertError(FRAME_SIZE, true, reader(frame(16_385, FrameType.DATA, 0, 1)));
        assertError(FRAME_SIZE, true, reader(frame(0xffffff, FrameType.HEADERS, 0, 1)));
        assertError(FRAME_SIZE, true, reader(frame(0xffffff, 0xee, 0, 0))); // even unknown types
        // Raising the limit admits the frame.
        byte[] big = frame(FrameType.DATA, 0, 1, new byte[20_000]);
        FrameReader r = reader(x -> x.setMaxFrameSize(32_768), big);
        assertEquals(20_000, ((Frame.Data) r.readFrame()).data().length);
    }

    @Test
    void fixedLengthFramesWithTheWrongLength() {
        assertError(FRAME_SIZE, true, reader(frame(FrameType.PING, 0, 0, new byte[7])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.PING, 0, 0, new byte[9])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.RST_STREAM, 0, 1, new byte[3])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.WINDOW_UPDATE, 0, 1, new byte[5])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.WINDOW_UPDATE, 0, 0, new byte[3])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.GOAWAY, 0, 0, new byte[7])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.SETTINGS, 0, 0, new byte[5])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.SETTINGS, FrameType.FLAG_ACK, 0, new byte[6])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.PUSH_PROMISE, FrameType.FLAG_END_HEADERS, 1, new byte[3])));
        assertError(FRAME_SIZE, true, reader(frame(FrameType.HEADERS, FrameType.FLAG_PRIORITY | FrameType.FLAG_END_HEADERS, 1, new byte[4])));
    }

    @Test
    void priorityWithTheWrongLengthIsAStreamErrorAndReadingContinues() throws IOException {
        FrameReader r = reader(frame(FrameType.PRIORITY, 0, 3, new byte[4]), ping());
        Http2Exception e = assertThrows(Http2Exception.class, r::readFrame);
        assertEquals(FRAME_SIZE, e.errorCode());
        assertEquals(3, e.streamId());
        assertInstanceOf(Frame.Ping.class, r.readFrame());
    }

    // --- padding -------------------------------------------------------------------------------

    @Test
    void paddingLongerThanThePayload() {
        // Pad Length 5 with only 4 bytes after it.
        assertError(PROTOCOL, true, reader(frame(FrameType.DATA, FrameType.FLAG_PADDED, 1, hex("05 00000000"))));
        // Pad Length equal to the payload length.
        assertError(PROTOCOL, true, reader(frame(FrameType.DATA, FrameType.FLAG_PADDED, 1, hex("03 0000"))));
        // HEADERS: the 5 priority bytes leave no room for 1 byte of padding.
        assertError(PROTOCOL, true, reader(frame(FrameType.HEADERS,
                FrameType.FLAG_PADDED | FrameType.FLAG_PRIORITY | FrameType.FLAG_END_HEADERS, 1, hex("01 00000000 0f"))));
        // PUSH_PROMISE: the promised stream id leaves no room.
        assertError(PROTOCOL, true, reader(frame(FrameType.PUSH_PROMISE,
                FrameType.FLAG_PADDED | FrameType.FLAG_END_HEADERS, 1, hex("01 00000002"))));
        // PADDED with no room even for the Pad Length.
        assertError(FRAME_SIZE, true, reader(frame(FrameType.DATA, FrameType.FLAG_PADDED, 1)));
    }

    @Test
    void paddingThatExactlyFitsIsAccepted() throws IOException {
        Frame.Data d = (Frame.Data) reader(frame(FrameType.DATA, FrameType.FLAG_PADDED, 1, hex("03 000000"))).readFrame();
        assertEquals(0, d.data().length);
        assertEquals(4, d.flowControlledLength());
        Frame.Headers h = (Frame.Headers) reader(frame(FrameType.HEADERS,
                FrameType.FLAG_PADDED | FrameType.FLAG_PRIORITY | FrameType.FLAG_END_HEADERS, 1, hex("01 80000003 0f 82 00"))).readFrame();
        assertArrayEquals(hex("82"), h.fieldBlock());
        assertEquals(new Frame.PrioritySpec(3, true, 16), h.priority());
        assertEquals(2, h.padding());
    }

    // --- stream identifiers --------------------------------------------------------------------

    @Test
    void streamFramesOnStreamZero() {
        assertError(PROTOCOL, true, reader(frame(FrameType.DATA, 0, 0, hex("00"))));
        assertError(PROTOCOL, true, reader(frame(FrameType.HEADERS, FrameType.FLAG_END_HEADERS, 0, hex("82"))));
        assertError(PROTOCOL, true, reader(frame(FrameType.PRIORITY, 0, 0, new byte[5])));
        assertError(PROTOCOL, true, reader(frame(FrameType.RST_STREAM, 0, 0, new byte[4])));
        assertError(PROTOCOL, true, reader(frame(FrameType.PUSH_PROMISE, FrameType.FLAG_END_HEADERS, 0, hex("00000002"))));
        assertError(PROTOCOL, true, reader(frame(FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 0, hex("82"))));
    }

    @Test
    void connectionFramesOnAStream() {
        assertError(PROTOCOL, true, reader(frame(FrameType.SETTINGS, 0, 1)));
        assertError(PROTOCOL, true, reader(frame(FrameType.PING, 0, 1, new byte[8])));
        assertError(PROTOCOL, true, reader(frame(FrameType.GOAWAY, 0, 1, new byte[8])));
    }

    @Test
    void pushPromiseOfStreamZero() {
        assertError(PROTOCOL, true, reader(frame(FrameType.PUSH_PROMISE, FrameType.FLAG_END_HEADERS, 1, hex("00000000"))));
    }

    @Test
    void pushPromiseIsReturnedForTheCallerToRefuse() throws IOException {
        Frame f = reader(frame(FrameType.PUSH_PROMISE, FrameType.FLAG_END_HEADERS, 1, hex("00000002 82"))).readFrame();
        Frame.PushPromise p = assertInstanceOf(Frame.PushPromise.class, f);
        assertEquals(2, p.promisedStreamId());
        assertArrayEquals(hex("82"), p.fieldBlock());
    }

    @Test
    void streamDependingOnItselfIsAStreamError() throws IOException {
        FrameReader r = reader(frame(FrameType.PRIORITY, 0, 5, hex("00000005 10")), ping());
        Http2Exception e = assertThrows(Http2Exception.class, r::readFrame);
        assertEquals(PROTOCOL, e.errorCode());
        assertEquals(5, e.streamId());
        assertInstanceOf(Frame.Ping.class, r.readFrame());
    }

    @Test
    void zeroWindowIncrement() throws IOException {
        assertError(PROTOCOL, true, reader(frame(FrameType.WINDOW_UPDATE, 0, 0, hex("00000000"))));
        // On a stream it only affects that stream, and the frame has been consumed.
        FrameReader r = reader(frame(FrameType.WINDOW_UPDATE, 0, 7, hex("80000000")), ping());
        Http2Exception e = assertThrows(Http2Exception.class, r::readFrame);
        assertEquals(PROTOCOL, e.errorCode());
        assertEquals(7, e.streamId());
        assertInstanceOf(Frame.Ping.class, r.readFrame());
    }

    // --- SETTINGS values -----------------------------------------------------------------------

    @Test
    void invalidSettingsValues() {
        assertError(PROTOCOL, true, reader(frame(FrameType.SETTINGS, 0, 0, hex("0002 00000002"))));
        assertError(ErrorCode.FLOW_CONTROL_ERROR, true, reader(frame(FrameType.SETTINGS, 0, 0, hex("0004 80000000"))));
        assertError(PROTOCOL, true, reader(frame(FrameType.SETTINGS, 0, 0, hex("0005 00003fff"))));
        assertError(PROTOCOL, true, reader(frame(FrameType.SETTINGS, 0, 0, hex("0005 01000000"))));
    }

    // --- field blocks --------------------------------------------------------------------------

    @Test
    void continuationWithoutHeaders() {
        assertError(PROTOCOL, true, reader(frame(FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 1, hex("82"))));
        // Also after a complete HEADERS.
        assertError(PROTOCOL, true, reader(
                frame(FrameType.HEADERS, FrameType.FLAG_END_HEADERS, 1, hex("82")),
                frame(FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 1, hex("84"))));
    }

    @Test
    void framesInterleavedInAFieldBlock() {
        byte[] open = frame(FrameType.HEADERS, 0, 1, hex("82"));
        byte[] end = frame(FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 1, hex("84"));
        for (byte[] intruder : new byte[][] {
            ping(),
            frame(FrameType.DATA, 0, 1, hex("00")),
            frame(FrameType.HEADERS, FrameType.FLAG_END_HEADERS, 3, hex("82")),
            frame(FrameType.WINDOW_UPDATE, 0, 0, hex("00000001")),
            frame(0xee, 0, 1, hex("00")), // even an extension frame (§5.5)
            frame(FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 3, hex("84")), // another stream
        }) {
            Http2Exception e = assertError(PROTOCOL, true, reader(open, intruder, end));
            assertContains(e.getMessage(), "field block");
        }
    }

    @Test
    void fieldBlockOverTheCap() {
        // One HEADERS frame already over the cap.
        assertError(ErrorCode.ENHANCE_YOUR_CALM, true,
                reader(r -> r.setMaxHeaderBlockSize(100), frame(FrameType.HEADERS, FrameType.FLAG_END_HEADERS, 1, new byte[101])));
        // Over the cap only once CONTINUATION frames are added; the oversize one is not read.
        byte[] open = frame(FrameType.HEADERS, 0, 1, new byte[60]);
        byte[] more = frame(FrameType.CONTINUATION, 0, 1, new byte[30]);
        byte[] tooMuch = frame(20, FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 1);
        assertError(ErrorCode.ENHANCE_YOUR_CALM, true, reader(r -> r.setMaxHeaderBlockSize(100), open, more, tooMuch));
        // Exactly at the cap is fine.
        byte[] fits = frame(FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 1, new byte[10]);
        assertDoesNotFail(reader(r -> r.setMaxHeaderBlockSize(100), open, more, fits));
    }

    @Test
    void continuationFloodOfEmptyFrames() {
        // Empty CONTINUATION frames never grow the block; the frame count still stops them.
        InputStream endless = new InputStream() {
            private final byte[] open = frame(FrameType.HEADERS, 0, 1, hex("82"));
            private final byte[] empty = frame(FrameType.CONTINUATION, 0, 1);
            private long pos;

            @Override
            public int read() {
                long p = pos++;
                if (p < open.length) return open[(int) p] & 0xff;
                return empty[(int) ((p - open.length) % empty.length)] & 0xff;
            }
        };
        FrameReader r = new FrameReader(endless);
        r.setMaxContinuationFrames(50);
        Http2Exception e = assertThrows(Http2Exception.class, r::readFrame);
        assertEquals(ErrorCode.ENHANCE_YOUR_CALM, e.errorCode());
    }

    @Test
    void continuationLargerThanMaxFrameSize() {
        assertError(FRAME_SIZE, true, reader(
                frame(FrameType.HEADERS, 0, 1, hex("82")),
                frame(16_385, FrameType.CONTINUATION, FrameType.FLAG_END_HEADERS, 1)));
    }

    @Test
    void pushPromiseContinuationsFollowTheSameRules() {
        assertError(PROTOCOL, true, reader(
                frame(FrameType.PUSH_PROMISE, 0, 1, hex("00000002 82")),
                ping()));
    }

    private static void assertDoesNotFail(FrameReader r) {
        try {
            Frame f = r.readFrame();
            assertInstanceOf(Frame.Headers.class, f);
            assertEquals(100, ((Frame.Headers) f).fieldBlock().length);
            assertNull(r.readFrame());
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void errorMessagesNameTheScope() {
        Http2Exception e = assertError(PROTOCOL, true, reader(frame(FrameType.DATA, 0, 0, hex("00"))));
        assertContains(e.getMessage(), "connection error PROTOCOL_ERROR");
        assertEquals(0, e.streamId());
        Http2Exception s = Http2Exception.streamError(3, ErrorCode.CANCEL, "x");
        assertContains(s.getMessage(), "stream 3 error CANCEL");
        assertThrows(IllegalArgumentException.class, () -> Http2Exception.streamError(0, ErrorCode.CANCEL, "x"));
    }

    @Test
    void unknownFrameIsSkippedWithoutAllocatingItsPayload() throws IOException {
        // A 16 KiB unknown frame on an otherwise tiny stream: skipped, then the PING is read.
        byte[] unknown = frame(FrameType.CONTINUATION + 1, 0xff, 0x7fffffff, new byte[16_384]);
        FrameReader r = new FrameReader(new ByteArrayInputStream(TestBytes.concat(unknown, ping())));
        assertInstanceOf(Frame.Ping.class, r.readFrame());
    }
}
