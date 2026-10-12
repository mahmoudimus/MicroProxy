package io.github.mahmoudimus.quic.connection;

import static io.github.mahmoudimus.quic.connection.StreamsStateTest.code;
import static io.github.mahmoudimus.quic.connection.StreamsStateTest.kind;
import static io.github.mahmoudimus.quic.connection.StreamsStateTest.resetFrame;
import static io.github.mahmoudimus.quic.connection.StreamsStateTest.stream;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.params.TransportParameters;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Stream state machines, flow control and the frames they generate. */
class StreamLifecycleTest {

    private static final long WINDOW = 1000;

    /** A client whose peer allows two streams of each kind and {@code WINDOW} bytes of credit. */
    private static StreamsState client() {
        StreamsState s = new StreamsState(Side.CLIENT, 4, 4, 1 << 20, 4 * WINDOW, WINDOW);
        s.setParams(TransportParameters.builder().initialMaxStreamsBidi(2).initialMaxStreamsUni(2)
                .initialMaxData(4 * WINDOW).initialMaxStreamDataBidiRemote(WINDOW).initialMaxStreamDataBidiLocal(WINDOW)
                .initialMaxStreamDataUni(WINDOW).build());
        return s;
    }

    private static List<Frame> frames(ByteBuffer buf) throws Exception {
        buf.flip();
        return FrameDecoder.decodeAll(buf, PacketType.ONE_RTT);
    }

    private static List<Frame> control(StreamsState s, Retransmits pending) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(1200);
        s.writeControlFrames(buf, pending, new Retransmits(), 1200);
        return frames(buf);
    }

    private static ByteBuffer data(String s) {
        return ByteBuffer.wrap(s.getBytes(StandardCharsets.US_ASCII));
    }

    // ---- send side ----

    @Test
    void sendStateMachineToDataRecvd() throws Exception {
        StreamsState s = client();
        Retransmits pending = new Retransmits();
        StreamId id = s.open(Dir.UNI);
        assertEquals(SendState.READY, s.sendState(id));
        assertEquals(5, s.write(id, data("hello"), pending));
        assertEquals(SendState.READY, s.sendState(id), "Send starts with the first frame sent");

        ByteBuffer buf = ByteBuffer.allocate(1200);
        List<StreamMeta> sent = s.writeStreamFrames(buf, 1200, true);
        assertEquals(List.of(new StreamMeta(id, 0, 5, false)), sent);
        assertEquals(SendState.SEND, s.sendState(id));
        Frame.Stream f = (Frame.Stream) frames(buf).get(0);
        assertEquals(id.value(), f.streamId());
        assertFalse(f.fin());

        s.finish(id);
        assertEquals(SendState.SEND, s.sendState(id), "the FIN is not sent yet");
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> s.write(id, data("x"), pending)));
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> s.finish(id)));

        buf = ByteBuffer.allocate(1200);
        sent = s.writeStreamFrames(buf, 1200, true);
        assertEquals(List.of(new StreamMeta(id, 5, 5, true)), sent, "an empty frame carries the FIN");
        assertEquals(SendState.DATA_SENT, s.sendState(id));

        s.receivedAckOf(new StreamMeta(id, 0, 5, false));
        assertEquals(SendState.DATA_SENT, s.sendState(id));
        assertEquals(1, s.sendStreams());
        s.receivedAckOf(new StreamMeta(id, 5, 5, true));
        assertNull(s.sendState(id), "released in DATA_RECVD");
        assertEquals(new StreamEvent.Finished(id), s.poll());
        assertEquals(0, s.sendStreams());
    }

    @Test
    void lostFrameIsRetransmittedWithItsFin() throws Exception {
        StreamsState s = client();
        Retransmits pending = new Retransmits();
        StreamId id = s.open(Dir.UNI);
        s.write(id, data("abcdef"), pending);
        s.finish(id);
        List<StreamMeta> sent = s.writeStreamFrames(ByteBuffer.allocate(1200), 1200, true);
        assertEquals(List.of(new StreamMeta(id, 0, 6, true)), sent);
        assertFalse(s.canSendStreamData());

        s.retransmit(sent.get(0));
        assertTrue(s.canSendStreamData());
        ByteBuffer buf = ByteBuffer.allocate(1200);
        assertEquals(sent, s.writeStreamFrames(buf, 1200, true));
        Frame.Stream f = (Frame.Stream) frames(buf).get(0);
        byte[] got = new byte[f.data().remaining()];
        f.data().get(got);
        assertArrayEquals("abcdef".getBytes(StandardCharsets.US_ASCII), got);
        assertTrue(f.fin());
    }

    @Test
    void resetSendsResetStreamWithFinalSizeAndReleasesOnAck() throws Exception {
        StreamsState s = client();
        Retransmits pending = new Retransmits();
        StreamId id = s.open(Dir.BI);
        s.write(id, data("0123456789"), pending);
        s.writeStreamFrames(ByteBuffer.allocate(1200), 1200, true);
        s.reset(id, 77, pending);
        assertEquals(SendState.RESET_SENT, s.sendState(id));
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> s.reset(id, 77, pending)), "redundant reset");
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> s.write(id, data("x"), pending)));
        assertFalse(s.canSendStreamData(), "reset streams send no STREAM frames");
        // Losing STREAM data of a reset stream does nothing
        s.retransmit(new StreamMeta(id, 0, 10, false));
        assertFalse(s.canSendStreamData());

        Retransmits sentFrames = new Retransmits();
        ByteBuffer buf = ByteBuffer.allocate(1200);
        s.writeControlFrames(buf, pending, sentFrames, 1200);
        assertEquals(List.of(new Frame.ResetStream(id.value(), 77, 10)), frames(buf));
        assertEquals(List.of(new Retransmits.PendingReset(id, 77)), sentFrames.resetStream);

        s.resetAcked(id);
        assertNull(s.sendState(id), "released in RESET_RECVD");
        // The bidirectional stream's receive half still counts
        assertEquals(RecvState.RECV, s.recvState(id));
    }

    @Test
    void stopSendingStopsWritesAndFinish() throws Exception {
        StreamsState s = client();
        Retransmits pending = new Retransmits();
        StreamId id = s.open(Dir.BI);
        s.receivedStopSending(new Frame.StopSending(id.value(), 9));
        assertEquals(new StreamEvent.Stopped(id, 9), s.poll());
        assertEquals(9, s.stopped(id));
        StreamException e = assertThrows(StreamException.class, () -> s.finish(id));
        assertEquals(StreamException.Kind.STOPPED, e.kind());
        assertEquals(9, e.errorCode());
        // The application answers with a reset, as RFC 9000 section 3.5 requires
        s.reset(id, 9, pending);
        assertEquals(SendState.RESET_SENT, s.sendState(id));
    }

    // ---- receive side ----

    @Test
    void recvStateMachineToDataRead() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        assertFalse(s.received(new Frame.Stream(id.value(), 0, data("hel"), false), 3));
        assertEquals(new StreamEvent.Opened(Dir.UNI), s.poll());
        assertEquals(id, s.accept(Dir.UNI));
        assertNull(s.accept(Dir.UNI));
        assertEquals(new StreamEvent.Readable(id), s.poll());
        assertEquals(RecvState.RECV, s.recvState(id));

        s.received(new Frame.Stream(id.value(), 5, data("!"), true), 1);
        assertEquals(RecvState.SIZE_KNOWN, s.recvState(id), "bytes 3 and 4 are missing");
        s.received(new Frame.Stream(id.value(), 3, data("lo"), false), 2);
        assertEquals(RecvState.DATA_RECVD, s.recvState(id));

        Retransmits pending = new Retransmits();
        StringBuilder text = new StringBuilder();
        try (Chunks chunks = s.read(id, true, pending)) {
            Chunk c;
            while ((c = chunks.next(Integer.MAX_VALUE)) != null) {
                text.append(new String(c.toByteArray(), StandardCharsets.US_ASCII));
            }
            assertEquals(6, chunks.bytesRead());
        }
        assertEquals("hello!", text.toString());
        assertNull(s.recvState(id), "released in DATA_READ");
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> s.read(id, true, pending)));
    }

    @Test
    void readBlocksUntilDataArrives() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.BI, 0);
        s.received(new Frame.Stream(id.value(), 2, data("cd"), false), 2);
        Retransmits pending = new Retransmits();
        try (Chunks chunks = s.read(id, true, pending)) {
            assertEquals(StreamException.Kind.BLOCKED, kind(() -> chunks.next(10)));
        }
        try (Chunks chunks = s.read(id, false, pending)) {
            Chunk c = chunks.next(10);
            assertEquals(2, c.offset(), "unordered reads return what is there");
        }
        assertEquals(StreamException.Kind.ILLEGAL_ORDERED_READ, kind(() -> s.read(id, true, pending)));
    }

    @Test
    void resetRecvdThenResetRead() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 1);
        s.received(new Frame.Stream(id.value(), 0, data("abc"), false), 3);
        assertFalse(s.receivedReset(resetFrame(id, 42, 10)));
        assertEquals(RecvState.RESET_RECVD, s.recvState(id));
        Retransmits pending = new Retransmits();
        assertEquals(42, s.takeReset(id, pending));
        assertNull(s.recvState(id), "released in RESET_READ");
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> s.takeReset(id, pending)));
        // Later frames for the stream are ignored
        assertFalse(s.received(new Frame.Stream(id.value(), 0, data("abc"), false), 3));
    }

    @Test
    void readReportsResetAfterBufferedDataIsDropped() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        s.received(new Frame.Stream(id.value(), 0, data("abc"), false), 3);
        s.receivedReset(resetFrame(id, 5, 3));
        try (Chunks chunks = s.read(id, true, new Retransmits())) {
            StreamException e = assertThrows(StreamException.class, () -> chunks.next(10));
            assertEquals(StreamException.Kind.RESET, e.kind());
            assertEquals(5, e.errorCode());
            assertThrows(StreamException.class, () -> chunks.next(10), "a reset is reported again");
        }
        assertNull(s.recvState(id));
    }

    @Test
    void stopQueuesStopSendingAndCredit() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.BI, 0);
        s.received(stream(id, 0, 800, false), 800);
        Retransmits pending = new Retransmits();
        s.stop(id, 3, pending);
        List<Frame> out = control(s, pending);
        assertTrue(out.contains(new Frame.StopSending(id.value(), 3)), out.toString());
        assertTrue(out.contains(new Frame.MaxData(4 * WINDOW + 800)), "discarded data returns its credit: " + out);
    }

    // ---- flow control ----

    @Test
    void streamFlowControlViolation() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        s.received(stream(id, 0, (int) WINDOW, false), (int) WINDOW);
        assertEquals(QuicException.FLOW_CONTROL_ERROR, code(() -> s.received(stream(id, WINDOW, 1, false), 1)));
        // A RESET_STREAM claiming a final size beyond the limit too
        assertEquals(QuicException.FLOW_CONTROL_ERROR, code(() -> s.receivedReset(resetFrame(id, 0, WINDOW + 1))));
    }

    @Test
    void connectionFlowControlViolation() throws Exception {
        StreamsState s = client();
        for (int i = 0; i < 4; i++) {
            s.received(stream(StreamId.of(Side.SERVER, Dir.BI, i), 0, (int) WINDOW, false), (int) WINDOW);
        }
        // Every stream has credit left, but the connection does not
        StreamId fifth = StreamId.of(Side.SERVER, Dir.UNI, 0);
        assertEquals(QuicException.FLOW_CONTROL_ERROR, code(() -> s.received(stream(fifth, 0, 1, false), 1)));
        // Retransmissions of data already counted are fine
        assertFalse(s.received(stream(StreamId.of(Side.SERVER, Dir.BI, 0), 0, 10, false), 10));
    }

    @Test
    void creditIsIssuedAsTheApplicationReads() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        s.received(stream(id, 0, 100, false), 100);
        Retransmits pending = new Retransmits();
        try (Chunks chunks = s.read(id, true, pending)) {
            chunks.next(100);
        }
        assertTrue(pending.maxStreamData.isEmpty(), "100 bytes is less than an eighth of the window");

        s.received(stream(id, 100, 200, false), 200);
        Chunks chunks = s.read(id, true, pending);
        chunks.next(200);
        chunks.close();
        assertTrue(chunks.shouldTransmit());
        assertTrue(pending.maxStreamData.contains(id));
        List<Frame> out = control(s, pending);
        assertTrue(out.contains(new Frame.MaxStreamData(id.value(), 300 + WINDOW)), out.toString());
        // The peer may now send up to the new limit
        assertFalse(s.received(stream(id, 300, (int) WINDOW, false), (int) WINDOW));
    }

    @Test
    void streamDataBlockedIsGeneratedOncePerLimit() throws Exception {
        StreamsState s = client();
        Retransmits pending = new Retransmits();
        StreamId id = s.open(Dir.BI);
        assertEquals(WINDOW, s.write(id, ByteBuffer.allocate(5000), pending));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> s.write(id, ByteBuffer.allocate(1), pending)));
        assertEquals(WINDOW, s.streamDataBlockedLimit(id));
        assertEquals(List.of(new Frame.StreamDataBlocked(id.value(), WINDOW)), control(s, pending));
        // Blocking again at the same limit queues nothing new
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> s.write(id, ByteBuffer.allocate(1), pending)));
        assertTrue(pending.streamDataBlocked.isEmpty());

        s.receivedMaxStreamData(id, 2 * WINDOW);
        assertEquals(new StreamEvent.Writable(id), s.poll());
        assertEquals(-1, s.streamDataBlockedLimit(id), "a raised limit makes the old frame stale");
        assertEquals(WINDOW, s.write(id, ByteBuffer.allocate(5000), pending));
    }

    @Test
    void dataBlockedOnConnectionLimit() throws Exception {
        StreamsState s = new StreamsState(Side.CLIENT, 4, 4, 1 << 20, WINDOW, WINDOW);
        s.setParams(TransportParameters.builder().initialMaxStreamsUni(2).initialMaxData(1500)
                .initialMaxStreamDataUni(WINDOW).build());
        Retransmits pending = new Retransmits();
        StreamId a = s.open(Dir.UNI);
        StreamId b = s.open(Dir.UNI);
        assertEquals(WINDOW, s.write(a, ByteBuffer.allocate(5000), pending));
        assertEquals(500, s.write(b, ByteBuffer.allocate(5000), pending));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> s.write(b, ByteBuffer.allocate(1), pending)));
        assertTrue(pending.dataBlocked);
        assertEquals(List.of(new Frame.DataBlocked(1500)), control(s, pending));

        s.receivedMaxData(1000); // smaller limits are ignored
        assertNull(s.poll());
        s.receivedMaxData(1600);
        assertEquals(new StreamEvent.Writable(b), s.poll());
        assertEquals(100, s.write(b, ByteBuffer.allocate(5000), pending));
    }

    @Test
    void streamsBlockedAndMaxStreams() throws Exception {
        StreamsState s = client();
        Retransmits pending = new Retransmits();
        s.open(Dir.UNI);
        s.open(Dir.UNI);
        assertNull(s.open(Dir.UNI), "the peer allows two");
        assertEquals(List.of(new Frame.StreamsBlocked(false, 2)), control(s, pending));
        s.receivedMaxStreams(Dir.UNI, 3);
        assertEquals(new StreamEvent.Available(Dir.UNI), s.poll());
        assertEquals(StreamId.of(Side.CLIENT, Dir.UNI, 2), s.open(Dir.UNI));
        assertEquals(QuicException.FRAME_ENCODING_ERROR,
                code(() -> s.receivedMaxStreams(Dir.BI, StreamsState.MAX_STREAM_COUNT + 1)));
    }

    @Test
    void maxStreamsIsIssuedAsRemoteStreamsClose() throws Exception {
        StreamsState s = new StreamsState(Side.SERVER, 8, 8, 1 << 20, 1 << 20, 1 << 16);
        Retransmits pending = new Retransmits();
        for (int i = 0; i < 2; i++) {
            StreamId id = StreamId.of(Side.CLIENT, Dir.UNI, i);
            s.received(stream(id, 0, 1, true), 1);
            try (Chunks chunks = s.read(id, true, pending)) {
                chunks.next(1);
                assertNull(chunks.next(1));
            }
        }
        assertEquals(10, s.maxRemote[Dir.UNI.ordinal()]);
        assertTrue(pending.maxStreamId[Dir.UNI.ordinal()], "two of eight closed: more than an eighth");
        assertEquals(List.of(new Frame.MaxStreams(false, 10)), control(s, pending));
        assertEquals(0, s.remoteOpenStreams(Dir.UNI), "no stream is open");
    }

    // ---- invalid frames ----

    @Test
    void finalSizeErrors() throws Exception {
        StreamsState s = client();
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        s.received(stream(id, 0, 10, true), 10);
        assertEquals(QuicException.FINAL_SIZE_ERROR, code(() -> s.received(stream(id, 8, 4, false), 4)), "past the final size");
        assertEquals(QuicException.FINAL_SIZE_ERROR, code(() -> s.received(stream(id, 0, 8, true), 8)), "a changed final size");
        assertEquals(QuicException.FINAL_SIZE_ERROR, code(() -> s.receivedReset(resetFrame(id, 0, 11))), "reset disagrees");
        assertFalse(s.received(stream(id, 0, 10, true), 10), "the same final size again is fine");

        StreamId other = StreamId.of(Side.SERVER, Dir.UNI, 1);
        s.received(stream(other, 0, 20, false), 20);
        assertEquals(QuicException.FINAL_SIZE_ERROR, code(() -> s.receivedReset(resetFrame(other, 0, 19))),
                "below data received");
        assertEquals(QuicException.FINAL_SIZE_ERROR, code(() -> s.received(stream(other, 0, 15, true), 15)),
                "a FIN below data received");
    }

    @Test
    void streamStateErrors() {
        StreamsState s = client();
        StreamId localUni = s.open(Dir.UNI);
        StreamId unopenedBi = StreamId.of(Side.CLIENT, Dir.BI, 1);
        StreamId remoteUni = StreamId.of(Side.SERVER, Dir.UNI, 0);
        assertEquals(QuicException.STREAM_STATE_ERROR, code(() -> s.received(stream(localUni, 0, 1, false), 1)),
                "STREAM on a send-only stream");
        assertEquals(QuicException.STREAM_STATE_ERROR, code(() -> s.receivedReset(resetFrame(localUni, 0, 0))),
                "RESET_STREAM on a send-only stream");
        assertEquals(QuicException.STREAM_STATE_ERROR, code(() -> s.received(stream(unopenedBi, 0, 1, false), 1)),
                "STREAM on an unopened local stream");
        assertEquals(QuicException.STREAM_STATE_ERROR, code(() -> s.receivedMaxStreamData(remoteUni, 10)),
                "MAX_STREAM_DATA on a receive-only stream");
        assertEquals(QuicException.STREAM_STATE_ERROR, code(() -> s.receivedMaxStreamData(unopenedBi, 10)),
                "MAX_STREAM_DATA on an unopened local stream");
        assertEquals(QuicException.STREAM_STATE_ERROR,
                code(() -> s.receivedStopSending(new Frame.StopSending(remoteUni.value(), 0))),
                "STOP_SENDING on a receive-only stream");
        assertEquals(QuicException.STREAM_STATE_ERROR,
                code(() -> s.receivedStopSending(new Frame.StopSending(unopenedBi.value(), 0))),
                "STOP_SENDING on an unopened local stream");
        assertEquals(QuicException.STREAM_STATE_ERROR,
                code(() -> s.receivedStreamDataBlocked(new Frame.StreamDataBlocked(localUni.value(), 0))),
                "STREAM_DATA_BLOCKED on a send-only stream");
    }

    @Test
    void streamLimitErrors() {
        StreamsState s = client(); // allows the server 4 streams of each kind
        StreamId beyond = StreamId.of(Side.SERVER, Dir.BI, 4);
        assertEquals(QuicException.STREAM_LIMIT_ERROR, code(() -> s.received(stream(beyond, 0, 1, false), 1)));
        assertEquals(QuicException.STREAM_LIMIT_ERROR, code(() -> s.receivedReset(resetFrame(beyond, 0, 0))));
        assertEquals(QuicException.STREAM_LIMIT_ERROR,
                code(() -> s.receivedStopSending(new Frame.StopSending(beyond.value(), 0))));
        assertEquals(QuicException.STREAM_LIMIT_ERROR, code(() -> s.receivedMaxStreamData(beyond, 1)));
    }

    @Test
    void framesImplicitlyOpenLowerStreams() throws Exception {
        StreamsState s = client();
        s.receivedStopSending(new Frame.StopSending(StreamId.of(Side.SERVER, Dir.BI, 2).value(), 1));
        assertEquals(new StreamEvent.Opened(Dir.BI), s.poll());
        assertEquals(StreamId.of(Side.SERVER, Dir.BI, 0), s.accept(Dir.BI));
        assertEquals(StreamId.of(Side.SERVER, Dir.BI, 1), s.accept(Dir.BI));
        assertEquals(StreamId.of(Side.SERVER, Dir.BI, 2), s.accept(Dir.BI));
        assertInstanceOf(StreamEvent.Stopped.class, s.poll());
    }

    @Test
    void closedConnectionRefusesWrites() throws Exception {
        StreamsState s = client();
        StreamId id = s.open(Dir.UNI);
        s.onConnectionClosed();
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> s.write(id, data("x"), new Retransmits())));
        assertNull(s.open(Dir.UNI));
    }

    @Test
    void streamIdLayout() {
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 5);
        assertEquals(23, id.value());
        assertEquals(Side.SERVER, id.initiator());
        assertEquals(Dir.UNI, id.dir());
        assertEquals(5, id.index());
        assertEquals("server unidirectional stream 5", id.toString());
        assertEquals(0, StreamId.of(Side.CLIENT, Dir.BI, 0).value());
        assertThrows(IllegalArgumentException.class, () -> new StreamId(-1));
    }
}
