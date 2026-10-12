/*
 * Ported from quinn-proto src/connection/streams/state.rs (tests), recv.rs (tests) and send.rs
 * (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.params.TransportParameters;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class StreamsStateTest {

    static StreamsState make(Side side) {
        return new StreamsState(side, 128, 128, 1024 * 1024, 1024 * 1024, 1024 * 1024);
    }

    static Frame.Stream stream(StreamId id, long offset, int length, boolean fin) {
        return new Frame.Stream(id.value(), offset, ByteBuffer.allocate(length), fin);
    }

    static Frame.ResetStream resetFrame(StreamId id, long errorCode, long finalSize) {
        return new Frame.ResetStream(id.value(), errorCode, finalSize);
    }

    static StreamException.Kind kind(ThrowingRunnable r) {
        try {
            r.run();
        } catch (StreamException e) {
            return e.kind();
        } catch (QuicException e) {
            throw new AssertionError(e);
        }
        return null;
    }

    static long code(ThrowingRunnable r) {
        try {
            r.run();
        } catch (QuicException e) {
            return e.code();
        } catch (StreamException e) {
            throw new AssertionError(e);
        }
        return -1;
    }

    interface ThrowingRunnable {
        void run() throws StreamException, QuicException;
    }

    @Test
    void sendWindowRetainsSelectivelyAckedData() throws Exception {
        StreamsState server = make(Side.SERVER);
        server.sendWindow = 24;
        server.setParams(TransportParameters.builder().initialMaxStreamsUni(1).initialMaxData(1000)
                .initialMaxStreamDataUni(1000).build());
        Retransmits pending = new Retransmits();
        StreamId id = server.open(Dir.UNI);
        server.write(id, ByteBuffer.wrap(new byte[24]), pending);
        Send send = server.send.get(id);
        assertEquals(new SendBuffer.Transmit(0, 16, false), send.pending.pollTransmit(16));
        assertEquals(16, send.pending.pollTransmit(16).start());
        assertEquals(23, send.pending.pollTransmit(16).start());

        server.receivedAckOf(new StreamMeta(id, 16, 23, false));
        assertEquals(0, server.writeLimit(), "acknowledged suffix still occupies storage");
        server.receivedAckOf(new StreamMeta(id, 0, 16, false));
        assertEquals(0, server.writeLimit(), "partial prefix keeps the original allocation");
        server.receivedAckOf(new StreamMeta(id, 23, 24, false));
        assertEquals(24, server.writeLimit());
        server.write(id, ByteBuffer.wrap(new byte[24]), pending);
        assertEquals(0, server.writeLimit());
    }

    @Test
    void resetReleasesRetainedSendStorage() throws Exception {
        StreamsState server = make(Side.SERVER);
        server.sendWindow = 24;
        server.setParams(TransportParameters.builder().initialMaxStreamsUni(1).initialMaxData(1000)
                .initialMaxStreamDataUni(1000).build());
        Retransmits pending = new Retransmits();
        StreamId id = server.open(Dir.UNI);
        server.write(id, ByteBuffer.wrap(new byte[24]), pending);
        Send send = server.send.get(id);
        send.pending.pollTransmit(16);
        send.pending.pollTransmit(16);
        server.receivedAckOf(new StreamMeta(id, 16, 23, false));
        assertEquals(0, server.writeLimit());
        server.reset(id, 0, pending);
        assertEquals(24, server.writeLimit(), "a reset releases the stream's buffered data");
        // Acknowledgements of reset streams change nothing
        server.receivedAckOf(new StreamMeta(id, 0, 16, false));
        assertEquals(24, server.writeLimit());
        assertFalse(server.send.get(id).isPending());
    }

    @Test
    void trivialFlowControl() throws Exception {
        StreamsState client = new StreamsState(Side.CLIENT, 1, 1, 1024 * 1024, 1024 * 1024, 1024 * 1024);
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        long initialMax = client.localMaxData;
        int messageSize = 2048;
        assertFalse(client.received(stream(id, 0, messageSize, true), 2048));
        assertEquals(2048, client.dataRecvd);
        assertEquals(0, client.localMaxData - initialMax);

        Retransmits pending = new Retransmits();
        Chunks chunks = client.read(id, true, pending);
        assertEquals(messageSize, chunks.next(messageSize).length());
        assertNull(chunks.next(0));
        chunks.close();
        assertTrue(chunks.shouldTransmit());
        assertTrue(pending.maxStreamId[Dir.UNI.ordinal()]);
        assertEquals(messageSize, client.localMaxData - initialMax);
    }

    @Test
    void resetFlowControl() throws Exception {
        StreamsState client = make(Side.CLIENT);
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        long initialMax = client.localMaxData;
        assertFalse(client.received(stream(id, 0, 2048, false), 2048));
        assertEquals(2048, client.dataRecvd);
        assertEquals(0, client.localMaxData - initialMax);

        Retransmits pending = new Retransmits();
        try (Chunks chunks = client.read(id, true, pending)) {
            chunks.next(1024);
        }
        assertEquals(1024, client.localMaxData - initialMax);
        assertFalse(client.receivedReset(resetFrame(id, 0, 4096)));
        assertEquals(4096, client.dataRecvd);
        assertEquals(4096, client.localMaxData - initialMax);

        // Reading after a reset issues no redundant credit
        Chunks chunks = client.read(id, true, pending);
        StreamException e = assertThrows(StreamException.class, () -> chunks.next(1024));
        assertEquals(StreamException.Kind.RESET, e.kind());
        assertEquals(0, e.errorCode());
        chunks.close();
        assertEquals(4096, client.dataRecvd);
        assertEquals(4096, client.localMaxData - initialMax);
    }

    @Test
    void resetAfterEmptyFrameFlowControl() throws Exception {
        StreamsState client = make(Side.CLIENT);
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        long initialMax = client.localMaxData;
        assertFalse(client.received(stream(id, 4096, 0, false), 0));
        assertEquals(4096, client.dataRecvd);
        assertEquals(0, client.localMaxData - initialMax);
        assertFalse(client.receivedReset(resetFrame(id, 0, 4096)));
        assertEquals(4096, client.dataRecvd);
        assertEquals(4096, client.localMaxData - initialMax);
    }

    @Test
    void duplicateResetFlowControl() throws Exception {
        StreamsState client = make(Side.CLIENT);
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        assertFalse(client.receivedReset(resetFrame(id, 0, 4096)));
        assertEquals(4096, client.dataRecvd);
        assertFalse(client.receivedReset(resetFrame(id, 0, 4096)));
        assertEquals(4096, client.dataRecvd);
    }

    @Test
    void recvStopped() throws Exception {
        StreamsState client = make(Side.CLIENT);
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        long initialMax = client.localMaxData;
        assertFalse(client.received(stream(id, 0, 32, false), 32));
        assertEquals(initialMax, client.localMaxData);

        Retransmits pending = new Retransmits();
        client.stop(id, 0, pending);
        assertEquals(1, pending.stopSending.size());
        assertFalse(pending.maxData);

        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> client.stop(id, 0, pending)));
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> client.read(id, true, pending)));
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> client.read(id, false, pending)));

        assertEquals(32, client.localMaxData - initialMax);
        assertFalse(client.received(stream(id, 32, 16, true), 16));
        assertEquals(48, client.localMaxData - initialMax);
        assertFalse(client.recv.containsKey(id));
    }

    @Test
    void stoppedReset() throws Exception {
        for (long finalOffset : new long[] {32, 48}) {
            StreamsState client = make(Side.CLIENT);
            long initialMaxData = client.localMaxData;
            StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
            assertFalse(client.received(stream(id, 0, 32, false), 32));

            Retransmits pending = new Retransmits();
            client.stop(id, 0, pending);
            assertEquals(1, pending.stopSending.size());
            assertFalse(pending.maxData);
            assertEquals(initialMaxData + 32, client.localMaxData);

            // The server complies
            long prevMax = client.maxRemote[Dir.UNI.ordinal()];
            assertFalse(client.receivedReset(resetFrame(id, 0, finalOffset)));
            assertFalse(client.recv.containsKey(id), "stream state is freed");
            assertEquals(prevMax + 1, client.maxRemote[Dir.UNI.ordinal()]);
            assertEquals(finalOffset, client.dataRecvd);
            assertEquals(initialMaxData + finalOffset, client.localMaxData);
        }
    }

    @Test
    void sendStopped() throws Exception {
        StreamsState server = make(Side.SERVER);
        server.setParams(TransportParameters.builder().initialMaxStreamsUni(1).initialMaxData(42)
                .initialMaxStreamDataUni(42).build());
        Retransmits pending = new Retransmits();
        StreamId id = server.open(Dir.UNI);

        server.receivedStopSending(new Frame.StopSending(id.value(), 0));
        assertTrue(server.events.contains(new StreamEvent.Stopped(id, 0)));
        server.events.clear();

        StreamException e = assertThrows(StreamException.class,
                () -> server.write(id, ByteBuffer.allocate(0), pending));
        assertEquals(StreamException.Kind.STOPPED, e.kind());
        assertEquals(0, e.errorCode());

        server.reset(id, 0, pending);
        assertEquals(StreamException.Kind.CLOSED_STREAM, kind(() -> server.write(id, ByteBuffer.allocate(0), pending)));

        // A duplicate frame changes nothing
        server.receivedStopSending(new Frame.StopSending(id.value(), 0));
        assertTrue(server.events.isEmpty());
    }

    @Test
    void finalOffsetFlowControl() {
        StreamsState client = make(Side.CLIENT);
        assertEquals(QuicException.FLOW_CONTROL_ERROR,
                code(() -> client.receivedReset(resetFrame(StreamId.of(Side.SERVER, Dir.UNI, 0), 0, VarInt.MAX))));
    }

    private static StreamsState prioritized(long maxData, long maxStreamData) {
        StreamsState server = make(Side.SERVER);
        server.setParams(TransportParameters.builder().initialMaxStreamsBidi(3).initialMaxData(maxData)
                .initialMaxStreamDataBidiRemote(maxStreamData).build());
        return server;
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    void streamPriority() throws Exception {
        StreamsState server = prioritized(10, 10);
        Retransmits pending = new Retransmits();
        StreamId high = server.open(Dir.BI);
        StreamId mid = server.open(Dir.BI);
        StreamId low = server.open(Dir.BI);
        server.write(mid, ByteBuffer.wrap(bytes("mid")), pending);
        server.setPriority(low, -1);
        server.write(low, ByteBuffer.wrap(bytes("low")), pending);
        server.setPriority(high, 1);
        server.write(high, ByteBuffer.wrap(bytes("high")), pending);

        List<StreamMeta> meta = server.writeStreamFrames(ByteBuffer.allocate(40), 40, true);
        assertEquals(high, meta.get(0).id());
        assertEquals(mid, meta.get(1).id());
        assertEquals(low, meta.get(2).id());
        assertFalse(server.canSendStreamData());
        assertEquals(0, server.pending.size());
    }

    @Test
    void requeueStreamPriority() throws Exception {
        StreamsState server = prioritized(1000, 1000);
        Retransmits pending = new Retransmits();
        StreamId high = server.open(Dir.BI);
        StreamId mid = server.open(Dir.BI);
        assertEquals(3, server.write(mid, ByteBuffer.wrap(bytes("mid")), pending));
        assertEquals(1, server.pending.size());
        server.setPriority(high, 1);
        assertEquals(200, server.write(high, ByteBuffer.allocate(200), pending));
        assertEquals(2, server.pending.size());

        // Lower the high priority stream; its queued entry keeps the old priority for one send
        server.setPriority(high, -1);
        ByteBuffer buf = ByteBuffer.allocate(1000);
        List<StreamMeta> meta = server.writeStreamFrames(buf, 40, true);
        assertEquals(1, meta.size());
        assertEquals(high, meta.get(0).id());
        assertEquals(2, server.pending.size(), "requeued with the new priority, not added twice");

        meta = server.writeStreamFrames(buf, 1000, true);
        assertEquals(2, meta.size());
        assertEquals(mid, meta.get(0).id());
        assertEquals(high, meta.get(1).id());
        assertFalse(server.canSendStreamData());
        assertEquals(0, server.pending.size());
    }

    @Test
    void sameStreamPriority() throws Exception {
        for (boolean fair : new boolean[] {true, false}) {
            StreamsState server = prioritized(300, 300);
            Retransmits pending = new Retransmits();
            StreamId a = server.open(Dir.BI);
            StreamId b = server.open(Dir.BI);
            StreamId c = server.open(Dir.BI);
            server.write(a, ByteBuffer.wrap(filled('a', 100)), pending);
            server.write(b, ByteBuffer.wrap(filled('b', 100)), pending);
            server.write(c, ByteBuffer.wrap(filled('c', 100)), pending);

            List<StreamId> ids = drainIds(server, fair);
            assertFalse(server.canSendStreamData());
            assertEquals(0, server.pending.size());
            if (fair) {
                // Requeued behind every stream of the same priority
                assertEquals(List.of(a, b, c, a, b, c, a, b, c), ids);
            } else {
                // Requeued ahead of the others
                assertEquals(List.of(a, a, a, b, b, b, c, c, c), ids);
            }
        }
    }

    @Test
    void unfairPriorityBump() throws Exception {
        StreamsState server = prioritized(300, 300);
        Retransmits pending = new Retransmits();
        StreamId a = server.open(Dir.BI);
        StreamId b = server.open(Dir.BI);
        StreamId c = server.open(Dir.BI);
        server.write(a, ByteBuffer.wrap(filled('a', 100)), pending);
        server.write(b, ByteBuffer.wrap(filled('b', 100)), pending);

        ByteBuffer buf = ByteBuffer.allocate(1024);
        List<StreamId> ids = new ArrayList<>();
        List<StreamMeta> first = server.writeStreamFrames(buf, buf.position() + 40, false);
        assertFalse(first.isEmpty());
        first.forEach(m -> ids.add(m.id()));

        server.setPriority(c, 1);
        server.write(c, ByteBuffer.wrap(filled('b', 100)), pending);
        while (true) {
            List<StreamMeta> meta = server.writeStreamFrames(buf, buf.position() + 40, false);
            if (meta.isEmpty()) {
                break;
            }
            meta.forEach(m -> ids.add(m.id()));
        }
        assertFalse(server.canSendStreamData());
        assertEquals(0, server.pending.size());
        // c bumps b but not a, which was already partly written
        assertEquals(List.of(a, a, a, c, c, c, b, b, b), ids);
    }

    private static List<StreamId> drainIds(StreamsState server, boolean fair) {
        ByteBuffer buf = ByteBuffer.allocate(1024);
        List<StreamId> ids = new ArrayList<>();
        while (true) {
            List<StreamMeta> meta = server.writeStreamFrames(buf, buf.position() + 40, fair);
            if (meta.isEmpty()) {
                return ids;
            }
            meta.forEach(m -> ids.add(m.id()));
        }
    }

    private static byte[] filled(char ch, int n) {
        byte[] b = new byte[n];
        java.util.Arrays.fill(b, (byte) ch);
        return b;
    }

    @Test
    void stopFinished() throws Exception {
        StreamsState client = make(Side.CLIENT);
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        client.received(stream(id, 0, 32, true), 32);
        client.stop(id, 0, new Retransmits());
        assertFalse(client.recv.containsKey(id), "stream is freed");
    }

    @Test
    void resetStreamCannotSend() throws Exception {
        StreamsState server = make(Side.SERVER);
        server.setParams(TransportParameters.builder().initialMaxStreamsUni(1).initialMaxData(42)
                .initialMaxStreamDataUni(42).build());
        Retransmits pending = new Retransmits();
        StreamId id = server.open(Dir.UNI);
        server.write(id, ByteBuffer.wrap(bytes("hello")), pending);
        server.reset(id, 0, pending);
        assertEquals(List.of(new Retransmits.PendingReset(id, 0)), pending.resetStream);
        assertFalse(server.canSendStreamData());
    }

    @Test
    void streamLimitFixed() throws Exception {
        StreamsState client = make(Side.CLIENT);
        // Opens streams 0 to 127
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 127), 0, 0, true), 0));
        // Stream 128 exceeds the limit
        assertEquals(QuicException.STREAM_LIMIT_ERROR,
                code(() -> client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 128), 0, 0, true), 0)));
        // Freeing stream 127 allows stream 128
        client.stop(StreamId.of(Side.SERVER, Dir.UNI, 127), 0, new Retransmits());
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 128), 0, 0, true), 0));
    }

    @Test
    void streamLimitGrows() throws Exception {
        StreamsState client = make(Side.CLIENT);
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 127), 0, 0, true), 0));
        assertEquals(QuicException.STREAM_LIMIT_ERROR,
                code(() -> client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 128), 0, 0, true), 0)));
        client.setMaxConcurrent(Dir.UNI, 129);
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 128), 0, 0, true), 0));
    }

    @Test
    void streamLimitShrinks() throws Exception {
        StreamsState client = make(Side.CLIENT);
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 127), 0, 0, true), 0));
        client.setMaxConcurrent(Dir.UNI, 127);
        client.stop(StreamId.of(Side.SERVER, Dir.UNI, 127), 0, new Retransmits());
        // Still beyond the (lowered) limit
        assertEquals(QuicException.STREAM_LIMIT_ERROR,
                code(() -> client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 128), 0, 0, true), 0)));
        // Free stream 126
        assertFalse(client.receivedReset(resetFrame(StreamId.of(Side.SERVER, Dir.UNI, 126), 0, 0)));
        client.stop(StreamId.of(Side.SERVER, Dir.UNI, 126), 0, new Retransmits());
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 128), 0, 0, true), 0));
    }

    @Test
    void remoteStreamCapacity() {
        StreamsState client = make(Side.CLIENT);
        for (int i = 0; i < 2; i++) {
            client.setMaxConcurrent(Dir.UNI, 200);
            client.setMaxConcurrent(Dir.BI, 201);
            assertEquals(200, client.maxRemote[Dir.UNI.ordinal()]);
            assertEquals(201, client.maxRemote[Dir.BI.ordinal()]);
            assertEquals(200, client.allocatedRemoteCount[Dir.UNI.ordinal()]);
            assertEquals(201, client.allocatedRemoteCount[Dir.BI.ordinal()]);
            // Slots are allocated lazily
            assertTrue(client.recv.isEmpty());
            assertTrue(client.send.isEmpty());
        }
    }

    @Test
    void outOfOrderImplicitOpen() throws Exception {
        StreamsState client = make(Side.CLIENT);
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 5), 0, 8, true), 8));
        assertEquals(6, client.nextRemote[Dir.UNI.ordinal()]);
        assertFalse(client.received(stream(StreamId.of(Side.SERVER, Dir.UNI, 3), 0, 4, true), 4));
        try (Chunks chunks = client.read(StreamId.of(Side.SERVER, Dir.UNI, 3), true, new Retransmits())) {
            assertEquals(4, chunks.next(4).length());
        }
    }

    @Test
    void frameForClosedStreamIsDropped() throws Exception {
        StreamsState client = make(Side.CLIENT);
        StreamId id = StreamId.of(Side.SERVER, Dir.UNI, 0);
        assertFalse(client.received(stream(id, 0, 4, true), 4));
        try (Chunks chunks = client.read(id, true, new Retransmits())) {
            assertEquals(4, chunks.next(4).length());
            assertNull(chunks.next(4));
        }
        assertFalse(client.recv.containsKey(id));
        // A stray retransmission does not resurrect the stream
        assertFalse(client.received(stream(id, 0, 4, true), 4));
        assertFalse(client.recv.containsKey(id));
    }

    @Test
    void churnKeepsMapsBounded() throws Exception {
        StreamsState client = make(Side.CLIENT);
        for (long i = 0; i < 5_000; i++) {
            client.setMaxConcurrent(Dir.UNI, i + 200);
            StreamId id = StreamId.of(Side.SERVER, Dir.UNI, i);
            assertFalse(client.received(stream(id, 0, 1, true), 1));
            try (Chunks chunks = client.read(id, true, new Retransmits())) {
                chunks.next(1);
                assertNull(chunks.next(1));
            }
        }
        assertEquals(0, client.recv.size());
        assertEquals(0, client.send.size());
    }

    @Test
    void expandReceiveWindow() {
        StreamsState server = make(Side.SERVER);
        long newWindow = 2 * server.receiveWindow;
        assertTrue(server.setReceiveWindow(newWindow));
        assertEquals(newWindow, server.receiveWindow);
        assertEquals(newWindow, server.localMaxData);
        assertEquals(0, server.receiveWindowShrinkDebt);
        long prev = server.localMaxData;
        assertTrue(server.addReadCredits(1024));
        assertEquals(0, server.receiveWindowShrinkDebt);
        assertEquals(prev + 1024, server.localMaxData);
    }

    @Test
    void shrinkReceiveWindow() {
        StreamsState server = make(Side.SERVER);
        long newWindow = server.receiveWindow / 2;
        long prev = server.localMaxData;
        long shrinkDiff = server.receiveWindow - newWindow;
        assertFalse(server.setReceiveWindow(newWindow));
        assertEquals(newWindow, server.receiveWindow);
        assertEquals(prev, server.localMaxData);
        assertEquals(shrinkDiff, server.receiveWindowShrinkDebt);

        // Credit is absorbed by the debt
        for (int i = 0; i < 2; i++) {
            long expectedDebt = server.receiveWindowShrinkDebt - 1024;
            assertFalse(server.addReadCredits(1024));
            assertEquals(expectedDebt, server.receiveWindowShrinkDebt);
            assertEquals(prev, server.localMaxData);
        }
        // Credit beyond the remaining debt
        long credits = 1024 * 512;
        long expected = server.localMaxData + (credits - server.receiveWindowShrinkDebt);
        server.addReadCredits(credits);
        assertEquals(0, server.receiveWindowShrinkDebt);
        assertEquals(expected, server.localMaxData);
        assertTrue(server.localMaxData > prev);
        // Then all of it counts
        expected = server.localMaxData + credits;
        assertTrue(server.addReadCredits(credits));
        assertEquals(0, server.receiveWindowShrinkDebt);
        assertEquals(expected, server.localMaxData);
    }

    @Test
    void expandSendWindow() throws Exception {
        StreamsState server = make(Side.SERVER);
        long initialSendWindow = server.sendWindow;
        long largerSendWindow = initialSendWindow * 2;
        // The peer allows more than the send window, so the local window limits
        server.setParams(TransportParameters.builder().initialMaxData(VarInt.MAX).initialMaxStreamDataUni(VarInt.MAX)
                .initialMaxStreamsUni(100).build());
        assertEquals(initialSendWindow, server.writeLimit());
        assertNull(server.poll());

        Retransmits retransmits = new Retransmits();
        StreamId id = server.open(Dir.UNI);
        assertNotNull(id);
        byte[] data = new byte[(int) initialSendWindow];
        assertEquals(data.length, server.write(id, ByteBuffer.wrap(data), retransmits));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> server.write(id, ByteBuffer.wrap(data), retransmits)));

        server.setSendWindow(largerSendWindow);
        assertEquals(new StreamEvent.Writable(id), server.poll());
        assertEquals(data.length, server.write(id, ByteBuffer.wrap(data), retransmits));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> server.write(id, ByteBuffer.wrap(data), retransmits)));
        assertNull(server.poll());

        // Acknowledging the data frees the window
        server.receivedAckOf(new StreamMeta(id, 0, largerSendWindow, false));
        assertEquals(new StreamEvent.Writable(id), server.poll());
        assertEquals(data.length, server.write(id, ByteBuffer.wrap(data), retransmits));
        assertEquals(data.length, server.write(id, ByteBuffer.wrap(data), retransmits));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> server.write(id, ByteBuffer.wrap(data), retransmits)));
    }

    @Test
    void shrinkSendWindow() throws Exception {
        StreamsState server = make(Side.SERVER);
        long initialSendWindow = server.sendWindow;
        long smallerSendWindow = server.sendWindow / 2;
        server.setParams(TransportParameters.builder().initialMaxData(VarInt.MAX).initialMaxStreamDataUni(VarInt.MAX)
                .initialMaxStreamsUni(100).build());
        assertEquals(initialSendWindow, server.writeLimit());
        assertNull(server.poll());

        Retransmits retransmits = new Retransmits();
        StreamId id = server.open(Dir.UNI);
        byte[] data = new byte[(int) initialSendWindow];
        assertEquals(data.length, server.write(id, ByteBuffer.wrap(data), retransmits));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> server.write(id, ByteBuffer.wrap(data), retransmits)));
        assertEquals(0, server.writeLimit());
        assertNull(server.poll());

        server.setSendWindow(smallerSendWindow);
        assertEquals(0, server.writeLimit());
        assertNull(server.poll());
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> server.write(id, ByteBuffer.wrap(data), retransmits)));

        // Acknowledging part of the data is not enough with the smaller window
        server.receivedAckOf(new StreamMeta(id, 0, smallerSendWindow, false));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> server.write(id, ByteBuffer.wrap(data), retransmits)));

        server.receivedAckOf(new StreamMeta(id, smallerSendWindow, initialSendWindow, false));
        assertEquals(new StreamEvent.Writable(id), server.poll());
        assertEquals(smallerSendWindow, server.writeLimit());
        assertEquals(smallerSendWindow, server.write(id, ByteBuffer.wrap(data), retransmits));
        assertEquals(StreamException.Kind.BLOCKED, kind(() -> server.write(id, ByteBuffer.wrap(data), retransmits)));
    }

    @Test
    void maxStreamDataOverStreamLimit() {
        StreamsState server = make(Side.SERVER);
        // The limit is 128, so the client may open streams 0 to 127
        StreamId id = StreamId.of(Side.CLIENT, Dir.BI, 1L << 40);
        assertEquals(QuicException.STREAM_LIMIT_ERROR, code(() -> server.receivedMaxStreamData(id, 1)));
    }

    @Test
    void reorderedFramesWhileStopped() throws Exception {
        // Ported from recv.rs
        long initialBytes = 3;
        long initialOffset = 3;
        long recvWindow = 8;
        Recv s = new Recv(recvWindow);
        long dataRecvd = 0;
        long[] r = s.ingest(initialOffset, ByteBuffer.allocate((int) initialBytes), false, 123, dataRecvd,
                dataRecvd + 1024);
        dataRecvd += r[0];
        assertEquals(initialOffset + initialBytes, r[0]);
        assertEquals(0, r[1]);

        long[] stop = s.stop();
        assertEquals(1, stop[1]);
        assertEquals(initialOffset + initialBytes, stop[0], "full connection credit is issued by stop");
        long[] msd = s.maxStreamData(recvWindow);
        assertEquals(0, msd[1]);
        assertEquals(recvWindow, msd[0], "stream credit isn't issued by stop");

        r = s.ingest(recvWindow - 1, ByteBuffer.allocate(1), false, 123, dataRecvd, dataRecvd + 1024);
        dataRecvd += r[0];
        assertEquals(recvWindow - (initialOffset + initialBytes), r[0]);
        assertEquals(0, r[1]);
        msd = s.maxStreamData(recvWindow);
        assertEquals(0, msd[1]);
        assertEquals(recvWindow, msd[0]);

        r = s.ingest(0, ByteBuffer.allocate((int) initialOffset), false, 123, dataRecvd, dataRecvd + 1024);
        assertEquals(0, r[0], "reordered frames don't issue connection credit for stopped streams");
        assertEquals(0, r[1]);
    }

    @Test
    void chunksSourceTakesViewsAndCountsChunks() {
        // Ported from send.rs (bytes_array)
        String full = "Hello World 123456789 ABCDEFGHJIJKLMNOPQRSTUVWXYZ";
        String[] parts = {"", "Hello ", "Wo", "", "r", "ld", "", " 12345678", "9 ABCDE", "F", "GHJIJKLMNOPQRSTUVWXYZ"};
        int lastChunkLen = parts[parts.length - 1].length();
        for (int limit = 0; limit < full.length(); limit++) {
            ByteBuffer[] chunks = new ByteBuffer[parts.length];
            for (int i = 0; i < parts.length; i++) {
                chunks[i] = ByteBuffer.wrap(bytes(parts[i]));
            }
            Send.ChunksSource array = new Send.ChunksSource(chunks);
            StringBuilder buf = new StringBuilder();
            int popped = 0;
            int consumed = 0;
            int remaining = limit;
            while (true) {
                ByteBuffer chunk = array.popChunk(remaining);
                consumed += array.lastConsumed();
                if (!chunk.hasRemaining()) {
                    break;
                }
                byte[] b = new byte[chunk.remaining()];
                chunk.get(b);
                buf.append(new String(b, StandardCharsets.US_ASCII));
                remaining -= b.length;
                popped++;
            }
            assertEquals(full.substring(0, limit), buf.toString());
            if (limit > full.length() - lastChunkLen) {
                assertEquals(parts.length - 1, consumed);
                assertEquals(popped + 2, consumed);
            }
        }
    }

    @Test
    void copyingSourceCopiesOnce() {
        // Ported from send.rs (byte_slice)
        String full = "Hello World 123456789 ABCDEFGHJIJKLMNOPQRSTUVWXYZ";
        for (int limit = 0; limit < full.length(); limit++) {
            Send.CopyingSource source = new Send.CopyingSource(ByteBuffer.wrap(bytes(full)));
            StringBuilder buf = new StringBuilder();
            int popped = 0;
            int consumed = 0;
            int remaining = limit;
            while (true) {
                ByteBuffer chunk = source.popChunk(remaining);
                consumed += source.lastConsumed();
                if (!chunk.hasRemaining()) {
                    break;
                }
                byte[] b = new byte[chunk.remaining()];
                chunk.get(b);
                buf.append(new String(b, StandardCharsets.US_ASCII));
                remaining -= b.length;
                popped++;
            }
            assertEquals(full.substring(0, limit), buf.toString());
            assertEquals(limit != 0 ? 1 : 0, popped);
            assertEquals(0, consumed);
        }
        Send.CopyingSource all = new Send.CopyingSource(ByteBuffer.wrap(bytes(full)));
        all.popChunk(full.length());
        assertEquals(1, all.lastConsumed());
    }
}
