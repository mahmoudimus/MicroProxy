/*
 * Ported from quinn-proto src/connection/streams/recv.rs (Recv) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import java.nio.ByteBuffer;

/** The receiving part of a stream. Owned by {@link StreamsState}; not thread-safe. */
final class Recv {

    final Assembler assembler = new Assembler();
    /** The MAX_STREAM_DATA most recently sent, or the initial window. */
    long sentMaxStreamData;
    /** The highest offset received. */
    long end;
    boolean stopped;
    /** The final size, or -1 while unknown. */
    long finalSize = -1;
    /** Whether a RESET_STREAM arrived. */
    boolean resetReceived;
    long resetErrorCode = -1;
    /** Offsets received, to tell {@link RecvState#DATA_RECVD} from {@link RecvState#SIZE_KNOWN}. */
    private final RangeSet received = new RangeSet();

    Recv(long initialMaxData) {
        this.sentMaxStreamData = initialMaxData;
    }

    /**
     * Processes a STREAM frame.
     *
     * @param received the connection's total received so far
     * @param maxData the connection's receive limit
     * @return the new bytes counted against connection flow control; and in [1], 1 if the stream
     *     was stopped and is now closed by the FIN
     */
    long[] ingest(long offset, ByteBuffer data, boolean fin, int allocationSize, long received, long maxData)
            throws QuicException {
        long frameEnd = offset + data.remaining();
        if (frameEnd >= 1L << 62) {
            throw new QuicException(QuicException.FLOW_CONTROL_ERROR, "maximum stream offset too large");
        }
        if (finalSize >= 0 && (frameEnd > finalSize || (fin && frameEnd != finalSize))) {
            throw new QuicException(QuicException.FINAL_SIZE_ERROR,
                    "stream data past or changing the final size " + finalSize);
        }
        // RFC 9000 section 4.5: a final size below data already received is an error too
        if (fin && frameEnd < end) {
            throw new QuicException(QuicException.FINAL_SIZE_ERROR,
                    "final size " + frameEnd + " below data already received up to " + end);
        }
        long newBytes = creditConsumedBy(frameEnd, received, maxData);
        // Stopped streams need only the size, not the data
        if (fin && !stopped && !resetReceived) {
            finalSize = frameEnd;
        }
        end = Math.max(end, frameEnd);
        if (!stopped) {
            if (!assembler.insert(offset, data, allocationSize)) {
                throw new QuicException(QuicException.INTERNAL_ERROR, "too many gaps in stream buffer");
            }
            this.received.insert(offset, frameEnd);
        }
        return new long[] {newBytes, fin && stopped ? 1 : 0};
    }

    /**
     * Stops accepting data at the application's request.
     *
     * @return {read credits issued for unread data, 1 if STOP_SENDING should be sent}
     */
    long[] stop() throws StreamException {
        if (stopped) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        stopped = true;
        assembler.clear();
        long readCredits = end - assembler.bytesRead();
        // Possibly spurious if everything already arrived, but useful if data is still missing
        return new long[] {readCredits, isReceiving() ? 1 : 0};
    }

    /**
     * The MAX_STREAM_DATA to advertise, and whether it moved enough to be worth sending: by at
     * least an eighth of the window.
     *
     * @return {limit, 1 if it should be sent}
     */
    long[] maxStreamData(long streamReceiveWindow) {
        long max = assembler.bytesRead() + streamReceiveWindow;
        long diff = max - sentMaxStreamData;
        boolean transmit = canSendFlowControl() && diff >= streamReceiveWindow / 8;
        return new long[] {max, transmit ? 1 : 0};
    }

    /** Records that a MAX_STREAM_DATA with this value was sent. */
    void recordSentMaxStreamData(long sentValue) {
        if (sentValue > sentMaxStreamData) {
            sentMaxStreamData = sentValue;
        }
    }

    /** Whether the final size is unknown: no FIN and no reset yet. */
    boolean finalOffsetUnknown() {
        return !resetReceived && finalSize < 0;
    }

    /** Whether MAX_STREAM_DATA updates are useful: the size is unknown and data is wanted. */
    boolean canSendFlowControl() {
        return finalOffsetUnknown() && !stopped;
    }

    /** Whether data is still accepted: no reset was received. */
    boolean isReceiving() {
        return !resetReceived;
    }

    /**
     * Processes RESET_STREAM.
     *
     * @return false if the reset was redundant
     */
    boolean reset(long errorCode, long finalOffset, long received, long maxData) throws QuicException {
        long known = finalSize;
        if (known >= 0) {
            if (known != finalOffset) {
                throw new QuicException(QuicException.FINAL_SIZE_ERROR, "inconsistent final size");
            }
        } else if (end > finalOffset) {
            throw new QuicException(QuicException.FINAL_SIZE_ERROR, "final size lower than high water mark");
        }
        creditConsumedBy(finalOffset, received, maxData);
        if (resetReceived) {
            return false;
        }
        resetReceived = true;
        finalSize = finalOffset;
        resetErrorCode = errorCode;
        // Drop the buffers so reads fail immediately rather than issue redundant credit
        assembler.clear();
        return true;
    }

    /** The reset error code, or -1. */
    long resetCode() {
        return resetReceived ? resetErrorCode : -1;
    }

    /** The flow control credit an offset consumes, or a FLOW_CONTROL_ERROR if it exceeds a limit. */
    private long creditConsumedBy(long offset, long received, long maxData) throws QuicException {
        long newBytes = Math.max(0, offset - end);
        if (offset > sentMaxStreamData) {
            throw new QuicException(QuicException.FLOW_CONTROL_ERROR,
                    "stream data at offset " + offset + " beyond MAX_STREAM_DATA " + sentMaxStreamData);
        }
        if (received + newBytes > maxData) {
            throw new QuicException(QuicException.FLOW_CONTROL_ERROR,
                    "connection data " + (received + newBytes) + " beyond MAX_DATA " + maxData);
        }
        return newBytes;
    }

    /** The RFC 9000 receive state while the stream is tracked. */
    RecvState state() {
        if (resetReceived) {
            return RecvState.RESET_RECVD;
        }
        if (finalSize < 0) {
            return RecvState.RECV;
        }
        RangeSet.Range first = received.peekMin();
        boolean complete = finalSize == 0 || (first != null && first.start() == 0 && first.end() >= finalSize);
        return complete ? RecvState.DATA_RECVD : RecvState.SIZE_KNOWN;
    }
}
