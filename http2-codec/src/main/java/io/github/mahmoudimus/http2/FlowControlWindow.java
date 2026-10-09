package io.github.mahmoudimus.http2;

/**
 * One HTTP/2 flow-control window (RFC 9113 §5.2, §6.9): of a stream, or of the connection when
 * {@link #streamId()} is 0. A window can go negative after SETTINGS_INITIAL_WINDOW_SIZE shrinks,
 * and never exceeds 2^31-1.
 *
 * <p>Plain data with no locking: callers that share a window between threads must guard it
 * themselves (typically with the connection's lock).
 */
public final class FlowControlWindow {

    private final int streamId;
    private long size;

    public FlowControlWindow(int streamId, int initialSize) {
        if (streamId < 0) throw new IllegalArgumentException("bad stream id " + streamId);
        if (initialSize < 0) throw new IllegalArgumentException("negative initial window " + initialSize);
        this.streamId = streamId;
        this.size = initialSize;
    }

    public int streamId() {
        return streamId;
    }

    /** The space left; negative if a SETTINGS change shrank the window below what was in flight. */
    public long size() {
        return size;
    }

    /** How much may be sent now: the size, or 0 if it is negative. */
    public int available() {
        return (int) Math.max(0, size);
    }

    /**
     * Credits the window, as a WINDOW_UPDATE does.
     *
     * @throws Http2Exception FLOW_CONTROL_ERROR if the window would exceed 2^31-1: a connection
     *     error for the connection window, a stream error for a stream's
     */
    public void increment(int increment) throws Http2Exception {
        if (increment <= 0) throw new IllegalArgumentException("window increment must be positive, got " + increment);
        if (size + increment > Http2Settings.MAX_WINDOW_SIZE) {
            String message = "window of " + (streamId == 0 ? "the connection" : "stream " + streamId)
                    + " would grow past 2^31-1 (" + size + " + " + increment + ")";
            throw streamId == 0
                    ? Http2Exception.connectionError(ErrorCode.FLOW_CONTROL_ERROR, message)
                    : Http2Exception.streamError(streamId, ErrorCode.FLOW_CONTROL_ERROR, message);
        }
        size += increment;
    }

    /**
     * Debits the window for a received flow-controlled frame.
     *
     * @throws Http2Exception FLOW_CONTROL_ERROR if the peer sent more than the window allowed
     *     (connection error for the connection window, stream error for a stream's)
     */
    public void receive(int length) throws Http2Exception {
        if (length < 0) throw new IllegalArgumentException("negative length");
        if (length > size) {
            String message = "peer sent " + length + " octets with only " + size + " left in the window of "
                    + (streamId == 0 ? "the connection" : "stream " + streamId);
            throw streamId == 0
                    ? Http2Exception.connectionError(ErrorCode.FLOW_CONTROL_ERROR, message)
                    : Http2Exception.streamError(streamId, ErrorCode.FLOW_CONTROL_ERROR, message);
        }
        size -= length;
    }

    /**
     * Debits the window for a frame about to be sent.
     *
     * @throws IllegalStateException if the window does not allow it: a bug in the caller
     */
    public void send(int length) {
        if (length < 0) throw new IllegalArgumentException("negative length");
        if (length > size) {
            throw new IllegalStateException("sending " + length + " octets with only " + size + " left in the window of "
                    + (streamId == 0 ? "the connection" : "stream " + streamId));
        }
        size -= length;
    }

    /**
     * Applies a change of SETTINGS_INITIAL_WINDOW_SIZE ({@code delta = new - old}) to a stream
     * window (§6.9.2). The result may be negative.
     *
     * @throws Http2Exception a connection error FLOW_CONTROL_ERROR if the window would exceed 2^31-1
     */
    public void adjust(long delta) throws Http2Exception {
        long next = size + delta;
        if (next > Http2Settings.MAX_WINDOW_SIZE) {
            throw Http2Exception.connectionError(ErrorCode.FLOW_CONTROL_ERROR,
                    "SETTINGS_INITIAL_WINDOW_SIZE change pushes the window of stream " + streamId + " past 2^31-1");
        }
        size = next;
    }

    @Override
    public String toString() {
        return "FlowControlWindow[stream=" + streamId + ", size=" + size + "]";
    }
}
