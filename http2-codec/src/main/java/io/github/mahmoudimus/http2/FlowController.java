package io.github.mahmoudimus.http2;

import java.util.HashMap;
import java.util.Map;

/**
 * Flow-control accounting for one connection (RFC 9113 §5.2, §6.9): the connection windows and a
 * send and a receive window for each open stream. It only counts; when to send WINDOW_UPDATE, and
 * how to share the send window between streams, is up to the caller.
 *
 * <ul>
 *   <li>Receiving: {@link #onDataReceived} debits the receive windows (raising FLOW_CONTROL_ERROR
 *       if the peer overran them); {@link #onWindowUpdateSent} credits them when the caller
 *       returns credit to the peer.
 *   <li>Sending: {@link #sendable} says how much DATA a stream may send now, {@link #onDataSent}
 *       debits it, and {@link #onWindowUpdateReceived} credits it.
 *   <li>Settings: {@link #onPeerInitialWindowSize} and {@link #onLocalInitialWindowSize} shift
 *       every stream's window by the change (§6.9.2); the connection windows are not affected.
 * </ul>
 *
 * <p>Plain data with no locking: the caller serializes access (usually under the connection's
 * lock), since frames are read on one thread and written from others.
 */
public final class FlowController {

    private final FlowControlWindow connectionSend = new FlowControlWindow(0, Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE);
    private final FlowControlWindow connectionReceive = new FlowControlWindow(0, Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE);
    private final Map<Integer, FlowControlWindow> streamSend = new HashMap<>();
    private final Map<Integer, FlowControlWindow> streamReceive = new HashMap<>();
    private int localInitialWindowSize;
    private int peerInitialWindowSize;

    /**
     * Creates flow-control accounting with the agreed initial stream windows.
     *
     * @param localInitialWindowSize the SETTINGS_INITIAL_WINDOW_SIZE in force for what this endpoint
     *     receives (65535 until the peer acknowledges another)
     * @param peerInitialWindowSize the peer's SETTINGS_INITIAL_WINDOW_SIZE, for what this endpoint sends
     */
    public FlowController(int localInitialWindowSize, int peerInitialWindowSize) {
        if (localInitialWindowSize < 0 || peerInitialWindowSize < 0) throw new IllegalArgumentException("negative window size");
        this.localInitialWindowSize = localInitialWindowSize;
        this.peerInitialWindowSize = peerInitialWindowSize;
    }

    /** Both directions at the protocol's initial 65535. */
    public FlowController() {
        this(Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE, Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE);
    }

    /**
     * Starts tracking a stream that has just opened.
     *
     * @param streamId the nonzero stream identifier
     */
    public void addStream(int streamId) {
        if (streamId <= 0) throw new IllegalArgumentException("bad stream id " + streamId);
        if (streamSend.containsKey(streamId)) throw new IllegalStateException("stream " + streamId + " is already tracked");
        streamSend.put(streamId, new FlowControlWindow(streamId, peerInitialWindowSize));
        streamReceive.put(streamId, new FlowControlWindow(streamId, localInitialWindowSize));
    }

    /**
     * Stops tracking a closed stream. Frames for it still count against the connection windows.
     *
     * @param streamId the closed stream identifier
     */
    public void removeStream(int streamId) {
        streamSend.remove(streamId);
        streamReceive.remove(streamId);
    }

    /**
     * Checks whether a stream is tracked.
     *
     * @param streamId the stream identifier to query
     * @return whether the stream is tracked
     */
    public boolean hasStream(int streamId) {
        return streamSend.containsKey(streamId);
    }

    /**
     * Accounts for a received flow-controlled frame (DATA: {@link Frame.Data#flowControlledLength()}).
     * The connection window is always debited; the stream's only if it is tracked.
     *
     * @param streamId the receiving stream identifier
     * @param length the flow-controlled octet count, including padding
     * @throws Http2Exception if a receive window is exceeded
     */
    public void onDataReceived(int streamId, int length) throws Http2Exception {
        connectionReceive.receive(length);
        FlowControlWindow w = streamReceive.get(streamId);
        if (w != null) w.receive(length);
    }

    /**
     * Credits a receive window for a WINDOW_UPDATE this endpoint sent (stream 0: the connection).
     *
     * @param streamId the stream identifier, or 0 for the connection
     * @param increment the positive credit sent
     * @throws Http2Exception if the receive window would exceed 2^31-1
     */
    public void onWindowUpdateSent(int streamId, int increment) throws Http2Exception {
        FlowControlWindow w = streamId == 0 ? connectionReceive : streamReceive.get(streamId);
        if (w != null) w.increment(increment);
    }

    /**
     * Credits a send window for a WINDOW_UPDATE received. Updates for streams not tracked are ignored.
     *
     * @param streamId the stream identifier, or 0 for the connection
     * @param increment the positive credit received
     * @throws Http2Exception if the send window would exceed 2^31-1
     */
    public void onWindowUpdateReceived(int streamId, int increment) throws Http2Exception {
        FlowControlWindow w = streamId == 0 ? connectionSend : streamSend.get(streamId);
        if (w != null) w.increment(increment);
    }

    /**
     * How many flow-controlled octets the stream may send now: the smaller of its and the connection's window.
     *
     * @param streamId the stream identifier to query
     * @return the available octet count, or 0 for an untracked stream
     */
    public int sendable(int streamId) {
        FlowControlWindow w = streamSend.get(streamId);
        if (w == null) return 0;
        return Math.min(w.available(), connectionSend.available());
    }

    /**
     * Debits the send windows for a flow-controlled frame being sent.
     *
     * @param streamId the nonzero stream identifier
     * @param length the flow-controlled octet count, including padding
     */
    public void onDataSent(int streamId, int length) {
        FlowControlWindow w = streamSend.get(streamId);
        if (w == null) throw new IllegalStateException("stream " + streamId + " is not tracked");
        if (length > sendable(streamId)) {
            throw new IllegalStateException("stream " + streamId + " may send " + sendable(streamId) + " octets, not " + length);
        }
        w.send(length);
        connectionSend.send(length);
    }

    /**
     * Applies a new SETTINGS_INITIAL_WINDOW_SIZE from the peer to every stream's send window.
     *
     * @param newSize the new nonnegative peer initial window size
     * @throws Http2Exception if any send window would exceed 2^31-1
     */
    public void onPeerInitialWindowSize(int newSize) throws Http2Exception {
        checkSize(newSize);
        long delta = (long) newSize - peerInitialWindowSize;
        for (FlowControlWindow w : streamSend.values()) w.adjust(delta);
        peerInitialWindowSize = newSize;
    }

    /**
     * Applies this endpoint's new SETTINGS_INITIAL_WINDOW_SIZE, once acknowledged, to every receive window.
     *
     * @param newSize the new nonnegative local initial window size
     * @throws Http2Exception if any receive window would exceed 2^31-1
     */
    public void onLocalInitialWindowSize(int newSize) throws Http2Exception {
        checkSize(newSize);
        long delta = (long) newSize - localInitialWindowSize;
        for (FlowControlWindow w : streamReceive.values()) w.adjust(delta);
        localInitialWindowSize = newSize;
    }

    /**
     * Returns the connection send window.
     *
     * @return the mutable connection send window
     */
    public FlowControlWindow connectionSendWindow() {
        return connectionSend;
    }

    /**
     * Returns the connection receive window.
     *
     * @return the mutable connection receive window
     */
    public FlowControlWindow connectionReceiveWindow() {
        return connectionReceive;
    }

    /**
     * The stream's send window, or null if it is not tracked.
     *
     * @param streamId the stream identifier to query
     * @return the mutable send window, or null if untracked
     */
    public FlowControlWindow streamSendWindow(int streamId) {
        return streamSend.get(streamId);
    }

    /**
     * The stream's receive window, or null if it is not tracked.
     *
     * @param streamId the stream identifier to query
     * @return the mutable receive window, or null if untracked
     */
    public FlowControlWindow streamReceiveWindow(int streamId) {
        return streamReceive.get(streamId);
    }

    private static void checkSize(int size) {
        if (size < 0) throw new IllegalArgumentException("negative initial window size " + size);
    }
}
