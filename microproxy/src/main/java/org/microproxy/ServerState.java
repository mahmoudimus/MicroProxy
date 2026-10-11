package org.microproxy;

/**
 * Where a proxy is in its life ({@link HttpProxyServer#state()}), with the names Envoy's admin
 * {@code /ready} answers and the numbers its {@code server.state} gauge shows. A proxy goes from
 * {@link #INITIALIZING} to {@link #LIVE} as it starts, to {@link #DRAINING} when it is drained or
 * stops accepting, and to {@link #STOPPED} once it has stopped.
 */
public enum ServerState {
    /** Serving: accepting connections and requests. {@code server.state} 0. */
    LIVE(0),
    /**
     * Draining ({@link HttpProxyServer#drain}), no longer accepting ({@link
     * HttpProxyServer#stopListeners}), or stopping: not ready for new traffic. {@code server.state} 1.
     */
    DRAINING(1),
    /** Made, not started yet. {@code server.state} 2. */
    PRE_INITIALIZING(2),
    /** Starting: the admin listener may answer while the proxy's own listeners are being bound. {@code server.state} 3. */
    INITIALIZING(3),
    /** Stopped: every listener and connection closed. {@code server.state} 4, MicroProxy's own (Envoy has no such state). */
    STOPPED(4);

    private final int code;

    ServerState(int code) {
        this.code = code;
    }

    /** {@return the value of the {@code server.state} gauge in this state, Envoy's number for it} */
    public int code() {
        return code;
    }
}
