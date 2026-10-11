package org.microproxy.impl;

import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3StreamValidator;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.microproxy.FullFlowContext;
import org.microproxy.frames.FrameDirection;

/**
 * The proxy's HTTP/3 connection to an origin server, shared by the exchanges for it ({@link
 * Http3Origins}): each exchange takes a request stream of its own ({@link #open}), an {@link
 * Http3UpstreamStream}, which writes the request and reads the response on the exchange's thread
 * (with the response's frames read ahead by the stream's {@link Http3StreamReader}). The QUIC
 * connection's stream limit is the server's: when it is reached, {@link #open} waits for a stream
 * to end.
 *
 * <p>A GOAWAY from the server stops new streams, and fails those it did not process with {@link
 * Unprocessed}, which the exchange logic retries on another connection. The connection closes when
 * it has been idle for the QUIC idle timeout, or when the proxy stops.
 */
final class Http3UpstreamConnection extends Http3Endpoint {

    private static final System.Logger LOG = System.getLogger(Http3UpstreamConnection.class.getName());

    /** A request the server never processed (GOAWAY, H3_REQUEST_REJECTED): safe to send again. */
    static final class Unprocessed extends IOException {
        Unprocessed(String message) {
            super(message);
        }
    }

    final Http3Origins origins;
    /** The key the connection is shared under. */
    final String key;
    final String hostAndPort;
    final InetSocketAddress remote;
    private final Http3Frames.Origin origin;

    // Guarded by stateLock.
    private final Map<Long, Http3UpstreamStream> streams = new HashMap<>();
    private final AtomicBoolean shutDown = new AtomicBoolean();

    Http3UpstreamConnection(DefaultHttpProxyServer server, Http3Origins origins, QuicConnection quic, String key,
            String hostAndPort) {
        super(server, quic, "[h3 " + hostAndPort + "] ", Http3StreamValidator.Role.CLIENT);
        this.origins = origins;
        this.key = key;
        this.hostAndPort = hostAndPort;
        this.remote = quic.remoteAddress();
        this.origin = new Http3Frames.Origin(-1, null, hostAndPort);
    }

    @Override
    FrameDirection receivedDirection() {
        return FrameDirection.FROM_SERVER;
    }

    @Override
    FrameDirection sentDirection() {
        return FrameDirection.TO_SERVER;
    }

    @Override
    Http3Frames.Origin frameOrigin() {
        return origin;
    }

    /** Starts HTTP/3: the control and QPACK streams, and a thread for the server's streams. */
    void begin() throws IOException {
        start();
        Thread.ofVirtual().name(server.name + "-h3-upstream-" + hostAndPort).start(this::acceptStreams);
    }

    /** Whether new streams may be opened: not after GOAWAY, nor once the connection has ended. */
    boolean usable() {
        if (closed) return false;
        stateLock.lock();
        try {
            return peerGoAway < 0;
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * A request stream for an exchange, waiting while the server's stream limit is reached.
     *
     * @throws Unprocessed if the server sent GOAWAY (before or while the stream was opened)
     * @throws IOException if the connection has ended
     */
    Http3UpstreamStream open(ClientFlowContext flow, String log, boolean headRequest) throws IOException {
        if (!usable()) throw new Unprocessed("the HTTP/3 connection to " + hostAndPort + " takes no new streams");
        QuicStream s = quic.openBidirectionalStream();
        FullFlowContext context = new FullFlowContext(flow, hostAndPort, null, remote);
        Http3UpstreamStream stream = new Http3UpstreamStream(this, s, context, log, headRequest);
        stateLock.lock();
        try {
            if (peerGoAway >= 0 && s.id() >= peerGoAway) {
                stream.abandon();
                throw new Unprocessed("GOAWAY from " + hostAndPort);
            }
            streams.put(s.id(), stream);
        } finally {
            stateLock.unlock();
        }
        stream.startReading(server.name + "-h3-upstream-" + s.id());
        return stream;
    }

    /** A stream's exchange is over. */
    void streamDone(Http3UpstreamStream stream) {
        stateLock.lock();
        try {
            streams.remove(stream.id, stream);
        } finally {
            stateLock.unlock();
        }
    }

    @Override
    void onRequestStream(QuicStream stream) throws IOException {
        connectionError(Http3ErrorCode.H3_STREAM_CREATION_ERROR, "a server opened a bidirectional stream");
    }

    @Override
    void onGoAway(long id) {
        origins.remove(this);
        List<Http3UpstreamStream> unprocessed = new ArrayList<>();
        stateLock.lock();
        try {
            for (Http3UpstreamStream s : streams.values()) {
                if (s.id >= id) unprocessed.add(s);
            }
        } finally {
            stateLock.unlock();
        }
        for (Http3UpstreamStream s : unprocessed) s.unprocessed("GOAWAY " + id + " from " + hostAndPort);
    }

    @Override
    void closed() {
        super.closed();
        if (!shutDown.compareAndSet(false, true)) return;
        origins.remove(this);
        List<Http3UpstreamStream> open;
        stateLock.lock();
        try {
            open = new ArrayList<>(streams.values());
        } finally {
            stateLock.unlock();
        }
        IOException cause = new IOException("the HTTP/3 connection to " + hostAndPort + " closed: " + quic.closeReason());
        for (Http3UpstreamStream s : open) s.connectionClosed(cause);
    }

    /** Closes the connection (CONNECTION_CLOSE with H3_NO_ERROR); its open streams fail. */
    void shutdown(String reason) {
        LOG.log(Level.DEBUG, logPrefix + "closing: " + reason);
        quic.close(Http3ErrorCode.H3_NO_ERROR.code(), reason);
        closed();
    }

    @Override
    public String toString() {
        return "Http3UpstreamConnection[" + hostAndPort + " " + remote + "]";
    }
}
