package org.microproxy.impl;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.X509TrustManager;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.quic.QuicContext;
import org.microproxy.quic.MessageFramer;
import org.microproxy.quic.QuicDatagram;
import org.microproxy.quic.QuicFraming;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicMessage;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.tls.SslContexts;

/**
 * An intercepted QUIC connection relayed stream by stream: the client's connection, which the
 * proxy accepted with a certificate it issued, paired with the proxy's connection to the server.
 * Each stream one side opens is opened on the other connection, of the same kind, and its data, its
 * end, a reset and a request to stop sending are passed on; datagrams go across one for one. The
 * {@link QuicInterceptor} sees it all, when there is one.
 *
 * <p><b>Flow control.</b> Each direction of each stream has a thread that reads at most {@link
 * #BUFFER} bytes, shows them to the hook and writes the result to the other side, blocking while
 * that side's flow control holds it back: nothing is buffered beyond one read, so a slow reader
 * slows its writer down end to end. A stream is opened on the other side when the peer's stream
 * limit allows it, which holds back the accepting of further streams.
 *
 * <p><b>Messages.</b> When the interceptor overrides {@link QuicInterceptor#streamMessage} and the
 * {@link QuicFraming} gives the connection a {@link MessageFramer}, each direction keeps the bytes
 * of a message until it is whole (a {@link MessageAssembler}), bounded by the framing's limit, and
 * passes each message through {@code streamMessage}, framing what it returns again; {@code
 * streamData} is not called on the connection's streams. A message over the limit, or bytes the
 * framer cannot read, reset the stream both ways on both connections ({@code Stream.abort}).
 *
 * <p><b>Stopping.</b> A peer's STOP_SENDING shows only when a write fails, so a thread per
 * direction also waits for it ({@link QuicStream#awaitStopped()}): the proxy then asks the other
 * side to stop sending, with the same code, and resets the stream towards the peer that asked (RFC
 * 9000 section 3.5).
 *
 * <p><b>Ending.</b> When either connection ends, the other is closed with the same application
 * error code and reason (a transport close or a timeout, with code 0); then {@code quicEnd}, or
 * {@code quicError} when the connection failed (a timeout, a stateless reset, a transport error).
 *
 * <p>Threads: two per connection accepting streams, one per direction of datagrams, and two per
 * direction of each stream; no {@code synchronized}.
 */
final class QuicSession implements QuicContext {

    private static final System.Logger LOG = System.getLogger(QuicSession.class.getName());

    /** The most bytes one read takes from a stream, and so one {@code streamData} call sees. */
    static final int BUFFER = 16 * 1024;
    /** Streams of each kind the server may open at once towards the proxy. */
    private static final int STREAMS = 100;
    /** The DATAGRAM frames the server may send ahead of the proxy, in bytes. */
    private static final int DATAGRAM_BUFFER = 1024 * 1024;

    /** The proxy's connection to a server, and the client endpoint (a UDP socket) it was made from. */
    record Upstream(QuicClient client, QuicConnection connection) implements AutoCloseable {
        @Override
        public void close() {
            connection.close();
            client.close();
        }
    }

    /**
     * Connects to the server of a flow intercepted stream by stream, from a UDP socket of its own:
     * the client's server name and ALPN protocols (the server's choice is the one the client is
     * then given), the server validated with {@code trust}, DATAGRAM frames accepted, and the
     * options' congestion controller.
     */
    static Upstream connect(DefaultHttpProxyServer server, ClientHello hello, X509TrustManager trust,
            InetSocketAddress address, Duration timeout) throws IOException {
        TlsConfig.Builder tls = TlsConfig.builder()
                .serverName(hello.sni())
                .alpnProtocols(hello.alpnProtocols().toArray(String[]::new));
        if (SslContexts.trustsAll(trust)) {
            tls.trustAllCertificates(true);
        } else {
            tls.trustManager(trust);
        }
        int idle = server.idleTimeoutMillis();
        TransportConfig transport = TransportConfig.builder()
                .maxIdleTimeout(idle > 0 ? Duration.ofMillis(idle) : Duration.ZERO)
                .maxConcurrentBidiStreams(STREAMS)
                .maxConcurrentUniStreams(STREAMS)
                .streamReceiveWindow(server.http3Options.streamReceiveWindow())
                .receiveWindow(server.http3Options.connectionReceiveWindow())
                .datagramReceiveBufferSize(DATAGRAM_BUFFER)
                .congestionControl(Http3Listener.congestionControl(server.http3Options))
                .build();
        ClientConfig config = ClientConfig.builder(tls.build()).transport(transport).build();
        boolean ipv6 = address.getAddress() instanceof Inet6Address;
        InetSocketAddress local = server.localAddress;
        InetSocketAddress bind = local != null && (local.getAddress() instanceof Inet6Address) == ipv6
                ? new InetSocketAddress(local.getAddress(), 0)
                : new InetSocketAddress(InetAddress.getByName(ipv6 ? "::" : "0.0.0.0"), 0);
        QuicClient client = QuicClient.create(config, bind, EndpointConfig.defaults());
        try {
            return new Upstream(client, client.connect(address, hello.sni(), timeout));
        } catch (IOException | RuntimeException e) {
            client.close();
            throw e;
        }
    }

    /** Whether an interceptor's class overrides {@code streamMessage}, so that it wants framed messages. */
    private static final ClassValue<Boolean> FRAMES = new ClassValue<>() {
        @Override
        protected Boolean computeValue(Class<?> type) {
            try {
                return type.getMethod("streamMessage", QuicMessage.class, QuicStreamContext.class).getDeclaringClass()
                        != QuicInterceptor.class;
            } catch (NoSuchMethodException e) {
                return false;
            }
        }
    };

    private final QuicInterceptor hooks;
    private final QuicFraming framing;
    /** The framer of the connection's streams, when the hooks want messages; null to pass reads on. */
    private final MessageFramer framer;
    private final QuicConnection client;
    private final QuicConnection server;
    private final FlowContext flow;
    private final HostAndPort target;
    private final InetSocketAddress serverAddress;
    private final String sni;
    private final String alpn;
    private final boolean masque;
    private final String logPrefix;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    // Guarded by lock.
    /** The session's threads still running: each removes itself when it ends, so streams that end free theirs. */
    private final Set<Thread> threads = new HashSet<>();
    /** The connection that ended first, and why; null while both are open. */
    private ConnectionError endedFirst;
    private boolean endedByClient;
    private boolean finished;
    private final AtomicReference<Throwable> error = new AtomicReference<>();

    /**
     * @param hooks the QUIC hooks, or null to relay without any
     * @param framing which streams the hooks see as messages, or null for the defaults
     * @param client the client's connection, accepted by the proxy
     * @param server the proxy's connection to the server
     */
    QuicSession(QuicInterceptor hooks, QuicFraming framing, QuicConnection client, QuicConnection server,
            FlowContext flow, HostAndPort target, InetSocketAddress serverAddress, boolean masque, String logPrefix) {
        this.hooks = hooks;
        this.framing = framing != null ? framing : QuicFraming.defaults();
        this.client = client;
        this.server = server;
        this.flow = flow;
        this.target = target;
        this.serverAddress = serverAddress;
        this.sni = client.serverName();
        String negotiated = server.alpn();
        this.alpn = negotiated == null || negotiated.isEmpty() ? null : negotiated;
        this.masque = masque;
        this.logPrefix = logPrefix;
        MessageFramer f = null;
        if (hooks != null && FRAMES.get(hooks.getClass())) {
            try {
                f = this.framing.framerFor(alpn, target.host(), sni);
            } catch (IllegalStateException e) {
                LOG.log(Level.WARNING, logPrefix + "QUIC to " + target + " (" + alpn + ") is not framed: " + e.getMessage());
            }
        }
        this.framer = f;
    }

    // ---------------------------------------------------------------------------------------
    // Running
    // ---------------------------------------------------------------------------------------

    /** Relays the connection until one side ends it, then closes the other, and calls the last hook. */
    void run() {
        if (hooks != null) {
            try {
                hooks.quicStart(this);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's quicStart threw", e);
            }
        }
        start("accept-client", () -> acceptStreams(true));
        start("accept-server", () -> acceptStreams(false));
        start("datagrams-to-server", () -> relayDatagrams(true));
        start("datagrams-to-client", () -> relayDatagrams(false));
        ConnectionError why;
        boolean byClient;
        lock.lock();
        try {
            while (endedFirst == null) changed.awaitUninterruptibly();
            why = endedFirst;
            byClient = endedByClient;
        } finally {
            lock.unlock();
        }
        QuicConnection other = byClient ? server : client;
        if (why.kind() == ConnectionError.Kind.APPLICATION_CLOSED) {
            other.close(why.code(), why.reason() == null ? "" : why.reason());
        } else {
            other.close(0, "");
        }
        if (failed(why)) {
            error.compareAndSet(null, new IOException((byClient ? "the client's" : "the server's")
                    + " QUIC connection failed: " + why));
        }
        client.close();
        server.close();
        List<Thread> all;
        lock.lock();
        try {
            finished = true;
            all = new ArrayList<>(threads);
        } finally {
            lock.unlock();
        }
        for (Thread t : all) {
            try {
                t.join(Duration.ofSeconds(5));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        LOG.log(Level.DEBUG, () -> logPrefix + "QUIC to " + target + " (" + alpn + ") ended by the "
                + (byClient ? "client" : "server") + ": " + why);
        if (hooks == null) return;
        Throwable failure = error.get();
        try {
            if (failure == null) {
                hooks.quicEnd(this);
            } else {
                hooks.quicError(this, failure);
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's " + (failure == null ? "quicEnd" : "quicError")
                    + " threw", e);
        }
    }

    /** Whether a connection's end is a failure: a timeout, a stateless reset or a transport error. */
    private static boolean failed(ConnectionError why) {
        return switch (why.kind()) {
            case TIMED_OUT, RESET, TRANSPORT_ERROR -> true;
            case CONNECTION_CLOSED -> why.code() != 0;
            default -> false;
        };
    }

    /** Starts a thread of the session's, unless it has finished. */
    private void start(String what, Runnable task) {
        lock.lock();
        try {
            if (finished) return;
            Thread t = Thread.ofVirtual().name("quic-" + flow.getConnectionId() + "-" + what).unstarted(() -> {
                try {
                    task.run();
                } finally {
                    forget(Thread.currentThread());
                }
            });
            threads.add(t);
            t.start();
        } finally {
            lock.unlock();
        }
    }

    /** A thread of the session's ended. */
    private void forget(Thread t) {
        lock.lock();
        try {
            threads.remove(t);
        } finally {
            lock.unlock();
        }
    }

    /** One side's connection is gone: the session ends, if it has not already. */
    private void ended(boolean byClient) {
        QuicConnection c = byClient ? client : server;
        ConnectionError why = c.closeReason();
        lock.lock();
        try {
            if (endedFirst != null) return;
            endedFirst = why != null ? why : ConnectionError.of(ConnectionError.Kind.LOCALLY_CLOSED);
            endedByClient = byClient;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /** Accepts the streams one side opens and opens each on the other side, until the side's connection ends. */
    private void acceptStreams(boolean fromClient) {
        QuicConnection from = fromClient ? client : server;
        QuicConnection to = fromClient ? server : client;
        try {
            while (true) {
                QuicStream accepted = from.acceptStream();
                // Waits while the other side's stream limit is reached, holding further streams back.
                QuicStream opened = accepted.isBidirectional() ? to.openBidirectionalStream() : to.openUnidirectionalStream();
                Stream s = fromClient ? new Stream(accepted, opened, true) : new Stream(opened, accepted, false);
                if (hooks != null) {
                    try {
                        hooks.streamOpened(s);
                    } catch (RuntimeException e) {
                        LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's streamOpened threw", e);
                    }
                }
                s.start();
            }
        } catch (IOException e) {
            // a connection ended: this side's (accepting), or the other's (opening)
        } finally {
            ended(from.isOpen() && !to.isOpen() ? !fromClient : fromClient);
        }
    }

    /** Relays one direction's datagrams, through the hook, until either connection ends. */
    private void relayDatagrams(boolean fromClient) {
        QuicConnection from = fromClient ? client : server;
        QuicConnection to = fromClient ? server : client;
        try {
            while (true) {
                byte[] data = from.receiveDatagram();
                byte[] result = data;
                if (hooks != null) {
                    try {
                        result = hooks.datagram(new QuicDatagram(data, fromClient, Instant.now()), this);
                    } catch (RuntimeException e) {
                        LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's datagram threw; passing it on", e);
                    }
                }
                if (result != null) sendDatagram(to, result);
            }
        } catch (IOException e) {
            // the connection ended
        }
    }

    /** Sends a datagram, dropping it when the receiver takes none or it is too large, as a network would. */
    private void sendDatagram(QuicConnection to, byte[] data) throws IOException {
        int max = to.maxDatagramSize();
        if (max < 0 || data.length > max) {
            if (LOG.isLoggable(Level.TRACE)) {
                LOG.log(Level.TRACE, logPrefix + "dropping a QUIC datagram of " + data.length + " bytes (" + max + " fit)");
            }
            return;
        }
        try {
            to.sendDatagram(data);
        } catch (IllegalStateException | IllegalArgumentException e) {
            // the peer takes no datagrams, or the path shrank
        }
    }

    /** Closes both connections (code 0), ending the session: the proxy is stopping. */
    void close() {
        client.close(0, "");
        server.close(0, "");
    }

    // ---------------------------------------------------------------------------------------
    // QuicContext
    // ---------------------------------------------------------------------------------------

    @Override
    public long connectionId() {
        return flow.getConnectionId();
    }

    @Override
    public InetSocketAddress clientAddress() {
        return flow.getClientAddress();
    }

    @Override
    public String host() {
        return target.host();
    }

    @Override
    public int port() {
        return target.port();
    }

    @Override
    public InetSocketAddress serverAddress() {
        return serverAddress;
    }

    @Override
    public String sni() {
        return sni;
    }

    @Override
    public String alpn() {
        return alpn;
    }

    @Override
    public boolean masque() {
        return masque;
    }

    @Override
    public FlowContext flowContext() {
        return flow;
    }

    @Override
    public void sendDatagram(boolean fromClient, byte[] data) {
        Objects.requireNonNull(data, "data");
        QuicConnection to = fromClient ? server : client;
        if (!to.isOpen()) throw new IllegalStateException("the QUIC connection to " + target + " has ended");
        try {
            sendDatagram(to, data.clone());
        } catch (IOException e) {
            throw new IllegalStateException("the QUIC connection to " + target + " has ended", e);
        }
    }

    @Override
    public String toString() {
        return "quic " + flow.getConnectionId() + " to " + target + " (" + alpn + ")";
    }

    // ---------------------------------------------------------------------------------------
    // Streams
    // ---------------------------------------------------------------------------------------

    /** One direction of a stream: the side it is read from, and the output the other side reads. */
    private static final class Direction {
        final boolean fromClient;
        final QuicStream source;
        final QuicStream sink;
        final OutputStream out;
        final ReentrantLock lock = new ReentrantLock();
        /** Set under {@link #lock}: the end, a reset or a stop was passed on. */
        boolean ended;
        /** The STOP_SENDING of the sink's side was handled, by the reader or the watcher. */
        final AtomicBoolean stopped = new AtomicBoolean();
        /** The thread running a {@code streamData} hook of this direction, whose sends wait for its result. */
        volatile Thread hookThread;
        /** Bytes that {@link #hookThread} sent during the hook, written after its result. */
        List<byte[]> pending;
        /** With a framer, the bytes read that do not make a whole message yet; null without one. */
        MessageAssembler assembler;

        Direction(boolean fromClient, QuicStream source, QuicStream sink) {
            this.fromClient = fromClient;
            this.source = source;
            this.sink = sink;
            this.out = sink.getOutputStream();
        }
    }

    /** A stream on both connections, as the hooks see it. */
    private final class Stream implements QuicStreamContext {
        final QuicStream clientSide;
        final QuicStream serverSide;
        final boolean clientInitiated;
        /** Client to server; null on a unidirectional stream the server opened. */
        final Direction toServer;
        /** Server to client; null on a unidirectional stream the client opened. */
        final Direction toClient;

        Stream(QuicStream clientSide, QuicStream serverSide, boolean clientInitiated) {
            this.clientSide = clientSide;
            this.serverSide = serverSide;
            this.clientInitiated = clientInitiated;
            boolean bidi = clientSide.isBidirectional();
            this.toServer = bidi || clientInitiated ? new Direction(true, clientSide, serverSide) : null;
            this.toClient = bidi || !clientInitiated ? new Direction(false, serverSide, clientSide) : null;
        }

        void start() {
            for (Direction d : new Direction[] {toServer, toClient}) {
                if (d == null) continue;
                if (framer != null) d.assembler = new MessageAssembler(framer, framing.maxMessageSize());
                String name = clientSide.id() + (d.fromClient ? "-to-server" : "-to-client");
                QuicSession.this.start(name, () -> pump(d));
                QuicSession.this.start(name + "-stop", () -> watchStop(d));
            }
        }

        /** Reads one direction, through the hook, to the other side, until it ends. */
        private void pump(Direction d) {
            InputStream in = d.source.getInputStream();
            byte[] buf = new byte[BUFFER];
            try {
                while (true) {
                    int n = in.read(buf);
                    if (n < 0) {
                        if (framer != null) leftover(d);
                        finish(d);
                        return;
                    }
                    if (n > 0 && framer != null) {
                        if (!frames(d, buf, n)) return;
                    } else if (n > 0) {
                        message(d, Arrays.copyOf(buf, n));
                    }
                }
            } catch (QuicStreamException e) {
                if (e.kind() == QuicStreamException.Kind.RESET) {
                    reset(d, e.errorCode());
                } else {
                    stopped(d, e.errorCode());
                }
            } catch (IOException e) {
                // the connection ended, or the proxy stopped the source (passing a STOP_SENDING on)
                markEnded(d);
            }
        }

        /** Waits for the sink's side to ask for the direction to stop, and passes that on. */
        private void watchStop(Direction d) {
            try {
                long code = d.sink.awaitStopped();
                if (code >= 0) stopped(d, code);
            } catch (IOException e) {
                // interrupted: the session is over
            }
        }

        /** Bytes read in one direction: through {@code streamData}, then to the other side. */
        private void message(Direction d, byte[] data) throws IOException {
            byte[] result = data;
            if (hooks != null) {
                d.hookThread = Thread.currentThread();
                try {
                    result = hooks.streamData(new QuicStreamMessage(data, d.fromClient, Instant.now()), this);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's streamData threw; passing the bytes on", e);
                    result = data;
                } finally {
                    d.hookThread = null;
                }
            }
            List<byte[]> added = d.pending;
            d.pending = null;
            d.lock.lock();
            try {
                if (d.ended) return;
                if (result != null && result.length > 0) d.out.write(result);
                if (added != null) {
                    for (byte[] bytes : added) {
                        if (bytes.length > 0) d.out.write(bytes);
                    }
                }
            } finally {
                d.lock.unlock();
            }
        }

        /**
         * Bytes read in one direction of a framed stream: kept until they make whole messages, each
         * of which goes through {@code streamMessage}. False when the stream was reset instead: a
         * message too large, or bytes the framer cannot read.
         */
        private boolean frames(Direction d, byte[] buf, int n) throws IOException {
            for (byte[] whole : d.assembler.add(buf, 0, n)) framed(d, whole);
            return d.assembler.failure() == null || abort(d, d.assembler.failure());
        }

        /** A whole message: through {@code streamMessage}, then what it returns, framed, to each side. */
        private void framed(Direction d, byte[] whole) throws IOException {
            List<byte[]> same = new ArrayList<>();
            List<byte[]> other = new ArrayList<>();
            d.hookThread = Thread.currentThread();
            try {
                QuicMessage message = new QuicMessage(framer.payload(whole), d.fromClient, clientSide.id(), alpn,
                        Instant.now());
                List<QuicMessage> result = hooks.streamMessage(message, this);
                if (result != null) {
                    for (QuicMessage m : result) {
                        if (m != null) (m.fromClient() == d.fromClient ? same : other).add(framer.frame(m.data()));
                    }
                }
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's streamMessage threw, or what it returned could"
                        + " not be framed; passing the message on", e);
                same = List.of(whole);
                other = List.of();
            } finally {
                d.hookThread = null;
            }
            List<byte[]> added = d.pending;
            d.pending = null;
            d.lock.lock();
            try {
                if (d.ended) return;
                for (byte[] bytes : same) {
                    if (bytes.length > 0) d.out.write(bytes);
                }
                if (added != null) {
                    for (byte[] bytes : added) {
                        if (bytes.length > 0) d.out.write(bytes);
                    }
                }
            } finally {
                d.lock.unlock();
            }
            for (byte[] bytes : other) {
                try {
                    send(!d.fromClient, bytes);
                } catch (IllegalStateException e) {
                    LOG.log(Level.DEBUG, () -> logPrefix + "dropping a QUIC message for the other side: " + e.getMessage());
                }
            }
        }

        /** The source finished with bytes that are not a whole message: passed on as they are. */
        private void leftover(Direction d) throws IOException {
            byte[] rest = d.assembler.rest();
            if (rest.length == 0) return;
            LOG.log(Level.DEBUG, () -> logPrefix + "QUIC stream " + clientSide.id() + " ended with " + rest.length
                    + " bytes that are not a whole message; passing them on");
            d.lock.lock();
            try {
                if (!d.ended) d.out.write(rest);
            } finally {
                d.lock.unlock();
            }
        }

        /**
         * A framed direction read a message too large, or bytes its framer cannot read: the stream
         * is reset towards both sides and both are asked to stop sending, with the framing's error
         * code, as a WebSocket message too big closes the connection with 1009. Returns false.
         */
        private boolean abort(Direction d, String why) {
            long code = framing.errorCode();
            LOG.log(Level.INFO, logPrefix + "QUIC stream " + clientSide.id() + " to " + target + ": the "
                    + (d.fromClient ? "client" : "server") + " sent " + why + "; resetting the stream with code " + code);
            // Both directions ended first, so that neither passes on what a peer does once it is told
            // (a server that finishes its side when its input is reset), then the resets and stops.
            Direction[] both = {toServer, toClient};
            boolean[] reset = new boolean[2];
            for (int i = 0; i < 2; i++) {
                Direction x = both[i];
                if (x == null) continue;
                // The proxy's own stop: a STOP_SENDING that answers it is not passed on as the peer's.
                x.stopped.set(true);
                x.lock.lock();
                try {
                    reset[i] = !x.ended;
                    x.ended = true;
                } finally {
                    x.lock.unlock();
                }
            }
            for (int i = 0; i < 2; i++) {
                if (!reset[i]) continue;
                try {
                    both[i].sink.reset(code);
                } catch (IOException | RuntimeException e) {
                    // gone already
                }
            }
            for (Direction x : both) {
                if (x == null) continue;
                try {
                    x.source.stopSending(code);
                } catch (IOException | RuntimeException e) {
                    // finished or reset meanwhile
                }
            }
            return false;
        }

        /** The source finished sending: {@code streamFinished}, then the FIN is passed on. */
        private void finish(Direction d) throws IOException {
            if (hooks != null) {
                try {
                    hooks.streamFinished(this, d.fromClient);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's streamFinished threw", e);
                }
            }
            d.lock.lock();
            try {
                if (d.ended) return;
                d.ended = true;
                d.out.close();
            } finally {
                d.lock.unlock();
            }
        }

        /** The source reset its sending part: {@code streamReset}, then the sink's is reset with the same code. */
        private void reset(Direction d, long code) {
            if (hooks != null) {
                try {
                    hooks.streamReset(this, d.fromClient, code);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's streamReset threw", e);
                }
            }
            d.lock.lock();
            try {
                if (d.ended) return;
                d.ended = true;
                d.sink.reset(code);
            } catch (IOException e) {
                // the stream or the connection is gone already
            } finally {
                d.lock.unlock();
            }
        }

        /**
         * The sink's side asked to stop sending, once: {@code streamStopped}, then the source is asked
         * the same and the sink reset (the answer RFC 9000 section 3.5 asks for).
         */
        private void stopped(Direction d, long code) {
            if (!d.stopped.compareAndSet(false, true)) return;
            if (hooks != null) {
                try {
                    hooks.streamStopped(this, !d.fromClient, code);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, logPrefix + "QUIC interceptor's streamStopped threw", e);
                }
            }
            try {
                d.source.stopSending(code);
            } catch (IOException | RuntimeException e) {
                // finished or reset meanwhile
            }
            d.lock.lock();
            try {
                if (d.ended) return;
                d.ended = true;
                d.sink.reset(code);
            } catch (IOException e) {
                // gone already
            } finally {
                d.lock.unlock();
            }
        }

        private void markEnded(Direction d) {
            d.lock.lock();
            try {
                d.ended = true;
            } finally {
                d.lock.unlock();
            }
        }

        // QuicStreamContext

        @Override
        public long streamId() {
            return clientSide.id();
        }

        @Override
        public long serverStreamId() {
            return serverSide.id();
        }

        @Override
        public boolean bidirectional() {
            return clientSide.isBidirectional();
        }

        @Override
        public boolean clientInitiated() {
            return clientInitiated;
        }

        @Override
        public void send(boolean fromClient, byte[] data) {
            Objects.requireNonNull(data, "data");
            Direction d = fromClient ? toServer : toClient;
            if (d == null) {
                throw new IllegalStateException("stream " + clientSide.id() + " is unidirectional, from the "
                        + (clientInitiated ? "client" : "server"));
            }
            if (d.hookThread == Thread.currentThread()) {
                if (d.pending == null) d.pending = new ArrayList<>();
                d.pending.add(data.clone());
                return;
            }
            d.lock.lock();
            try {
                if (d.ended) {
                    throw new IllegalStateException("stream " + clientSide.id() + ": the "
                            + (fromClient ? "client's" : "server's") + " side has ended");
                }
                if (data.length > 0) d.out.write(data);
            } catch (IOException e) {
                d.ended = true;
                throw new IllegalStateException("stream " + clientSide.id() + ": " + e.getMessage(), e);
            } finally {
                d.lock.unlock();
            }
        }

        @Override
        public QuicContext connection() {
            return QuicSession.this;
        }

        @Override
        public long connectionId() {
            return QuicSession.this.connectionId();
        }

        @Override
        public InetSocketAddress clientAddress() {
            return QuicSession.this.clientAddress();
        }

        @Override
        public String host() {
            return QuicSession.this.host();
        }

        @Override
        public int port() {
            return QuicSession.this.port();
        }

        @Override
        public InetSocketAddress serverAddress() {
            return QuicSession.this.serverAddress();
        }

        @Override
        public String sni() {
            return QuicSession.this.sni();
        }

        @Override
        public String alpn() {
            return QuicSession.this.alpn();
        }

        @Override
        public boolean masque() {
            return QuicSession.this.masque();
        }

        @Override
        public FlowContext flowContext() {
            return QuicSession.this.flowContext();
        }

        @Override
        public void sendDatagram(boolean fromClient, byte[] data) {
            QuicSession.this.sendDatagram(fromClient, data);
        }

        @Override
        public String toString() {
            return "quic stream " + clientSide.id() + " of " + QuicSession.this;
        }
    }
}
