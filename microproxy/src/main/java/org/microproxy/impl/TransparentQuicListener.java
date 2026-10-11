package org.microproxy.impl;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.packet.PacketDecodeException;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.ProtocolException;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import org.microproxy.ClientHello;
import org.microproxy.FullFlowContext;
import org.microproxy.Http3Options;
import org.microproxy.KeyMaterial;

/**
 * The transparent QUIC listener ({@link org.microproxy.HttpProxyServerBootstrap#withTransparentQuicPort}):
 * one UDP socket that QUIC redirected by a firewall arrives at, from many clients, which the
 * listener intercepts (HTTP/3 with a certificate the proxy issues) or relays untouched to the
 * server, flow by flow, as the transparent TLS listener does for TCP.
 *
 * <p><b>Demultiplexing.</b> The socket is a {@link QuicServer}'s, whose endpoint routes the
 * datagrams of intercepted connections by the connection IDs the proxy issued, before anything
 * else sees them (so a client that moves to new connection IDs after the handshake stays on its
 * connection). The listener's {@link QuicServer.DatagramFilter} gets every other datagram, and
 * keeps flows by client address: each flow knows the Destination Connection ID of the client's
 * Initial packets and, once relayed, the connection IDs its server chose (the Source Connection
 * IDs of the server's long header packets). A short header packet that names none of those (the
 * server issued more IDs in encrypted frames) goes to the client address's most recently active
 * relayed flow, and so do packets of versions the proxy cannot read.
 *
 * <p><b>New flows.</b> A client's first Initial starts a pending flow: its datagrams are held
 * while {@link QuicClientHello} reads the ClientHello from them (decrypting the Initial packets),
 * then {@link ClientConnection#decideTransparentQuic} decides, on a thread of its own, by the SNI
 * (the destination: that host, on the transparent TLS port). An intercepted flow's datagrams are
 * then {@linkplain QuicServer#inject injected} into the QUIC server, whose handshake presents a
 * certificate for the SNI, and the connection it accepts is served HTTP/3 by the {@link
 * ClientConnection} that decided ({@link #acceptLoop}, by client address and the Initials'
 * Destination Connection ID). A relayed flow gets a UDP socket to its server, which its client's
 * datagrams are written to, and a virtual thread that sends the server's datagrams back to the
 * client from the listener's socket (so that the NAT that redirected the client maps the replies
 * back to the address the client sent to).
 *
 * <p><b>Bounds.</b> Pending flows, in total and per client IP address; the datagrams and bytes
 * each holds, and the bytes all hold together; how long one may stay pending; relayed flows, in
 * total and per client IP address, and how long one lives idle ({@link Http3Options}).
 *
 * <p><b>Threads and locks.</b> The QUIC server's receiving thread runs the filter; {@link #lock}
 * guards the flows, and is held while datagrams are injected or written to a relay socket, so
 * that they keep their order. Trackers and the client connections' callbacks run outside it. No
 * {@code synchronized}.
 */
final class TransparentQuicListener implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(TransparentQuicListener.class.getName());

    /** The ALPN identifier of HTTP/3, the only protocol intercepted. */
    static final String H3 = "h3";

    /** The datagrams a pending flow holds, retransmissions included. */
    private static final int MAX_HELD_DATAGRAMS = 2 * QuicClientHello.MAX_DATAGRAMS;
    /** The bytes a pending flow holds. */
    private static final int MAX_HELD_BYTES = 64 * 1024;
    /** The smallest datagram a client's first Initial comes in (RFC 9000 section 14.1). */
    private static final int MIN_INITIAL_DATAGRAM = 1200;
    /** Server connection IDs a relayed flow remembers. */
    private static final int MAX_SERVER_CIDS = 8;
    /** How long an intercepted connection may take to complete its handshake. */
    private static final long HANDSHAKE_NANOS = TimeUnit.SECONDS.toNanos(10);

    private enum State {
        /** Reading the ClientHello. */
        PENDING,
        /** The ClientHello is read; the decision is being made. */
        DECIDING,
        /** Its datagrams go to the QUIC server, until it routes them itself. */
        INTERCEPTED,
        /** Its datagrams go to the server. */
        RELAYED
    }

    /** A client flow: a client address and the Destination Connection ID of its Initials. */
    private record FlowKey(InetSocketAddress client, ConnectionId destinationId) {}

    /** An intercepted flow whose QUIC handshake is under way: who serves it once accepted. */
    private record Accepting(ClientConnection client, String sni, long deadline) {}

    private final class Flow {
        final InetSocketAddress client;
        final ConnectionId destinationId;
        State state = State.PENDING;
        /** Whether the flow counts as pending, against the bounds. */
        boolean counted = true;
        QuicClientHello reader;
        final ArrayDeque<ByteBuffer> held = new ArrayDeque<>();
        int heldBytes;
        /** Until when the flow may stay pending, or keeps routing to the QUIC server. */
        long deadline;
        /** When a datagram last went either way, for a relayed flow. */
        long lastActive;
        final Set<ConnectionId> serverIds = new LinkedHashSet<>();
        DatagramChannel upstream;
        ClientConnection connection;
        FullFlowContext serverFlow;

        Flow(InetSocketAddress client, ConnectionId destinationId, QuicClientHello reader, long now) {
            this.client = client;
            this.destinationId = destinationId;
            this.reader = reader;
            this.deadline = now + options.transparentPendingTimeout().toNanos();
        }

        boolean pending() {
            return state == State.PENDING || state == State.DECIDING;
        }

        String log() {
            return "transparent QUIC " + client + " (" + destinationId + "): ";
        }
    }

    private final DefaultHttpProxyServer server;
    private final Http3Options options;
    /** The certificate for a server name; null when nothing can be intercepted. */
    private final Function<String, KeyMaterial> keys;
    private final QuicServer quic;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition stopped = lock.newCondition();
    // Guarded by lock.
    private final Map<InetSocketAddress, List<Flow>> flows = new HashMap<>();
    private final Map<InetAddress, Integer> pendingBySource = new HashMap<>();
    private final Map<InetAddress, Integer> relayedBySource = new HashMap<>();
    private final Map<FlowKey, Accepting> accepting = new HashMap<>();
    private int pending;
    private int relayed;
    private long heldBytes;
    private boolean closed;

    /** Datagrams dropped: past a bound, unreadable Initials, refused flows. */
    private final AtomicLong dropped = new AtomicLong();
    private final Thread acceptor;
    private final Thread sweeper;

    private TransparentQuicListener(DefaultHttpProxyServer server, InetSocketAddress address,
            Function<String, KeyMaterial> keys) throws IOException {
        this.server = server;
        this.options = server.http3Options;
        this.keys = keys;
        this.quic = QuicServer.bind(address, Http3Listener.serverConfig(server, keys != null ? keys : sni -> null),
                EndpointConfig.defaults(), this::filter);
        this.acceptor = Thread.ofVirtual().name(server.name + "-quic-acceptor").start(this::acceptLoop);
        this.sweeper = Thread.ofVirtual().name(server.name + "-quic-sweeper").start(this::sweepLoop);
    }

    /**
     * Binds the listener on UDP {@code address} and starts it.
     *
     * @param keys the certificate for a server name, or null when no flow can be intercepted
     * @throws IOException if the port cannot be bound
     */
    static TransparentQuicListener start(DefaultHttpProxyServer server, InetSocketAddress address,
            Function<String, KeyMaterial> keys) throws IOException {
        return new TransparentQuicListener(server, address, keys);
    }

    /** The UDP address the listener is bound to. */
    InetSocketAddress localAddress() {
        return quic.localAddress();
    }

    // ---------------------------------------------------------------------------------------
    // Datagrams from clients
    // ---------------------------------------------------------------------------------------

    /** Every datagram the QUIC server's connections do not claim: true when the listener took it. */
    private boolean filter(InetSocketAddress from, ByteBuffer datagram) {
        Flow relay;
        lock.lock();
        try {
            if (closed) return true;
            Flow flow = find(from, datagram);
            if (flow == null) return newFlow(from, datagram);
            switch (flow.state) {
                case PENDING, DECIDING -> {
                    hold(flow, datagram);
                    if (flow.state == State.PENDING) read(flow, datagram);
                    return true;
                }
                case INTERCEPTED -> {
                    quic.inject(from, datagram);
                    return true;
                }
                case RELAYED -> {
                    flow.lastActive = System.nanoTime();
                    write(flow, datagram);
                    relay = flow;
                }
                default -> throw new IllegalStateException();
            }
        } finally {
            lock.unlock();
        }
        if (!server.trackers.isEmpty()) {
            int n = datagram.remaining();
            server.trackers.fire(t -> t.bytesReceivedFromClient(relay.connection.connectionFlowContext(), n));
            server.trackers.fire(t -> t.bytesSentToServer(relay.serverFlow, n));
        }
        return true;
    }

    /**
     * The flow of a client's datagram: by the Destination Connection ID of a long header packet,
     * or the first bytes of a short header one; else, for anything but a new Initial, the client
     * address's most recently active relayed flow. Holds lock.
     */
    private Flow find(InetSocketAddress from, ByteBuffer datagram) {
        List<Flow> list = flows.get(from);
        if (list == null || !datagram.hasRemaining()) return null;
        int at = datagram.position();
        boolean longHeader = (datagram.get(at) & 0x80) != 0;
        for (Flow f : list) {
            if (longHeader) {
                if (datagram.remaining() < 6) break;
                int length = datagram.get(at + 5) & 0xff;
                if (matches(datagram, at + 6, length, f.destinationId)) return f;
                for (ConnectionId id : f.serverIds) {
                    if (matches(datagram, at + 6, length, id)) return f;
                }
            } else {
                for (ConnectionId id : f.serverIds) {
                    if (matches(datagram, at + 1, id.length(), id)) return f;
                }
            }
        }
        if (longHeader && isInitial(datagram)) return null;
        Flow latest = null;
        for (Flow f : list) {
            if (f.state == State.RELAYED && (latest == null || f.lastActive - latest.lastActive > 0)) latest = f;
        }
        return latest;
    }

    private static boolean matches(ByteBuffer datagram, int at, int length, ConnectionId id) {
        if (id.length() != length || at + length > datagram.limit()) return false;
        for (int i = 0; i < length; i++) {
            if (datagram.get(at + i) != id.get(i)) return false;
        }
        return true;
    }

    /** Whether the datagram starts with an Initial packet of a version the proxy reads. */
    private static boolean isInitial(ByteBuffer datagram) {
        try {
            return ProtectedPacket.parse(datagram.duplicate(), 0).type() == PacketType.INITIAL;
        } catch (PacketDecodeException e) {
            return false;
        }
    }

    /**
     * A datagram of no known flow: a new client's first Initial starts a pending flow, within the
     * bounds. Anything else is the QUIC server's to answer (Version Negotiation for unknown
     * versions, a stateless reset for unknown connections). Holds lock.
     */
    private boolean newFlow(InetSocketAddress from, ByteBuffer datagram) {
        QuicClientHello reader;
        try {
            reader = QuicClientHello.start(datagram);
        } catch (QuicClientHello.UnknownVersion e) {
            // Nowhere to relay it: the destination is in the ClientHello, which the proxy cannot
            // read. The server's Version Negotiation makes the client try a version it can.
            LOG.log(Level.DEBUG, () -> "transparent QUIC " + from + ": " + e.getMessage() + "; Version Negotiation");
            return false;
        } catch (TlsClientHello.Malformed e) {
            return false;
        }
        if (datagram.remaining() < MIN_INITIAL_DATAGRAM || server.isStopping()) {
            dropped.incrementAndGet();
            return true;
        }
        InetAddress source = from.getAddress();
        if (pending >= options.transparentMaxPending()
                || pendingBySource.getOrDefault(source, 0) >= options.transparentMaxPendingPerSource()
                || heldBytes + datagram.remaining() > options.transparentMaxBufferedBytes()) {
            dropped.incrementAndGet();
            LOG.log(Level.DEBUG, () -> "transparent QUIC " + from + ": too many new clients; dropping an Initial");
            return true;
        }
        Flow flow = new Flow(from, reader.destinationId(), reader, System.nanoTime());
        flows.computeIfAbsent(from, k -> new ArrayList<>(1)).add(flow);
        pending++;
        pendingBySource.merge(source, 1, Integer::sum);
        hold(flow, datagram);
        read(flow, datagram);
        return true;
    }

    /** Holds a pending flow's datagram, within the bounds. Holds lock. */
    private void hold(Flow flow, ByteBuffer datagram) {
        int n = datagram.remaining();
        if (flow.held.size() >= MAX_HELD_DATAGRAMS || flow.heldBytes + n > MAX_HELD_BYTES
                || heldBytes + n > options.transparentMaxBufferedBytes()) {
            dropped.incrementAndGet();
            return;
        }
        flow.held.add(datagram);
        flow.heldBytes += n;
        heldBytes += n;
    }

    /** Reads a pending flow's datagram for the ClientHello; once it is complete, decides. Holds lock. */
    private void read(Flow flow, ByteBuffer datagram) {
        ClientHello hello;
        try {
            hello = flow.reader.offer(datagram);
        } catch (TlsClientHello.Malformed | TlsClientHello.TooLarge e) {
            LOG.log(Level.DEBUG, () -> flow.log() + "no readable ClientHello (" + e.getMessage() + "); dropping");
            dropped.addAndGet(flow.held.size());
            forget(flow);
            return;
        }
        if (hello == null) return;
        flow.reader = null;
        flow.state = State.DECIDING;
        Accepting retried = options.retry() ? retried(flow, hello) : null;
        if (retried != null) {
            // The client's Initials again, after the QUIC server's Retry: decided already.
            intercepted(flow, retried.client(), retried.sni());
            return;
        }
        Thread.ofVirtual().name(server.name + "-quic-decide").start(() -> decide(flow, hello));
    }

    /**
     * The decision on the client's flow that the QUIC server answered with a Retry: an intercepted
     * flow of the same client address and SNI whose handshake has not completed. Holds lock.
     */
    private Accepting retried(Flow flow, ClientHello hello) {
        for (Iterator<Map.Entry<FlowKey, Accepting>> it = accepting.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<FlowKey, Accepting> e = it.next();
            if (e.getKey().client().equals(flow.client) && e.getValue().sni().equalsIgnoreCase(String.valueOf(hello.sni()))) {
                it.remove();
                return e.getValue();
            }
        }
        return null;
    }

    // ---------------------------------------------------------------------------------------
    // Deciding
    // ---------------------------------------------------------------------------------------

    /** Decides on a flow whose ClientHello is read, on a thread of its own. */
    private void decide(Flow flow, ClientHello hello) {
        ClientConnection client = new ClientConnection(server, flow.client);
        if (hello.sni() == null) {
            LOG.log(Level.DEBUG, () -> flow.log() + "a ClientHello without SNI: the server cannot be told; dropping");
            ProtocolException e = new ProtocolException("transparent QUIC flow with a ClientHello without SNI");
            server.trackers.fire(t -> t.connectionExceptionCaught(client.connectionFlowContext(), e));
            drop(flow);
            return;
        }
        String hostAndPort = new HostAndPort(hello.sni(), server.transparentTlsPort).toString();
        ClientConnection.QuicDecision decision = client.decideTransparentQuic(hello, hostAndPort, keys != null);
        switch (decision.verdict()) {
            case INTERCEPT -> {
                LOG.log(Level.DEBUG, () -> flow.log() + "intercepting " + hostAndPort);
                lock.lock();
                try {
                    if (isGone(flow)) {
                        client.endTransparentQuic(false);
                        return;
                    }
                    intercepted(flow, client, hello.sni());
                } finally {
                    lock.unlock();
                }
            }
            case RELAY -> {
                LOG.log(Level.DEBUG, () -> flow.log() + "relaying to " + hostAndPort + ": " + decision.reason());
                relay(flow, client, hello.sni(), hostAndPort);
            }
            case DROP -> {
                LOG.log(Level.DEBUG, () -> flow.log() + "dropping: " + decision.reason());
                drop(flow);
                client.endTransparentQuic(false);
            }
        }
    }

    /** Whether the flow was forgotten while it was decided on (timed out, or the listener closed). Holds lock. */
    private boolean isGone(Flow flow) {
        if (closed) return true;
        List<Flow> list = flows.get(flow.client);
        return list == null || !list.contains(flow);
    }

    /**
     * Hands an intercepted flow's datagrams to the QUIC server, in order, and those that follow
     * until the server routes them itself; the connection it accepts goes to {@code client}.
     * Holds lock.
     */
    private void intercepted(Flow flow, ClientConnection client, String sni) {
        unpend(flow);
        flow.state = State.INTERCEPTED;
        flow.deadline = System.nanoTime() + options.transparentPendingTimeout().toNanos();
        accepting.put(new FlowKey(flow.client, flow.destinationId), new Accepting(client, sni,
                System.nanoTime() + options.transparentPendingTimeout().toNanos() + HANDSHAKE_NANOS));
        for (ByteBuffer datagram : flow.held) quic.inject(flow.client, datagram);
        release(flow);
    }

    /** Relays a flow to its server: a socket of its own, its held datagrams first. */
    private void relay(Flow flow, ClientConnection client, String sni, String hostAndPort) {
        InetSocketAddress remote;
        DatagramChannel channel;
        try {
            remote = server.serverResolver.resolve(sni, server.transparentTlsPort);
            channel = DatagramChannel.open(remote.getAddress() instanceof Inet6Address
                    ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET);
            try {
                channel.connect(remote);
            } catch (IOException | RuntimeException e) {
                channel.close();
                throw e;
            }
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.DEBUG, () -> flow.log() + "cannot relay to " + hostAndPort + " (" + e + "); dropping");
            FullFlowContext serverFlow = new FullFlowContext(client.connectionFlowContext(), hostAndPort, null, null);
            server.trackers.fire(t -> t.serverConnectionExceptionCaught(serverFlow, e));
            drop(flow);
            client.endTransparentQuic(false);
            return;
        }
        boolean started = false;
        lock.lock();
        try {
            InetAddress source = flow.client.getAddress();
            if (isGone(flow)) {
                // forgotten meanwhile
            } else if (relayed >= options.transparentMaxRelayFlows()
                    || relayedBySource.getOrDefault(source, 0) >= options.transparentMaxRelayFlowsPerSource()) {
                LOG.log(Level.DEBUG, () -> flow.log() + "too many relayed flows; dropping");
                dropped.addAndGet(flow.held.size());
                forget(flow);
            } else {
                unpend(flow);
                flow.state = State.RELAYED;
                flow.upstream = channel;
                flow.connection = client;
                flow.serverFlow = new FullFlowContext(client.connectionFlowContext(), hostAndPort, null, remote);
                flow.lastActive = System.nanoTime();
                relayed++;
                relayedBySource.merge(source, 1, Integer::sum);
                for (ByteBuffer datagram : flow.held) write(flow, datagram);
                release(flow);
                started = true;
            }
        } finally {
            lock.unlock();
        }
        if (!started) {
            closeQuietly(channel);
            client.endTransparentQuic(false);
            return;
        }
        server.trackers.fire(t -> t.serverConnected(flow.serverFlow, remote));
        Thread.ofVirtual().name(server.name + "-quic-relay").start(() -> relayReplies(flow));
    }

    /** Drops a flow that was refused or cannot go anywhere. */
    private void drop(Flow flow) {
        lock.lock();
        try {
            dropped.addAndGet(flow.held.size());
            if (!isGone(flow)) forget(flow);
        } finally {
            lock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Relaying
    // ---------------------------------------------------------------------------------------

    /** Writes a client's datagram to a relayed flow's server. Holds lock, which keeps them in order. */
    private void write(Flow flow, ByteBuffer datagram) {
        try {
            flow.upstream.write(datagram.duplicate());
        } catch (PortUnreachableException e) {
            // ICMP from an earlier datagram; the server may come up, or the flow idles out.
        } catch (IOException e) {
            LOG.log(Level.DEBUG, () -> flow.log() + "relaying to the server failed: " + e);
        }
    }

    /** Sends a relayed flow's server datagrams to its client from the listener's socket, until it closes. */
    private void relayReplies(Flow flow) {
        ByteBuffer buf = ByteBuffer.allocate(65536);
        while (true) {
            buf.clear();
            try {
                flow.upstream.read(buf);
            } catch (PortUnreachableException e) {
                continue;
            } catch (ClosedChannelException e) {
                return;
            } catch (IOException e) {
                LOG.log(Level.DEBUG, () -> flow.log() + "reading from the server failed: " + e);
                return;
            }
            buf.flip();
            int n = buf.remaining();
            lock.lock();
            try {
                if (flow.upstream == null || !flow.upstream.isOpen()) return;
                flow.lastActive = System.nanoTime();
                learnServerId(flow, buf);
            } finally {
                lock.unlock();
            }
            quic.send(buf, flow.client);
            if (!server.trackers.isEmpty()) {
                server.trackers.fire(t -> t.bytesReceivedFromServer(flow.serverFlow, n));
                server.trackers.fire(t -> t.bytesSentToClient(flow.connection.connectionFlowContext(), n));
            }
        }
    }

    /**
     * Remembers the connection ID a server chose, from the Source Connection ID of its long header
     * packets: the client's packets carry it as their Destination Connection ID. Holds lock.
     */
    private static void learnServerId(Flow flow, ByteBuffer datagram) {
        int at = datagram.position();
        if (datagram.remaining() < 7 || (datagram.get(at) & 0x80) == 0) return;
        int dcidLength = datagram.get(at + 5) & 0xff;
        int scidAt = at + 6 + dcidLength;
        if (dcidLength > ConnectionId.MAX_LENGTH || scidAt >= datagram.limit()) return;
        int scidLength = datagram.get(scidAt) & 0xff;
        if (scidLength > ConnectionId.MAX_LENGTH || scidAt + 1 + scidLength > datagram.limit()) return;
        ConnectionId id = ConnectionId.of(datagram.array(), datagram.arrayOffset() + scidAt + 1, scidLength);
        if (flow.serverIds.contains(id) || flow.serverIds.size() >= MAX_SERVER_CIDS) return;
        flow.serverIds.add(id);
    }

    // ---------------------------------------------------------------------------------------
    // Accepting intercepted connections
    // ---------------------------------------------------------------------------------------

    private void acceptLoop() {
        while (true) {
            QuicConnection connection;
            try {
                connection = quic.accept();
            } catch (IOException e) {
                if (!server.isStopping()) LOG.log(Level.DEBUG, server.name + " transparent QUIC listener stopped: " + e);
                return;
            }
            Accepting a;
            lock.lock();
            try {
                a = accepting.remove(new FlowKey(connection.remoteAddress(), connection.initialDestinationId()));
            } finally {
                lock.unlock();
            }
            if (a == null) {
                // Not one the listener decided to intercept (its decision has expired).
                connection.close(0x0100, "");
                continue;
            }
            if (server.isStopping()) {
                connection.close(0x0100, "the proxy is stopping");
                a.client().endTransparentQuic(false);
                continue;
            }
            server.acceptTransparentQuic(connection, a.client());
        }
    }

    // ---------------------------------------------------------------------------------------
    // Ending flows
    // ---------------------------------------------------------------------------------------

    /** Forgets flows past their time, every half second or so, until the listener closes. */
    private void sweepLoop() {
        long period = Math.min(TimeUnit.MILLISECONDS.toNanos(500), options.transparentPendingTimeout().toNanos() / 2);
        while (true) {
            List<Flow> idle = new ArrayList<>();
            List<ClientConnection> abandoned = new ArrayList<>();
            lock.lock();
            try {
                if (!closed) stopped.awaitNanos(period);
                if (closed) return;
                long now = System.nanoTime();
                long idleNanos = options.transparentRelayIdleTimeout().toNanos();
                for (List<Flow> list : new ArrayList<>(flows.values())) {
                    for (Flow f : new ArrayList<>(list)) {
                        if (f.state == State.RELAYED) {
                            if (now - f.lastActive - idleNanos > 0) {
                                idle.add(f);
                                endRelay(f);
                            }
                        } else if (now - f.deadline > 0) {
                            if (f.pending()) {
                                LOG.log(Level.DEBUG, () -> f.log() + "still pending after "
                                        + options.transparentPendingTimeout().toMillis() + " ms; dropping");
                                dropped.addAndGet(f.held.size());
                            }
                            forget(f);
                        }
                    }
                }
                for (Iterator<Accepting> it = accepting.values().iterator(); it.hasNext(); ) {
                    Accepting a = it.next();
                    if (now - a.deadline() > 0) {
                        it.remove();
                        abandoned.add(a.client());
                    }
                }
            } catch (InterruptedException e) {
                return;
            } finally {
                lock.unlock();
            }
            for (Flow f : idle) relayEnded(f);
            for (ClientConnection c : abandoned) c.endTransparentQuic(false);
        }
    }

    /** Takes a relayed flow out of the listener and closes its socket. Holds lock. */
    private void endRelay(Flow f) {
        closeQuietly(f.upstream);
        relayed--;
        decrement(relayedBySource, f.client.getAddress());
        remove(f);
    }

    /** Tells trackers and filters that a relayed flow ended. */
    private void relayEnded(Flow f) {
        LOG.log(Level.DEBUG, () -> f.log() + "relay idle; closed");
        server.trackers.fire(t -> t.serverDisconnected(f.serverFlow, f.serverFlow.getRemoteAddress()));
        f.connection.endTransparentQuic(true);
    }

    /** Takes a pending or intercepted flow out of the listener. Holds lock. */
    private void forget(Flow flow) {
        unpend(flow);
        release(flow);
        remove(flow);
    }

    /** Stops counting a flow as pending. Holds lock. */
    private void unpend(Flow flow) {
        if (!flow.counted) return;
        flow.counted = false;
        pending--;
        decrement(pendingBySource, flow.client.getAddress());
    }

    /** Lets go of the datagrams a flow held. Holds lock. */
    private void release(Flow flow) {
        heldBytes -= flow.heldBytes;
        flow.heldBytes = 0;
        flow.held.clear();
        flow.reader = null;
    }

    private void remove(Flow flow) {
        List<Flow> list = flows.get(flow.client);
        if (list != null && list.remove(flow) && list.isEmpty()) flows.remove(flow.client);
    }

    private static void decrement(Map<InetAddress, Integer> counts, InetAddress key) {
        counts.computeIfPresent(key, (k, n) -> n > 1 ? n - 1 : null);
    }

    private static void closeQuietly(DatagramChannel channel) {
        if (channel == null) return;
        try {
            channel.close();
        } catch (IOException e) {
            // closing anyway
        }
    }

    // ---------------------------------------------------------------------------------------
    // For tests and monitoring
    // ---------------------------------------------------------------------------------------

    /** The flows pending: ClientHellos being read or decided on. */
    int pendingFlows() {
        lock.lock();
        try {
            return pending;
        } finally {
            lock.unlock();
        }
    }

    /** The flows relayed. */
    int relayedFlows() {
        lock.lock();
        try {
            return relayed;
        } finally {
            lock.unlock();
        }
    }

    /** The bytes of datagrams pending flows hold. */
    long heldBytes() {
        lock.lock();
        try {
            return heldBytes;
        } finally {
            lock.unlock();
        }
    }

    /** The datagrams dropped so far. */
    long droppedDatagrams() {
        return dropped.get();
    }

    /** Closes the relays and the QUIC server (and with it the intercepted connections). */
    @Override
    public void close() {
        List<Flow> relays = new ArrayList<>();
        List<ClientConnection> abandoned = new ArrayList<>();
        lock.lock();
        try {
            if (closed) return;
            closed = true;
            stopped.signalAll();
            for (List<Flow> list : new ArrayList<>(flows.values())) {
                for (Flow f : new ArrayList<>(list)) {
                    if (f.state == State.RELAYED) {
                        relays.add(f);
                        endRelay(f);
                    } else {
                        forget(f);
                    }
                }
            }
            for (Accepting a : accepting.values()) abandoned.add(a.client());
            accepting.clear();
        } finally {
            lock.unlock();
        }
        for (Flow f : relays) relayEnded(f);
        for (ClientConnection c : abandoned) c.endTransparentQuic(false);
        quic.close();
        try {
            acceptor.join(5000);
            sweeper.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
