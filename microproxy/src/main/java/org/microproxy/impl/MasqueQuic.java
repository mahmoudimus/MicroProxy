package org.microproxy.impl;

import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.microproxy.ClientHello;
import org.microproxy.KeyMaterial;

/**
 * Decides on the QUIC inside CONNECT-UDP flows ({@link org.microproxy.Http3Options#connectUdpInterceptQuic()}),
 * as the transparent QUIC listener decides on redirected QUIC: a virtual listener, whose {@link
 * QuicFlows} and {@link QuicServer} have no socket. A flow to one of the QUIC ports whose first
 * datagram from the client is a QUIC Initial hands its client's datagrams to the flows ({@link
 * Inner#fromClient}), under an address the listener makes up for it ({@link #attach}); the QUIC
 * server's datagrams for that address go back into the flow, towards the client. The decision is
 * made with the flow's target as the server: an intercepted flow is served as HTTP/3 or stream by
 * stream, by a client connection of the MASQUE client's ({@link ClientConnection#ClientConnection(
 * ClientConnection, InetSocketAddress)}); a relayed one goes back to the flow, which sends its held
 * datagrams to the target, and every later one, as any CONNECT-UDP flow does.
 */
final class MasqueQuic implements AutoCloseable {

    /** The made-up addresses of the flows: an IPv6 unique local prefix, then a counter. */
    private static final byte[] PREFIX = {(byte) 0xfd, 0x6d, 0x61, 0x73, 0x71, 0x75, 0x65, 0x00};

    private final Set<Integer> ports;
    private final QuicFlows flows;
    private final QuicServer quic;
    private final Map<InetSocketAddress, Inner> byAddress = new ConcurrentHashMap<>();
    private final AtomicLong next = new AtomicLong();

    /** @param keys the certificate for a server name, or null when nothing can be intercepted */
    MasqueQuic(DefaultHttpProxyServer server, Function<String, KeyMaterial> keys) {
        this.ports = server.http3Options.connectUdpQuicPorts();
        this.flows = new QuicFlows(server, keys, byAddress::get, server.name + "-masque-quic");
        this.quic = QuicServer.unbound(address(0), Http3Listener.serverConfig(server, keys != null ? keys : sni -> null),
                EndpointConfig.defaults(), this::filter, this::send);
        flows.start(quic);
    }

    /** Whether the QUIC of flows to {@code port} is decided on. */
    boolean inspects(int port) {
        return ports.isEmpty() || ports.contains(port);
    }

    /**
     * Inspects the client datagrams of {@code flow} for QUIC; {@code connections} makes the client
     * connection that decides on it.
     */
    Inner attach(UdpFlow flow, Function<InetSocketAddress, ClientConnection> connections) {
        Inner inner = new Inner(address(next.incrementAndGet()), flow, connections);
        byAddress.put(inner.address, inner);
        return inner;
    }

    private static InetSocketAddress address(long n) {
        byte[] bytes = new byte[16];
        System.arraycopy(PREFIX, 0, bytes, 0, PREFIX.length);
        for (int i = 0; i < 8; i++) bytes[15 - i] = (byte) (n >>> (8 * i));
        try {
            return new InetSocketAddress(InetAddress.getByAddress(bytes), 443);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e); // sixteen bytes are always an address
        }
    }

    /** The datagrams no connection claims: those of flows still attached go to the flows. */
    private boolean filter(InetSocketAddress from, ByteBuffer datagram) {
        return !byAddress.containsKey(from) || flows.filter(from, datagram);
    }

    /** A datagram of the QUIC server's, for the client of the flow the address is. */
    private void send(ByteBuffer datagram, InetSocketAddress to) {
        Inner inner = byAddress.get(to);
        if (inner == null) return;
        byte[] payload = new byte[datagram.remaining()];
        datagram.get(payload);
        inner.flow.toClientFromProxy(payload);
    }

    @Override
    public void close() {
        flows.close();
    }

    /** What the flows' decision is, for a flow's datagrams from the client. */
    private enum Mode {
        /** No datagram yet: the first says whether the flow carries QUIC. */
        FIRST,
        /** Its datagrams go to the QUIC server: the ClientHello is read, or the connection intercepted. */
        QUIC,
        /** Its datagrams go to the target, as any flow's do. */
        RELAYED
    }

    /** One CONNECT-UDP flow, as the flows see it: the origin of its client's QUIC. */
    final class Inner implements QuicFlows.Origin {
        final InetSocketAddress address;
        final UdpFlow flow;
        private final Function<InetSocketAddress, ClientConnection> connections;
        private volatile Mode mode = Mode.FIRST;
        /** The client connection that decided to relay the flow, told once when it ends; null for none. */
        private final AtomicReference<ClientConnection> relayedBy = new AtomicReference<>();
        /** Closes the intercepted connection; null while there is none. */
        private volatile Runnable closeIntercepted;
        private volatile boolean ended;

        Inner(InetSocketAddress address, UdpFlow flow, Function<InetSocketAddress, ClientConnection> connections) {
            this.address = address;
            this.flow = flow;
            this.connections = connections;
        }

        /**
         * A UDP payload from the client: true when it went to the QUIC server, false when the flow
         * sends it to the target. The first payload decides whether the flow carries QUIC: a QUIC
         * Initial (of a version the proxy reads) does.
         */
        boolean fromClient(byte[] payload) {
            Mode m = mode;
            if (m == Mode.RELAYED || ended) return false;
            ByteBuffer datagram = ByteBuffer.wrap(payload);
            if (m == Mode.FIRST) {
                if (!QuicFlows.isInitial(datagram)) {
                    mode = Mode.RELAYED;
                    return false;
                }
                mode = Mode.QUIC;
            }
            quic.receive(address, datagram);
            return true;
        }

        /** The flow ended: its QUIC connection closes, and the client connection that relayed it is told. */
        void ended() {
            ended = true;
            byAddress.remove(address);
            flows.forget(this);
            Runnable close = closeIntercepted;
            if (close != null) close.run();
            ClientConnection c = relayedBy.getAndSet(null);
            if (c != null) c.endTransparentQuic(true);
        }

        // QuicFlows.Origin

        @Override
        public HostAndPort destination(ClientHello hello) {
            return new HostAndPort(flow.host(), flow.port());
        }

        @Override
        public InetSocketAddress address(HostAndPort destination) {
            return flow.targetAddress();
        }

        @Override
        public ClientConnection connection(InetSocketAddress client) {
            return connections.apply(flow.targetAddress());
        }

        @Override
        public boolean masque() {
            return true;
        }

        @Override
        public boolean relay(ClientConnection connection, List<ByteBuffer> held) {
            mode = Mode.RELAYED;
            relayedBy.set(connection);
            for (ByteBuffer datagram : held) takeRelayed(datagram);
            if (ended) {
                ClientConnection c = relayedBy.getAndSet(null);
                if (c != null) c.endTransparentQuic(true);
            }
            return true;
        }

        @Override
        public boolean takeRelayed(ByteBuffer datagram) {
            if (mode != Mode.RELAYED) return false;
            byte[] payload = new byte[datagram.remaining()];
            datagram.duplicate().get(payload);
            flow.toTargetFromProxy(payload);
            return true;
        }

        @Override
        public void intercepted(Runnable close) {
            closeIntercepted = close;
            if (ended) close.run();
        }

        @Override
        public String toString() {
            return "CONNECT-UDP flow to " + flow.host() + ":" + flow.port() + " as " + address;
        }
    }
}
