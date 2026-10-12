package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.frame.Frame;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ActivityTracker;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.FullFlowContext;
import org.microproxy.HostResolver;
import org.microproxy.Http3Options;
import org.microproxy.HttpFiltersAdapter;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TlsHellos;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * The transparent QUIC listener datagram by datagram: what it relays and how (both ways, by the
 * connection IDs it learns, from the listener's own socket), and its bounds on new clients, held
 * bytes and relayed flows, against a fake server that only counts and echoes datagrams.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TransparentQuicListenerTest {

    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
    private static final ConnectionId CLIENT_ID = ConnectionId.of(new byte[] {1, 2, 3, 4});
    private static final HostResolver TEST_HOSTS = (host, port) -> {
        if (host.endsWith(".test")) return new InetSocketAddress(LOOPBACK, port);
        throw new UnknownHostException(host);
    };

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> events = new CopyOnWriteArrayList<>();
    private DefaultHttpProxyServer proxy;
    private DatagramSocket server;
    private int dcids;

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /** A transparent proxy relaying every flow (no MITM manager) to {@link #server}, recording tracker events. */
    private HttpProxyServerBootstrap relaying(Http3Options options) throws IOException {
        server = socket(LOOPBACK);
        return MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(server.getLocalPort())
                .withTransparentQuicPort(0)
                .withServerResolver(TEST_HOSTS)
                .withHttp3Options(options)
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void clientConnected(FlowContext flow) {
                        events.add("connected quic=" + flow.isTransparentQuic());
                    }

                    @Override
                    public void transparentQuicFlowDecided(FlowContext flow, ClientHello hello, boolean intercepted,
                            String reason) {
                        events.add("decided " + hello.sni() + " " + intercepted + " " + reason);
                    }

                    @Override
                    public void serverConnected(FullFlowContext flow, InetSocketAddress address) {
                        events.add("server " + flow.getServerHostAndPort());
                    }

                    @Override
                    public void serverDisconnected(FullFlowContext flow, InetSocketAddress address) {
                        events.add("server closed");
                    }

                    @Override
                    public void clientDisconnected(FlowContext flow, javax.net.ssl.SSLSession session) {
                        events.add("disconnected");
                    }

                    @Override
                    public void connectionExceptionCaught(FlowContext flow, Throwable cause) {
                        events.add("exception " + cause.getClass().getSimpleName());
                    }
                });
    }

    private void start(HttpProxyServerBootstrap b) {
        proxy = (DefaultHttpProxyServer) b.start();
    }

    private TransparentQuicListener listener() {
        return proxy.transparentQuicListener();
    }

    private InetSocketAddress quicAddress() {
        return new InetSocketAddress(LOOPBACK, proxy.getTransparentQuicAddress().getPort());
    }

    private DatagramSocket socket(InetAddress address) throws IOException {
        DatagramSocket s = new DatagramSocket(0, address);
        s.setSoTimeout(5000);
        closeables.add(s);
        return s;
    }

    private static void send(DatagramSocket from, ByteBuffer datagram, InetSocketAddress to) throws IOException {
        byte[] b = bytes(datagram);
        from.send(new DatagramPacket(b, b.length, to));
    }

    private static byte[] bytes(ByteBuffer datagram) {
        byte[] b = new byte[datagram.remaining()];
        datagram.duplicate().get(b);
        return b;
    }

    private static DatagramPacket receive(DatagramSocket s) throws IOException {
        DatagramPacket p = new DatagramPacket(new byte[2048], 2048);
        s.receive(p);
        return p;
    }

    /** Whether {@code s} receives nothing for a while. */
    private static boolean quiet(DatagramSocket s) throws IOException {
        s.setSoTimeout(500);
        try {
            s.receive(new DatagramPacket(new byte[2048], 2048));
            return false;
        } catch (SocketTimeoutException expected) {
            return true;
        } finally {
            s.setSoTimeout(5000);
        }
    }

    private ConnectionId nextDcid() {
        byte[] id = new byte[8];
        Arrays.fill(id, (byte) ++dcids);
        return ConnectionId.of(id);
    }

    /** A client's first Initial carrying a whole ClientHello for {@code sni} offering {@code alpn}. */
    private ByteBuffer hello(ConnectionId dcid, String sni, String alpn) {
        byte[] message = TlsHellos.build(sni == null ? List.of() : List.of(sni), List.of(alpn), 0x0304);
        return QuicClientHelloTest.initial(QuicVersion.V1, dcid, CLIENT_ID, 0,
                List.of(new Frame.Crypto(0, ByteBuffer.wrap(message))));
    }

    /** A client's first Initial carrying only the start of a large ClientHello: the flow stays pending. */
    private ByteBuffer partialHello(ConnectionId dcid) {
        byte[] message = QuicClientHelloTest.large("pending.test", 4000);
        return QuicClientHelloTest.initial(QuicVersion.V1, dcid, CLIENT_ID, 0,
                List.of(new Frame.Crypto(0, ByteBuffer.wrap(message, 0, 1000))));
    }

    /** A server's long header packet choosing {@code serverId}, as a server's Initial would. */
    private static byte[] serverLongHeader(ConnectionId serverId) {
        ByteBuffer b = ByteBuffer.allocate(1200);
        b.put((byte) 0xc0).putInt(1).put((byte) CLIENT_ID.length()).put(CLIENT_ID.toByteArray())
                .put((byte) serverId.length()).put(serverId.toByteArray());
        new Random(1).ints(b.remaining(), 0, 256).forEach(i -> b.put((byte) i));
        return b.array();
    }

    /** A client's short header packet for {@code serverId}. */
    private static ByteBuffer shortHeader(ConnectionId serverId, int marker) {
        ByteBuffer b = ByteBuffer.allocate(100);
        b.put((byte) 0x41).put(serverId.toByteArray()).put((byte) marker);
        while (b.hasRemaining()) b.put((byte) 7);
        return b.flip();
    }

    @Test
    void relaysBothWaysFromTheListenersSocketAndFollowsTheServersConnectionIds() throws Exception {
        start(relaying(Http3Options.builder().transparentRelayIdleTimeout(Duration.ofSeconds(1)).build()));
        DatagramSocket client = socket(LOOPBACK);
        ByteBuffer first = hello(nextDcid(), "relay.test", "h3");
        send(client, first, quicAddress());

        // The server gets the client's datagram as it was sent.
        DatagramPacket atServer = receive(server);
        assertArrayEquals(bytes(first), Arrays.copyOf(atServer.getData(), atServer.getLength()));
        InetSocketAddress relaySocket = (InetSocketAddress) atServer.getSocketAddress();

        // Its answer reaches the client from the listener's own address.
        ConnectionId serverId = ConnectionId.of(new byte[] {9, 9, 9, 9, 9, 9, 9, 9});
        byte[] answer = serverLongHeader(serverId);
        server.send(new DatagramPacket(answer, answer.length, relaySocket));
        DatagramPacket atClient = receive(client);
        assertArrayEquals(answer, Arrays.copyOf(atClient.getData(), atClient.getLength()));
        assertEquals(quicAddress().getPort(), atClient.getPort());

        // Short header packets for the server's connection ID follow the flow, and so do packets
        // for IDs the proxy could not see and of versions it cannot read.
        send(client, shortHeader(serverId, 1), quicAddress());
        assertEquals(1, receive(server).getData()[1 + serverId.length()]);
        send(client, shortHeader(ConnectionId.of(new byte[] {5, 5, 5, 5, 5, 5, 5, 5}), 2), quicAddress());
        assertEquals(2, receive(server).getData()[9]);
        ByteBuffer unknownVersion = ByteBuffer.allocate(1200).put((byte) 0xc0).putInt(0x1a2a3a4a).put((byte) 0)
                .put((byte) 0).flip().limit(1200);
        send(client, unknownVersion, quicAddress());
        DatagramPacket version = receive(server);
        assertEquals(0x1a2a3a4a, ByteBuffer.wrap(version.getData(), 1, 4).getInt());
        assertEquals(1, listener().relayedFlows());
        assertEquals(0, listener().pendingFlows());
        assertEquals(0, listener().heldBytes());

        // Idle, the flow ends, and the server hears no more of the client.
        eventually("the idle relay to close", () -> listener().relayedFlows() == 0);
        send(client, shortHeader(serverId, 3), quicAddress());
        assertTrue(quiet(server));
        eventually("the flow's end reported", () -> events.contains("disconnected"));
        assertEquals(List.of("connected quic=true", "decided relay.test false no MITM manager",
                "server relay.test:" + server.getLocalPort(), "server closed", "disconnected"), events);
    }

    @Test
    void boundsNewClientsPerSourceAndInTotal() throws Exception {
        start(relaying(Http3Options.builder().transparentMaxPending(6, 4)
                .transparentPendingTimeout(Duration.ofSeconds(3)).build()));
        DatagramSocket one = socket(LOOPBACK);
        DatagramSocket two = socket(InetAddress.getByName("127.0.0.2"));
        DatagramSocket three = socket(InetAddress.getByName("127.0.0.3"));
        for (int i = 0; i < 6; i++) send(one, partialHello(nextDcid()), quicAddress());
        eventually("four pending from one address", () -> listener().droppedDatagrams() == 2);
        assertEquals(4, listener().pendingFlows());
        for (int i = 0; i < 6; i++) send(two, partialHello(nextDcid()), quicAddress());
        eventually("six pending in all", () -> listener().droppedDatagrams() == 6);
        assertEquals(6, listener().pendingFlows());
        send(three, partialHello(nextDcid()), quicAddress());
        eventually("none more", () -> listener().droppedDatagrams() == 7);
        assertEquals(6, listener().pendingFlows());
        assertTrue(listener().heldBytes() >= 6 * 1200);

        // They never complete: forgotten after the pending timeout, with what they held.
        eventually("the pending flows to time out", () -> listener().pendingFlows() == 0);
        assertEquals(0, listener().heldBytes());
        assertTrue(quiet(server), "nothing was relayed");
        send(three, hello(nextDcid(), "relay.test", "h3"), quicAddress());
        receive(server);
    }

    @Test
    void boundsTheBytesHeldForNewClients() throws Exception {
        start(relaying(Http3Options.builder().transparentMaxPending(1000, 1000).transparentMaxBufferedBytes(65_536).build()));
        DatagramSocket client = socket(LOOPBACK);
        for (int i = 0; i < 80; i++) send(client, partialHello(nextDcid()), quicAddress());
        eventually("every Initial handled", () -> listener().pendingFlows() + listener().droppedDatagrams() == 80);
        assertTrue(listener().heldBytes() <= 65_536, "held " + listener().heldBytes());
        assertEquals(65_536 / 1200, listener().pendingFlows());
    }

    @Test
    void boundsRelayedFlowsPerSourceAndInTotal() throws Exception {
        start(relaying(Http3Options.builder().transparentMaxRelayFlows(2, 1).build()));
        DatagramSocket one = socket(LOOPBACK);
        DatagramSocket two = socket(InetAddress.getByName("127.0.0.2"));
        DatagramSocket three = socket(InetAddress.getByName("127.0.0.3"));
        send(one, hello(nextDcid(), "relay.test", "h3"), quicAddress());
        receive(server);
        send(one, hello(nextDcid(), "relay.test", "h3"), quicAddress());
        assertTrue(quiet(server), "a second flow of the same address is past its bound");
        send(two, hello(nextDcid(), "relay.test", "h3"), quicAddress());
        receive(server);
        send(three, hello(nextDcid(), "relay.test", "h3"), quicAddress());
        assertTrue(quiet(server), "a third flow is past the total");
        assertEquals(2, listener().relayedFlows());
        assertEquals(0, listener().pendingFlows());
    }

    @Test
    void initialsThatCannotBeReadStartNoFlow() throws Exception {
        start(relaying(Http3Options.DEFAULT));
        DatagramSocket client = socket(LOOPBACK);
        ByteBuffer forged = hello(nextDcid(), "relay.test", "h3");
        forged.put(forged.limit() - 1, (byte) (forged.get(forged.limit() - 1) ^ 1));
        send(client, forged, quicAddress());
        eventually("the forged Initial dropped", () -> listener().droppedDatagrams() == 1);
        // A cut one is no QUIC packet at all: the QUIC server drops it.
        ByteBuffer cut = hello(nextDcid(), "relay.test", "h3");
        cut.limit(1000);
        send(client, cut, quicAddress());
        assertEquals(0, listener().pendingFlows());
        assertTrue(quiet(server));
    }

    @Test
    void unknownVersionsOfNewClientsGetVersionNegotiation() throws Exception {
        start(relaying(Http3Options.DEFAULT));
        DatagramSocket client = socket(LOOPBACK);
        ByteBuffer unknown = ByteBuffer.allocate(1200).put((byte) 0xc0).putInt(0x1a2a3a4a).put((byte) 8)
                .put(nextDcid().toByteArray()).put((byte) 4).put(CLIENT_ID.toByteArray()).flip().limit(1200);
        send(client, unknown, quicAddress());
        DatagramPacket vn = receive(client);
        ByteBuffer b = ByteBuffer.wrap(vn.getData(), 0, vn.getLength());
        assertEquals(0x80, b.get() & 0x80);
        assertEquals(0, b.getInt(), "Version Negotiation");
        b.position(b.position() + 1 + (b.get(b.position()) & 0xff));
        b.position(b.position() + 1 + (b.get(b.position()) & 0xff));
        List<Integer> versions = new ArrayList<>();
        while (b.hasRemaining()) versions.add(b.getInt());
        assertTrue(versions.contains(1), versions.toString());
        assertTrue(quiet(server));
    }

    @Test
    void aFilterAnsweringTheMadeUpConnectDropsTheFlow() throws Exception {
        start(relaying(Http3Options.DEFAULT).withFiltersSource((request, flow) -> new HttpFiltersAdapter(request, flow) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                return ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.FORBIDDEN, "blocked");
            }
        }));
        DatagramSocket client = socket(LOOPBACK);
        send(client, hello(nextDcid(), "blocked.test", "h3"), quicAddress());
        eventually("the decision", () -> events.stream().anyMatch(e -> e.startsWith("decided")));
        assertTrue(events.contains("decided blocked.test false a filter answered its CONNECT"), events.toString());
        assertTrue(quiet(server));
        assertEquals(0, listener().relayedFlows());
        eventually("the flow's end reported", () -> events.contains("disconnected"));
    }

    @Test
    void aClientHelloWithoutSniCannotBeRouted() throws Exception {
        start(relaying(Http3Options.DEFAULT));
        DatagramSocket client = socket(LOOPBACK);
        send(client, hello(nextDcid(), null, "h3"), quicAddress());
        eventually("the failure reported", () -> events.contains("exception ProtocolException"));
        assertTrue(quiet(server));
        assertEquals(0, listener().pendingFlows());
        assertNull(events.stream().filter(e -> e.startsWith("decided")).findFirst().orElse(null));
        assertFalse(events.contains("connected quic=true"));
    }
}
