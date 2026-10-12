package org.microproxy;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link MasqueBridge} for a CONNECT-UDP flow over HTTP/2: a UDP socket on loopback whose datagrams
 * go to the flow's target in DATAGRAM capsules on the stream, and whose target's datagrams, read
 * from the stream's capsules, go back to the local client. A {@code QuicClient} connecting to
 * {@link #address()} so runs its QUIC inside the flow. {@link #moveTo} carries the client's
 * datagrams over to another flow to the same target.
 */
public final class H2MasqueBridge implements AutoCloseable {

    private volatile H2StreamClient.Stream flow;
    private final DatagramSocket socket;
    private volatile SocketAddress peer;
    /** The datagrams for the client that came back through each flow. */
    private final Map<H2StreamClient.Stream, AtomicLong> received = new ConcurrentHashMap<>();

    public H2MasqueBridge(H2StreamClient.Stream flow) throws IOException {
        this.flow = flow;
        this.socket = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, 0));
        Thread.ofVirtual().name("h2-masque-bridge-out").start(this::out);
        listen(flow);
    }

    private void listen(H2StreamClient.Stream s) {
        Thread.ofVirtual().name("h2-masque-bridge-capsules").start(() -> capsules(s));
    }

    /**
     * Sends the client's datagrams through another flow from now on; what still comes back through
     * the old one goes to the client too, until that flow ends.
     *
     * @return the flow left
     */
    public H2StreamClient.Stream moveTo(H2StreamClient.Stream next) {
        H2StreamClient.Stream old = flow;
        listen(next);
        flow = next;
        return old;
    }

    /** How many datagrams for the client came back through {@code s}. */
    public long receivedThrough(H2StreamClient.Stream s) {
        AtomicLong n = received.get(s);
        return n == null ? 0 : n.get();
    }

    public InetSocketAddress address() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    private void out() {
        byte[] buf = new byte[65535];
        while (!socket.isClosed()) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(p);
                peer = p.getSocketAddress();
                flow.sendDatagramCapsule(Arrays.copyOf(p.getData(), p.getLength()));
            } catch (IOException e) {
                if (socket.isClosed()) return;
                // the flow ended: datagrams wait for the next one, as UDP would lose them
            }
        }
    }

    private void capsules(H2StreamClient.Stream s) {
        try {
            for (byte[] payload; (payload = s.readDatagram()) != null; ) {
                SocketAddress to = peer;
                if (to == null) continue;
                received.computeIfAbsent(s, k -> new AtomicLong()).incrementAndGet();
                socket.send(new DatagramPacket(payload, payload.length, to));
            }
        } catch (IOException e) {
            // the stream ended
        }
    }

    @Override
    public void close() {
        socket.close();
    }
}
