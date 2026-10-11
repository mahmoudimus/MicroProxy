package org.microproxy;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.Arrays;

/**
 * A UDP socket on loopback whose datagrams go through a CONNECT-UDP tunnel, as a MASQUE client's
 * operating system would send them: what a local client sends to {@link #address()} goes to the
 * tunnel's target as a UDP payload (in a QUIC DATAGRAM frame when it fits, else in a DATAGRAM
 * capsule), and what comes back, either way, goes to that client. A {@code QuicClient} connecting
 * to {@link #address()} so runs its QUIC inside the flow. {@link #moveTo} carries the client's
 * datagrams over to another flow to the same target, as a MASQUE client whose own connection to the
 * proxy changed would.
 */
public final class MasqueBridge implements AutoCloseable {

    /** What a DATAGRAM frame carries besides the payload: a quarter stream ID and a context ID. */
    private static final int OVERHEAD = 16;

    private volatile H3TestClient client;
    private volatile H3TestClient.Tunnel tunnel;
    private final DatagramSocket socket;
    private volatile SocketAddress peer;

    public MasqueBridge(H3TestClient client, H3TestClient.Tunnel tunnel) throws IOException {
        this.client = client;
        this.tunnel = tunnel;
        this.socket = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, 0));
        Thread.ofVirtual().name("masque-bridge-out").start(this::out);
        listen(tunnel);
    }

    private void listen(H3TestClient.Tunnel t) {
        Thread.ofVirtual().name("masque-bridge-datagrams").start(() -> datagrams(t));
        Thread.ofVirtual().name("masque-bridge-capsules").start(() -> capsules(t));
    }

    /**
     * Sends the client's datagrams through another flow from now on; what still comes back through
     * the old one goes to the client too, until that flow ends.
     *
     * @return the flow left
     */
    public H3TestClient.Tunnel moveTo(H3TestClient next, H3TestClient.Tunnel nextTunnel) {
        H3TestClient.Tunnel old = tunnel;
        listen(nextTunnel);
        client = next;
        tunnel = nextTunnel;
        return old;
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
                byte[] payload = Arrays.copyOf(p.getData(), p.getLength());
                H3TestClient.Tunnel t = tunnel;
                if (payload.length + OVERHEAD <= client.quic.maxDatagramSize()) {
                    t.sendDatagram(payload);
                } else {
                    t.sendDatagramCapsule(payload);
                }
            } catch (IOException e) {
                return;
            }
        }
    }

    private void datagrams(H3TestClient.Tunnel t) {
        try {
            while (!socket.isClosed()) {
                byte[] content = t.receiveDatagram(Duration.ofMillis(200));
                if (content != null) back(H3TestClient.udpPayload(content));
            }
        } catch (IOException e) {
            // closed
        }
    }

    private void capsules(H3TestClient.Tunnel t) {
        try {
            for (H3TestClient.Capsule c; (c = t.readCapsule()) != null; ) {
                if (c.type() == 0) back(H3TestClient.udpPayload(c.value()));
            }
        } catch (IOException e) {
            // the stream ended
        }
    }

    private void back(byte[] payload) throws IOException {
        SocketAddress to = peer;
        if (payload == null || to == null) return;
        socket.send(new DatagramPacket(payload, payload.length, to));
    }

    @Override
    public void close() {
        socket.close();
    }
}
