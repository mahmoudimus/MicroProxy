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
 * to {@link #address()} so runs its QUIC inside the flow.
 */
public final class MasqueBridge implements AutoCloseable {

    /** What a DATAGRAM frame carries besides the payload: a quarter stream ID and a context ID. */
    private static final int OVERHEAD = 16;

    private final H3TestClient client;
    private final H3TestClient.Tunnel tunnel;
    private final DatagramSocket socket;
    private volatile SocketAddress peer;

    public MasqueBridge(H3TestClient client, H3TestClient.Tunnel tunnel) throws IOException {
        this.client = client;
        this.tunnel = tunnel;
        this.socket = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, 0));
        Thread.ofVirtual().name("masque-bridge-out").start(this::out);
        Thread.ofVirtual().name("masque-bridge-datagrams").start(this::datagrams);
        Thread.ofVirtual().name("masque-bridge-capsules").start(this::capsules);
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
                if (payload.length + OVERHEAD <= client.quic.maxDatagramSize()) {
                    tunnel.sendDatagram(payload);
                } else {
                    tunnel.sendDatagramCapsule(payload);
                }
            } catch (IOException e) {
                return;
            }
        }
    }

    private void datagrams() {
        try {
            while (!socket.isClosed()) {
                byte[] content = tunnel.receiveDatagram(Duration.ofMillis(200));
                if (content != null) back(H3TestClient.udpPayload(content));
            }
        } catch (IOException e) {
            // closed
        }
    }

    private void capsules() {
        try {
            for (H3TestClient.Capsule c; (c = tunnel.readCapsule()) != null; ) {
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
