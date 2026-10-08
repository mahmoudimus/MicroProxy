package org.microproxy.dns;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;

/** UDP with TCP fallback. Each query uses a fresh socket and thus a random source port. */
final class UdpDnsTransport implements DnsTransport {
    private final List<InetSocketAddress> servers;
    private final int timeoutMillis;

    UdpDnsTransport(List<InetSocketAddress> servers, int timeoutMillis) {
        if (servers.isEmpty()) throw new IllegalArgumentException("no DNS servers");
        this.servers = servers;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public byte[] exchange(byte[] query) throws IOException {
        IOException last = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            for (InetSocketAddress server : servers) {
                try {
                    byte[] response = udp(server, query);
                    if (response.length > 2 && (response[2] & 0x02) != 0) {
                        return tcp(server, query);
                    }
                    return response;
                } catch (IOException e) {
                    last = e;
                }
            }
        }
        throw last;
    }

    private byte[] udp(InetSocketAddress server, byte[] query) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(server);
            socket.setSoTimeout(timeoutMillis);
            socket.send(new DatagramPacket(query, query.length));
            long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
            byte[] buf = new byte[65535];
            while (true) {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);
                // Ignore datagrams that do not answer this query (spoofing / stale replies).
                if (packet.getLength() >= 12 && buf[0] == query[0] && buf[1] == query[1]) {
                    return java.util.Arrays.copyOf(buf, packet.getLength());
                }
                int remaining = (int) ((deadline - System.nanoTime()) / 1_000_000L);
                if (remaining <= 0) throw new SocketTimeoutException("no matching DNS response");
                socket.setSoTimeout(remaining);
            }
        }
    }

    private byte[] tcp(InetSocketAddress server, byte[] query) throws IOException {
        try (Socket socket = new Socket(Proxy.NO_PROXY)) {
            socket.connect(server, timeoutMillis);
            socket.setSoTimeout(timeoutMillis);
            OutputStream out = socket.getOutputStream();
            out.write(new byte[] {(byte) (query.length >> 8), (byte) query.length});
            out.write(query);
            out.flush();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            byte[] response = new byte[in.readUnsignedShort()];
            in.readFully(response);
            return response;
        }
    }
}
