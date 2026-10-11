package org.microproxy;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A UDP relay for tests: datagrams from clients go on to a target at once, and the target's
 * answers come back after a fixed delay, in order. It makes a QUIC handshake take at least that
 * long, so that a client's 0-RTT data surely goes out before the handshake completes. Each client
 * address gets a socket of its own toward the target.
 */
final class UdpDelayRelay implements AutoCloseable {

    private final DatagramSocket front;
    private final InetSocketAddress target;
    private final long delayNanos;
    private final Map<SocketAddress, DatagramSocket> backs = new ConcurrentHashMap<>();
    private volatile boolean closed;

    /** A relay on {@code port} (0 for any) of the loopback interface. */
    UdpDelayRelay(int port, InetSocketAddress target, long delayMillis) throws IOException {
        this.front = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, port));
        this.target = target;
        this.delayNanos = delayMillis * 1_000_000L;
        Thread.ofVirtual().name("udp-relay-front").start(this::fromClients);
    }

    int port() {
        return front.getLocalPort();
    }

    InetSocketAddress address() {
        return new InetSocketAddress(TestSupport.LOOPBACK, port());
    }

    private void fromClients() {
        byte[] buf = new byte[65536];
        while (!closed) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                front.receive(p);
                SocketAddress client = p.getSocketAddress();
                DatagramSocket back = backs.computeIfAbsent(client, this::open);
                back.send(new DatagramPacket(Arrays.copyOf(p.getData(), p.getLength()), p.getLength(), target));
            } catch (IOException | RuntimeException e) {
                if (closed) return;
            }
        }
    }

    private DatagramSocket open(SocketAddress client) {
        try {
            DatagramSocket back = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, 0));
            LinkedBlockingQueue<Delayed> queue = new LinkedBlockingQueue<>();
            Thread.ofVirtual().name("udp-relay-back").start(() -> fromTarget(back, queue));
            Thread.ofVirtual().name("udp-relay-delay").start(() -> toClient(queue, client));
            return back;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Delayed(long due, byte[] datagram) {}

    /** The target's datagrams for one client, stamped with when they may go on. */
    private void fromTarget(DatagramSocket back, LinkedBlockingQueue<Delayed> queue) {
        byte[] buf = new byte[65536];
        while (!closed) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                back.receive(p);
                queue.add(new Delayed(System.nanoTime() + delayNanos, Arrays.copyOf(p.getData(), p.getLength())));
            } catch (IOException e) {
                if (closed) return;
            }
        }
    }

    /** Sends each datagram once its delay has passed, in order. */
    private void toClient(LinkedBlockingQueue<Delayed> queue, SocketAddress client) {
        try {
            while (!closed) {
                Delayed d = queue.poll(100, TimeUnit.MILLISECONDS);
                if (d == null) continue;
                long wait;
                while ((wait = d.due() - System.nanoTime()) > 0) {
                    Thread.sleep(wait / 1_000_000L, (int) (wait % 1_000_000L));
                }
                front.send(new DatagramPacket(d.datagram(), d.datagram().length, client));
            }
        } catch (IOException e) {
            // closed
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        closed = true;
        front.close();
        backs.values().forEach(DatagramSocket::close);
    }
}
