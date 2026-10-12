package org.microproxy.impl;

import io.github.mahmoudimus.http3.QuicVarInt;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.FlowContext;
import org.microproxy.udp.UdpContext;
import org.microproxy.udp.UdpInterceptor;
import org.microproxy.udp.UdpMessage;

/**
 * One CONNECT-UDP flow (MASQUE, RFC 9298): the UDP payloads a client sends in HTTP Datagrams
 * (RFC 9297), with context ID 0, go to the target from a UDP socket of the flow's own, connected
 * to it, and the target's datagrams go back to the client the same way. The client's datagrams
 * arrive in QUIC DATAGRAM frames, which the connection hands over ({@link #fromClient}), or in
 * DATAGRAM capsules on the request stream, which {@link #run} reads; unknown capsules are skipped,
 * and payloads with another context ID dropped.
 *
 * <p>Each direction has a queue of bounded length and size, from which a thread of its own sends:
 * a datagram that finds its queue full is dropped, as a network drops what it cannot carry, so a
 * client that does not read its stream (where datagrams go as capsules) or a target that does not
 * keep up holds up neither the other direction nor the connection. The {@link UdpInterceptor}
 * runs on those threads. The flow ends when the client ends or resets its stream, when nothing
 * has moved either way for the idle timeout, or when its socket fails.
 *
 * <p>Threads: the stream's (capsules, {@link #run}), one receiving from the target, one sending to
 * the target, one sending to the client. No {@code synchronized}: each queue has a lock and a
 * condition.
 */
final class UdpFlow implements UdpContext {

    private static final System.Logger LOG = System.getLogger(UdpFlow.class.getName());

    /** The largest UDP payload over IPv4 and IPv6 (65535 minus the IP and UDP headers). */
    static final int MAX_PAYLOAD = 65527;
    /** The capsule type of HTTP Datagrams on the stream (RFC 9297 section 3.5). */
    static final long DATAGRAM_CAPSULE = 0x00;

    /** The client side of a flow: its request stream, and its connection's datagrams. */
    interface Client {
        /** The stream's bytes after the response head: capsules (RFC 9297 section 3.2). */
        InputStream capsules();

        /** Sets how long a read of {@link #capsules} waits, in ms. */
        void setReadTimeout(int millis);

        /**
         * Sends an HTTP Datagram of the stream with {@code content} (a context ID, then the
         * payload): in a QUIC DATAGRAM frame when the client accepts them and it fits, else in a
         * DATAGRAM capsule on the stream, which waits for flow control.
         */
        void sendDatagram(byte[] content) throws IOException;

        /** Ends the stream: with its FIN when {@code clean}, else by resetting it. */
        void endFlow(boolean clean);

        /**
         * Routes the stream's HTTP Datagrams to {@code flow}; false if the client connection may
         * have no more flows.
         */
        boolean attach(UdpFlow flow);

        /** The flow ended: its datagrams go nowhere from now on. */
        void detach(UdpFlow flow);
    }

    /** A datagram waiting to be sent, and whether it was {@linkplain #send injected} (hooks skip it). */
    private record Item(byte[] data, boolean injected, Instant received) {}

    /** One direction's datagrams waiting to be sent: bounded, dropping what does not fit. */
    private static final class Queue {
        private final ReentrantLock lock = new ReentrantLock();
        private final Condition notEmpty = lock.newCondition();
        private final ArrayDeque<Item> items = new ArrayDeque<>();
        private final int maxItems;
        private final long maxBytes;
        private long bytes;
        private boolean closed;
        final AtomicLong dropped = new AtomicLong();

        Queue(int maxItems, long maxBytes) {
            this.maxItems = maxItems;
            this.maxBytes = maxBytes;
        }

        /** Queues {@code item}, or drops it (false) when the queue is full or closed. */
        boolean offer(Item item) {
            lock.lock();
            try {
                if (closed || items.size() >= maxItems || bytes + item.data().length > maxBytes) {
                    dropped.incrementAndGet();
                    return false;
                }
                items.addLast(item);
                bytes += item.data().length;
                notEmpty.signal();
                return true;
            } finally {
                lock.unlock();
            }
        }

        /** The next item, waiting for one; null once the queue is closed. */
        Item take() throws InterruptedException {
            lock.lock();
            try {
                while (items.isEmpty() && !closed) notEmpty.await();
                if (closed) return null;
                Item item = items.pollFirst();
                bytes -= item.data().length;
                return item;
            } finally {
                lock.unlock();
            }
        }

        void close() {
            lock.lock();
            try {
                closed = true;
                items.clear();
                bytes = 0;
                notEmpty.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }

    /** The flow was idle for the idle timeout. */
    private static final class Idle extends IOException {
        Idle() {
            super("idle");
        }
    }

    private final Client client;
    private final DatagramChannel socket;
    private final HostAndPort target;
    private final InetSocketAddress targetAddress;
    private final ClientFlowContext flow;
    private final String logPrefix;
    private final UdpInterceptor hooks;
    private final long idleNanos;
    private final Queue toTarget;
    private final Queue toClient;
    private final AtomicLong lastActivity = new AtomicLong(System.nanoTime());
    private final AtomicBoolean ended = new AtomicBoolean();
    private final AtomicLong fromClient = new AtomicLong();
    private final AtomicLong fromTarget = new AtomicLong();
    private volatile boolean started;
    private Thread receiver;
    private Thread targetSender;
    private Thread clientSender;

    /**
     * @param socket a UDP socket connected to the target, which the flow closes when it ends
     * @param hooks the UDP hooks, or null for none
     */
    UdpFlow(Client client, DatagramChannel socket, HostAndPort target, InetSocketAddress targetAddress,
            ClientFlowContext flow, String logPrefix, UdpInterceptor hooks, Duration idleTimeout, int maxQueued,
            long maxQueuedBytes) {
        this.client = client;
        this.socket = socket;
        this.target = target;
        this.targetAddress = targetAddress;
        this.flow = flow;
        this.logPrefix = logPrefix;
        this.hooks = hooks;
        this.idleNanos = idleTimeout.toNanos();
        this.toTarget = new Queue(maxQueued, maxQueuedBytes);
        this.toClient = new Queue(maxQueued, maxQueuedBytes);
    }

    // ---------------------------------------------------------------------------------------
    // Running
    // ---------------------------------------------------------------------------------------

    /**
     * Relays the flow until it ends, reading the stream's capsules on the calling thread (the
     * stream's), and closes it.
     */
    void run(String name) {
        boolean clean = false;
        try {
            receiver = Thread.ofVirtual().name(name + "-from-target").start(this::receiveFromTarget);
            targetSender = Thread.ofVirtual().name(name + "-to-target").start(this::sendToTarget);
            clientSender = Thread.ofVirtual().name(name + "-to-client").start(this::sendToClient);
            started = true;
            if (hooks != null) {
                try {
                    hooks.udpStart(this);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, logPrefix + "udpStart threw", e);
                }
            }
            readCapsules();
            // The client ended its stream: the flow is over (RFC 9298 section 3).
            clean = true;
        } catch (Idle e) {
            LOG.log(Level.DEBUG, logPrefix + "UDP flow to " + target + " idle for " + Duration.ofNanos(idleNanos).toMillis()
                    + " ms; closing it");
            clean = true;
        } catch (IOException e) {
            if (!ended.get()) LOG.log(Level.DEBUG, logPrefix + "UDP flow to " + target + " ended: " + e);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "unexpected error in the UDP flow to " + target, e);
        } finally {
            end(clean);
            join(receiver);
            join(targetSender);
            join(clientSender);
        }
    }

    private static void join(Thread t) {
        if (t == null) return;
        try {
            t.join(java.time.Duration.ofSeconds(5));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Reads the stream's capsules until it ends: DATAGRAM capsules are the client's datagrams. */
    private void readCapsules() throws IOException {
        int idleMillis = (int) Math.min(Integer.MAX_VALUE, Duration.ofNanos(idleNanos).toMillis());
        client.setReadTimeout(Math.max(50, Math.min(1000, idleMillis / 4)));
        InputStream in = new IdleChecking(client.capsules());
        while (!ended.get()) {
            long type = QuicVarInt.read(in);
            if (type < 0) return;
            long length = QuicVarInt.read(in);
            if (length < 0) throw new EOFException("the stream ended inside a capsule");
            if (type != DATAGRAM_CAPSULE) {
                // Unknown capsules are skipped (RFC 9297 section 3.2), however long, without buffering.
                in.skipNBytes(length);
                continue;
            }
            if (length > MAX_PAYLOAD + QuicVarInt.MAX_LENGTH) {
                throw new IOException("a DATAGRAM capsule of " + length + " bytes, larger than any UDP payload");
            }
            byte[] content = in.readNBytes((int) length);
            if (content.length < length) throw new EOFException("the stream ended inside a capsule");
            fromClient(content);
        }
    }

    /** The capsules' bytes, failing with {@link Idle} once the flow has been idle for the idle timeout. */
    private final class IdleChecking extends InputStream {
        private final InputStream in;

        IdleChecking(InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            while (true) {
                try {
                    return in.read(b, off, len);
                } catch (SocketTimeoutException e) {
                    if (ended.get()) throw new EOFException("the flow ended");
                    if (System.nanoTime() - lastActivity.get() >= idleNanos) throw new Idle();
                }
            }
        }
    }

    /**
     * An HTTP Datagram of the client's (from a QUIC DATAGRAM frame or a DATAGRAM capsule): a
     * context ID, then, for context ID 0, a UDP payload, which is queued for the target. Other
     * contexts are dropped (RFC 9298 section 4).
     */
    void fromClient(byte[] content) {
        if (ended.get()) return;
        long context = QuicVarInt.read(content, 0, content.length);
        if (context != 0) return;
        lastActivity.set(System.nanoTime());
        fromClient.incrementAndGet();
        byte[] payload = Arrays.copyOfRange(content, 1, content.length);
        if (payload.length > MAX_PAYLOAD) return;
        toTarget.offer(new Item(payload, false, Instant.now()));
    }

    private void receiveFromTarget() {
        ByteBuffer buffer = ByteBuffer.allocate(MAX_PAYLOAD + 1);
        try {
            while (!ended.get()) {
                buffer.clear();
                int n;
                try {
                    n = socket.read(buffer);
                } catch (PortUnreachableException e) {
                    // An ICMP error for an earlier datagram: UDP goes on.
                    continue;
                }
                if (n < 0) return;
                lastActivity.set(System.nanoTime());
                fromTarget.incrementAndGet();
                toClient.offer(new Item(Arrays.copyOf(buffer.array(), n), false, Instant.now()));
            }
        } catch (ClosedChannelException e) {
            // the flow ended
        } catch (IOException e) {
            if (!ended.get()) {
                LOG.log(Level.DEBUG, logPrefix + "receiving from " + target + " failed: " + e);
                end(false);
            }
        }
    }

    private void sendToTarget() {
        try {
            for (Item item; (item = toTarget.take()) != null; ) {
                byte[] data = item.injected() ? item.data() : hook(item, true);
                if (data == null) continue;
                try {
                    socket.write(ByteBuffer.wrap(data));
                } catch (PortUnreachableException e) {
                    // An ICMP error for an earlier datagram: UDP goes on.
                }
            }
        } catch (ClosedChannelException e) {
            // the flow ended
        } catch (IOException e) {
            if (!ended.get()) {
                LOG.log(Level.DEBUG, logPrefix + "sending to " + target + " failed: " + e);
                end(false);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void sendToClient() {
        try {
            for (Item item; (item = toClient.take()) != null; ) {
                byte[] data = item.injected() ? item.data() : hook(item, false);
                if (data == null) continue;
                byte[] content = new byte[data.length + 1];
                System.arraycopy(data, 0, content, 1, data.length);
                client.sendDatagram(content);
            }
        } catch (IOException e) {
            if (!ended.get()) {
                LOG.log(Level.DEBUG, logPrefix + "sending to the client failed: " + e);
                end(false);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** What the hook makes of a datagram: the payload to send, or null to drop it. */
    private byte[] hook(Item item, boolean fromClient) {
        if (hooks == null) return item.data();
        UdpMessage message = new UdpMessage(item.data(), fromClient, item.received());
        try {
            return hooks.udpMessage(message, this);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "udpMessage threw; passing the datagram on", e);
            return item.data();
        }
    }

    /** Ends the flow, once: the queues and the socket close, the stream ends ({@code clean}) or is reset. */
    void end(boolean clean) {
        if (!ended.compareAndSet(false, true)) return;
        toTarget.close();
        toClient.close();
        try {
            socket.close();
        } catch (IOException e) {
            // closing anyway
        }
        client.endFlow(clean);
        long dropped = toTarget.dropped.get() + toClient.dropped.get();
        LOG.log(Level.DEBUG, logPrefix + "UDP flow to " + target + " ended: " + fromClient.get() + " datagrams from the client, "
                + fromTarget.get() + " from the target, " + dropped + " dropped");
        if (hooks != null && started) {
            try {
                hooks.udpEnd(this);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, logPrefix + "udpEnd threw", e);
            }
        }
    }

    /** Datagrams dropped so far, both ways, because a queue was full. */
    long dropped() {
        return toTarget.dropped.get() + toClient.dropped.get();
    }

    // ---------------------------------------------------------------------------------------
    // UdpContext
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
    public InetSocketAddress targetAddress() {
        return targetAddress;
    }

    @Override
    public FlowContext flowContext() {
        return flow;
    }

    @Override
    public void send(boolean fromClient, byte[] data) {
        Objects.requireNonNull(data, "data");
        if (ended.get()) throw new IllegalStateException("the UDP flow to " + target + " has ended");
        if (data.length > MAX_PAYLOAD) throw new IllegalArgumentException("a UDP payload of " + data.length + " bytes");
        (fromClient ? toTarget : toClient).offer(new Item(data.clone(), true, Instant.now()));
    }

    @Override
    public String toString() {
        return "UdpFlow[" + target + "]";
    }
}
