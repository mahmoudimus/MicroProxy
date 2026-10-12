/*
 * Ported from quinn-proto src/connection/datagrams.rs (DatagramState, DatagramBuffer) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.VarInt;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;

/**
 * The unreliable datagrams (RFC 9221) of a connection: received ones waiting for the application,
 * and queued ones waiting for a packet. Both queues are bounded in bytes; the oldest datagrams are
 * dropped to make room.
 */
final class DatagramState {

    /** The DATAGRAM frame overhead bound: type and a length of up to 8 bytes. */
    static final int SIZE_BOUND = 1 + 8;
    /** Accounting overhead per queued datagram, standing in for quinn's {@code size_of::<Datagram>()}. */
    private static final int OVERHEAD = 32;

    private final ArrayDeque<ByteBuffer> incoming = new ArrayDeque<>();
    private final ArrayDeque<ByteBuffer> outgoing = new ArrayDeque<>();
    private long incomingBytes;
    private long outgoingBytes;

    /**
     * Stores a received datagram.
     *
     * @return true if the queue was empty, so the application should be told
     * @throws QuicException {@code PROTOCOL_VIOLATION} if datagrams are refused or it is oversized
     */
    boolean received(ByteBuffer data, int window) throws QuicException {
        if (window <= 0) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "unexpected DATAGRAM frame");
        }
        int size = data.remaining() + OVERHEAD;
        if (size > window) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "oversized datagram");
        }
        boolean wasEmpty = incoming.isEmpty();
        while (incomingBytes + size > window) {
            recv(); // drop the stalest
        }
        // Copy: the frame is a view into the packet buffer
        ByteBuffer copy = ByteBuffer.allocate(data.remaining()).put(data.duplicate()).flip();
        incoming.addLast(copy);
        incomingBytes += size;
        return wasEmpty;
    }

    ByteBuffer recv() {
        ByteBuffer d = incoming.pollFirst();
        if (d != null) {
            incomingBytes -= d.remaining() + OVERHEAD;
        }
        return d;
    }

    /** Queues a datagram, dropping the oldest unsent ones to make room. */
    void send(ByteBuffer data, int bufferSize) {
        int size = data.remaining() + OVERHEAD;
        while (!outgoing.isEmpty() && outgoingBytes + size > bufferSize) {
            ByteBuffer dropped = outgoing.pollFirst();
            outgoingBytes -= dropped.remaining() + OVERHEAD;
        }
        outgoing.addLast(data);
        outgoingBytes += size;
    }

    boolean hasOutgoing() {
        return !outgoing.isEmpty();
    }

    /** Whether the next datagram fits a frame of {@code maxFrame} bytes. */
    boolean canSend(int maxFrame) {
        ByteBuffer d = outgoing.peekFirst();
        return d != null && d.remaining() + 1 + VarInt.size(d.remaining()) <= maxFrame;
    }

    /**
     * Writes the next datagram as a DATAGRAM frame if it fits below {@code limit}.
     *
     * @return true if a frame was written
     */
    boolean write(ByteBuffer out, int limit) {
        ByteBuffer d = outgoing.peekFirst();
        if (d == null) {
            return false;
        }
        int len = d.remaining();
        int frameLength = 1 + VarInt.size(len) + len;
        if (out.position() + frameLength > limit) {
            return false;
        }
        outgoing.pollFirst();
        outgoingBytes -= len + OVERHEAD;
        out.put((byte) 0x31);
        VarInt.write(out, len);
        out.put(d);
        return true;
    }

    /** Drops queued datagrams larger than {@code maxPayload}, after the path MTU shrank. */
    void dropOversized(int maxPayload) {
        outgoing.removeIf(d -> {
            if (d.remaining() > maxPayload) {
                outgoingBytes -= d.remaining() + OVERHEAD;
                return true;
            }
            return false;
        });
    }
}
