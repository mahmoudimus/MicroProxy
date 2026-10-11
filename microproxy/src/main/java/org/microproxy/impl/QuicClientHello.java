// Ported from mitmproxy (MIT License, see META-INF/LICENSE-mitmproxy.txt):
// mitmproxy/proxy/layers/quic/_client_hello_parser.py, quic_parse_client_hello_from_datagrams:
// the first packet must be an Initial, the ClientHello is read from the client's datagrams with
// the Initial keys of its Destination Connection ID, null means more datagrams are needed, and a
// packet that cannot be read makes the ClientHello invalid.
// Changes: instead of feeding the datagrams to a QUIC server connection whose TLS layer is patched
// to stop at the ClientHello, the Initial packets are decrypted here and their CRYPTO frames put
// together, in order or not, across packets and datagrams; QUIC version 2 (RFC 9369); bounds on
// the message size and on the datagrams read.
package org.microproxy.impl;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.frame.FrameException;
import io.github.mahmoudimus.quic.packet.Packet;
import io.github.mahmoudimus.quic.packet.PacketDecodeException;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import io.github.mahmoudimus.quic.packet.UnsupportedVersionException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.microproxy.ClientHello;

/**
 * Reads the TLS ClientHello a QUIC client sends in its first Initial packets, without a handshake:
 * the Initial keys follow from the Destination Connection ID of the client's first Initial (RFC
 * 9001 section 5.2, for QUIC version 1 and 2), so the proxy can decrypt them, put the CRYPTO frames
 * back together and parse the message, as {@link TlsClientHello} does for TLS over TCP.
 *
 * <p>A ClientHello may take several Initial packets, in several datagrams: post-quantum key shares
 * make browsers' larger than one, and their CRYPTO frames come out of order and mixed with PING and
 * PADDING. The message may be {@link TlsClientHello#MAX_MESSAGE_SIZE} long at most, and must be
 * complete within {@link #MAX_DATAGRAMS} datagrams.
 *
 * <p>Datagrams are copied before their protection is removed, so the caller keeps the originals to
 * relay or to hand to a QUIC server. Not thread-safe: one per pending client.
 */
final class QuicClientHello {

    /** The datagrams a ClientHello may span: a few for real ones. */
    static final int MAX_DATAGRAMS = 16;

    /** The largest CRYPTO stream offset read: the largest ClientHello and its handshake header. */
    private static final int MAX_CRYPTO = TlsClientHello.MAX_MESSAGE_SIZE + 4;
    /** Handshake message type of a ClientHello. */
    private static final int CLIENT_HELLO = 1;

    /** The client's first datagram is not a QUIC version 1 or 2 Initial the proxy can read. */
    static final class UnknownVersion extends Exception {
        final int version;

        UnknownVersion(int version) {
            super(String.format("QUIC version 0x%08x", version));
            this.version = version;
        }
    }

    private final QuicVersion version;
    private final ConnectionId destinationId;
    private final ConnectionId sourceId;
    private final DirectionalKeys keys;
    /** The CRYPTO stream received so far, grown as needed up to {@link #MAX_CRYPTO}. */
    private byte[] crypto = new byte[1024];
    /** The ranges of {@link #crypto} received, start to end, merged. */
    private final TreeMap<Integer, Integer> received = new TreeMap<>();
    private long largestPacketNumber = -1;
    private int datagrams;
    private boolean authenticated;

    private QuicClientHello(QuicVersion version, ConnectionId destinationId, ConnectionId sourceId) {
        this.version = version;
        this.destinationId = destinationId;
        this.sourceId = sourceId;
        this.keys = Keys.initial(version, destinationId, true).remote();
    }

    /**
     * Starts reading a client's ClientHello from the first datagram it sent, which must start with
     * an Initial packet; the datagram itself is read by {@link #offer}.
     *
     * @throws UnknownVersion if the datagram is a long header packet of another QUIC version
     * @throws TlsClientHello.Malformed if it does not start with an Initial packet
     */
    static QuicClientHello start(ByteBuffer datagram) throws UnknownVersion, TlsClientHello.Malformed {
        ProtectedPacket first;
        try {
            first = ProtectedPacket.parse(datagram.duplicate(), 0);
        } catch (UnsupportedVersionException e) {
            throw new UnknownVersion(e.version());
        } catch (PacketDecodeException e) {
            throw new TlsClientHello.Malformed("not a QUIC packet: " + e.getMessage());
        }
        if (first.type() != PacketType.INITIAL) {
            throw new TlsClientHello.Malformed("the first packet is " + first.type() + ", not an Initial");
        }
        return new QuicClientHello(first.version(), first.destinationId(), first.sourceId());
    }

    /** The client's QUIC version. */
    QuicVersion version() {
        return version;
    }

    /** The Destination Connection ID of the client's Initial packets, which picked their keys. */
    ConnectionId destinationId() {
        return destinationId;
    }

    /** The client's Source Connection ID. */
    ConnectionId sourceId() {
        return sourceId;
    }

    /**
     * Reads the Initial packets of one more of the client's datagrams (the first one included):
     * those with the first one's version and Destination Connection ID. Other packets are skipped,
     * and so are later Initials that fail authentication.
     *
     * @param datagram the datagram, between its position and limit; not modified
     * @return the ClientHello once all of it has arrived, else null
     * @throws TlsClientHello.Malformed if the first Initial cannot be decrypted, a frame is
     *     malformed, or the CRYPTO frames carry something else than a ClientHello
     * @throws TlsClientHello.TooLarge if the ClientHello is larger than {@link
     *     TlsClientHello#MAX_MESSAGE_SIZE}, or still incomplete after {@link #MAX_DATAGRAMS}
     *     datagrams
     */
    ClientHello offer(ByteBuffer datagram) throws TlsClientHello.Malformed, TlsClientHello.TooLarge {
        if (++datagrams > MAX_DATAGRAMS) {
            throw new TlsClientHello.TooLarge("no complete ClientHello in " + MAX_DATAGRAMS + " datagrams");
        }
        // Removing protection works in place: on a copy, so the datagram can still be relayed.
        ByteBuffer copy = ByteBuffer.allocate(datagram.remaining()).put(datagram.duplicate()).flip();
        List<ProtectedPacket> packets;
        try {
            packets = ProtectedPacket.splitDatagram(copy, 0, false);
        } catch (PacketDecodeException e) {
            if (!authenticated) throw new TlsClientHello.Malformed("unreadable Initial: " + e.getMessage());
            return null;
        }
        for (ProtectedPacket p : packets) {
            if (p.type() != PacketType.INITIAL || p.version() != version || !p.destinationId().equals(destinationId)) {
                continue;
            }
            Packet packet;
            try {
                packet = p.unprotect(keys, largestPacketNumber);
            } catch (QuicException e) {
                throw new TlsClientHello.Malformed("Initial packet: " + e.getMessage());
            }
            if (packet == null) {
                if (!authenticated) throw new TlsClientHello.Malformed("the Initial packet failed authentication");
                continue;
            }
            authenticated = true;
            largestPacketNumber = Math.max(largestPacketNumber, packet.header().packetNumber());
            try {
                for (Frame frame : FrameDecoder.decodeAll(packet.payload(), PacketType.INITIAL)) {
                    if (frame instanceof Frame.Crypto c) received(c.offset(), c.data());
                }
            } catch (FrameException e) {
                throw new TlsClientHello.Malformed("Initial frames: " + e.getMessage());
            }
        }
        if (!authenticated) throw new TlsClientHello.Malformed("no Initial packet in the first datagram");
        return complete();
    }

    /** Puts CRYPTO data where it belongs in the stream. */
    private void received(long offset, ByteBuffer data) throws TlsClientHello.TooLarge {
        int length = data.remaining();
        if (length == 0) return;
        if (offset + length > MAX_CRYPTO) {
            throw new TlsClientHello.TooLarge("CRYPTO data past " + MAX_CRYPTO + " bytes");
        }
        int start = (int) offset;
        int end = start + length;
        if (end > crypto.length) crypto = Arrays.copyOf(crypto, Math.min(MAX_CRYPTO, Math.max(end, crypto.length * 2)));
        data.get(crypto, start, length);
        // Merge [start, end) with the ranges it touches.
        Map.Entry<Integer, Integer> before = received.floorEntry(start);
        if (before != null && before.getValue() >= start) {
            start = before.getKey();
            end = Math.max(end, before.getValue());
        }
        for (Map.Entry<Integer, Integer> next = received.ceilingEntry(start); next != null && next.getKey() <= end;
                next = received.ceilingEntry(start)) {
            end = Math.max(end, next.getValue());
            received.remove(next.getKey());
        }
        received.put(start, end);
    }

    /** The ClientHello if its bytes have all arrived, else null. */
    private ClientHello complete() throws TlsClientHello.Malformed, TlsClientHello.TooLarge {
        Map.Entry<Integer, Integer> first = received.firstEntry();
        int contiguous = first != null && first.getKey() == 0 ? first.getValue() : 0;
        if (contiguous < 4) return null;
        if ((crypto[0] & 0xff) != CLIENT_HELLO) {
            throw new TlsClientHello.Malformed("the first handshake message is not a ClientHello");
        }
        int bodySize = (crypto[1] & 0xff) << 16 | (crypto[2] & 0xff) << 8 | (crypto[3] & 0xff);
        if (bodySize > TlsClientHello.MAX_MESSAGE_SIZE) {
            throw new TlsClientHello.TooLarge("ClientHello of " + bodySize + " bytes exceeds "
                    + TlsClientHello.MAX_MESSAGE_SIZE);
        }
        if (contiguous < bodySize + 4) return null;
        return TlsClientHello.parse(Arrays.copyOf(crypto, bodySize + 4));
    }
}
