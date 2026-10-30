package io.github.mahmoudimus.quic.interop;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Records real UDP traffic while forwarding it immediately, without scheduling or RTT delays. */
final class DatagramCapture implements AutoCloseable {
    private final DatagramChannel socket;
    private final List<byte[]> clientPackets = new CopyOnWriteArrayList<>();
    private final Thread receiver;

    DatagramCapture(InetSocketAddress server) throws IOException {
        socket = DatagramChannel.open();
        socket.bind(new InetSocketAddress(server.getAddress(), 0));
        receiver = Thread.ofVirtual().start(() -> {
            InetSocketAddress client = null;
            try {
                while (socket.isOpen()) {
                    ByteBuffer packet = ByteBuffer.allocate(65_535);
                    InetSocketAddress from = (InetSocketAddress) socket.receive(packet);
                    packet.flip();
                    if (from.equals(server)) {
                        if (client != null) socket.send(packet, client);
                    } else {
                        client = from;
                        byte[] copy = new byte[packet.remaining()];
                        packet.duplicate().get(copy);
                        clientPackets.add(copy);
                        socket.send(packet, server);
                    }
                }
            } catch (IOException closed) {
                // close() releases the blocking receive.
            }
        });
    }

    int port() throws IOException { return ((InetSocketAddress) socket.getLocalAddress()).getPort(); }

    record Bytes(long zeroRttStream, long oneRttPackets) {}

    Bytes bytes(CipherSuite suite, byte[] earlySecret) throws Exception {
        var received = new HashMap<Long, BitSet>();
        long largestEarly = -1;
        long oneRtt = 0;
        for (byte[] datagram : clientPackets) {
            ByteBuffer input = ByteBuffer.wrap(datagram.clone());
            while (input.hasRemaining()) {
                ProtectedPacket protectedPacket = ProtectedPacket.parse(input, 8);
                if (protectedPacket.type() == PacketType.ONE_RTT) oneRtt += protectedPacket.length();
                if (protectedPacket.type() != PacketType.ZERO_RTT) continue;
                var keys = DirectionalKeys.fromSecret(suite, earlySecret, protectedPacket.version());
                var packet = protectedPacket.unprotect(keys, largestEarly);
                if (packet == null) throw new IOException("could not decrypt captured 0-RTT packet");
                largestEarly = Math.max(largestEarly, packet.header().packetNumber());
                for (Frame frame : FrameDecoder.decodeAll(packet.payload(), PacketType.ZERO_RTT)) {
                    if (frame instanceof Frame.Stream stream) {
                        int offset = Math.toIntExact(stream.offset());
                        received.computeIfAbsent(stream.streamId(), unused -> new BitSet())
                                .set(offset, offset + stream.data().remaining());
                    }
                }
            }
        }
        return new Bytes(received.values().stream().mapToLong(BitSet::cardinality).sum(), oneRtt);
    }

    @Override public void close() throws IOException {
        socket.close();
        try { receiver.join(5000); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
