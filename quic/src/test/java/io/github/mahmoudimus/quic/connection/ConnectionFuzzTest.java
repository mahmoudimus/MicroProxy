package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.packet.PacketBuilder;
import io.github.mahmoudimus.quic.packet.PacketHeader;
import io.github.mahmoudimus.quic.packet.PacketNumber;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Feeds connections and endpoints hostile input from a fixed seed: random datagrams, mutated
 * real datagrams, and authenticated 1-RTT packets with random frames. Nothing may throw, and an
 * authenticated packet may close the connection only with a protocol error code, never {@code
 * INTERNAL_ERROR}.
 */
class ConnectionFuzzTest {

    @Test
    void randomAndMutatedDatagramsNeverThrow() throws Exception {
        Random random = new Random(20261011);
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        // Real datagrams to mutate
        StreamId s = client.openStream(Dir.BI);
        client.write(s, ByteBuffer.wrap(new byte[5000]));
        pair.client.drive(pair.time);
        List<ByteBuffer> samples = new ArrayList<>(pair.client.outbound);
        pair.client.outbound.clear();
        for (int i = 0; i < 3000; i++) {
            byte[] d;
            if (i % 3 == 0 || samples.isEmpty()) {
                d = new byte[1 + random.nextInt(1500)];
                random.nextBytes(d);
            } else {
                ByteBuffer sample = samples.get(random.nextInt(samples.size()));
                d = new byte[sample.remaining()];
                sample.duplicate().get(d);
                int flips = 1 + random.nextInt(4);
                for (int f = 0; f < flips; f++) {
                    d[random.nextInt(d.length)] ^= (byte) (1 + random.nextInt(255));
                }
                if (random.nextBoolean()) {
                    d = java.util.Arrays.copyOf(d, 1 + random.nextInt(d.length));
                }
            }
            Endpoint.DatagramEvent e = pair.server.endpoint.handle(pair.time, pair.client.address, 0,
                    ByteBuffer.wrap(d.clone()));
            if (e instanceof Endpoint.DatagramEvent.Deliver deliver) {
                deliver.connection().handleDatagram(pair.time, pair.client.address, 0, ByteBuffer.wrap(d));
            }
            server.pollTransmit(pair.time, 4);
        }
        assertTrue(!server.isClosed(), "unauthenticated garbage closed the connection: " + server.closeReason());
        pair.drive();
        assertTrue(!client.isClosed());
    }

    @Test
    void authenticatedRandomFramesCloseCleanly() {
        Random random = new Random(7);
        int internalErrors = 0;
        int closed = 0;
        for (int round = 0; round < 300; round++) {
            Pair pair = new Pair();
            Connection client = pair.connect();
            Connection server = pair.serverConnection();
            pair.drive();
            Keys keys = client.recovery().space(SpaceId.DATA).keys();
            for (int i = 0; i < 5 && !server.isClosed(); i++) {
                ByteBuffer payload = ByteBuffer.allocate(1100);
                int frames = 1 + random.nextInt(4);
                for (int f = 0; f < frames; f++) {
                    writeRandomFrame(payload, random);
                }
                long pn = client.recovery().nextPacketNumber(SpaceId.DATA);
                ByteBuffer buf = ByteBuffer.allocate(1452);
                PacketBuilder builder = new PacketBuilder(buf, 1452);
                ByteBuffer out = builder.begin(new PacketHeader.Short(false, client.keyPhase(), client.remoteCid(), pn,
                        PacketNumber.encodedLength(pn, client.recovery().space(SpaceId.DATA).largestAckedPacket())),
                        keys.local());
                payload.flip();
                if (payload.remaining() > out.remaining()) {
                    payload.limit(payload.position() + out.remaining());
                }
                out.put(payload);
                builder.finish();
                server.handleDatagram(pair.time, pair.client.address, 0, builder.datagram());
                server.pollTransmit(pair.time, 4);
            }
            ConnectionError reason = server.closeReason();
            closed += reason != null ? 1 : 0;
            if (reason != null && reason.code() == QuicException.INTERNAL_ERROR) {
                internalErrors++;
                System.out.println("INTERNAL_ERROR: " + reason);
            }
        }
        assertTrue(closed > 100, "only " + closed + " rounds reached frame processing errors");
        assertTrue(internalErrors == 0, internalErrors + " internal errors");
    }

    /** A random frame: a known type with random varint fields, or random bytes. */
    private static void writeRandomFrame(ByteBuffer out, Random random) {
        int[] types = {0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x30, 0x31, 0xaf};
        if (random.nextInt(10) == 0) {
            byte[] junk = new byte[random.nextInt(40)];
            random.nextBytes(junk);
            out.put(junk);
            return;
        }
        int type = types[random.nextInt(types.length)];
        VarInt.write(out, type);
        int fields = 1 + random.nextInt(5);
        for (int i = 0; i < fields && out.remaining() > 20; i++) {
            long v = switch (random.nextInt(4)) {
                case 0 -> random.nextInt(4);
                case 1 -> random.nextInt(64);
                case 2 -> random.nextInt(1 << 20);
                default -> random.nextLong(VarInt.MAX);
            };
            VarInt.write(out, v);
        }
        if (random.nextBoolean() && out.remaining() > 100) {
            byte[] data = new byte[random.nextInt(60)];
            random.nextBytes(data);
            out.put(data);
        }
    }
}
