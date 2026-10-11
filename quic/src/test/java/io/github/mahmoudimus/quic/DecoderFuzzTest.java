package io.github.mahmoudimus.quic;

import static io.github.mahmoudimus.quic.TestVectors.hex;
import static io.github.mahmoudimus.quic.TestVectors.vector;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.packet.PacketDecodeException;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import io.github.mahmoudimus.quic.params.TransportParameters;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Feeds random and mutated input to the frame, header and transport parameter decoders with a
 * fixed seed. The only exceptions allowed are {@link QuicException} (frames, parameters, reserved
 * bits) and {@link PacketDecodeException} (headers).
 */
class DecoderFuzzTest {

    private static final long SEED = 0x5eed_c0deL;
    private static final int ROUNDS = 20_000;

    private interface Decoder {
        void decode(byte[] input) throws Exception;
    }

    private static List<byte[]> frameSeeds() {
        List<Frame> frames = List.of(
                Frame.Ack.of(3, new Frame.EcnCounts(1, 2, 3), 1, 2, 3, 5, 10, 11, 14, 1000, 100_000),
                new Frame.Crypto(100, ByteBuffer.wrap(new byte[40])),
                new Frame.Stream(4, 1 << 20, ByteBuffer.wrap(new byte[30]), true),
                new Frame.NewConnectionId(9, 3, ConnectionId.of(hex("0102030405")),
                        StatelessResetToken.of(new byte[16])),
                Frame.ConnectionClose.of(7, 8, "reason"),
                Frame.ApplicationClose.of(7, "app"),
                new Frame.NewToken(ByteBuffer.wrap(new byte[12])),
                new Frame.AckFrequency(1, 2, 3, 4),
                new Frame.Datagram(ByteBuffer.wrap(new byte[9])),
                new Frame.MaxStreams(true, 100),
                new Frame.PathChallenge(42));
        List<byte[]> seeds = new ArrayList<>();
        for (Frame f : frames) {
            ByteBuffer out = ByteBuffer.allocate(f.encodedLength());
            f.encode(out);
            seeds.add(out.array());
        }
        return seeds;
    }

    private static byte[] mutate(Random r, byte[] seed) {
        byte[] b = seed.clone();
        switch (r.nextInt(4)) {
            case 0 -> {
                for (int i = 0, n = 1 + r.nextInt(4); i < n && b.length > 0; i++) {
                    b[r.nextInt(b.length)] ^= (byte) (1 << r.nextInt(8));
                }
            }
            case 1 -> b = Arrays.copyOf(b, r.nextInt(b.length + 1));
            case 2 -> {
                if (b.length > 0) b[r.nextInt(b.length)] = (byte) r.nextInt(256);
            }
            default -> {
                byte[] extra = new byte[r.nextInt(16)];
                r.nextBytes(extra);
                b = Arrays.copyOf(b, b.length + extra.length);
                System.arraycopy(extra, 0, b, seed.length, extra.length);
            }
        }
        return b;
    }

    private static void fuzz(String name, List<byte[]> seeds, Decoder decoder) {
        Random r = new Random(SEED ^ name.hashCode());
        for (int i = 0; i < ROUNDS; i++) {
            byte[] input;
            if (r.nextInt(4) == 0) {
                input = new byte[r.nextInt(64)];
                r.nextBytes(input);
            } else {
                input = mutate(r, seeds.get(r.nextInt(seeds.size())));
            }
            try {
                decoder.decode(input);
            } catch (QuicException | PacketDecodeException expected) {
                // Documented decode failures.
            } catch (Throwable t) {
                fail(name + " threw " + t + " for " + TestVectors.hex(input), t);
            }
        }
    }

    @Test
    void frames() {
        fuzz("frames", frameSeeds(), input -> {
            for (PacketType t : new PacketType[] {PacketType.INITIAL, PacketType.ZERO_RTT, PacketType.ONE_RTT}) {
                FrameDecoder.decodeAll(ByteBuffer.wrap(input), t);
            }
        });
    }

    @Test
    void headersAndProtection() {
        List<byte[]> seeds = List.of(
                vector("rfc9001.client-initial.protected"),
                vector("rfc9369.server-initial.protected"),
                vector("rfc9001.retry"),
                vector("rfc9369.retry"),
                hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"),
                hex("80 00000000 00 04 00000000 0a1a2a3a"),
                hex("80 0a1a2a3a 04 00000000 04 00000000 00"));
        ConnectionId dcid = ConnectionId.of(hex("8394c8f03e515708"));
        Keys server = Keys.initial(QuicVersion.V1, dcid, true);
        fuzz("headers", seeds, input -> {
            for (int idLength : new int[] {0, 8}) {
                for (boolean grease : new boolean[] {false, true}) {
                    for (ProtectedPacket p : ProtectedPacket.splitDatagram(ByteBuffer.wrap(input.clone()), idLength, grease)) {
                        if (p.type().isProtected()) {
                            p.unprotect(server.remote(), -1);
                        } else if (p.type() == PacketType.RETRY) {
                            p.verifyRetry(dcid);
                        }
                    }
                }
            }
        });
    }

    @Test
    void transportParameters() throws Exception {
        List<byte[]> seeds = List.of(
                TransportParameters.builder().initialMaxData(1 << 20).maxIdleTimeout(30_000)
                        .initialSourceConnectionId(ConnectionId.of(hex("0102"))).build().encode(),
                TransportParameters.builder().statelessResetToken(StatelessResetToken.of(new byte[16]))
                        .originalDestinationConnectionId(ConnectionId.of(hex("03"))).maxDatagramFrameSize(1200)
                        .greaseQuicBit(true).minAckDelay(1000).build().encode(),
                hex("0d 2d 7f000001 002a 00000000000000000000000000000001 0018 01 42 abababababababababababababababab"),
                hex("11 08 00000001 00000001"));
        fuzz("transport parameters", seeds, input -> {
            TransportParameters.decode(input, true);
            TransportParameters.decode(input, false);
        });
    }
}
