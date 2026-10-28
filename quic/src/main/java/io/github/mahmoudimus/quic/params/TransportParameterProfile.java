package io.github.mahmoudimus.quic.params;

import io.github.mahmoudimus.quic.VarInt;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.random.RandomGenerator;

/**
 * Which transport parameters a client's {@code quic_transport_parameters} carries, in what order,
 * and what it adds that QUIC does not need: the parts of a browser's QUIC fingerprint the
 * parameters make. The values of the parameters that configure the connection come from the
 * connection's own {@link TransportParameters}, so what is advertised is what the connection does;
 * a parameter the profile leaves out is advertised as its default, which the connection must then
 * hold to (for {@code ack_delay_exponent}, {@code max_ack_delay} and {@code
 * active_connection_id_limit}).
 */
public final class TransportParameterProfile {

    /** In {@link #ids}: a GREASE parameter (RFC 9000 section 18.1), its id and value random. */
    public static final long GREASE = -1;
    /** {@code version_information} (RFC 9368), with a GREASE version among the available ones. */
    public static final long VERSION_INFORMATION = 0x11;

    private final String name;
    private final List<Long> ids;
    private final boolean shuffle;
    private final Map<Long, byte[]> fixed;

    /**
     * @param name the profile's name
     * @param ids the parameters, in order: ids the connection sets, {@link #GREASE}, {@link
     *     #VERSION_INFORMATION}, or ids of {@code fixed}
     * @param shuffle whether each connection sends them in a random order
     * @param fixed values sent as they are, by id, such as Google's {@code google_connection_options}
     */
    public TransportParameterProfile(String name, List<Long> ids, boolean shuffle, Map<Long, byte[]> fixed) {
        this.name = name;
        this.ids = List.copyOf(ids);
        this.shuffle = shuffle;
        this.fixed = Map.copyOf(fixed);
    }

    /**
     * Chrome 156's, as captured over HTTP/3: {@code max_idle_timeout}, {@code max_udp_payload_size},
     * the four flow-control limits, both stream limits, an empty {@code initial_source_connection_id},
     * {@code version_information} with a GREASE version, {@code max_datagram_frame_size} 65536,
     * {@code google_connection_options} {@code ORIG} (0x3128) and a GREASE parameter, shuffled per
     * connection.
     *
     * @return the profile
     */
    public static TransportParameterProfile chrome156() {
        Map<Long, byte[]> fixed = new LinkedHashMap<>();
        fixed.put(0x3128L, "ORIG".getBytes(StandardCharsets.US_ASCII));
        fixed.put(0x20L, varint(65_536));
        return new TransportParameterProfile("chrome-156", List.of(0x1L, 0x3L, 0x4L, 0x5L, 0x6L, 0x7L, 0x8L, 0x9L, 0xfL,
                VERSION_INFORMATION, 0x20L, 0x3128L, GREASE), true, fixed);
    }

    /** {@return the profile's name} */
    public String name() {
        return name;
    }

    /**
     * The {@code quic_transport_parameters} body for a connection.
     *
     * @param actual the connection's parameters, whose values the profile's ids take
     * @param version the connection's QUIC version, for {@code version_information}
     * @param random the source of the order and the GREASE values
     * @return the encoded parameters
     */
    public byte[] encode(TransportParameters actual, int version, RandomGenerator random) {
        Map<Long, byte[]> values = split(actual.encode());
        List<Long> order = new ArrayList<>(ids);
        if (shuffle) {
            for (int i = order.size() - 1; i > 0; i--) Collections.swap(order, i, random.nextInt(i + 1));
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (long id : order) {
            if (id == GREASE) {
                // 31 * N + 27, with a random value of up to 15 bytes, as Chrome's are
                long greaseId = 31L * random.nextLong(1L << 56) + 27;
                byte[] value = new byte[random.nextInt(16)];
                random.nextBytes(value);
                write(out, greaseId, value);
            } else if (id == VERSION_INFORMATION) {
                write(out, id, versionInformation(version, random));
            } else if (fixed.containsKey(id)) {
                write(out, id, fixed.get(id));
            } else if (values.containsKey(id)) {
                write(out, id, values.get(id));
            }
        }
        return out.toByteArray();
    }

    /** Chosen version, then the version and a GREASE one (0x?a?a?a?a) in either order. */
    private static byte[] versionInformation(int version, RandomGenerator random) {
        int grease = 0;
        for (int i = 0; i < 4; i++) grease = (grease << 8) | (random.nextInt(16) << 4) | 0x0a;
        ByteBuffer b = ByteBuffer.allocate(12).putInt(version);
        if (random.nextBoolean()) {
            b.putInt(version).putInt(grease);
        } else {
            b.putInt(grease).putInt(version);
        }
        return b.array();
    }

    private static Map<Long, byte[]> split(byte[] encoded) {
        Map<Long, byte[]> out = new LinkedHashMap<>();
        ByteBuffer b = ByteBuffer.wrap(encoded);
        while (b.hasRemaining()) {
            long id = VarInt.read(b);
            int length = (int) VarInt.read(b);
            byte[] value = new byte[length];
            b.get(value);
            out.put(id, value);
        }
        return out;
    }

    private static void write(ByteArrayOutputStream out, long id, byte[] value) {
        ByteBuffer b = ByteBuffer.allocate(VarInt.size(id) + VarInt.size(value.length) + value.length);
        VarInt.write(b, id);
        VarInt.write(b, value.length);
        b.put(value);
        out.writeBytes(b.array());
    }

    private static byte[] varint(long v) {
        ByteBuffer b = ByteBuffer.allocate(VarInt.size(v));
        VarInt.write(b, v);
        return b.array();
    }

    @Override
    public String toString() {
        return "TransportParameterProfile[" + name + "]";
    }
}
