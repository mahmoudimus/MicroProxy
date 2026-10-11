/*
 * Ported from quinn-proto src/transport_parameters.rs (ReservedTransportParameter) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.params;

import io.github.mahmoudimus.quic.VarInt;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/**
 * A transport parameter this module does not interpret, kept as received: a reserved (GREASE)
 * parameter or an extension. Decoding preserves unknown parameters so that they can be inspected
 * or re-sent; peers must ignore them (RFC 9000 section 18.1).
 *
 * @param id the parameter ID
 * @param value the raw value
 */
public record UnknownParameter(long id, byte[] value) {

    /** The longest value {@link #grease} generates, as quinn, quic-go and quiche do. */
    public static final int MAX_GREASE_LENGTH = 16;

    /**
     * An unknown parameter.
     *
     * @param id the parameter ID
     * @param value the raw value, copied
     */
    public UnknownParameter {
        if (id < 0 || id > VarInt.MAX) {
            throw new IllegalArgumentException("parameter ID " + id);
        }
        value = value.clone();
    }

    /**
     * A reserved parameter with a random ID of the form {@code 31 * N + 27} and up to 15 random
     * bytes, to exercise the peer's handling of unknown parameters (RFC 9000 section 18.1).
     *
     * @param random the source of randomness
     * @return the parameter
     */
    public static UnknownParameter grease(Random random) {
        long n = (random.nextLong() >>> 2) % ((VarInt.MAX - 27) / 31);
        byte[] value = new byte[random.nextInt(MAX_GREASE_LENGTH)];
        random.nextBytes(value);
        return new UnknownParameter(31 * n + 27, value);
    }

    /**
     * Whether an ID is reserved for GREASE, that is, of the form {@code 31 * N + 27}.
     *
     * @param id the parameter ID
     * @return true for a reserved ID
     */
    public static boolean isReserved(long id) {
        return id % 31 == 27;
    }

    /**
     * The raw value.
     *
     * @return a copy of the value
     */
    @Override
    public byte[] value() {
        return value.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof UnknownParameter p && id == p.id && Arrays.equals(value, p.value);
    }

    @Override
    public int hashCode() {
        return Long.hashCode(id) * 31 + Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "UnknownParameter[id=0x" + Long.toHexString(id) + ", value=" + HexFormat.of().formatHex(value) + "]";
    }
}
