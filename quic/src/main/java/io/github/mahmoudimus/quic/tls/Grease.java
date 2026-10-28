package io.github.mahmoudimus.quic.tls;

import java.util.random.RandomGenerator;

/**
 * The GREASE values (RFC 8701) one ClientHello uses, drawn per connection the way BoringSSL
 * draws them: one for the cipher suites, one shared by the supported groups and the key shares,
 * one for each of the two GREASE extensions (which must differ), one for the supported versions
 * and one for the signature algorithms.
 *
 * @param cipher the GREASE cipher suite
 * @param group the GREASE named group, in {@code supported_groups} and {@code key_share}
 * @param extension1 the type of the first GREASE extension
 * @param extension2 the type of the last GREASE extension
 * @param version the GREASE version in {@code supported_versions}
 * @param signature the GREASE signature scheme in {@code signature_algorithms}
 */
public record Grease(int cipher, int group, int extension1, int extension2, int version, int signature) {

    /**
     * Draws a hello's values from {@code random}.
     *
     * @param random the source of randomness
     * @return the values, with {@code extension1 != extension2}
     */
    public static Grease random(RandomGenerator random) {
        int first = value(random);
        int last;
        do {
            last = value(random);
        } while (last == first);
        return new Grease(value(random), value(random), first, last, value(random), value(random));
    }

    /**
     * Whether {@code value} is one of the sixteen GREASE values, {@code 0x0a0a} to {@code 0xfafa}.
     *
     * @param value a cipher suite, group, extension type, version or signature scheme
     * @return whether it is reserved for GREASE
     */
    public static boolean isGrease(int value) {
        return (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff);
    }

    private static int value(RandomGenerator random) {
        return 0x0a0a + 0x1010 * random.nextInt(16);
    }
}
