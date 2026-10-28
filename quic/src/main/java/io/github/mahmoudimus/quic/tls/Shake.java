package io.github.mahmoudimus.quic.tls;

/**
 * SHAKE128 and SHAKE256, the extendable-output functions of FIPS 202, which the JDK does not
 * offer as a public API: a Keccak-f[1600] sponge with a rate of 168 or 136 bytes and the SHAKE
 * domain separation ({@code 1111}). Input is absorbed with {@link #update}, then any amount of
 * output is squeezed with {@link #read}, in as many calls as wanted.
 */
final class Shake {

    private static final long[] ROUND_CONSTANTS = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };

    private final long[] state = new long[25];
    private final int rate;
    private int position;
    private boolean squeezing;

    private Shake(int rate) {
        this.rate = rate;
    }

    /** {@return a SHAKE128 instance, rate 168 bytes} */
    static Shake shake128() {
        return new Shake(168);
    }

    /** {@return a SHAKE256 instance, rate 136 bytes} */
    static Shake shake256() {
        return new Shake(136);
    }

    /**
     * Absorbs {@code data}.
     *
     * @throws IllegalStateException once output has been read
     */
    Shake update(byte[] data) {
        return update(data, 0, data.length);
    }

    /**
     * Absorbs {@code length} bytes of {@code data} from {@code offset}.
     *
     * @throws IllegalStateException once output has been read
     */
    Shake update(byte[] data, int offset, int length) {
        if (squeezing) throw new IllegalStateException("SHAKE input after output");
        for (int i = 0; i < length; i++) {
            xorByte(position++, data[offset + i]);
            if (position == rate) {
                keccak(state);
                position = 0;
            }
        }
        return this;
    }

    /** Squeezes the next {@code out.length} bytes of output into {@code out}. */
    void read(byte[] out) {
        if (!squeezing) {
            // pad10*1 after the SHAKE suffix 1111 (FIPS 202 section 6.2)
            xorByte(position, (byte) 0x1f);
            xorByte(rate - 1, (byte) 0x80);
            keccak(state);
            position = 0;
            squeezing = true;
        }
        for (int i = 0; i < out.length; i++) {
            if (position == rate) {
                keccak(state);
                position = 0;
            }
            out[i] = (byte) (state[position >>> 3] >>> (8 * (position & 7)));
            position++;
        }
    }

    private void xorByte(int at, byte b) {
        state[at >>> 3] ^= (b & 0xffL) << (8 * (at & 7));
    }

    /** Keccak-f[1600] (FIPS 202 section 3.3), lanes indexed {@code x + 5y}. */
    static void keccak(long[] a) {
        long[] c = new long[5];
        for (long rc : ROUND_CONSTANTS) {
            // theta
            for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[x + y] ^= d;
            }
            // rho and pi: walk the 24 lanes other than (0, 0)
            int x = 1;
            int y = 0;
            long current = a[1];
            for (int t = 0; t < 24; t++) {
                int nx = y;
                int ny = (2 * x + 3 * y) % 5;
                x = nx;
                y = ny;
                long next = a[x + 5 * y];
                a[x + 5 * y] = Long.rotateLeft(current, ((t + 1) * (t + 2) / 2) % 64);
                current = next;
            }
            // chi
            for (int row = 0; row < 25; row += 5) {
                for (int i = 0; i < 5; i++) c[i] = a[row + i];
                for (int i = 0; i < 5; i++) a[row + i] = c[i] ^ (~c[(i + 1) % 5] & c[(i + 2) % 5]);
            }
            // iota
            a[0] ^= rc;
        }
    }
}
