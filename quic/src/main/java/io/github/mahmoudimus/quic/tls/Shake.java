package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge;
import java.util.Arrays;
import java.util.Objects;

/**
 * SHAKE128/256 using Java generated from the verified Dafny sponge and permutation.
 * The facade owns the generated state and enforces its API preconditions.
 * Compiler/runtime correctness and JVM timing are separate trust assumptions.
 */
final class Shake {
    private final Sponge sponge;

    private Shake(int rate) {
        sponge = new Sponge();
        sponge.__ctor(rate);
    }

    static Shake shake128() {
        return new Shake(168);
    }

    static Shake shake256() {
        return new Shake(136);
    }

    Shake update(byte[] data) {
        return update(data, 0, data.length);
    }

    Shake update(byte[] data, int offset, int length) {
        // Preserve phase-error precedence; the generated update validates the
        // complete slice before writing state, including overflow-safe bounds.
        if (sponge.squeezing) throw new IllegalStateException("SHAKE input after output");
        Objects.requireNonNull(data);
        int status = sponge.Update(data, offset, length);
        if (status == 1) throw new IllegalStateException("SHAKE input after output");
        if (status == 2) throw new IndexOutOfBoundsException("SHAKE input slice");
        return this;
    }

    void read(byte[] out) {
        sponge.Read(Objects.requireNonNull(out));
    }

    void destroy() {
        sponge.Destroy();
    }

    /** Keccak-f[1600], preserving any caller-owned tail after the first 25 lanes. */
    static void keccak(long[] state) {
        Objects.requireNonNull(state);
        if (state.length < 25) throw new IllegalArgumentException("Keccak state shorter than 25 lanes");
        if (state.length == 25) {
            io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.Permute(state);
            return;
        }
        long[] lanes = Arrays.copyOf(state, 25);
        try {
            io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.__default.Permute(lanes);
            System.arraycopy(lanes, 0, state, 0, lanes.length);
        } finally {
            Arrays.fill(lanes, 0L);
        }
    }
}
