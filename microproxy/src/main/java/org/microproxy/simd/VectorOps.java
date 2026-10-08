package org.microproxy.simd;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorMask;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

/**
 * The Vector API version of {@link Simd.Ops}. Only loaded when {@code jdk.incubator.vector} is in
 * the boot layer; see {@link Simd}.
 */
final class VectorOps implements Simd.Ops {

    private static final VectorSpecies<Byte> SPECIES = ByteVector.SPECIES_PREFERRED;
    private static final VectorSpecies<Integer> INTS = IntVector.SPECIES_PREFERRED;
    /** Below two vectors' worth of bytes the scalar code is faster. */
    private static final int MIN_VECTOR_LENGTH = Math.max(32, 2 * SPECIES.length());
    private static final Simd.Ops SCALAR = Simd.scalar();

    @Override
    public int indexOf(byte[] a, int from, int to, byte value) {
        if (to - from < MIN_VECTOR_LENGTH) return SCALAR.indexOf(a, from, to, value);
        int i = from;
        int bound = from + SPECIES.loopBound(to - from);
        for (; i < bound; i += SPECIES.length()) {
            VectorMask<Byte> hits = ByteVector.fromArray(SPECIES, a, i).eq(value);
            if (hits.anyTrue()) return i + hits.firstTrue();
        }
        return SCALAR.indexOf(a, i, to, value);
    }

    @Override
    public void xorMask(byte[] a, int off, int len, int mask) {
        if (len < MIN_VECTOR_LENGTH) {
            SCALAR.xorMask(a, off, len, mask);
            return;
        }
        // The mask repeated across the vector, in memory order (lanes are little-endian, and the
        // vector length is a multiple of 4, so it lines up with every vector).
        ByteVector m = IntVector.broadcast(INTS, Integer.reverseBytes(mask)).reinterpretAsBytes();
        int bound = SPECIES.loopBound(len);
        int i = 0;
        for (; i < bound; i += SPECIES.length()) {
            ByteVector.fromArray(SPECIES, a, off + i).lanewise(VectorOperators.XOR, m).intoArray(a, off + i);
        }
        // The rest starts at a multiple of 4, so the mask's phase is unchanged.
        SCALAR.xorMask(a, off + i, len - i, mask);
    }

    @Override
    public String description() {
        return "vector " + SPECIES.vectorBitSize() + "-bit";
    }
}
