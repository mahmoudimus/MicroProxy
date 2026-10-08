package org.microproxy.simd;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * The scalar and (when the JVM has the Vector API module) SIMD implementations agree with naive
 * loops. The build runs this class twice: as is, and with {@code --add-modules
 * jdk.incubator.vector}, where {@code microproxy.expectSimd} makes it insist on the SIMD path.
 */
class SimdTest {

    private static List<Simd.Ops> implementations() {
        List<Simd.Ops> ops = new ArrayList<>(List.of(Simd.scalar()));
        if (Simd.vector() != null) ops.add(Simd.vector());
        return ops;
    }

    @Test
    void theExpectedImplementationIsActive() {
        if (Boolean.getBoolean("microproxy.expectSimd")) {
            assertTrue(Simd.isVectorized(), Simd.ops().description());
            assertTrue(Simd.ops().description().startsWith("vector"));
        } else if (Simd.vector() == null) {
            assertEquals("scalar", Simd.ops().description());
        }
    }

    @Test
    void indexOfMatchesANaiveScan() {
        Random random = new Random(1);
        for (Simd.Ops ops : implementations()) {
            for (int trial = 0; trial < 2000; trial++) {
                byte[] a = new byte[random.nextInt(300)];
                for (int i = 0; i < a.length; i++) a[i] = (byte) (random.nextInt(4) == 0 ? '\n' : 'a' + random.nextInt(3));
                if (random.nextBoolean()) java.util.Arrays.fill(a, (byte) 'x');
                int from = a.length == 0 ? 0 : random.nextInt(a.length);
                int to = from + (a.length - from == 0 ? 0 : random.nextInt(a.length - from + 1));
                int expected = -1;
                for (int i = from; i < to; i++) {
                    if (a[i] == '\n') {
                        expected = i;
                        break;
                    }
                }
                assertEquals(expected, ops.indexOf(a, from, to, (byte) '\n'), ops.description());
            }
        }
    }

    @Test
    void xorMaskMatchesANaiveLoop() {
        Random random = new Random(2);
        for (Simd.Ops ops : implementations()) {
            for (int trial = 0; trial < 2000; trial++) {
                byte[] a = new byte[random.nextInt(600)];
                random.nextBytes(a);
                int mask = random.nextInt();
                int off = a.length == 0 ? 0 : random.nextInt(a.length);
                int len = a.length - off == 0 ? 0 : random.nextInt(a.length - off + 1);
                byte[] expected = a.clone();
                for (int i = 0; i < len; i++) expected[off + i] ^= (byte) (mask >>> (24 - 8 * (i & 3)));
                ops.xorMask(a, off, len, mask);
                assertArrayEquals(expected, a, ops.description());
            }
        }
    }
}
