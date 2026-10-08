package org.microproxy.simd;

import java.lang.System.Logger.Level;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Locale;

/**
 * Byte loops on the proxy's hot paths, with an optional SIMD implementation.
 *
 * <p>The SIMD version uses the Vector API, which is still an incubating JDK module. It is used
 * only when the JVM runs with {@code --add-modules jdk.incubator.vector} (the JVM then prints an
 * incubator warning at startup). The system property {@code microproxy.simd} can be {@code
 * auto} (the default: use SIMD when the module is present), {@code true} (warn if it is not), or
 * {@code false} (never). Without the module the scalar version runs, so the proxy needs nothing
 * beyond JDK 21.
 *
 * <p>Public for use across MicroProxy's packages; not a supported API.
 */
public final class Simd {

    private static final System.Logger LOG = System.getLogger(Simd.class.getName());

    /** The operations, in scalar and SIMD flavours. */
    public interface Ops {
        /** The index of the first {@code value} in {@code a[from, to)}, or -1. */
        int indexOf(byte[] a, int from, int to, byte value);

        /**
         * XORs {@code a[off, off + len)} with the 4-byte {@code mask} repeated, starting with its
         * most significant byte: WebSocket (un)masking.
         */
        void xorMask(byte[] a, int off, int len, int mask);

        /** A short description, such as {@code scalar} or {@code vector 256-bit}. */
        String description();
    }

    private static final Ops SCALAR = new Scalar();
    private static final Ops OPS = choose();

    private Simd() {}

    /** The implementation in use. */
    public static Ops ops() {
        return OPS;
    }

    /** The scalar implementation, always available. */
    public static Ops scalar() {
        return SCALAR;
    }

    /** The SIMD implementation, or {@code null} if the Vector API module is not present. */
    public static Ops vector() {
        if (ModuleLayer.boot().findModule("jdk.incubator.vector").isEmpty()) return null;
        try {
            return (Ops) Class.forName("org.microproxy.simd.VectorOps").getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException | LinkageError e) {
            LOG.log(Level.WARNING, "Vector API present but unusable: " + e);
            return null;
        }
    }

    public static boolean isVectorized() {
        return OPS != SCALAR;
    }

    public static int indexOf(byte[] a, int from, int to, byte value) {
        return OPS.indexOf(a, from, to, value);
    }

    public static void xorMask(byte[] a, int off, int len, int mask) {
        OPS.xorMask(a, off, len, mask);
    }

    private static Ops choose() {
        String setting = System.getProperty("microproxy.simd", "auto").strip().toLowerCase(Locale.ROOT);
        if (setting.equals("false")) return SCALAR;
        Ops vector = vector();
        if (vector != null) return vector;
        if (setting.equals("true")) {
            LOG.log(Level.WARNING, "microproxy.simd=true but the JVM was not started with "
                    + "--add-modules jdk.incubator.vector; using scalar code");
        }
        return SCALAR;
    }

    /** Plain Java, processing eight bytes at a time where it helps. */
    static final class Scalar implements Ops {
        private static final VarHandle LONG = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);
        private static final VarHandle LONG_LE = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
        private static final long ONES = 0x0101010101010101L;
        private static final long HIGHS = 0x8080808080808080L;

        @Override
        public int indexOf(byte[] a, int from, int to, byte value) {
            int i = from;
            long pattern = ONES * (value & 0xff);
            for (; i + 8 <= to; i += 8) {
                // A zero byte in w marks a match; the lowest flagged byte is the first one.
                long w = (long) LONG_LE.get(a, i) ^ pattern;
                long found = (w - ONES) & ~w & HIGHS;
                if (found != 0) return i + (Long.numberOfTrailingZeros(found) >>> 3);
            }
            for (; i < to; i++) {
                if (a[i] == value) return i;
            }
            return -1;
        }

        @Override
        public void xorMask(byte[] a, int off, int len, int mask) {
            long wide = (mask & 0xFFFFFFFFL) << 32 | (mask & 0xFFFFFFFFL);
            int i = 0;
            for (; i + 8 <= len; i += 8) {
                LONG.set(a, off + i, (long) LONG.get(a, off + i) ^ wide);
            }
            for (; i < len; i++) {
                a[off + i] ^= (byte) (mask >>> (24 - 8 * (i & 3)));
            }
        }

        @Override
        public String description() {
            return "scalar";
        }
    }
}
