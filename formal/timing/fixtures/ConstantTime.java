/** Positive control: branch-free full-length compare and masked select. */
public final class ConstantTime {
    public static byte[] select(byte[] c, byte[] expected, byte[] candidate, byte[] fallback) {
        int diff = 0;
        for (int i = 0; i < 1088; i++) {
            diff |= c[i] ^ expected[i];
        }
        int mask = (diff - 1) >> 31;
        byte[] r = new byte[32];
        for (int i = 0; i < 32; i++) {
            r[i] = (byte) ((candidate[i] & mask) | (fallback[i] & ~mask));
        }
        return r;
    }
}
