/** Negative control: early-exit comparison of secret ciphertext bytes. */
public final class EarlyCompare {
    public static int run(byte[] c, byte[] expected) {
        for (int i = 0; i < 1088; i++) {
            if (c[i] != expected[i]) {
                return 0;
            }
        }
        return 1;
    }
}
