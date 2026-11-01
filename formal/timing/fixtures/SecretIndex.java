/** Negative control: secret-dependent array index. */
public final class SecretIndex {
    public static int run(byte[] secret, int[] table) {
        return table[secret[0] & 3];
    }
}
