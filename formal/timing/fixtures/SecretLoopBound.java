/** Negative control: secret loop bound. */
public final class SecretLoopBound {
    public static int run(byte[] secret) {
        int total = 0;
        for (int i = 0; i < secret[0]; i++) {
            total += i;
        }
        return total;
    }
}
