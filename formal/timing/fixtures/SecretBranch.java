/** Negative control: branches on secret payload. */
public final class SecretBranch {
    public static int run(byte[] secret) {
        if (secret[0] != 0) {
            return 1;
        }
        return 2;
    }
}
