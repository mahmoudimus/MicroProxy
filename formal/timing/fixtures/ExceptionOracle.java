/** Negative control: exception decision depends on secret payload. */
public final class ExceptionOracle {
    public static int run(byte[] secret) {
        if (secret[0] == 0) {
            throw new IllegalArgumentException("bad");
        }
        return 1;
    }
}
