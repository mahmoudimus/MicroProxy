import java.security.MessageDigest;
/** Negative control: branches on a comparison result derived from secrets. */
public final class SecretDigestBranch {
    public static int run(byte[] a, byte[] b) {
        if (MessageDigest.isEqual(a, b)) {
            return 1;
        }
        return 0;
    }
}
