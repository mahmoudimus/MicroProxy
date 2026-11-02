import java.security.MessageDigest;
/** Negative control: a digest comparison over secret heap contents.
 *
 * Since the F3 heap-content classification, this is rejected *at the call site*
 * (`public-argument-only ... secret heap argument`) instead of at the branch on
 * the secret result: the ordinary external call may branch on the contents and
 * the model's Call step cannot see that. Branching on a secret call result is
 * still covered by SecretBranch / SecretResultBranch (secret scalar arguments).
 */
public final class SecretDigestBranch {
    public static int run(byte[] a, byte[] b) {
        if (MessageDigest.isEqual(a, b)) {
            return 1;
        }
        return 0;
    }
}
