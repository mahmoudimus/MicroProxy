// F3 regression: an ordinary external call receiving secret array *contents*.
// No JDK/provider constant-time claim is made; the reviewed runtime contract is
// treated as potentially value-dependent, so the default public-scalar-and-heap
// classification must reject the secret heap argument. `HeapExternalPublic` is
// the accepted public control.
public class HeapExternalCompare {
  public static boolean run(byte[] a, byte[] b) {
    return java.security.MessageDigest.isEqual(a, b);
  }
}
