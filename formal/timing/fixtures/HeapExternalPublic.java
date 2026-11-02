// F3 control: the same ordinary external call with public array contents is
// admitted, proving the gate keys on heap taint rather than the target name.
public class HeapExternalPublic {
  public static boolean run(byte[] a, byte[] b) {
    return java.security.MessageDigest.isEqual(a, b);
  }
}
