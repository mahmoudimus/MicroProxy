// The helper's declared result follows its arguments. A secret argument makes
// the call result secret, so branching on it must be rejected.
public class SecretResultBranch {
  static int pass(int value) { return value; }
  public static int run(int[] a, int secret) {
    int r = pass(secret);
    if (r == 0) { return 1; }
    return 0;
  }
}
