// A helper contract cannot declare a public result while receiving a secret
// array: the heap argument taint participates in the call-result rule.
public class HeapResultLaunder {
  static int first(int[] a) { return a[0]; }
  public static int run(int[] a) {
    int r = first(a);
    if (r == 0) { return 1; }
    return 0;
  }
}
