// Unit-test-only self-recursive helper: the inliner must fail closed on a cycle
// instead of expanding forever (F9).
public class RecursiveCallee {
  static int count(int[] a, int n) {
    if (n <= 0) { return a[0]; }
    return count(a, n - 1);
  }
}
