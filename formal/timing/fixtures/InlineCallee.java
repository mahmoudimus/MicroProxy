// Unit-test callee for the checked inline-expansion rule.
public class InlineCallee {
  public static int add(int a, int b) { return a + b; }
  public static int sub(int a, int b) { return a - b; }
  public static void clear(int[] a) {
    for (int i = 0; i < a.length; i++) { a[i] = 0; }
  }
  public static void write(int[] a, int value) { a[0] = value; }
  public static int[] make(int n) { return new int[n]; }
}
