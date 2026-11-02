// Unit-test caller for the checked inline-expansion rule.
public class InlineCaller {
  public static int addPublic(int value) {
    int r = InlineCallee.add(value, 1);
    if (r == 0) { return 1; }
    return 0;
  }
  public static int addSecret(int value) {
    int r = InlineCallee.add(value, 1);
    if (r == 0) { return 1; }
    return 0;
  }
  public static int clearThenRead(int[] a) {
    InlineCallee.clear(a);
    return a[0];
  }
  public static int writeThenRead(int[] a, int value) {
    InlineCallee.write(a, value);
    return a[0];
  }
  public static int subResult(int value) {
    int r = InlineCallee.sub(value, 1);
    return r;
  }
}
