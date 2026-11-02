// An opaque helper call is not a declassification: even if the real callee
// clears the array, the caller certificate cannot branch on its contents.
public class PostWipeLaunder {
  static void wipe(int[] a) {
    for (int i = 0; i < a.length; i++) { a[i] = 0; }
  }
  public static int run(int[] a) {
    wipe(a);
    if (a[0] == 0) { return 1; }
    return 0;
  }
}
