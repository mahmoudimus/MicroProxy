// Public long first, secret array parameter at JVM slot 2; role metadata must
// survive the two-slot offset.
public class LongSlotArray {
  public static int run(long value, int[] a) {
    if (a[0] == 0) { return (int) value; }
    return 0;
  }
}
