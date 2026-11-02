// Public long occupies JVM local slots 0-1; the private int is slot 2. A wrong
// slot mapping would miss the secret branch.
public class LongSlotPrivate {
  public static int run(long value, int secret) {
    if (secret == 0) { return (int) value; }
    return 0;
  }
}
