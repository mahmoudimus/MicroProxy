// Public long first (2 JVM slots), public int second, long return register.
public class LongSlotPublic {
  public static long run(long value, int factor) {
    if (factor == 0) { return value; }
    return value + (long) factor;
  }
}
