// Unit-test-only shape of the generated NativeCodec.Extract body: the secret
// accumulator is copied through locals and must reach the private output
// register (F1: a `copy` that reads the wrong operand makes it dead).
public class ExtractShape {
  public static int extract(long value, int shift, int bits) {
    long word = value;
    long shifted = word >>> shift;
    long masked = shifted & ((1 << bits) - 1);
    return (int) masked;
  }
}
