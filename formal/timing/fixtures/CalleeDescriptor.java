// A same-owner/same-name helper with a different return descriptor is not the
// reviewed NativeCodec target (JII)I and must fail closed.
public class CalleeDescriptor {
  static long Extract(long value, int shift, int bits) { return value + shift + bits; }
  public static long run(long value, int shift, int bits) { return Extract(value, shift, bits); }
}
