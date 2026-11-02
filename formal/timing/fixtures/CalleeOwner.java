// A same-name/same-descriptor helper on a different owner is not the reviewed
// NativeCodec target and must fail closed as an unlisted call.
public class CalleeOwner {
  static int Extract(long value, int shift, int bits) { return (int) value + shift + bits; }
  public static int run(long value, int shift, int bits) { return Extract(value, shift, bits); }
}
