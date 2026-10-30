// Class L
// Dafny class L compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes;


@SuppressWarnings({"unchecked", "deprecation"})
public class L {
  public L() {
  }
  public static java.util.ArrayList<java.lang.Long> IntegerRange(java.math.BigInteger lo, java.math.BigInteger hi) {
    java.util.ArrayList<java.lang.Long> arr = new java.util.ArrayList<>();
    for (java.math.BigInteger j = lo; j.compareTo(hi) < 0; j = j.add(java.math.BigInteger.ONE)) { arr.add(java.lang.Long.valueOf(j.longValue())); }
    return arr;
  }
  public static long Witness = ((java.lang.Number) (java.math.BigInteger.ZERO)).longValue();
  public static boolean _Is(long __source) {
    return true;
  }
  private static final dafny.TypeDescriptor<java.lang.Long> _TYPE = dafny.TypeDescriptor.longWithDefault(Witness);
  public static dafny.TypeDescriptor<java.lang.Long> _typeDescriptor() {
    return (dafny.TypeDescriptor<java.lang.Long>) (dafny.TypeDescriptor<?>) _TYPE;
  }
}
