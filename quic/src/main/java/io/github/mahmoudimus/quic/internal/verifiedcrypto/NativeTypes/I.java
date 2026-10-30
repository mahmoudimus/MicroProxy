// Class I
// Dafny class I compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes;


@SuppressWarnings({"unchecked", "deprecation"})
public class I {
  public I() {
  }
  public static java.util.ArrayList<java.lang.Integer> IntegerRange(java.math.BigInteger lo, java.math.BigInteger hi) {
    java.util.ArrayList<java.lang.Integer> arr = new java.util.ArrayList<>();
    for (java.math.BigInteger j = lo; j.compareTo(hi) < 0; j = j.add(java.math.BigInteger.ONE)) { arr.add(java.lang.Integer.valueOf(j.intValue())); }
    return arr;
  }
  public static int Witness = ((java.lang.Number) (java.math.BigInteger.ZERO)).intValue();
  public static boolean _Is(int __source) {
    return true;
  }
  private static final dafny.TypeDescriptor<java.lang.Integer> _TYPE = dafny.TypeDescriptor.intWithDefault(Witness);
  public static dafny.TypeDescriptor<java.lang.Integer> _typeDescriptor() {
    return (dafny.TypeDescriptor<java.lang.Integer>) (dafny.TypeDescriptor<?>) _TYPE;
  }
}
