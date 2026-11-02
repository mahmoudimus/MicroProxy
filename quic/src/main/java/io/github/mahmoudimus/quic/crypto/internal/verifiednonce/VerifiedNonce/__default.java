// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce;


@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static byte[] Nonce(byte[] iv, long pn)
  {
    byte[] nonce = new byte[0];
    if(true) {
      byte[] _nw0 = (byte[]) dafny.TypeDescriptor.BYTE.fillThenReturnArray(dafny.TypeDescriptor.BYTE.newArray(dafny.Helpers.toIntChecked((java.math.BigInteger.valueOf(12L)), "Java arrays may be no larger than the maximum 32-bit signed int")), (byte) 0);
      nonce = _nw0;
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.ZERO)).intValue())] = (iv)[(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))];
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.ONE)).intValue())] = (iv)[(dafny.Helpers.toInt((java.math.BigInteger.ONE)))];
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(2L))).intValue())] = (iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(2L))))];
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(3L))).intValue())] = (iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(3L))))];
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(4L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(4L))))]) ^ (((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(pn, (byte) 56)) & ((long) 255L)))))));
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(5L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(5L))))]) ^ (((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(pn, (byte) 48)) & ((long) 255L)))))));
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(6L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(6L))))]) ^ (((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(pn, (byte) 40)) & ((long) 255L)))))));
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(7L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(7L))))]) ^ (((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(pn, (byte) 32)) & ((long) 255L)))))));
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(8L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(8L))))]) ^ (((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(pn, (byte) 24)) & ((long) 255L)))))));
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(9L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(9L))))]) ^ (((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(pn, (byte) 16)) & ((long) 255L)))))));
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(10L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(10L))))]) ^ (((byte) ((long) (long) (((long) dafny.Helpers.bv64ShiftRight(pn, (byte) 8)) & ((long) 255L)))))));
      (nonce)[dafny.Helpers.toInt(((java.math.BigInteger.valueOf(11L))).intValue())] = (byte) (byte) ((byte)(((iv)[(dafny.Helpers.toInt((java.math.BigInteger.valueOf(11L))))]) ^ (((byte) ((long) (long) ((pn) & ((long) 255L)))))));
    }
    return nonce;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce._default";
  }
}
