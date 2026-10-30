// Class __default
// Dafny class __default compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static boolean ValidRate(java.math.BigInteger rate) {
    return (java.util.Objects.equals(rate, java.math.BigInteger.valueOf(136L))) || (java.util.Objects.equals(rate, java.math.BigInteger.valueOf(168L)));
  }
  public static boolean Valid(State s) {
    return (((java.util.Objects.equals(java.math.BigInteger.valueOf(((s).dtor_lanes()).length()), java.math.BigInteger.valueOf(25L))) && (__default.ValidRate((s).dtor_rate()))) && (((s).dtor_position()).signum() != -1)) && ((((s).dtor_squeezing()) ? (((s).dtor_position()).compareTo((s).dtor_rate()) <= 0) : (((s).dtor_position()).compareTo((s).dtor_rate()) < 0)));
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec._default";
  }
}
