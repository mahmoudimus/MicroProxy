// Class Residue
// Dafny class Residue compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.PolynomialRing;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class Residue {
  public java.math.BigInteger _e;
  public java.math.BigInteger _o;
  public Residue (java.math.BigInteger e, java.math.BigInteger o) {
    this._e = e;
    this._o = o;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Residue o = (Residue)other;
    return true && java.util.Objects.equals(this._e, o._e) && java.util.Objects.equals(this._o, o._o);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._e);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._o);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("PolynomialRing.Residue.Pair");
    s.append("(");
    s.append(dafny.Helpers.toString(this._e));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._o));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Residue> _TYPE = dafny.TypeDescriptor.<Residue>referenceWithInitializer(Residue.class, () -> Residue.Default());
  public static dafny.TypeDescriptor<Residue> _typeDescriptor() {
    return (dafny.TypeDescriptor<Residue>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Residue theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.PolynomialRing.Residue.create(java.math.BigInteger.ZERO, java.math.BigInteger.ZERO);
  public static Residue Default() {
    return theDefault;
  }
  public static Residue create(java.math.BigInteger e, java.math.BigInteger o) {
    return new Residue(e, o);
  }
  public static Residue create_Pair(java.math.BigInteger e, java.math.BigInteger o) {
    return create(e, o);
  }
  public boolean is_Pair() { return true; }
  public java.math.BigInteger dtor_e() {
    return this._e;
  }
  public java.math.BigInteger dtor_o() {
    return this._o;
  }
}
