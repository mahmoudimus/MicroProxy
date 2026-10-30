// Class FeedResult_Full
// Dafny class FeedResult_Full compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class FeedResult_Full extends FeedResult {
  public dafny.DafnySequence<? extends java.math.BigInteger> _coeffs;
  public java.math.BigInteger _consumed;
  public FeedResult_Full (dafny.DafnySequence<? extends java.math.BigInteger> coeffs, java.math.BigInteger consumed) {
    super();
    this._coeffs = coeffs;
    this._consumed = consumed;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FeedResult_Full o = (FeedResult_Full)other;
    return true && java.util.Objects.equals(this._coeffs, o._coeffs) && java.util.Objects.equals(this._consumed, o._consumed);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._coeffs);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._consumed);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("SamplingSpec.FeedResult.Full");
    s.append("(");
    s.append(dafny.Helpers.toString(this._coeffs));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._consumed));
    s.append(")");
    return s.toString();
  }
}
