// Class FeedResult_Full
// Dafny class FeedResult_Full compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling;

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

@SuppressWarnings({"unchecked", "deprecation"})
public class FeedResult_Full extends FeedResult {
  public int[] _coeffs;
  public int _consumed;
  public FeedResult_Full (int[] coeffs, int consumed) {
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
    return true && this._coeffs == o._coeffs && this._consumed == o._consumed;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._coeffs);
    hash = ((hash << 5) + hash) + java.lang.Integer.hashCode(this._consumed);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("NativeSampling.FeedResult.Full");
    s.append("(");
    s.append(dafny.Helpers.toString(this._coeffs));
    s.append(", ");
    s.append(this._consumed);
    s.append(")");
    return s.toString();
  }
}
