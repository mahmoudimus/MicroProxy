// Class DecodeResult_Decoded
// Dafny class DecodeResult_Decoded compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class DecodeResult_Decoded extends DecodeResult {
  public int[] _words;
  public DecodeResult_Decoded (int[] words) {
    super();
    this._words = words;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    DecodeResult_Decoded o = (DecodeResult_Decoded)other;
    return true && this._words == o._words;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._words);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("NativeCodec.DecodeResult.Decoded");
    s.append("(");
    s.append(dafny.Helpers.toString(this._words));
    s.append(")");
    return s.toString();
  }
}
