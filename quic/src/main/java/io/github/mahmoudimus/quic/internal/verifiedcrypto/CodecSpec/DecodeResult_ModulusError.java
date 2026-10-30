// Class DecodeResult_ModulusError
// Dafny class DecodeResult_ModulusError compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class DecodeResult_ModulusError extends DecodeResult {
  public DecodeResult_ModulusError () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    DecodeResult_ModulusError o = (DecodeResult_ModulusError)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("CodecSpec.DecodeResult.ModulusError");
    return s.toString();
  }
}
