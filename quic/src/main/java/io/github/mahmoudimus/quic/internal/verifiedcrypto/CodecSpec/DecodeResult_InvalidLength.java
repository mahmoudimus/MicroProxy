// Class DecodeResult_InvalidLength
// Dafny class DecodeResult_InvalidLength compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class DecodeResult_InvalidLength extends DecodeResult {
  public DecodeResult_InvalidLength () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    DecodeResult_InvalidLength o = (DecodeResult_InvalidLength)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("CodecSpec.DecodeResult.InvalidLength");
    return s.toString();
  }
}
