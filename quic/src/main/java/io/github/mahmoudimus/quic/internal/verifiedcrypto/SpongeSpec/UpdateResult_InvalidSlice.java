// Class UpdateResult_InvalidSlice
// Dafny class UpdateResult_InvalidSlice compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class UpdateResult_InvalidSlice extends UpdateResult {
  public UpdateResult_InvalidSlice () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    UpdateResult_InvalidSlice o = (UpdateResult_InvalidSlice)other;
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
    s.append("SpongeSpec.UpdateResult.InvalidSlice");
    return s.toString();
  }
}
