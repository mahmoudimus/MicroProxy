// Class UpdateResult_InputAfterOutput
// Dafny class UpdateResult_InputAfterOutput compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class UpdateResult_InputAfterOutput extends UpdateResult {
  public UpdateResult_InputAfterOutput () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    UpdateResult_InputAfterOutput o = (UpdateResult_InputAfterOutput)other;
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
    s.append("SpongeSpec.UpdateResult.InputAfterOutput");
    return s.toString();
  }
}
