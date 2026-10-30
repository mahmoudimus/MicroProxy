// Class UpdateResult_Updated
// Dafny class UpdateResult_Updated compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class UpdateResult_Updated extends UpdateResult {
  public State _state;
  public UpdateResult_Updated (State state) {
    super();
    this._state = state;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    UpdateResult_Updated o = (UpdateResult_Updated)other;
    return true && java.util.Objects.equals(this._state, o._state);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._state);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("SpongeSpec.UpdateResult.Updated");
    s.append("(");
    s.append(dafny.Helpers.toString(this._state));
    s.append(")");
    return s.toString();
  }
}
