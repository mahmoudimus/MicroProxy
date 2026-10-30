// Class Result_Failure<T>
// Dafny class Result_Failure<T> compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class Result_Failure<T> extends Result<T> {
  public FailureKind _reason;
  public Result_Failure (dafny.TypeDescriptor<T> _td_T, FailureKind reason) {
    super(_td_T);
    this._reason = reason;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Result_Failure<T> o = (Result_Failure<T>)other;
    return true && java.util.Objects.equals(this._reason, o._reason);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._reason);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("KemSpec.Result.Failure");
    s.append("(");
    s.append(dafny.Helpers.toString(this._reason));
    s.append(")");
    return s.toString();
  }
}
