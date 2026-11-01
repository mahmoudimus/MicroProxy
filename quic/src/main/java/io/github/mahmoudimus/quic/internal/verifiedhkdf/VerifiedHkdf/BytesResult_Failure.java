// Class BytesResult_Failure
// Dafny class BytesResult_Failure compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public class BytesResult_Failure extends BytesResult {
  public FailureKind _reason;
  public BytesResult_Failure (FailureKind reason) {
    super();
    this._reason = reason;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    BytesResult_Failure o = (BytesResult_Failure)other;
    return true && java.util.Objects.equals(this._reason, o._reason);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._reason);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("VerifiedHkdf.BytesResult.Failure");
    s.append("(");
    s.append(dafny.Helpers.toString(this._reason));
    s.append(")");
    return s.toString();
  }
}
