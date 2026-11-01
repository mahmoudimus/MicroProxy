// Class BytesResult_Success
// Dafny class BytesResult_Success compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public class BytesResult_Success extends BytesResult {
  public dafny.DafnySequence<? extends java.lang.Byte> _bytes;
  public BytesResult_Success (dafny.DafnySequence<? extends java.lang.Byte> bytes) {
    super();
    this._bytes = bytes;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    BytesResult_Success o = (BytesResult_Success)other;
    return true && java.util.Objects.equals(this._bytes, o._bytes);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._bytes);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("VerifiedHkdf.BytesResult.Success");
    s.append("(");
    s.append(dafny.Helpers.toString(this._bytes));
    s.append(")");
    return s.toString();
  }
}
