// Class FailureKind_InvalidHash
// Dafny class FailureKind_InvalidHash compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public class FailureKind_InvalidHash extends FailureKind {
  public FailureKind_InvalidHash () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FailureKind_InvalidHash o = (FailureKind_InvalidHash)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("VerifiedHkdf.FailureKind.InvalidHash");
    return s.toString();
  }
}
