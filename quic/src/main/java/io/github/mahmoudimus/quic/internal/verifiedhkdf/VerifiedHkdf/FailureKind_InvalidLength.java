// Class FailureKind_InvalidLength
// Dafny class FailureKind_InvalidLength compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public class FailureKind_InvalidLength extends FailureKind {
  public FailureKind_InvalidLength () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FailureKind_InvalidLength o = (FailureKind_InvalidLength)other;
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
    s.append("VerifiedHkdf.FailureKind.InvalidLength");
    return s.toString();
  }
}
