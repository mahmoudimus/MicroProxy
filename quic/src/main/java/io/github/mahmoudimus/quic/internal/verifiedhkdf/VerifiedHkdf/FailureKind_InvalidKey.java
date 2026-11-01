// Class FailureKind_InvalidKey
// Dafny class FailureKind_InvalidKey compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public class FailureKind_InvalidKey extends FailureKind {
  public FailureKind_InvalidKey () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FailureKind_InvalidKey o = (FailureKind_InvalidKey)other;
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
    s.append("VerifiedHkdf.FailureKind.InvalidKey");
    return s.toString();
  }
}
