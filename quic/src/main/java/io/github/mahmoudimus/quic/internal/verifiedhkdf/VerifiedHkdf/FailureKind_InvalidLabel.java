// Class FailureKind_InvalidLabel
// Dafny class FailureKind_InvalidLabel compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public class FailureKind_InvalidLabel extends FailureKind {
  public FailureKind_InvalidLabel () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FailureKind_InvalidLabel o = (FailureKind_InvalidLabel)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("VerifiedHkdf.FailureKind.InvalidLabel");
    return s.toString();
  }
}
