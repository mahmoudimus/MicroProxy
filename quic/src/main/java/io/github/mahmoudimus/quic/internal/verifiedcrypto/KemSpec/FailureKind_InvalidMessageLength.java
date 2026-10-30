// Class FailureKind_InvalidMessageLength
// Dafny class FailureKind_InvalidMessageLength compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class FailureKind_InvalidMessageLength extends FailureKind {
  public FailureKind_InvalidMessageLength () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FailureKind_InvalidMessageLength o = (FailureKind_InvalidMessageLength)other;
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
    s.append("KemSpec.FailureKind.InvalidMessageLength");
    return s.toString();
  }
}
