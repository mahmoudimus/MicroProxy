// Class FailureKind_InvalidSeedLength
// Dafny class FailureKind_InvalidSeedLength compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class FailureKind_InvalidSeedLength extends FailureKind {
  public FailureKind_InvalidSeedLength () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FailureKind_InvalidSeedLength o = (FailureKind_InvalidSeedLength)other;
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
    s.append("KemSpec.FailureKind.InvalidSeedLength");
    return s.toString();
  }
}
