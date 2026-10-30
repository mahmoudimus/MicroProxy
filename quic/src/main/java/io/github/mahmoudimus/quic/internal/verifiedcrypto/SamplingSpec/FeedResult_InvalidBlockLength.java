// Class FeedResult_InvalidBlockLength
// Dafny class FeedResult_InvalidBlockLength compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class FeedResult_InvalidBlockLength extends FeedResult {
  public FeedResult_InvalidBlockLength () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    FeedResult_InvalidBlockLength o = (FeedResult_InvalidBlockLength)other;
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
    s.append("SamplingSpec.FeedResult.InvalidBlockLength");
    return s.toString();
  }
}
