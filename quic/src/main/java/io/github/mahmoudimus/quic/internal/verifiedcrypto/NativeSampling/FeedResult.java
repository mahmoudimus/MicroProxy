// Class FeedResult
// Dafny class FeedResult compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedSampling.*;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class FeedResult {
  public FeedResult() {
  }
  private static final dafny.TypeDescriptor<FeedResult> _TYPE = dafny.TypeDescriptor.<FeedResult>referenceWithInitializer(FeedResult.class, () -> FeedResult.Default());
  public static dafny.TypeDescriptor<FeedResult> _typeDescriptor() {
    return (dafny.TypeDescriptor<FeedResult>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final FeedResult theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.FeedResult.create_InvalidPrefix();
  public static FeedResult Default() {
    return theDefault;
  }
  public static FeedResult create_InvalidPrefix() {
    return new FeedResult_InvalidPrefix();
  }
  public static FeedResult create_InvalidBlockLength() {
    return new FeedResult_InvalidBlockLength();
  }
  public static FeedResult create_Full(int[] coeffs, int consumed) {
    return new FeedResult_Full(coeffs, consumed);
  }
  public static FeedResult create_NeedMore(int[] coeffs, int consumed) {
    return new FeedResult_NeedMore(coeffs, consumed);
  }
  public boolean is_InvalidPrefix() { return this instanceof FeedResult_InvalidPrefix; }
  public boolean is_InvalidBlockLength() { return this instanceof FeedResult_InvalidBlockLength; }
  public boolean is_Full() { return this instanceof FeedResult_Full; }
  public boolean is_NeedMore() { return this instanceof FeedResult_NeedMore; }
  public int[] dtor_coeffs() {
    FeedResult d = this;
    if (d instanceof FeedResult_Full) { return ((FeedResult_Full)d)._coeffs; }
    return ((FeedResult_NeedMore)d)._coeffs;
  }
  public int dtor_consumed() {
    FeedResult d = this;
    if (d instanceof FeedResult_Full) { return ((FeedResult_Full)d)._consumed; }
    return ((FeedResult_NeedMore)d)._consumed;
  }
}
