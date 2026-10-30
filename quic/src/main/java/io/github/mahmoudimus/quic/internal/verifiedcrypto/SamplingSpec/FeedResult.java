// Class FeedResult
// Dafny class FeedResult compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class FeedResult {
  public FeedResult() {
  }
  private static final dafny.TypeDescriptor<FeedResult> _TYPE = dafny.TypeDescriptor.<FeedResult>referenceWithInitializer(FeedResult.class, () -> FeedResult.Default());
  public static dafny.TypeDescriptor<FeedResult> _typeDescriptor() {
    return (dafny.TypeDescriptor<FeedResult>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final FeedResult theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.FeedResult.create_InvalidPrefix();
  public static FeedResult Default() {
    return theDefault;
  }
  public static FeedResult create_InvalidPrefix() {
    return new FeedResult_InvalidPrefix();
  }
  public static FeedResult create_InvalidBlockLength() {
    return new FeedResult_InvalidBlockLength();
  }
  public static FeedResult create_Full(dafny.DafnySequence<? extends java.math.BigInteger> coeffs, java.math.BigInteger consumed) {
    return new FeedResult_Full(coeffs, consumed);
  }
  public static FeedResult create_NeedMore(dafny.DafnySequence<? extends java.math.BigInteger> coeffs, java.math.BigInteger consumed) {
    return new FeedResult_NeedMore(coeffs, consumed);
  }
  public boolean is_InvalidPrefix() { return this instanceof FeedResult_InvalidPrefix; }
  public boolean is_InvalidBlockLength() { return this instanceof FeedResult_InvalidBlockLength; }
  public boolean is_Full() { return this instanceof FeedResult_Full; }
  public boolean is_NeedMore() { return this instanceof FeedResult_NeedMore; }
  public dafny.DafnySequence<? extends java.math.BigInteger> dtor_coeffs() {
    FeedResult d = this;
    if (d instanceof FeedResult_Full) { return ((FeedResult_Full)d)._coeffs; }
    return ((FeedResult_NeedMore)d)._coeffs;
  }
  public java.math.BigInteger dtor_consumed() {
    FeedResult d = this;
    if (d instanceof FeedResult_Full) { return ((FeedResult_Full)d)._consumed; }
    return ((FeedResult_NeedMore)d)._consumed;
  }
}
