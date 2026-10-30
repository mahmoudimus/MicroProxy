// Class DecodeResult
// Dafny class DecodeResult compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class DecodeResult {
  public DecodeResult() {
  }
  private static final dafny.TypeDescriptor<DecodeResult> _TYPE = dafny.TypeDescriptor.<DecodeResult>referenceWithInitializer(DecodeResult.class, () -> DecodeResult.Default());
  public static dafny.TypeDescriptor<DecodeResult> _typeDescriptor() {
    return (dafny.TypeDescriptor<DecodeResult>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final DecodeResult theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.DecodeResult.create_InvalidWidth();
  public static DecodeResult Default() {
    return theDefault;
  }
  public static DecodeResult create_InvalidWidth() {
    return new DecodeResult_InvalidWidth();
  }
  public static DecodeResult create_InvalidLength() {
    return new DecodeResult_InvalidLength();
  }
  public static DecodeResult create_ModulusError() {
    return new DecodeResult_ModulusError();
  }
  public static DecodeResult create_Decoded(int[] words) {
    return new DecodeResult_Decoded(words);
  }
  public boolean is_InvalidWidth() { return this instanceof DecodeResult_InvalidWidth; }
  public boolean is_InvalidLength() { return this instanceof DecodeResult_InvalidLength; }
  public boolean is_ModulusError() { return this instanceof DecodeResult_ModulusError; }
  public boolean is_Decoded() { return this instanceof DecodeResult_Decoded; }
  public int[] dtor_words() {
    DecodeResult d = this;
    return ((DecodeResult_Decoded)d)._words;
  }
}
