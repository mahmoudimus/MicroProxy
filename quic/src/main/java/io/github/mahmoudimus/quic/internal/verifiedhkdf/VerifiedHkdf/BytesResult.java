// Class BytesResult
// Dafny class BytesResult compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public abstract class BytesResult {
  public BytesResult() {
  }
  private static final dafny.TypeDescriptor<BytesResult> _TYPE = dafny.TypeDescriptor.<BytesResult>referenceWithInitializer(BytesResult.class, () -> BytesResult.Default());
  public static dafny.TypeDescriptor<BytesResult> _typeDescriptor() {
    return (dafny.TypeDescriptor<BytesResult>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final BytesResult theDefault = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult.create_Success(dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE));
  public static BytesResult Default() {
    return theDefault;
  }
  public static BytesResult create_Success(dafny.DafnySequence<? extends java.lang.Byte> bytes) {
    return new BytesResult_Success(bytes);
  }
  public static BytesResult create_Failure(FailureKind reason) {
    return new BytesResult_Failure(reason);
  }
  public boolean is_Success() { return this instanceof BytesResult_Success; }
  public boolean is_Failure() { return this instanceof BytesResult_Failure; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_bytes() {
    BytesResult d = this;
    return ((BytesResult_Success)d)._bytes;
  }
  public FailureKind dtor_reason() {
    BytesResult d = this;
    return ((BytesResult_Failure)d)._reason;
  }
}
