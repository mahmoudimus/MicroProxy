// Class Result<T>
// Dafny class Result<T> compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Result<T> {
  protected dafny.TypeDescriptor<T> _td_T;
  public Result(dafny.TypeDescriptor<T> _td_T) {
    this._td_T = _td_T;
  }
  public static <T> dafny.TypeDescriptor<Result<T>> _typeDescriptor(dafny.TypeDescriptor<T> _td_T) {
    return (dafny.TypeDescriptor<Result<T>>) (dafny.TypeDescriptor<?>) dafny.TypeDescriptor.<Result<T>>referenceWithInitializer(Result.class, () -> Result.<T>Default(_td_T));
  }

  public static <T> Result<T> Default(dafny.TypeDescriptor<T> _td_T) {
    return io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Result.<T>create_Failure(_td_T, FailureKind.Default());
  }
  public static <T> Result<T> create_Failure(dafny.TypeDescriptor<T> _td_T, FailureKind reason) {
    return new Result_Failure<T>(_td_T, reason);
  }
  public static <T> Result<T> create_Success(dafny.TypeDescriptor<T> _td_T, T value) {
    return new Result_Success<T>(_td_T, value);
  }
  public boolean is_Failure() { return this instanceof Result_Failure; }
  public boolean is_Success() { return this instanceof Result_Success; }
  public FailureKind dtor_reason() {
    Result<T> d = this;
    return ((Result_Failure<T>)d)._reason;
  }
  public T dtor_value() {
    Result<T> d = this;
    return ((Result_Success<T>)d)._value;
  }
}
