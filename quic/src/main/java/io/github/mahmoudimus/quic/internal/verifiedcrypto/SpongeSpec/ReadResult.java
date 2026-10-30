// Class ReadResult
// Dafny class ReadResult compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class ReadResult {
  public State _state;
  public dafny.DafnySequence<? extends java.lang.Byte> _bytes;
  public ReadResult (State state, dafny.DafnySequence<? extends java.lang.Byte> bytes) {
    this._state = state;
    this._bytes = bytes;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ReadResult o = (ReadResult)other;
    return true && java.util.Objects.equals(this._state, o._state) && java.util.Objects.equals(this._bytes, o._bytes);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._state);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._bytes);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("SpongeSpec.ReadResult.ReadResult");
    s.append("(");
    s.append(dafny.Helpers.toString(this._state));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._bytes));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<ReadResult> _TYPE = dafny.TypeDescriptor.<ReadResult>referenceWithInitializer(ReadResult.class, () -> ReadResult.Default());
  public static dafny.TypeDescriptor<ReadResult> _typeDescriptor() {
    return (dafny.TypeDescriptor<ReadResult>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final ReadResult theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.ReadResult.create(State.Default(), dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE));
  public static ReadResult Default() {
    return theDefault;
  }
  public static ReadResult create(State state, dafny.DafnySequence<? extends java.lang.Byte> bytes) {
    return new ReadResult(state, bytes);
  }
  public static ReadResult create_ReadResult(State state, dafny.DafnySequence<? extends java.lang.Byte> bytes) {
    return create(state, bytes);
  }
  public boolean is_ReadResult() { return true; }
  public State dtor_state() {
    return this._state;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_bytes() {
    return this._bytes;
  }
}
