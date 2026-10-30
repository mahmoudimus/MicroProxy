// Class UpdateResult
// Dafny class UpdateResult compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class UpdateResult {
  public UpdateResult() {
  }
  private static final dafny.TypeDescriptor<UpdateResult> _TYPE = dafny.TypeDescriptor.<UpdateResult>referenceWithInitializer(UpdateResult.class, () -> UpdateResult.Default());
  public static dafny.TypeDescriptor<UpdateResult> _typeDescriptor() {
    return (dafny.TypeDescriptor<UpdateResult>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final UpdateResult theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.UpdateResult.create_Updated(State.Default());
  public static UpdateResult Default() {
    return theDefault;
  }
  public static UpdateResult create_Updated(State state) {
    return new UpdateResult_Updated(state);
  }
  public static UpdateResult create_InputAfterOutput() {
    return new UpdateResult_InputAfterOutput();
  }
  public static UpdateResult create_InvalidSlice() {
    return new UpdateResult_InvalidSlice();
  }
  public boolean is_Updated() { return this instanceof UpdateResult_Updated; }
  public boolean is_InputAfterOutput() { return this instanceof UpdateResult_InputAfterOutput; }
  public boolean is_InvalidSlice() { return this instanceof UpdateResult_InvalidSlice; }
  public State dtor_state() {
    UpdateResult d = this;
    return ((UpdateResult_Updated)d)._state;
  }
}
