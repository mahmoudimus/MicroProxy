// Class State
// Dafny class State compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class State {
  public dafny.DafnySequence<? extends java.lang.Long> _lanes;
  public java.math.BigInteger _rate;
  public java.math.BigInteger _position;
  public boolean _squeezing;
  public State (dafny.DafnySequence<? extends java.lang.Long> lanes, java.math.BigInteger rate, java.math.BigInteger position, boolean squeezing) {
    this._lanes = lanes;
    this._rate = rate;
    this._position = position;
    this._squeezing = squeezing;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    State o = (State)other;
    return true && java.util.Objects.equals(this._lanes, o._lanes) && java.util.Objects.equals(this._rate, o._rate) && java.util.Objects.equals(this._position, o._position) && this._squeezing == o._squeezing;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._lanes);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._rate);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._position);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._squeezing);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("SpongeSpec.State.State");
    s.append("(");
    s.append(dafny.Helpers.toString(this._lanes));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._rate));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._position));
    s.append(", ");
    s.append(this._squeezing);
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<State> _TYPE = dafny.TypeDescriptor.<State>referenceWithInitializer(State.class, () -> State.Default());
  public static dafny.TypeDescriptor<State> _typeDescriptor() {
    return (dafny.TypeDescriptor<State>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final State theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.State.create(dafny.DafnySequence.<java.lang.Long> empty(dafny.TypeDescriptor.LONG), java.math.BigInteger.ZERO, java.math.BigInteger.ZERO, false);
  public static State Default() {
    return theDefault;
  }
  public static State create(dafny.DafnySequence<? extends java.lang.Long> lanes, java.math.BigInteger rate, java.math.BigInteger position, boolean squeezing) {
    return new State(lanes, rate, position, squeezing);
  }
  public static State create_State(dafny.DafnySequence<? extends java.lang.Long> lanes, java.math.BigInteger rate, java.math.BigInteger position, boolean squeezing) {
    return create(lanes, rate, position, squeezing);
  }
  public boolean is_State() { return true; }
  public dafny.DafnySequence<? extends java.lang.Long> dtor_lanes() {
    return this._lanes;
  }
  public java.math.BigInteger dtor_rate() {
    return this._rate;
  }
  public java.math.BigInteger dtor_position() {
    return this._position;
  }
  public boolean dtor_squeezing() {
    return this._squeezing;
  }
}
