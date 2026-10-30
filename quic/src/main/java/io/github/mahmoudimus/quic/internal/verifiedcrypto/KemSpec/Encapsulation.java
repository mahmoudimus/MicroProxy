// Class Encapsulation
// Dafny class Encapsulation compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class Encapsulation {
  public dafny.DafnySequence<? extends java.lang.Byte> _key;
  public dafny.DafnySequence<? extends java.lang.Byte> _ciphertext;
  public Encapsulation (dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    this._key = key;
    this._ciphertext = ciphertext;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Encapsulation o = (Encapsulation)other;
    return true && java.util.Objects.equals(this._key, o._key) && java.util.Objects.equals(this._ciphertext, o._ciphertext);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ciphertext);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("KemSpec.Encapsulation.Encapsulation");
    s.append("(");
    s.append(dafny.Helpers.toString(this._key));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._ciphertext));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Encapsulation> _TYPE = dafny.TypeDescriptor.<Encapsulation>referenceWithInitializer(Encapsulation.class, () -> Encapsulation.Default());
  public static dafny.TypeDescriptor<Encapsulation> _typeDescriptor() {
    return (dafny.TypeDescriptor<Encapsulation>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Encapsulation theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.Encapsulation.create(dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE), dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE));
  public static Encapsulation Default() {
    return theDefault;
  }
  public static Encapsulation create(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    return new Encapsulation(key, ciphertext);
  }
  public static Encapsulation create_Encapsulation(dafny.DafnySequence<? extends java.lang.Byte> key, dafny.DafnySequence<? extends java.lang.Byte> ciphertext) {
    return create(key, ciphertext);
  }
  public boolean is_Encapsulation() { return true; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_key() {
    return this._key;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_ciphertext() {
    return this._ciphertext;
  }
}
