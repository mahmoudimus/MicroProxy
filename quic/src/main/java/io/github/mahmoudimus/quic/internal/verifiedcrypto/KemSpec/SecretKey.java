// Class SecretKey
// Dafny class SecretKey compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class SecretKey {
  public dafny.DafnySequence<? extends java.lang.Byte> _seed;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> _s;
  public PublicKey _ek;
  public SecretKey (dafny.DafnySequence<? extends java.lang.Byte> seed, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> s, PublicKey ek) {
    this._seed = seed;
    this._s = s;
    this._ek = ek;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    SecretKey o = (SecretKey)other;
    return true && java.util.Objects.equals(this._seed, o._seed) && java.util.Objects.equals(this._s, o._s) && java.util.Objects.equals(this._ek, o._ek);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._seed);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._s);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ek);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder ss = new StringBuilder();
    ss.append("KemSpec.SecretKey.SecretKey");
    ss.append("(");
    ss.append(dafny.Helpers.toString(this._seed));
    ss.append(", ");
    ss.append(dafny.Helpers.toString(this._s));
    ss.append(", ");
    ss.append(dafny.Helpers.toString(this._ek));
    ss.append(")");
    return ss.toString();
  }
  private static final dafny.TypeDescriptor<SecretKey> _TYPE = dafny.TypeDescriptor.<SecretKey>referenceWithInitializer(SecretKey.class, () -> SecretKey.Default());
  public static dafny.TypeDescriptor<SecretKey> _typeDescriptor() {
    return (dafny.TypeDescriptor<SecretKey>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final SecretKey theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.SecretKey.create(dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE), dafny.DafnySequence.<dafny.DafnySequence<? extends java.math.BigInteger>> empty(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER)), PublicKey.Default());
  public static SecretKey Default() {
    return theDefault;
  }
  public static SecretKey create(dafny.DafnySequence<? extends java.lang.Byte> seed, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> s, PublicKey ek) {
    return new SecretKey(seed, s, ek);
  }
  public static SecretKey create_SecretKey(dafny.DafnySequence<? extends java.lang.Byte> seed, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> s, PublicKey ek) {
    return create(seed, s, ek);
  }
  public boolean is_SecretKey() { return true; }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_seed() {
    return this._seed;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> dtor_s() {
    return this._s;
  }
  public PublicKey dtor_ek() {
    return this._ek;
  }
}
