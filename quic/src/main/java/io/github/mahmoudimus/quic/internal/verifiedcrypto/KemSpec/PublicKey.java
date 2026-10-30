// Class PublicKey
// Dafny class PublicKey compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class PublicKey {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> _matrix;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> _t;
  public dafny.DafnySequence<? extends java.lang.Byte> _rho;
  public dafny.DafnySequence<? extends java.lang.Byte> _encoded;
  public dafny.DafnySequence<? extends java.lang.Byte> _hash;
  public PublicKey (dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> matrix, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> t, dafny.DafnySequence<? extends java.lang.Byte> rho, dafny.DafnySequence<? extends java.lang.Byte> encoded, dafny.DafnySequence<? extends java.lang.Byte> hash) {
    this._matrix = matrix;
    this._t = t;
    this._rho = rho;
    this._encoded = encoded;
    this._hash = hash;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    PublicKey o = (PublicKey)other;
    return true && java.util.Objects.equals(this._matrix, o._matrix) && java.util.Objects.equals(this._t, o._t) && java.util.Objects.equals(this._rho, o._rho) && java.util.Objects.equals(this._encoded, o._encoded) && java.util.Objects.equals(this._hash, o._hash);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._matrix);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._t);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._rho);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._encoded);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._hash);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("KemSpec.PublicKey.PublicKey");
    s.append("(");
    s.append(dafny.Helpers.toString(this._matrix));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._t));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._rho));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._encoded));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._hash));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<PublicKey> _TYPE = dafny.TypeDescriptor.<PublicKey>referenceWithInitializer(PublicKey.class, () -> PublicKey.Default());
  public static dafny.TypeDescriptor<PublicKey> _typeDescriptor() {
    return (dafny.TypeDescriptor<PublicKey>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final PublicKey theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.PublicKey.create(dafny.DafnySequence.<dafny.DafnySequence<? extends java.math.BigInteger>> empty(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER)), dafny.DafnySequence.<dafny.DafnySequence<? extends java.math.BigInteger>> empty(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER)), dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE), dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE), dafny.DafnySequence.<java.lang.Byte> empty(dafny.TypeDescriptor.BYTE));
  public static PublicKey Default() {
    return theDefault;
  }
  public static PublicKey create(dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> matrix, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> t, dafny.DafnySequence<? extends java.lang.Byte> rho, dafny.DafnySequence<? extends java.lang.Byte> encoded, dafny.DafnySequence<? extends java.lang.Byte> hash) {
    return new PublicKey(matrix, t, rho, encoded, hash);
  }
  public static PublicKey create_PublicKey(dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> matrix, dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> t, dafny.DafnySequence<? extends java.lang.Byte> rho, dafny.DafnySequence<? extends java.lang.Byte> encoded, dafny.DafnySequence<? extends java.lang.Byte> hash) {
    return create(matrix, t, rho, encoded, hash);
  }
  public boolean is_PublicKey() { return true; }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> dtor_matrix() {
    return this._matrix;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends java.math.BigInteger>> dtor_t() {
    return this._t;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_rho() {
    return this._rho;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_encoded() {
    return this._encoded;
  }
  public dafny.DafnySequence<? extends java.lang.Byte> dtor_hash() {
    return this._hash;
  }
}
