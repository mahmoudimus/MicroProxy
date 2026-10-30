// Class PublicKey
// Dafny class PublicKey compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeKeccak.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolynomialRing.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.VerifiedPolynomial.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativePolynomial.*;

@SuppressWarnings({"unchecked", "deprecation"})
public class PublicKey {
  public PublicKey() {
    this.destroyed = false;
    this._matrix = new int[0][];
    this._t = new int[0][];
    this._rho = new byte[0];
    this._encoded = new byte[0];
    this._hash = new byte[0];
  }
  public boolean destroyed;
  public void __ctor(int[][] a, int[][] words, byte[] seed, byte[] bytes, byte[] digest)
  {
    (this)._matrix = a;
    (this)._t = words;
    (this)._rho = seed;
    (this)._encoded = bytes;
    (this)._hash = digest;
    (this).destroyed = false;
  }
  public void Destroy()
  {
    __default.WipePolys((this).matrix());
    __default.WipePolys((this).t());
    __default.WipeBytes((this).rho());
    __default.WipeBytes((this).encoded());
    __default.WipeBytes((this).hash());
    (this).destroyed = true;
  }
  public int[][] _matrix;
  public int[][] matrix()
  {
    return this._matrix;
  }
  public int[][] _t;
  public int[][] t()
  {
    return this._t;
  }
  public byte[] _rho;
  public byte[] rho()
  {
    return this._rho;
  }
  public byte[] _encoded;
  public byte[] encoded()
  {
    return this._encoded;
  }
  public byte[] _hash;
  public byte[] hash()
  {
    return this._hash;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.PublicKey";
  }
}
