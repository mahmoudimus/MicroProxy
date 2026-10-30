// Class SecretKey
// Dafny class SecretKey compiled into Java
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
public class SecretKey {
  public SecretKey() {
    this.destroyed = false;
    this._s = new int[0][];
    this._ek = null;
    this._seed = new byte[0];
  }
  public boolean destroyed;
  public void __ctor(byte[] bytes, int[][] words, PublicKey publicKey)
  {
    (this)._seed = bytes;
    (this)._s = words;
    (this)._ek = publicKey;
    (this).destroyed = false;
  }
  public void Destroy()
  {
    __default.WipeBytes((this).seed());
    __default.WipePolys((this).s());
    ((this).ek()).Destroy();
    (this).destroyed = true;
  }
  public int[][] _s;
  public int[][] s()
  {
    return this._s;
  }
  public PublicKey _ek;
  public PublicKey ek()
  {
    return this._ek;
  }
  public byte[] _seed;
  public byte[] seed()
  {
    return this._seed;
  }
  @Override
  public java.lang.String toString() {
    return "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.SecretKey";
  }
}
