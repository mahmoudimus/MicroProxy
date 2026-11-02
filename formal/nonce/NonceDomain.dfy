// Universal public-domain checks for VerifiedNonce.Nonce.
//
// These methods deliberately quantify over an unconstrained 64-bit packet
// number and an arbitrary 12-byte IV. They prove that the implementation's
// postconditions cover every packet-number bit pattern, that equal output
// contents imply equal packet numbers under a fixed IV, and that distinct
// packet numbers produce distinct output contents. They are verified with the
// kernel source included by the replay runner.

include "Nonce.dfy"

module NonceDomain {
  import V = VerifiedNonce

  // All 2^64 packet-number patterns are accepted. There is no packet-number
  // precondition, no 62-bit narrowing, and no sign-bit restriction.
  method AllPacketNumbers(iv: array<bv8>, pn: bv64)
    requires iv.Length == 12
  {
    var nonce := V.Nonce(iv, pn);
    assert nonce.Length == 12;
    assert nonce != iv;
    assert nonce[..] == V.NonceBytes(iv[..], pn);
    assert nonce[0] == iv[0] && nonce[1] == iv[1]
        && nonce[2] == iv[2] && nonce[3] == iv[3];
    assert nonce[4] == iv[4] ^ V.B7(pn);
    assert nonce[5] == iv[5] ^ V.B6(pn);
    assert nonce[6] == iv[6] ^ V.B5(pn);
    assert nonce[7] == iv[7] ^ V.B4(pn);
    assert nonce[8] == iv[8] ^ V.B3(pn);
    assert nonce[9] == iv[9] ^ V.B2(pn);
    assert nonce[10] == iv[10] ^ V.B1(pn);
    assert nonce[11] == iv[11] ^ V.B0(pn);
  }

  // Array-level injectivity under one fixed IV: two fresh outputs with equal
  // contents cannot come from different packet numbers.
  method EqualContentsImplyEqualPacketNumbers(iv: array<bv8>, p: bv64, q: bv64)
    requires iv.Length == 12
  {
    var a := V.Nonce(iv, p);
    var b := V.Nonce(iv, q);
    assert a[..] == V.NonceBytes(iv[..], p);
    assert b[..] == V.NonceBytes(iv[..], q);
    if a[..] == b[..] {
      V.NonceContentsInjective(iv, p, q, a, b);
      assert p == q;
    }
  }

  // The contrapositive, directly at the byte-array content level: distinct
  // packet numbers give different 12-byte nonce contents.
  method DistinctPacketNumbersHaveDistinctNonces(iv: array<bv8>, p: bv64, q: bv64)
    requires iv.Length == 12
    requires p != q
  {
    V.NonceBytesDistinct(iv[..], p, q);
    var a := V.Nonce(iv, p);
    var b := V.Nonce(iv, q);
    assert a[..] == V.NonceBytes(iv[..], p);
    assert b[..] == V.NonceBytes(iv[..], q);
    assert a[..] != b[..];
  }
}
