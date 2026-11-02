// Verified QUIC packet-number nonce construction.
//
// The production operation is exactly the old handwritten PacketKey.nonce:
// given a 12-byte IV and a full 64-bit packet number, allocate a fresh 12-byte
// array, copy the first four IV bytes unchanged, and replace each of the last
// eight bytes with iv[4+j] XOR the big-endian byte j of the packet number.
//
// Domain: iv.Length == 12 is the only caller precondition, matching the
// PacketKey constructor check. The packet number has no precondition: all
// 2^64 bit patterns are in the domain, including Java longs whose sign bit is
// set. There is no 62-bit packet-number restriction here; that protocol-level
// limit is a caller policy, not part of this primitive.
//
// This file proves the byte-array operation and its specification, not AEAD
// security, crypto hardness, JVM timing, constant-time execution, or erasure.
// It has no {:axiom}, {:extern}, assume, or {:verify false} declaration. The
// checked-in generated Java is produced by the pinned Dafny compiler from this
// exact source and is compared byte for byte during replay.

module VerifiedNonce {

  // The big-endian bytes of a bv64. B0 is the least significant byte and B7
  // is the most significant byte. They are ghost specification functions; the
  // executable body below extracts the same bytes with primitive long shifts,
  // masks and byte casts, so the generated Java has no sequence or per-byte
  // boxed payload path. Bridge assertions prove each body byte equals its Bk.
  ghost function B0(pn: bv64): bv8 { (pn & 0xFF) as bv8 }
  ghost function B1(pn: bv64): bv8 { ((pn >> 8) & 0xFF) as bv8 }
  ghost function B2(pn: bv64): bv8 { ((pn >> 16) & 0xFF) as bv8 }
  ghost function B3(pn: bv64): bv8 { ((pn >> 24) & 0xFF) as bv8 }
  ghost function B4(pn: bv64): bv8 { ((pn >> 32) & 0xFF) as bv8 }
  ghost function B5(pn: bv64): bv8 { ((pn >> 40) & 0xFF) as bv8 }
  ghost function B6(pn: bv64): bv8 { ((pn >> 48) & 0xFF) as bv8 }
  ghost function B7(pn: bv64): bv8 { ((pn >> 56) & 0xFF) as bv8 }

  // Mathematical big-endian encoding, most significant byte first.
  ghost function PacketNumberBytes(pn: bv64): seq<bv8>
    ensures |PacketNumberBytes(pn)| == 8
  {
    [ B7(pn), B6(pn), B5(pn), B4(pn), B3(pn), B2(pn), B1(pn), B0(pn) ]
  }

  // The complete 12-byte mathematical result under a fixed IV.
  ghost function NonceBytes(iv: seq<bv8>, pn: bv64): seq<bv8>
    requires |iv| == 12
    ensures |NonceBytes(iv, pn)| == 12
    ensures NonceBytes(iv, pn)[..4] == iv[..4]
  {
    iv[..4] + [ iv[4] ^ B7(pn), iv[5] ^ B6(pn), iv[6] ^ B5(pn), iv[7] ^ B4(pn),
                iv[8] ^ B3(pn), iv[9] ^ B2(pn), iv[10] ^ B1(pn), iv[11] ^ B0(pn) ]
  }

  // XOR with a fixed byte is cancellative.
  lemma XorCancel(a: bv8, x: bv8, y: bv8)
    requires a ^ x == a ^ y
    ensures x == y
  {
  }

  // Eight byte extractions determine the whole 64-bit packet number.
  lemma Decompose(p: bv64)
    ensures p == ((B7(p) as bv64) << 56) | ((B6(p) as bv64) << 48)
              | ((B5(p) as bv64) << 40) | ((B4(p) as bv64) << 32)
              | ((B3(p) as bv64) << 24) | ((B2(p) as bv64) << 16)
              | ((B1(p) as bv64) << 8) | (B0(p) as bv64)
  {
  }

  // Big-endian byte equality implies packet-number equality. This is the
  // scalar packing lemma used by the full array/spec injectivity proof.
  lemma PacketNumberBytesInjective(p: bv64, q: bv64)
    requires B7(p) == B7(q) && B6(p) == B6(q) && B5(p) == B5(q) && B4(p) == B4(q)
          && B3(p) == B3(q) && B2(p) == B2(q) && B1(p) == B1(q) && B0(p) == B0(q)
    ensures p == q
  {
    Decompose(p);
    Decompose(q);
  }

  // Injectivity of the full 12-byte mathematical result under a fixed IV.
  // The four unchanged prefix bytes carry no packet-number information, so
  // the eight XORed tail bytes must determine the packet number. The
  // {:isolate_assertions} attribute is a solver-granularity choice only: every
  // assertion is still verified, with no trusted step added.
  lemma {:isolate_assertions} NonceBytesInjective(iv: seq<bv8>, p: bv64, q: bv64)
    requires |iv| == 12
    requires NonceBytes(iv, p) == NonceBytes(iv, q)
    ensures p == q
  {
    assert NonceBytes(iv, p)[4] == NonceBytes(iv, q)[4];
    assert NonceBytes(iv, p)[5] == NonceBytes(iv, q)[5];
    assert NonceBytes(iv, p)[6] == NonceBytes(iv, q)[6];
    assert NonceBytes(iv, p)[7] == NonceBytes(iv, q)[7];
    assert NonceBytes(iv, p)[8] == NonceBytes(iv, q)[8];
    assert NonceBytes(iv, p)[9] == NonceBytes(iv, q)[9];
    assert NonceBytes(iv, p)[10] == NonceBytes(iv, q)[10];
    assert NonceBytes(iv, p)[11] == NonceBytes(iv, q)[11];
    XorCancel(iv[4], B7(p), B7(q));
    XorCancel(iv[5], B6(p), B6(q));
    XorCancel(iv[6], B5(p), B5(q));
    XorCancel(iv[7], B4(p), B4(q));
    XorCancel(iv[8], B3(p), B3(q));
    XorCancel(iv[9], B2(p), B2(q));
    XorCancel(iv[10], B1(p), B1(q));
    XorCancel(iv[11], B0(p), B0(q));
    PacketNumberBytesInjective(p, q);
  }

  // Contrapositive form: distinct packet numbers yield distinct nonces under
  // the same fixed IV, at the mathematical byte-sequence level.
  lemma NonceBytesDistinct(iv: seq<bv8>, p: bv64, q: bv64)
    requires |iv| == 12
    requires p != q
    ensures NonceBytes(iv, p) != NonceBytes(iv, q)
  {
    if NonceBytes(iv, p) == NonceBytes(iv, q) {
      NonceBytesInjective(iv, p, q);
    }
  }

  // Array-level injectivity: two calls under the same fixed IV whose fresh
  // output arrays have equal contents must have received the same packet
  // number. This is not inferred from a scalar model; it uses the method
  // postconditions that relate both arrays to NonceBytes.
  lemma NonceContentsInjective(iv: array<bv8>, p: bv64, q: bv64,
                               a: array<bv8>, b: array<bv8>)
    requires iv.Length == 12 && a.Length == 12 && b.Length == 12
    requires a[..] == NonceBytes(iv[..], p)
    requires b[..] == NonceBytes(iv[..], q)
    requires a[..] == b[..]
    ensures p == q
  {
    NonceBytesInjective(iv[..], p, q);
  }

  // Primitive byte-array implementation. The postcondition is deliberately
  // elementwise as well as whole-sequence: the first four bytes are copied,
  // the last eight bytes are the big-endian XOR, the output is a new 12-byte
  // array, and the caller's IV is unchanged. Every output element is proven.
  method {:isolate_assertions} Nonce(iv: array<bv8>, pn: bv64) returns (nonce: array<bv8>)
    requires iv.Length == 12
    ensures nonce.Length == 12
    ensures nonce != iv
    ensures iv[..] == old(iv[..])
    ensures nonce[0] == old(iv[0]) && nonce[1] == old(iv[1])
         && nonce[2] == old(iv[2]) && nonce[3] == old(iv[3])
    ensures nonce[4] == old(iv[4]) ^ B7(pn)
    ensures nonce[5] == old(iv[5]) ^ B6(pn)
    ensures nonce[6] == old(iv[6]) ^ B5(pn)
    ensures nonce[7] == old(iv[7]) ^ B4(pn)
    ensures nonce[8] == old(iv[8]) ^ B3(pn)
    ensures nonce[9] == old(iv[9]) ^ B2(pn)
    ensures nonce[10] == old(iv[10]) ^ B1(pn)
    ensures nonce[11] == old(iv[11]) ^ B0(pn)
    ensures nonce[..] == NonceBytes(old(iv[..]), pn)
  {
    nonce := new bv8[12];
    nonce[0] := iv[0]; nonce[1] := iv[1]; nonce[2] := iv[2]; nonce[3] := iv[3];
    nonce[4] := iv[4] ^ ((pn >> 56) & 0xFF) as bv8;
    nonce[5] := iv[5] ^ ((pn >> 48) & 0xFF) as bv8;
    nonce[6] := iv[6] ^ ((pn >> 40) & 0xFF) as bv8;
    nonce[7] := iv[7] ^ ((pn >> 32) & 0xFF) as bv8;
    nonce[8] := iv[8] ^ ((pn >> 24) & 0xFF) as bv8;
    nonce[9] := iv[9] ^ ((pn >> 16) & 0xFF) as bv8;
    nonce[10] := iv[10] ^ ((pn >> 8) & 0xFF) as bv8;
    nonce[11] := iv[11] ^ (pn & 0xFF) as bv8;
    // Name the twelve concrete sequence elements so the whole-sequence
    // postcondition does not require one monolithic solver query.
    assert nonce[0] == NonceBytes(old(iv[..]), pn)[0];
    assert nonce[1] == NonceBytes(old(iv[..]), pn)[1];
    assert nonce[2] == NonceBytes(old(iv[..]), pn)[2];
    assert nonce[3] == NonceBytes(old(iv[..]), pn)[3];
    assert nonce[4] == NonceBytes(old(iv[..]), pn)[4];
    assert nonce[5] == NonceBytes(old(iv[..]), pn)[5];
    assert nonce[6] == NonceBytes(old(iv[..]), pn)[6];
    assert nonce[7] == NonceBytes(old(iv[..]), pn)[7];
    assert nonce[8] == NonceBytes(old(iv[..]), pn)[8];
    assert nonce[9] == NonceBytes(old(iv[..]), pn)[9];
    assert nonce[10] == NonceBytes(old(iv[..]), pn)[10];
    assert nonce[11] == NonceBytes(old(iv[..]), pn)[11];
  }
}
