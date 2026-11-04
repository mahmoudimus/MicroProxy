// SPDX-License-Identifier: Apache-2.0
//
// Universal two-run source-trace harnesses over the actual verified HKDF
// methods.  These call the real Extract/Expand/LabelInfo/ExpandLabel bodies
// (including their ghost trace out-parameters) and prove that, whenever the
// public shape inputs agree, the observations agree for arbitrary private
// salt/IKM/PRK/info/context byte contents and arbitrary label-unit values.
//
// The harnesses do NOT prove compiler/JVM trace preservation, physical timing,
// HMAC security, provider correctness, or Java adapter refinement.  The
// Dafny proof is the universal source-level statement; the resolved-AST
// coverage checker separately checks that every executable branch, loop,
// read, call, sequence operation and allocation has a matching observation.
include "../../dafny/hkdf/Hkdf.dfy"

module HkdfTrace {
  import opened VerifiedHkdf

  // ---------------------------------------------------------------
  // Universal paired executions over arbitrary private contents.
  // ---------------------------------------------------------------
  method CheckExtract(hashLen: int, salt1: seq<bv8>, ikm1: seq<bv8>,
                      salt2: seq<bv8>, ikm2: seq<bv8>)
    requires |salt1| == |salt2| && |ikm1| == |ikm2|
  {
    var r1, {:ghost} t1 := Extract(hashLen, salt1, ikm1);
    var r2, {:ghost} t2 := Extract(hashLen, salt2, ikm2);
    assert t1 == t2;
    assert r1.Success? == r2.Success?;
    assert r1.Success? ==> |r1.bytes| == |r2.bytes|;
    assert r1.Failure? ==> r1.reason == r2.reason;
  }

  method CheckExpand(hashLen: int, prk1: seq<bv8>, info1: seq<bv8>,
                     prk2: seq<bv8>, info2: seq<bv8>, length: int)
    requires |prk1| == |prk2| && |info1| == |info2|
  {
    var r1, {:ghost} t1 := Expand(hashLen, prk1, info1, length);
    var r2, {:ghost} t2 := Expand(hashLen, prk2, info2, length);
    assert t1 == t2;
    assert r1.Success? == r2.Success?;
    assert r1.Success? ==> |r1.bytes| == |r2.bytes|;
    assert r1.Failure? ==> r1.reason == r2.reason;
  }

  method CheckLabelInfo(labelUnits1: seq<bv16>, context1: seq<bv8>,
                        labelUnits2: seq<bv16>, context2: seq<bv8>, length: int)
    requires labelUnits1 == labelUnits2 && |context1| == |context2|
  {
    var r1, {:ghost} t1 := LabelInfo(labelUnits1, context1, length);
    var r2, {:ghost} t2 := LabelInfo(labelUnits2, context2, length);
    assert t1 == t2;
    assert r1.Success? == r2.Success?;
    assert r1.Success? ==> |r1.bytes| == |r2.bytes|;
    assert r1.Failure? ==> r1.reason == r2.reason;
  }

  method CheckExpandLabel(hashLen: int, secret1: seq<bv8>, labelUnits1: seq<bv16>,
                          context1: seq<bv8>, secret2: seq<bv8>, labelUnits2: seq<bv16>,
                          context2: seq<bv8>, length: int)
    requires |secret1| == |secret2| && labelUnits1 == labelUnits2 && |context1| == |context2|
  {
    var r1, {:ghost} t1 := ExpandLabel(hashLen, secret1, labelUnits1, context1, length);
    var r2, {:ghost} t2 := ExpandLabel(hashLen, secret2, labelUnits2, context2, length);
    assert t1 == t2;
    assert r1.Success? == r2.Success?;
    assert r1.Success? ==> |r1.bytes| == |r2.bytes|;
    assert r1.Failure? ==> r1.reason == r2.reason;
  }

  // ---------------------------------------------------------------
  // Boundary and validation cases over arbitrary secret contents.
  // ---------------------------------------------------------------
  method CheckAcceptedBoundaries(hashLen: int, ikm: seq<bv8>, prk: seq<bv8>,
                                 info: seq<bv8>, context: seq<bv8>)
    requires ValidHash(hashLen) && |prk| > 0 && |context| <= 255
  {
    // Empty salt and empty IKM are accepted by the real Extract body.
    var e, {:ghost} te := Extract(hashLen, [], ikm);
    assert e.Success? && |e.bytes| == hashLen;
    assert te == ExtractTrace(hashLen, 0, |ikm|);

    var e0, {:ghost} te0 := Extract(hashLen, [], []);
    assert e0.Success? && |e0.bytes| == hashLen;
    assert te0 == ExtractTrace(hashLen, 0, 0);

    // Zero-length output still executes the validation and the final slice.
    var z, {:ghost} tz := Expand(hashLen, prk, info, 0);
    assert z.Success? && |z.bytes| == 0;
    assert tz == ExpandTrace(hashLen, |prk|, |info|, 0);

    // Empty info and a short non-empty PRK are accepted.
    var zi, {:ghost} tzi := Expand(hashLen, [0 as bv8], [], hashLen);
    assert zi.Success? && |zi.bytes| == hashLen;
    assert tzi == ExpandTrace(hashLen, 1, 0, hashLen);

    // The RFC one-byte counter maximum is exactly 255 blocks.
    var m, {:ghost} tm := Expand(hashLen, prk, info, 255 * hashLen);
    assert m.Success? && |m.bytes| == 255 * hashLen;
    assert tm == ExpandTrace(hashLen, |prk|, |info|, 255 * hashLen);

    // Empty label/context and zero requested length are accepted (existing policy).
    var l, {:ghost} tl := LabelInfo([], context, 0);
    assert l.Success? && |l.bytes| == 10 + |context|;
    assert tl == LabelInfoTrace([], |context|, 0);

    var l0, {:ghost} tl0 := LabelInfo([], [], 0);
    assert l0.Success? && |l0.bytes| == 10;
    assert tl0 == LabelInfoTrace([], 0, 0);

    var x, {:ghost} tx := ExpandLabel(hashLen, prk, [], context, 0);
    assert x.Success? && |x.bytes| == 0;
    assert tx == ExpandLabelTrace(hashLen, |prk|, [], |context|, 0);

    var x0, {:ghost} tx0 := ExpandLabel(hashLen, prk, [], [], 0);
    assert x0.Success? && |x0.bytes| == 0;
    assert tx0 == ExpandLabelTrace(hashLen, |prk|, [], 0, 0);
  }

  method CheckAcceptedHashLengths(ikm: seq<bv8>, prk: seq<bv8>, info: seq<bv8>, context: seq<bv8>)
    requires |prk| > 0 && |context| <= 255
  {
    var a32, {:ghost} t32 := Extract(32, [], ikm);
    assert a32.Success? && |a32.bytes| == 32;
    assert t32 == ExtractTrace(32, 0, |ikm|);
    var a48, {:ghost} t48 := Extract(48, [], ikm);
    assert a48.Success? && |a48.bytes| == 48;
    assert t48 == ExtractTrace(48, 0, |ikm|);
    var a64, {:ghost} t64 := Extract(64, [], ikm);
    assert a64.Success? && |a64.bytes| == 64;
    assert t64 == ExtractTrace(64, 0, |ikm|);

    var b32, {:ghost} u32 := Expand(32, prk, info, 32);
    assert b32.Success? && |b32.bytes| == 32;
    assert u32 == ExpandTrace(32, |prk|, |info|, 32);
    var b48, {:ghost} u48 := Expand(48, prk, info, 48);
    assert b48.Success? && |b48.bytes| == 48;
    assert u48 == ExpandTrace(48, |prk|, |info|, 48);
    var b64, {:ghost} u64 := Expand(64, prk, info, 64);
    assert b64.Success? && |b64.bytes| == 64;
    assert u64 == ExpandTrace(64, |prk|, |info|, 64);
  }

  method CheckInvalidHash(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>)
    requires !ValidHash(hashLen)
  {
    var r, {:ghost} t := Extract(hashLen, salt, ikm);
    assert r == Failure(InvalidHash);
    assert t == ExtractTrace(hashLen, |salt|, |ikm|);
  }

  method CheckInvalidLengthExpand(hashLen: int, prk: seq<bv8>, info: seq<bv8>, length: int)
    requires ValidHash(hashLen) && (length < 0 || length > 255 * hashLen)
  {
    var r, {:ghost} t := Expand(hashLen, prk, info, length);
    assert r == Failure(InvalidLength);
    assert t == ExpandTrace(hashLen, |prk|, |info|, length);
  }

  method CheckInvalidKeyExpand(hashLen: int, info: seq<bv8>, length: int)
    requires ValidHash(hashLen) && 0 <= length <= 255 * hashLen
  {
    var r, {:ghost} t := Expand(hashLen, [], info, length);
    assert r == Failure(InvalidKey);
    assert t == ExpandTrace(hashLen, 0, |info|, length);
  }

  method CheckInvalidLengthLabel(labelUnits: seq<bv16>, context: seq<bv8>, length: int)
    requires length < 0 || length > 65535 || |labelUnits| > 249 || |context| > 255
  {
    var r, {:ghost} t := LabelInfo(labelUnits, context, length);
    assert r == Failure(InvalidLength);
    assert t == LabelInfoTrace(labelUnits, |context|, length);
  }

  method CheckInvalidLabel(labelUnits: seq<bv16>, context: seq<bv8>, length: int)
    requires LabelLengthsValid(labelUnits, context, length) && !Ascii(labelUnits)
  {
    var r, {:ghost} t := LabelInfo(labelUnits, context, length);
    assert r == Failure(InvalidLabel);
    assert t == LabelInfoTrace(labelUnits, |context|, length);
  }
}
