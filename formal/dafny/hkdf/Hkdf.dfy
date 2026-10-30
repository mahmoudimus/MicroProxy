// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// The RFC 5869 feedback/accumulator proof structure is adapted from AWS
// aws-cryptographic-material-providers-library, AwsCryptographyPrimitives/src/
// HKDF/HKDF.dfy at c787ad12612ac0f35975afe9209e5dbe6b546654.
// This standalone kernel uses deterministic mathematical block functions and
// proves full result equations. The external Mac contract below is its sole
// trusted assumption. Java/JCE binding correctness and timing are outside it.
module VerifiedHkdf {
  datatype FailureKind = InvalidHash | InvalidKey | InvalidLength | InvalidLabel
  datatype BytesResult = Success(bytes: seq<bv8>) | Failure(reason: FailureKind)

  predicate ValidHash(hashLen: int) { hashLen in {32, 48, 64} }

  // Deterministic abstract HMAC. The adapter must implement the requested
  // SHA-256, SHA-384, or SHA-512 HMAC and satisfy the output-length contract.
  function {:extern "io.github.mahmoudimus.verifiedcrypto.JdkHmac", "compute"} {:axiom}
    Mac(hashLen: int, key: seq<bv8>, input: seq<bv8>): seq<bv8>
    requires ValidHash(hashLen) && |key| > 0
    ensures |Mac(hashLen, key, input)| == hashLen

  ghost function NormalizedSalt(hashLen: int, salt: seq<bv8>): seq<bv8>
    requires ValidHash(hashLen)
    ensures |NormalizedSalt(hashLen, salt)| > 0
  {
    if |salt| == 0 then seq(hashLen, i => 0 as bv8) else salt
  }

  ghost function ExtractSpec(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>): BytesResult {
    if !ValidHash(hashLen) then Failure(InvalidHash)
    else Success(Mac(hashLen, NormalizedSalt(hashLen, salt), ikm))
  }

  // RFC 5869 T(0) = empty and T(i) = HMAC(PRK, T(i-1) || info || i).
  // The counter is a single byte; the verified domain limits it to 1..255.
  ghost function Block(hashLen: int, prk: seq<bv8>, info: seq<bv8>, i: nat): seq<bv8>
    requires ValidHash(hashLen) && |prk| > 0 && i <= 255
    ensures |Block(hashLen, prk, info, i)| == (if i == 0 then 0 else hashLen)
    decreases i
  {
    if i == 0 then []
    else Mac(hashLen, prk, Block(hashLen, prk, info, i - 1) + info + [i as bv8])
  }

  // Mathematical concatenation T(1) || ... || T(n), separate from the loop.
  ghost function Blocks(hashLen: int, prk: seq<bv8>, info: seq<bv8>, n: nat): seq<bv8>
    requires ValidHash(hashLen) && |prk| > 0 && n <= 255
    ensures |Blocks(hashLen, prk, info, n)| == n * hashLen
    decreases n
  {
    if n == 0 then []
    else Blocks(hashLen, prk, info, n - 1) + Block(hashLen, prk, info, n)
  }

  ghost function ExpandedBytes(hashLen: int, prk: seq<bv8>, info: seq<bv8>, length: int): seq<bv8>
    requires ValidHash(hashLen) && |prk| > 0 && 0 <= length <= 255 * hashLen
    ensures |ExpandedBytes(hashLen, prk, info, length)| == length
  {
    var n := (length + hashLen - 1) / hashLen;
    Blocks(hashLen, prk, info, n)[..length]
  }

  ghost function ExpandSpec(hashLen: int, prk: seq<bv8>, info: seq<bv8>, length: int): BytesResult {
    if !ValidHash(hashLen) then Failure(InvalidHash)
    else if length < 0 || length > 255 * hashLen then Failure(InvalidLength)
    else if |prk| == 0 then Failure(InvalidKey)
    else Success(ExpandedBytes(hashLen, prk, info, length))
  }

  ghost predicate Ascii(labelUnits: seq<bv16>) {
    forall i :: 0 <= i < |labelUnits| ==> labelUnits[i] <= 127
  }

  ghost function AsciiBytes(labelUnits: seq<bv16>): seq<bv8>
    requires Ascii(labelUnits)
    ensures |AsciiBytes(labelUnits)| == |labelUnits|
    decreases |labelUnits|
  {
    if |labelUnits| == 0 then []
    else AsciiBytes(labelUnits[..|labelUnits| - 1]) + [labelUnits[|labelUnits| - 1] as bv8]
  }

  ghost predicate LabelLengthsValid(labelUnits: seq<bv16>, context: seq<bv8>, length: int) {
    0 <= length <= 65535 && |labelUnits| <= 249 && |context| <= 255
  }

  // TLS 1.3 HkdfLabel, RFC 8446 section 7.1. Empty labels remain accepted
  // for compatibility with the existing public Java helper.
  ghost function LabelBytesSpec(labelUnits: seq<bv16>, context: seq<bv8>, length: int): seq<bv8>
    requires LabelLengthsValid(labelUnits, context, length) && Ascii(labelUnits)
    ensures |LabelBytesSpec(labelUnits, context, length)| == 10 + |labelUnits| + |context|
  {
    [(length / 256) as bv8, (length % 256) as bv8, (6 + |labelUnits|) as bv8] +
    [116, 108, 115, 49, 51, 32] + AsciiBytes(labelUnits) + [|context| as bv8] + context
  }

  ghost function LabelInfoSpec(labelUnits: seq<bv16>, context: seq<bv8>, length: int): BytesResult {
    if !LabelLengthsValid(labelUnits, context, length) then Failure(InvalidLength)
    else if !Ascii(labelUnits) then Failure(InvalidLabel)
    else Success(LabelBytesSpec(labelUnits, context, length))
  }

  ghost function ExpandLabelSpec(hashLen: int, secret: seq<bv8>, labelUnits: seq<bv16>, context: seq<bv8>, length: int): BytesResult {
    if !ValidHash(hashLen) then Failure(InvalidHash)
    else match LabelInfoSpec(labelUnits, context, length)
      case Failure(reason) => Failure(reason)
      case Success(info) => ExpandSpec(hashLen, secret, info, length)
  }

  // One-step ASCII mapping fact used by the serializer loop.
  lemma AsciiBytesAppend(labelUnits: seq<bv16>, i: nat)
    requires i < |labelUnits|
    requires forall j :: 0 <= j <= i ==> labelUnits[j] <= 127
    ensures AsciiBytes(labelUnits[..i]) + [labelUnits[i] as bv8] == AsciiBytes(labelUnits[..i + 1])
  {
    assert labelUnits[..i + 1][..i] == labelUnits[..i];
    assert labelUnits[..i + 1][i] == labelUnits[i];
  }

  method Extract(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>) returns (r: BytesResult)
    ensures r == ExtractSpec(hashLen, salt, ikm)
    ensures r.Success? <==> ValidHash(hashLen)
    ensures r.Success? ==> |r.bytes| == hashLen
  {
    if !ValidHash(hashLen) { r := Failure(InvalidHash); return; }
    var key := salt;
    if |key| == 0 {
      key := seq(hashLen, i => 0 as bv8);
    }
    assert key == NormalizedSalt(hashLen, salt);
    r := Success(Mac(hashLen, key, ikm));
  }

  method Expand(hashLen: int, prk: seq<bv8>, info: seq<bv8>, length: int) returns (r: BytesResult)
    ensures r == ExpandSpec(hashLen, prk, info, length)
    ensures r.Success? <==> ValidHash(hashLen) && 0 <= length <= 255 * hashLen && |prk| > 0
    ensures r.Success? ==> |r.bytes| == length
  {
    if !ValidHash(hashLen) { r := Failure(InvalidHash); return; }
    if length < 0 || length > 255 * hashLen { r := Failure(InvalidLength); return; }
    if |prk| == 0 { r := Failure(InvalidKey); return; }

    var n := (length + hashLen - 1) / hashLen;
    assert 0 <= n <= 255;
    assert length <= n * hashLen;
    var i := 0;
    var previous: seq<bv8> := [];
    var output: seq<bv8> := [];
    while i < n
      invariant 0 <= i <= n <= 255
      invariant previous == Block(hashLen, prk, info, i)
      invariant output == Blocks(hashLen, prk, info, i)
      invariant |previous| == (if i == 0 then 0 else hashLen)
      invariant |output| == i * hashLen
      decreases n - i
    {
      // Feedback, info, and the one-byte RFC counter all enter the MAC.
      var counter := i + 1;
      var next := Mac(hashLen, prk, previous + info + [counter as bv8]);
      assert next == Block(hashLen, prk, info, i + 1);
      output := output + next;
      previous := next;
      i := i + 1;
      assert output == Blocks(hashLen, prk, info, i);
    }
    // Only the final concatenation is truncated, including the zero case.
    r := Success(output[..length]);
  }

  method LabelInfo(labelUnits: seq<bv16>, context: seq<bv8>, length: int) returns (r: BytesResult)
    ensures r == LabelInfoSpec(labelUnits, context, length)
    ensures r.Success? <==> LabelLengthsValid(labelUnits, context, length) && Ascii(labelUnits)
    ensures r.Success? ==> |r.bytes| == 10 + |labelUnits| + |context|
  {
    if length < 0 || length > 65535 || |labelUnits| > 249 || |context| > 255 {
      r := Failure(InvalidLength); return;
    }
    var ascii: seq<bv8> := [];
    var i := 0;
    while i < |labelUnits|
      invariant 0 <= i <= |labelUnits|
      invariant forall j :: 0 <= j < i ==> labelUnits[j] <= 127
      invariant ascii == AsciiBytes(labelUnits[..i])
      decreases |labelUnits| - i
    {
      if labelUnits[i] > 127 {
        assert !Ascii(labelUnits);
        r := Failure(InvalidLabel); return;
      }
      AsciiBytesAppend(labelUnits, i);
      ascii := ascii + [labelUnits[i] as bv8];
      i := i + 1;
    }
    assert Ascii(labelUnits);
    assert labelUnits[..i] == labelUnits;
    assert ascii == AsciiBytes(labelUnits);
    // Explicit serializer: uint16 length, uint8 prefixed-label length,
    // ASCII "tls13 ", label, uint8 context length, context.
    var header: seq<bv8> := [(length / 256) as bv8, (length % 256) as bv8, (6 + |labelUnits|) as bv8];
    var prefix: seq<bv8> := [116, 108, 115, 49, 51, 32];
    var serialized := header + prefix + ascii + [|context| as bv8] + context;
    assert serialized == LabelBytesSpec(labelUnits, context, length);
    r := Success(serialized);
  }

  method ExpandLabel(hashLen: int, secret: seq<bv8>, labelUnits: seq<bv16>, context: seq<bv8>, length: int) returns (r: BytesResult)
    ensures r == ExpandLabelSpec(hashLen, secret, labelUnits, context, length)
    ensures r.Success? <==> (ValidHash(hashLen) && LabelLengthsValid(labelUnits, context, length) && Ascii(labelUnits)
      && length <= 255 * hashLen && |secret| > 0)
    ensures r.Success? ==> |r.bytes| == length
  {
    if !ValidHash(hashLen) { r := Failure(InvalidHash); return; }
    var encoded := LabelInfo(labelUnits, context, length);
    match encoded {
      case Failure(reason) => r := Failure(reason);
      case Success(info) => r := Expand(hashLen, secret, info, length);
    }
  }
}
