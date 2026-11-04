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

  // ------------------------------------------------------------------
  // Ghost source-trace vocabulary.  Every event is a flat seq<int>; the
  // Dafny Java compiler erases these ghost functions and the ghost trace
  // out-parameters, so the generated Java remains unchanged.
  //
  // Event encodings:
  //   [10,id,taken]                         branch
  //   [11,id,index,bound]                   loop entry / iteration
  //   [12,id,addr]                          sequence read
  //   [13,id,target,arity]                  owned call
  //   [14,id,target,alg,keyLen,inLen,outLen] HMAC call
  //   [15,id,size]                          sequence allocation
  //   [16,id,leftLen,rightLen]              sequence concatenation
  //   [17,id,seqLen,lo,hi]                  sequence slice
  //   [18,id,target,payloadLen]             datatype construction
  //   [19,add,sub,mul,div,mod,bit,shift]    static executable op counts
  //   [20,id,addr]                          sequence write (reserved)
  // ------------------------------------------------------------------
  ghost function EvBranch(id: int, taken: bool): seq<int> { [10,id,if taken then 1 else 0] }
  ghost function EvLoop(id: int, index: int, bound: int): seq<int> { [11,id,index,bound] }
  ghost function EvRead(id: int, addr: int): seq<int> { [12,id,addr] }
  ghost function EvCall(id: int, target: int, arity: int): seq<int> { [13,id,target,arity] }
  ghost function EvMac(id: int, target: int, alg: int, keyLen: int, inputLen: int, outLen: int): seq<int> { [14,id,target,alg,keyLen,inputLen,outLen] }
  ghost function EvAlloc(id: int, size: int): seq<int> { [15,id,size] }
  ghost function EvConcat(id: int, leftLen: int, rightLen: int): seq<int> { [16,id,leftLen,rightLen] }
  ghost function EvSlice(id: int, seqLen: int, lo: int, hi: int): seq<int> { [17,id,seqLen,lo,hi] }
  ghost function EvCreate(id: int, target: int, payloadLen: int): seq<int> { [18,id,target,payloadLen] }
  ghost function EvOps(add: int, sub: int, mul: int, div: int, mod: int, bit: int, shift: int): seq<int> { [19,add,sub,mul,div,mod,bit,shift] }
  ghost function EvWrite(id: int, addr: int): seq<int> { [20,id,addr] }

  // Public trace equations.  These depend only on the public inputs that the
  // existing timing classification already treats as public: hash length,
  // sequence lengths, label units, requested length and validation policy.
  // Secret payload bytes and HMAC results never enter the trace.
  ghost function ExtractTrace(hashLen: int, saltLen: int, ikmLen: int): seq<int> {
    if !ValidHash(hashLen) then
      EvCall(1, 2, 1) + EvBranch(2, true) + EvCreate(3, 20, 0) + EvCreate(4, 11, 0)
    else
      []
  }


  ghost function ExpandStep(hashLen: int, prkLen: int, infoLen: int, n: int, i: int): seq<int>
    requires 0 <= i < n
  {
    EvLoop(15, i, n) +
    EvConcat(16, if i == 0 then 0 else hashLen, infoLen) +
    EvAlloc(17, 1) +
    EvConcat(18, (if i == 0 then 0 else hashLen) + infoLen, 1) +
    EvMac(19, 1, hashLen, prkLen, (if i == 0 then 0 else hashLen) + infoLen + 1, hashLen) +
    EvConcat(20, i * hashLen, hashLen)
  }

  ghost function ExpandIters(hashLen: int, prkLen: int, infoLen: int, n: int, i: int): seq<int>
    requires 0 <= i <= n
    decreases i
  {
    if i == 0 then [] else ExpandIters(hashLen, prkLen, infoLen, n, i - 1) + ExpandStep(hashLen, prkLen, infoLen, n, i - 1)
  }

  ghost function ExpandTrace(hashLen: int, prkLen: int, infoLen: int, length: int): seq<int> {
    var n := if ValidHash(hashLen) then (length + hashLen - 1) / hashLen else 0;
    EvCall(1, 2, 1) + EvBranch(2, !ValidHash(hashLen)) +
    (if !ValidHash(hashLen) then
       EvCreate(3, 20, 0) + EvCreate(4, 11, 0)
     else
       EvBranch(5, length < 0) + EvBranch(6, length > 255 * hashLen) +
       (if length < 0 || length > 255 * hashLen then
          EvCreate(7, 21, 0) + EvCreate(8, 11, 0)
        else
          EvBranch(9, prkLen == 0) +
          (if prkLen == 0 then
             EvCreate(10, 22, 0) + EvCreate(11, 11, 0)
           else
             EvAlloc(12, 0) + EvAlloc(13, 0) + EvLoop(14, 0, n) +
             ExpandIters(hashLen, prkLen, infoLen, n, n) +
             EvSlice(21, n * hashLen, 0, length) +
             EvCreate(22, 10, length))))
  }

  ghost function ExpandPrefix(hashLen: int, prkLen: int, infoLen: int, length: int, i: int): seq<int>
    requires ValidHash(hashLen) && 0 <= length <= 255 * hashLen && prkLen > 0
    requires 0 <= i <= (length + hashLen - 1) / hashLen
  {
    var n := (length + hashLen - 1) / hashLen;
    assert hashLen != 0;
    EvCall(1, 2, 1) + EvBranch(2, false) + EvBranch(5, false) + EvBranch(6, false) + EvBranch(9, false) +
    EvAlloc(12, 0) + EvAlloc(13, 0) + EvLoop(14, 0, n) + ExpandIters(hashLen, prkLen, infoLen, n, i)
  }

  ghost function LabelStepOk(labelUnits: seq<bv16>, i: int): seq<int>
    requires 0 <= i < |labelUnits|
  {
    EvLoop(9, i, |labelUnits|) + EvRead(10, i) + EvBranch(11, false) +
    EvRead(14, i) + EvAlloc(15, 1) + EvConcat(16, i, 1)
  }

  ghost function LabelPrefixFrom(labelUnits: seq<bv16>, start: int, k: int): seq<int>
    requires 0 <= start <= k <= |labelUnits|
    decreases k - start
  {
    if start == k then [] else LabelPrefixFrom(labelUnits, start, k - 1) + LabelStepOk(labelUnits, k - 1)
  }

  ghost function LabelScanFrom(labelUnits: seq<bv16>, i: int): seq<int>
    requires 0 <= i <= |labelUnits|
    decreases |labelUnits| - i
  {
    if i == |labelUnits| then []
    else
      EvLoop(9, i, |labelUnits|) + EvRead(10, i) + EvBranch(11, labelUnits[i] > 127) +
      (if labelUnits[i] > 127 then
         EvCreate(12, 23, 0) + EvCreate(13, 11, 0)
       else
         EvRead(14, i) + EvAlloc(15, 1) + EvConcat(16, i, 1) + LabelScanFrom(labelUnits, i + 1))
  }

  lemma LabelPrefixFromCons(labelUnits: seq<bv16>, start: int, k: int)
    requires 0 <= start < k <= |labelUnits|
    ensures LabelPrefixFrom(labelUnits, start, k) ==
      LabelStepOk(labelUnits, start) + LabelPrefixFrom(labelUnits, start + 1, k)
    decreases k - start
  {
    if start + 1 == k {
      assert LabelPrefixFrom(labelUnits, start, k) ==
        LabelPrefixFrom(labelUnits, start, k - 1) + LabelStepOk(labelUnits, k - 1);
      assert LabelPrefixFrom(labelUnits, start, start) == [];
    } else {
      LabelPrefixFromCons(labelUnits, start, k - 1);
      assert LabelPrefixFrom(labelUnits, start, k) ==
        LabelPrefixFrom(labelUnits, start, k - 1) + LabelStepOk(labelUnits, k - 1);
    }
  }

  lemma LabelScanFromSplit(labelUnits: seq<bv16>, start: int, k: int)
    requires 0 <= start <= k <= |labelUnits|
    requires forall j :: start <= j < k ==> labelUnits[j] <= 127
    ensures LabelScanFrom(labelUnits, start) ==
      LabelPrefixFrom(labelUnits, start, k) + LabelScanFrom(labelUnits, k)
    decreases k - start
  {
    if start == k {
    } else {
      assert labelUnits[start] <= 127;
      assert LabelScanFrom(labelUnits, start) ==
        EvLoop(9, start, |labelUnits|) + EvRead(10, start) + EvBranch(11, false) +
        EvRead(14, start) + EvAlloc(15, 1) + EvConcat(16, start, 1) +
        LabelScanFrom(labelUnits, start + 1);
      assert LabelStepOk(labelUnits, start) ==
        EvLoop(9, start, |labelUnits|) + EvRead(10, start) + EvBranch(11, false) +
        EvRead(14, start) + EvAlloc(15, 1) + EvConcat(16, start, 1);
      LabelScanFromSplit(labelUnits, start + 1, k);
      LabelPrefixFromCons(labelUnits, start, k);
    }
  }

  ghost predicate LabelShapeOk(labelUnits: seq<bv16>, contextLen: int, length: int) {
    0 <= length <= 65535 && |labelUnits| <= 249 && 0 <= contextLen <= 255 && Ascii(labelUnits)
  }

  ghost function LabelLead(labelUnits: seq<bv16>, contextLen: int, length: int): seq<int> {
    var c1 := length < 0;
    var c2 := length > 65535;
    var c3 := |labelUnits| > 249;
    var c4 := contextLen > 255;
    EvBranch(1, c1) + EvBranch(2, c2) + EvBranch(3, c3) + EvBranch(4, c4) +
    (if c1 || c2 || c3 || c4 then
       EvCreate(5, 21, 0) + EvCreate(6, 11, 0)
     else
       EvAlloc(7, 0) + EvLoop(8, 0, |labelUnits|))
  }

  ghost function LabelInfoTrace(labelUnits: seq<bv16>, contextLen: int, length: int): seq<int> {
    var invalid := length < 0 || length > 65535 || |labelUnits| > 249 || contextLen > 255;
    LabelLead(labelUnits, contextLen, length) +
    (if invalid then []
     else
       LabelScanFrom(labelUnits, 0) +
       (if Ascii(labelUnits) then
          EvAlloc(17, 3) + EvAlloc(18, 6) + EvConcat(19, 3, 6) +
          EvConcat(20, 9, |labelUnits|) + EvAlloc(21, 1) +
          EvConcat(22, 9 + |labelUnits|, 1) +
          EvConcat(23, 10 + |labelUnits|, contextLen) +
          EvCreate(24, 10, 10 + |labelUnits| + contextLen)
        else []))
  }

  lemma LabelInfoShape(labelUnits: seq<bv16>, context: seq<bv8>, length: int)
    ensures LabelInfoSpec(labelUnits, context, length).Success? ==
      LabelShapeOk(labelUnits, |context|, length)
  {
    if !LabelLengthsValid(labelUnits, context, length) || !Ascii(labelUnits) {
      assert LabelInfoSpec(labelUnits, context, length) == Failure(if !LabelLengthsValid(labelUnits, context, length) then InvalidLength else InvalidLabel);
    } else {
      assert LabelInfoSpec(labelUnits, context, length) == Success(LabelBytesSpec(labelUnits, context, length));
    }
  }

  ghost function ExpandLabelTrace(hashLen: int, secretLen: int, labelUnits: seq<bv16>, contextLen: int, length: int): seq<int> {
    EvCall(1, 2, 1) + EvBranch(2, !ValidHash(hashLen)) +
    (if !ValidHash(hashLen) then
       EvCreate(3, 20, 0) + EvCreate(4, 11, 0)
     else
       EvCall(5, 3, 3) + LabelInfoTrace(labelUnits, contextLen, length) +
       EvBranch(6, LabelShapeOk(labelUnits, contextLen, length)) +
       (if LabelShapeOk(labelUnits, contextLen, length) then
          EvCall(7, 4, 4) + ExpandTrace(hashLen, secretLen, 10 + |labelUnits| + contextLen, length)
        else EvCreate(8, 11, 0)))
  }

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

  method Extract(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>) returns (r: BytesResult, ghost trace: seq<int>)
    ensures r == ExtractSpec(hashLen, salt, ikm)
    ensures r.Success? <==> ValidHash(hashLen)
    ensures r.Success? ==> |r.bytes| == hashLen
    ensures trace == ExtractTrace(hashLen, |salt|, |ikm|)
  {
    trace := [];
    trace := trace + EvCall(1, 2, 1) + EvBranch(2, !ValidHash(hashLen));
    if !ValidHash(hashLen) {
      trace := trace + EvCreate(3, 20, 0) + EvCreate(4, 11, 0);
      r := Failure(InvalidHash); return;
    }
    var key := salt;
    trace := trace + EvBranch(5, |key| == 0);
    if |key| == 0 {
      trace := trace + EvAlloc(6, hashLen);
      key := seq(hashLen, i => 0 as bv8);
    }
    assert key == NormalizedSalt(hashLen, salt);
    assert |key| == (if |salt| == 0 then hashLen else |salt|);
    trace := trace + EvMac(7, 1, hashLen, |key|, |ikm|, hashLen) + EvCreate(8, 10, |Mac(hashLen, key, ikm)|);
    trace := [];
    r := Success(Mac(hashLen, key, ikm));
  }

  method {:isolate_assertions} Expand(hashLen: int, prk: seq<bv8>, info: seq<bv8>, length: int) returns (r: BytesResult, ghost trace: seq<int>)
    ensures r == ExpandSpec(hashLen, prk, info, length)
    ensures r.Success? <==> ValidHash(hashLen) && 0 <= length <= 255 * hashLen && |prk| > 0
    ensures r.Success? ==> |r.bytes| == length
    ensures trace == ExpandTrace(hashLen, |prk|, |info|, length)
  {
    trace := [];
    trace := trace + EvCall(1, 2, 1) + EvBranch(2, !ValidHash(hashLen));
    if !ValidHash(hashLen) {
      trace := trace + EvCreate(3, 20, 0) + EvCreate(4, 11, 0);
      r := Failure(InvalidHash); return;
    }
    trace := trace + EvBranch(5, length < 0) + EvBranch(6, length > 255 * hashLen);
    if length < 0 || length > 255 * hashLen {
      trace := trace + EvCreate(7, 21, 0) + EvCreate(8, 11, 0);
      r := Failure(InvalidLength); return;
    }
    trace := trace + EvBranch(9, |prk| == 0);
    if |prk| == 0 {
      trace := trace + EvCreate(10, 22, 0) + EvCreate(11, 11, 0);
      r := Failure(InvalidKey); return;
    }

    var n := (length + hashLen - 1) / hashLen;
    assert 0 <= n <= 255;
    assert length <= n * hashLen;
    var i := 0;
    trace := trace + EvAlloc(12, 0);
    var previous: seq<bv8> := [];
    trace := trace + EvAlloc(13, 0);
    var output: seq<bv8> := [];
    trace := trace + EvLoop(14, 0, n);
    while i < n
      invariant 0 <= i <= n <= 255
      invariant previous == Block(hashLen, prk, info, i)
      invariant output == Blocks(hashLen, prk, info, i)
      invariant |previous| == (if i == 0 then 0 else hashLen)
      invariant |output| == i * hashLen
      invariant trace == ExpandPrefix(hashLen, |prk|, |info|, length, i)
      decreases n - i
    {
      trace := trace + EvLoop(15, i, n);
      // Feedback, info, and the one-byte RFC counter all enter the MAC.
      var counter := i + 1;
      trace := trace + EvConcat(16, |previous|, |info|) + EvAlloc(17, 1) +
        EvConcat(18, |previous + info|, |[counter as bv8]|) +
        EvMac(19, 1, hashLen, |prk|, |previous + info + [counter as bv8]|, hashLen);
      var next := Mac(hashLen, prk, previous + info + [counter as bv8]);
      assert next == Block(hashLen, prk, info, i + 1);
      trace := trace + EvConcat(20, |output|, |next|);
      output := output + next;
      previous := next;
      i := i + 1;
      assert output == Blocks(hashLen, prk, info, i);
      assert trace == ExpandPrefix(hashLen, |prk|, |info|, length, i);
    }
    // Only the final concatenation is truncated, including the zero case.
    assert trace == ExpandPrefix(hashLen, |prk|, |info|, length, n);
    trace := trace + EvSlice(21, |output|, 0, length) + EvCreate(22, 10, |output[..length]|);
    r := Success(output[..length]);
  }

  method {:isolate_assertions} LabelInfo(labelUnits: seq<bv16>, context: seq<bv8>, length: int) returns (r: BytesResult, ghost trace: seq<int>)
    ensures r == LabelInfoSpec(labelUnits, context, length)
    ensures r.Success? <==> LabelLengthsValid(labelUnits, context, length) && Ascii(labelUnits)
    ensures r.Success? ==> |r.bytes| == 10 + |labelUnits| + |context|
    ensures trace == LabelInfoTrace(labelUnits, |context|, length)
  {
    trace := [];
    trace := trace + EvBranch(1, length < 0) + EvBranch(2, length > 65535) +
      EvBranch(3, |labelUnits| > 249) + EvBranch(4, |context| > 255);
    if length < 0 || length > 65535 || |labelUnits| > 249 || |context| > 255 {
      trace := trace + EvCreate(5, 21, 0) + EvCreate(6, 11, 0);
      r := Failure(InvalidLength); return;
    }
    trace := trace + EvAlloc(7, 0);
    var ascii: seq<bv8> := [];
    var i := 0;
    trace := trace + EvLoop(8, 0, |labelUnits|);
    while i < |labelUnits|
      invariant 0 <= i <= |labelUnits|
      invariant forall j :: 0 <= j < i ==> labelUnits[j] <= 127
      invariant ascii == AsciiBytes(labelUnits[..i])
      invariant trace == LabelLead(labelUnits, |context|, length) + LabelPrefixFrom(labelUnits, 0, i)
      decreases |labelUnits| - i
    {
      trace := trace + EvLoop(9, i, |labelUnits|) + EvRead(10, i) +
        EvBranch(11, labelUnits[i] > 127);
      if labelUnits[i] > 127 {
        trace := trace + EvCreate(12, 23, 0) + EvCreate(13, 11, 0);
        assert !Ascii(labelUnits);
        LabelScanFromSplit(labelUnits, 0, i);
        assert LabelScanFrom(labelUnits, i) ==
          EvLoop(9, i, |labelUnits|) + EvRead(10, i) + EvBranch(11, true) +
          EvCreate(12, 23, 0) + EvCreate(13, 11, 0);
        r := Failure(InvalidLabel); return;
      }
      AsciiBytesAppend(labelUnits, i);
      trace := trace + EvRead(14, i) + EvAlloc(15, 1) + EvConcat(16, |ascii|, |[labelUnits[i] as bv8]|);
      ascii := ascii + [labelUnits[i] as bv8];
      i := i + 1;
    }
    assert Ascii(labelUnits);
    assert labelUnits[..i] == labelUnits;
    assert ascii == AsciiBytes(labelUnits);
    LabelScanFromSplit(labelUnits, 0, |labelUnits|);
    assert LabelScanFrom(labelUnits, |labelUnits|) == [];
    assert LabelPrefixFrom(labelUnits, 0, |labelUnits|) == LabelScanFrom(labelUnits, 0);
    // Explicit serializer: uint16 length, uint8 prefixed-label length,
    // ASCII "tls13 ", label, uint8 context length, context.
    trace := trace + EvAlloc(17, 3);
    var header: seq<bv8> := [(length / 256) as bv8, (length % 256) as bv8, (6 + |labelUnits|) as bv8];
    trace := trace + EvAlloc(18, 6);
    var prefix: seq<bv8> := [116, 108, 115, 49, 51, 32];
    trace := trace + EvConcat(19, |header|, |prefix|) +
      EvConcat(20, |header + prefix|, |ascii|) + EvAlloc(21, 1) +
      EvConcat(22, |header + prefix + ascii|, |[|context| as bv8]|) +
      EvConcat(23, |header + prefix + ascii + [|context| as bv8]|, |context|);
    var serialized := header + prefix + ascii + [|context| as bv8] + context;
    trace := trace + EvCreate(24, 10, |serialized|);
    assert serialized == LabelBytesSpec(labelUnits, context, length);
    r := Success(serialized);
  }

  method {:isolate_assertions} ExpandLabel(hashLen: int, secret: seq<bv8>, labelUnits: seq<bv16>, context: seq<bv8>, length: int) returns (r: BytesResult, ghost trace: seq<int>)
    ensures r == ExpandLabelSpec(hashLen, secret, labelUnits, context, length)
    ensures r.Success? <==> (ValidHash(hashLen) && LabelLengthsValid(labelUnits, context, length) && Ascii(labelUnits)
      && length <= 255 * hashLen && |secret| > 0)
    ensures r.Success? ==> |r.bytes| == length
    ensures trace == ExpandLabelTrace(hashLen, |secret|, labelUnits, |context|, length)
  {
    trace := [];
    trace := trace + EvCall(1, 2, 1) + EvBranch(2, !ValidHash(hashLen));
    if !ValidHash(hashLen) {
      trace := trace + EvCreate(3, 20, 0) + EvCreate(4, 11, 0);
      r := Failure(InvalidHash); return;
    }
    trace := trace + EvCall(5, 3, 3);
    var encoded, {:ghost} encTrace := LabelInfo(labelUnits, context, length);
    trace := trace + encTrace;
    assert encTrace == LabelInfoTrace(labelUnits, |context|, length);
    LabelInfoShape(labelUnits, context, length);
    trace := trace + EvBranch(6, encoded.Success?);
    match encoded {
      case Failure(reason) =>
        trace := trace + EvCreate(8, 11, 0);
        r := Failure(reason);
      case Success(info) =>
        assert |info| == 10 + |labelUnits| + |context|;
        trace := trace + EvCall(7, 4, 4);
        ghost var expTrace: seq<int>;
        r, expTrace := Expand(hashLen, secret, info, length);
        trace := trace + expTrace;
        assert expTrace == ExpandTrace(hashLen, |secret|, |info|, length);
    }
  }
}
