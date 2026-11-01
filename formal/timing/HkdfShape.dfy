// SPDX-License-Identifier: Apache-2.0
//
// Source-level SHAPE lemma for the unchanged verified HKDF kernel.
//
// This file imports formal/dafny/hkdf/Hkdf.dfy without modification. It does
// NOT prove compiler/JVM trace preservation, constant-time execution, or that
// the Java bytecode refines this source. It proves the functional invariant
// that justifies marking the generated result *tags* and output *lengths*
// public in the bytecode trace certificates:
//
//   for equal public hash length / output length / label length+ASCII /
//   key length, the result constructor (Success or named Failure) and the
//   success length are equal, regardless of secret salt/IKM/PRK/context
//   contents.
//
// Payload bytes and PRK/IKM/context values remain private. The actual Java
// control flow is checked separately by formal/timing/run.py.
include "../dafny/hkdf/Hkdf.dfy"

module HkdfShape {
  import opened VerifiedHkdf

  lemma ExtractShape(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>)
    ensures ExtractSpec(hashLen, salt, ikm).Success? == ValidHash(hashLen)
    ensures ExtractSpec(hashLen, salt, ikm).Success? ==>
      |ExtractSpec(hashLen, salt, ikm).bytes| == hashLen
  {
    if ValidHash(hashLen) {
      assert ExtractSpec(hashLen, salt, ikm) == Success(Mac(hashLen, NormalizedSalt(hashLen, salt), ikm));
    } else {
      assert ExtractSpec(hashLen, salt, ikm) == Failure(InvalidHash);
    }
  }

  lemma ExpandShape(hashLen: int, prk: seq<bv8>, info: seq<bv8>, length: int)
    ensures ExpandSpec(hashLen, prk, info, length).Success? ==
      (ValidHash(hashLen) && 0 <= length <= 255 * hashLen && |prk| > 0)
    ensures ExpandSpec(hashLen, prk, info, length).Success? ==>
      |ExpandSpec(hashLen, prk, info, length).bytes| == length
  {
    if !ValidHash(hashLen) {
      assert ExpandSpec(hashLen, prk, info, length) == Failure(InvalidHash);
    } else if length < 0 || length > 255 * hashLen {
      assert ExpandSpec(hashLen, prk, info, length) == Failure(InvalidLength);
    } else if |prk| == 0 {
      assert ExpandSpec(hashLen, prk, info, length) == Failure(InvalidKey);
    } else {
      assert ExpandSpec(hashLen, prk, info, length) == Success(ExpandedBytes(hashLen, prk, info, length));
    }
  }

  // Number of feedback blocks the source loop performs. It is a function of
  // public hash length and requested output length only.
  function BlocksNeeded(hashLen: int, length: int): int
    requires hashLen > 0
  {
    (length + hashLen - 1) / hashLen
  }

  lemma BlocksNeededPublic(hashLen: int, length: int, hashLen2: int, length2: int)
    requires hashLen == hashLen2 && length == length2 && hashLen > 0
    ensures BlocksNeeded(hashLen, length) == BlocksNeeded(hashLen2, length2)
  {}

  lemma LabelShape(labelUnits: seq<bv16>, context: seq<bv8>, length: int)
    ensures LabelInfoSpec(labelUnits, context, length).Success? ==
      (LabelLengthsValid(labelUnits, context, length) && Ascii(labelUnits))
    ensures LabelInfoSpec(labelUnits, context, length).Success? ==>
      |LabelInfoSpec(labelUnits, context, length).bytes| == 10 + |labelUnits| + |context|
  {
    if !LabelLengthsValid(labelUnits, context, length) {
      assert LabelInfoSpec(labelUnits, context, length) == Failure(InvalidLength);
    } else if !Ascii(labelUnits) {
      assert LabelInfoSpec(labelUnits, context, length) == Failure(InvalidLabel);
    } else {
      assert LabelInfoSpec(labelUnits, context, length) ==
        Success(LabelBytesSpec(labelUnits, context, length));
    }
  }

  lemma ExpandLabelShape(hashLen: int, secret: seq<bv8>, labelUnits: seq<bv16>,
                         context: seq<bv8>, length: int)
    ensures ExpandLabelSpec(hashLen, secret, labelUnits, context, length).Success? ==
      (ValidHash(hashLen) && LabelLengthsValid(labelUnits, context, length) &&
       Ascii(labelUnits) && length <= 255 * hashLen && |secret| > 0)
    ensures ExpandLabelSpec(hashLen, secret, labelUnits, context, length).Success? ==>
      |ExpandLabelSpec(hashLen, secret, labelUnits, context, length).bytes| == length
  {
    if !ValidHash(hashLen) {
      assert ExpandLabelSpec(hashLen, secret, labelUnits, context, length) == Failure(InvalidHash);
    } else {
      match LabelInfoSpec(labelUnits, context, length) {
        case Failure(reason) =>
          assert ExpandLabelSpec(hashLen, secret, labelUnits, context, length) == Failure(reason);
        case Success(info) =>
          ExpandShape(hashLen, secret, info, length);
          assert ExpandLabelSpec(hashLen, secret, labelUnits, context, length) ==
            ExpandSpec(hashLen, secret, info, length);
      }
    }
  }

  // Equal public shape inputs give equal result constructors and success
  // lengths even when all secret sequences differ arbitrarily.
  lemma ShapeIndependent(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>, salt2: seq<bv8>, ikm2: seq<bv8>)
    ensures ExtractSpec(hashLen, salt, ikm).Success? == ExtractSpec(hashLen, salt2, ikm2).Success?
    ensures ExtractSpec(hashLen, salt, ikm).Success? ==>
      |ExtractSpec(hashLen, salt, ikm).bytes| == |ExtractSpec(hashLen, salt2, ikm2).bytes|
  {
    ExtractShape(hashLen, salt, ikm);
    ExtractShape(hashLen, salt2, ikm2);
  }

  lemma ExpandShapeIndependent(hashLen: int, prk: seq<bv8>, info: seq<bv8>, length: int,
                               prk2: seq<bv8>, info2: seq<bv8>)
    requires |prk| == |prk2|
    ensures ExpandSpec(hashLen, prk, info, length).Success? == ExpandSpec(hashLen, prk2, info2, length).Success?
    ensures ExpandSpec(hashLen, prk, info, length).Success? ==>
      |ExpandSpec(hashLen, prk, info, length).bytes| == |ExpandSpec(hashLen, prk2, info2, length).bytes|
  {
    ExpandShape(hashLen, prk, info, length);
    ExpandShape(hashLen, prk2, info2, length);
  }

  lemma LabelShapeIndependent(labelUnits: seq<bv16>, context: seq<bv8>, length: int,
                              labelUnits2: seq<bv16>, context2: seq<bv8>)
    requires labelUnits == labelUnits2 && |context| == |context2|
    ensures LabelInfoSpec(labelUnits, context, length).Success? ==
      LabelInfoSpec(labelUnits2, context2, length).Success?
    ensures LabelInfoSpec(labelUnits, context, length).Success? ==>
      |LabelInfoSpec(labelUnits, context, length).bytes| ==
      |LabelInfoSpec(labelUnits2, context2, length).bytes|
  {
    LabelShape(labelUnits, context, length);
    LabelShape(labelUnits2, context2, length);
  }
}
