// SPDX-License-Identifier: Apache-2.0
// Standards-based scalar kernel. EverQUIC's packet-number secrecy model motivates
// the observer; this is new Dafny code, not a transfer of its F*/C theorems.
module PacketSpec {
  const Sign: bv64 := 0x8000000000000000
  const Limit: bv64 := 0x4000000000000000
  ghost function SL(a: bv64, b: bv64): bool { (a ^ Sign) < (b ^ Sign) }
  ghost function Decode(largest: bv64, truncated: bv64, length: bv64): bv64
    requires 1 <= length <= 4
  {
    var expected := largest + 1;
    var win := (1 as bv64) << (8 * length);
    var half := win >> 1;
    var candidate := (expected & !(win - 1)) | (truncated & (win - 1));
    if !SL(expected - half, candidate) && SL(candidate, Limit - win) then candidate + win
    else if SL(expected + half, candidate) && !SL(candidate, win) then candidate - win
    else candidate
  }
  ghost function Prefix(word: bv64, length: bv64): bv64
    requires 1 <= length <= 4
  {
    if length == 1 then (word >> 24) & 255
    else if length == 2 then (word >> 16) & 65535
    else if length == 3 then (word >> 8) & 0xffffff
    else word & 0xffffffff
  }
  ghost function Unprotect(word: bv64, mask: bv64): bv64 {
    var first := (word >> 32) & 255;
    var bits: bv64 := if (first & 128) != 0 then 15 else 31;
    var clear := first ^ ((mask >> 32) & bits);
    var length := 1 + (clear & 3);
    var active := (mask & 0xff000000)
      | (if length >= 2 then mask & 0x00ff0000 else 0)
      | (if length >= 3 then mask & 0x0000ff00 else 0)
      | (if length >= 4 then mask & 0x000000ff else 0);
    (clear << 32) | ((word & 0xffffffff) ^ active)
  }
  // JVM word shifts mask the count to six bits. All executable shifts in this
  // kernel use counts below64; lowering those intrinsics preserves their value.
  lemma BoundedJvmShift(value: bv64, count: bv64)
    requires count < 64
    ensures (count & 63) == count
    ensures value >> count == value >> (count & 63)
    ensures value << count == value << (count & 63)
  {}
}
module io { module github { module mahmoudimus { module quic { module internal { module verified {
  import S = PacketSpec
  method ShiftRight(value: bv64, count: bv64) returns (r: bv64)
    requires count < 64
    ensures r == value >> count
    ensures r == value >> (count & 63)
  {
    S.BoundedJvmShift(value, count);
    r := value >> count;
  }
  method ShiftLeft(value: bv64, count: bv64) returns (r: bv64)
    requires count < 64
    ensures r == value << count
    ensures r == value << (count & 63)
  {
    S.BoundedJvmShift(value, count);
    r := value << count;
  }
  method Less(a: bv64, b: bv64) returns (r: bv64)
    ensures r == (if a < b then 1 else 0)
  {
    var ah := ShiftRight(a, 1);
    var bh := ShiftRight(b, 1);
    r := ShiftRight(ah - bh - ((!a & b) & 1), 63);
  }
  method SignedLess(a: bv64, b: bv64) returns (r: bv64)
    ensures r == (if S.SL(a, b) then 1 else 0)
  {
    r := Less(a ^ 0x8000000000000000, b ^ 0x8000000000000000);
  }
  method {:isolate_assertions} Decode(largest: bv64, truncated: bv64, length: bv64) returns (r: bv64)
    requires 1 <= length <= 4
    ensures r == S.Decode(largest, truncated, length)
  {
    var expected := largest + 1;
    assert 8 * length < 64;
    var win := ShiftLeft(1, 8 * length);
    var half := ShiftRight(win, 1);
    var candidate := (expected & !(win - 1)) | (truncated & (win - 1));
    var above := SignedLess(expected - half, candidate);
    var room := SignedLess(candidate, 0x4000000000000000 - win);
    var add := (1 - above) & room;
    var below := SignedLess(expected + half, candidate);
    var tooSmall := SignedLess(candidate, win);
    var subtract := below & (1 - tooSmall) & (1 - add);
    assert add <= 1 && subtract <= 1;
    assert (win & (0 as bv64 - add)) == (if add == 1 then win else 0);
    assert (win & (0 as bv64 - subtract)) == (if subtract == 1 then win else 0);
    r := candidate + (win & (0 as bv64 - add)) - (win & (0 as bv64 - subtract));
    assert (add == 1) == (!S.SL(expected - half, candidate) && S.SL(candidate, 0x4000000000000000 - win));
    assert (subtract == 1) == (add == 0 && S.SL(expected + half, candidate) && !S.SL(candidate, win));
    ghost var selectedAdd := add;
    ghost var selectedSub := subtract;
    if selectedAdd == 1 {
      assert subtract == 0;
      assert r == candidate + win;
      assert S.Decode(largest, truncated, length) == candidate + win;
    } else if selectedSub == 1 {
      assert r == candidate - win;
      assert S.Decode(largest, truncated, length) == candidate - win;
    } else {
      assert add == 0 && subtract == 0;
      assert r == candidate;
      assert S.Decode(largest, truncated, length) == candidate;
    }
  }
  method ReadPrefix(word: bv64, length: bv64) returns (r: bv64)
    requires 1 <= length <= 4
    ensures r == S.Prefix(word, length)
  {
    assert 8 * (4 - length) < 64;
    r := ShiftRight(word & 0xffffffff, 8 * (4 - length));
  }
  method Unprotect(word: bv64, mask: bv64) returns (r: bv64)
    ensures r == S.Unprotect(word, mask)
    ensures r >> 40 == 0
  {
    var upper := ShiftRight(word, 32);
    var first := upper & 255;
    var form := ShiftRight(first, 7);
    var bits := 31 - 16 * (form & 1);
    var maskFirst := ShiftRight(mask, 32);
    var clear := first ^ (maskFirst & bits);
    var length := 1 + (clear & 3);
    var lt2 := ShiftRight(length - 2, 63);
    var lt3 := ShiftRight(length - 3, 63);
    var lt4 := ShiftRight(length - 4, 63);
    var ge2 := 1 ^ lt2;
    var ge3 := 1 ^ lt3;
    var ge4 := 1 ^ lt4;
    var active := (mask & 0xff000000)
      | (mask & 0x00ff0000 & (0 as bv64 - ge2))
      | (mask & 0x0000ff00 & (0 as bv64 - ge3))
      | (mask & 0x000000ff & (0 as bv64 - ge4));
    var header := ShiftLeft(clear, 32);
    r := header | ((word & 0xffffffff) ^ active);
  }
} } } } } }
