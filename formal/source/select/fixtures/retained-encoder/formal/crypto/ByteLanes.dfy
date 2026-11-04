include "SpongeSpec.dfy"

// Byte/lane representation lemmas for the FIPS202 little-endian state mapping.
module ByteLanes {
  import S = SpongeSpec
  function {:opaque} Octet(word: bv64, slot: bv64): bv8
    requires slot < 8
  { ((word >> (8*slot)) & 255) as bv8 }
  lemma OctetEquation(word: bv64, slot: bv64)
    requires slot < 8
    ensures Octet(word,slot) == ((word >> (8*slot)) & 255) as bv8
  { reveal Octet(); }

  function {:opaque} Pack8(a: bv8,b: bv8,c: bv8,d: bv8,e: bv8,f: bv8,g: bv8,h: bv8): bv64 {
    (a as bv64) | ((b as bv64)<<8) | ((c as bv64)<<16) | ((d as bv64)<<24) |
    ((e as bv64)<<32) | ((f as bv64)<<40) | ((g as bv64)<<48) | ((h as bv64)<<56)
  }
  lemma Pack8Octets(a: bv8,b: bv8,c: bv8,d: bv8,e: bv8,f: bv8,g: bv8,h: bv8)
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),0) == a
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),1) == b
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),2) == c
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),3) == d
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),4) == e
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),5) == f
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),6) == g
    ensures Octet(Pack8(a,b,c,d,e,f,g,h),7) == h
  { reveal Pack8(); reveal Octet(); }
  lemma RebuildWord(word: bv64)
    ensures Pack8(Octet(word,0),Octet(word,1),Octet(word,2),Octet(word,3),
                  Octet(word,4),Octet(word,5),Octet(word,6),Octet(word,7)) == word
  { reveal Pack8(); reveal Octet(); }
  lemma SingleByteXor(word: bv64, value: bv8, slot: bv64, observed: bv64)
    requires slot < 8 && observed < 8
    ensures Octet(word ^ ((value as bv64) << (8*slot)),observed) ==
      (Octet(word,observed) ^ (if slot == observed then value else 0 as bv8))
  { reveal Octet(); }

  ghost function {:opaque} Pack(bytes: seq<bv8>): seq<bv64>
    requires |bytes| == 200 ensures |Pack(bytes)| == 25
  {
    seq(25,i requires 0 <= i < 25 =>
      Pack8(bytes[8*i],bytes[8*i+1],bytes[8*i+2],bytes[8*i+3],
            bytes[8*i+4],bytes[8*i+5],bytes[8*i+6],bytes[8*i+7]))
  }
  ghost function {:opaque} Unpack(lanes: seq<bv64>): seq<bv8>
    requires |lanes| == 25 ensures |Unpack(lanes)| == 200
  { seq(200,i requires 0 <= i < 200 => Octet(lanes[i/8],(i%8) as bv64)) }
  lemma PackAt(bytes: seq<bv8>, i: int)
    requires |bytes| == 200 && 0 <= i < 25
    ensures Pack(bytes)[i] == Pack8(bytes[8*i],bytes[8*i+1],bytes[8*i+2],bytes[8*i+3],
                                   bytes[8*i+4],bytes[8*i+5],bytes[8*i+6],bytes[8*i+7])
  { reveal Pack(); }
  lemma UnpackAt(lanes: seq<bv64>, i: int)
    requires |lanes| == 25 && 0 <= i < 200
    ensures Unpack(lanes)[i] == Octet(lanes[i/8],(i%8) as bv64)
  { reveal Unpack(); }

  lemma SpecByteAt(lanes: seq<bv64>, at: int)
    requires |lanes| == 25 && 0 <= at < 200
    ensures S.ByteAt(lanes,at) == Octet(lanes[at/8],(at%8) as bv64)
  {
    S.ByteAtEquation(lanes,at);
    OctetEquation(lanes[at/8],(at%8) as bv64);
  }

  lemma PackedByteAt(bytes: seq<bv8>, lane: int, slot: int)
    requires |bytes| == 200 && 0 <= lane < 25 && 0 <= slot < 8
    ensures Octet(Pack(bytes)[lane],slot as bv64) == bytes[8*lane+slot]
  {
    var j := 8*lane;
    PackAt(bytes,lane);
    Pack8Octets(bytes[j],bytes[j+1],bytes[j+2],bytes[j+3],
                bytes[j+4],bytes[j+5],bytes[j+6],bytes[j+7]);
    if slot == 0 {} else if slot == 1 {} else if slot == 2 {} else if slot == 3 {}
    else if slot == 4 {} else if slot == 5 {} else if slot == 6 {} else { assert slot == 7; }
  }

  lemma PackBytesRoundtrip(bytes: seq<bv8>)
    requires |bytes| == 200
    ensures Unpack(Pack(bytes)) == bytes
  {
    forall i | 0 <= i < 200
      ensures Unpack(Pack(bytes))[i] == bytes[i]
    {
      UnpackAt(Pack(bytes),i);
      PackedByteAt(bytes,i/8,i%8);
      assert 8*(i/8)+i%8 == i;
    }
  }
  lemma UnpackLanesRoundtrip(lanes: seq<bv64>)
    requires |lanes| == 25
    ensures Pack(Unpack(lanes)) == lanes
  {
    forall i | 0 <= i < 25
      ensures Pack(Unpack(lanes))[i] == lanes[i]
    {
      PackAt(Unpack(lanes),i);
      UnpackAt(lanes,8*i); UnpackAt(lanes,8*i+1);
      UnpackAt(lanes,8*i+2); UnpackAt(lanes,8*i+3);
      UnpackAt(lanes,8*i+4); UnpackAt(lanes,8*i+5);
      UnpackAt(lanes,8*i+6); UnpackAt(lanes,8*i+7);
      RebuildWord(lanes[i]);
    }
  }
}
