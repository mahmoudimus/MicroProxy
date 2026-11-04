include "NativeField.dfy"
include "Polynomial.dfy"
include "../source/SourceTrace.dfy"

// Native-array refinement of the FIPS203 polynomial specification. Runtime
// coefficients and indices are primitive Java ints. Mathematical sequences are
// ghost snapshots only. The Go-derived butterfly formulas retain their original
// provenance; the array refinement and range proofs are new work.
module NativePolynomial {
  import T = NativeTypes
  import S = PolySpec
  import R = PolynomialRing
  import F = NativeField
  import P = VerifiedPolynomial
  import ST = SourceTrace

  ghost function BranchFalsePrefix(siteBase: int, k: int): seq<int>
    requires 0 <= k
    decreases k
    ensures |BranchFalsePrefix(siteBase,k)| == 4*k
    ensures forall j :: 0 <= j < k ==> BranchFalsePrefix(siteBase,k)[4*j..4*j+4] == ST.Branch(siteBase+j,false)
  { if k <= 0 then [] else BranchFalsePrefix(siteBase,k-1) + ST.Branch(siteBase+k-1,false) }
  ghost function ChunkTrace(siteBase: int, k: int): seq<int>
    requires 0 <= k
    ensures ChunkTrace(siteBase,k) == BranchFalsePrefix(siteBase,k) + ST.Branch(siteBase+k,true) + ST.Ops(0,0,0,0,0,0,0)
  { BranchFalsePrefix(siteBase,k) + ST.Branch(siteBase+k,true) + ST.Ops(0,0,0,0,0,0,0) }
  lemma ChunkTraceContent(siteBase: int, k: int)
    requires 0 <= k
    ensures |ChunkTrace(siteBase,k)| == 4*k+12
    ensures forall j :: 0 <= j < k ==> ChunkTrace(siteBase,k)[4*j..4*j+4] == ST.Branch(siteBase+j,false)
    ensures ChunkTrace(siteBase,k)[4*k..4*k+4] == ST.Branch(siteBase+k,true)
    ensures ChunkTrace(siteBase,k)[4*k+4..4*k+12] == ST.Ops(0,0,0,0,0,0,0)
  {
    ST.BranchShape(siteBase+k,true); ST.OpsShape(0,0,0,0,0,0,0);
    var a := BranchFalsePrefix(siteBase,k);
    var b := ST.Branch(siteBase+k,true);
    var c := ST.Ops(0,0,0,0,0,0,0);
    assert ChunkTrace(siteBase,k) == a+b+c;
    assert |a| == 4*k; assert |b| == 4; assert |c| == 8;
    calc {
      |ChunkTrace(siteBase,k)|;
      == |a+b+c|;
      == |a|+|b|+|c|;
      == 4*k+4+8;
      == 4*k+12;
    }
  }
  ghost function FieldAddCallee(): seq<int>
  { ST.Ops(1,0,0,0,0,0,0) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1) }
  ghost function FieldSubCallee(): seq<int>
  { ST.Ops(1,1,0,0,0,0,0) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1) }
  ghost function FieldMulCallee(): seq<int>
  { ST.Ops(0,0,1,0,0,0,0) + ST.Call(2,2,1) + ST.Ops(0,1,2,0,0,0,1)
    + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1) }
  ghost function FieldMulSubCallee(): seq<int>
  { ST.Ops(1,1,1,0,0,0,0) + ST.Call(3,2,1) + ST.Ops(0,1,2,0,0,0,1)
    + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1) }
  ghost function FieldAddMulCallee(): seq<int>
  { ST.Ops(1,0,2,0,0,0,0) + ST.Call(4,2,1) + ST.Ops(0,1,2,0,0,0,1)
    + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1) }
  ghost function ZetasStep(i: int): seq<int>
    requires 0 <= i < 128
  { ST.LoopCheck(200,true,i) + ST.Call(422,39,1) + ZetasValue(i as T.I).1 + ST.Write(500,0,i) }
  ghost function {:opaque} ZetasUpTo(n: int): seq<int>
    requires 0 <= n <= 128
    decreases n
  { if n <= 0 then [] else ZetasUpTo(n-1) + ZetasStep(n-1) }
  lemma ZetasUpToZero()
    ensures ZetasUpTo(0) == []
  { reveal ZetasUpTo(); }
  lemma ZetasUpToSucc(n: int)
    requires 0 <= n < 128
    requires 0 <= n
    ensures ZetasUpTo(n+1) == ZetasUpTo(n) + ZetasStep(n)
  { reveal ZetasUpTo(); }
  ghost function NewZetasTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(100,128) + ST.LoopBound(200,128)
    + ZetasUpTo(128) + ST.LoopCheck(200,false,128) }
  ghost function GammasStep(i: int): seq<int>
    requires 0 <= i < 128
  { ST.LoopCheck(201,true,i) + ST.Call(423,49,1) + GammasValue(i as T.I).1 + ST.Write(501,0,i) }
  ghost function {:opaque} GammasUpTo(n: int): seq<int>
    requires 0 <= n <= 128
    decreases n
  { if n <= 0 then [] else GammasUpTo(n-1) + GammasStep(n-1) }
  lemma GammasUpToZero()
    ensures GammasUpTo(0) == []
  { reveal GammasUpTo(); }
  lemma GammasUpToSucc(n: int)
    requires 0 <= n < 128
    requires 0 <= n
    ensures GammasUpTo(n+1) == GammasUpTo(n) + GammasStep(n)
  { reveal GammasUpTo(); }
  ghost function NewGammasTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(101,128) + ST.LoopBound(201,128)
    + GammasUpTo(128) + ST.LoopCheck(201,false,128) }
  ghost function AddStep(i: int): seq<int>
  { ST.LoopCheck(202,true,i) + ST.Read(502,0,i) + ST.Read(503,1,i) + ST.Call(400,3,2)
    + FieldAddCallee() + ST.Write(504,2,i) }
  ghost function {:opaque} AddUpTo(n: int): seq<int>
    decreases n
  { if n <= 0 then [] else AddUpTo(n-1) + AddStep(n-1) }
  lemma AddUpToZero()
    ensures AddUpTo(0) == []
  { reveal AddUpTo(); }
  lemma AddUpToSucc(n: int) requires 0 <= n ensures AddUpTo(n+1) == AddUpTo(n) + AddStep(n) { reveal AddUpTo(); }
  ghost function AddTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(102,256) + ST.LoopBound(202,256)
    + AddUpTo(256) + ST.LoopCheck(202,false,256) }
  ghost function SubStep(i: int): seq<int>
  { ST.LoopCheck(203,true,i) + ST.Read(505,0,i) + ST.Read(506,1,i) + ST.Call(401,4,2)
    + FieldSubCallee() + ST.Write(507,2,i) }
  ghost function {:opaque} SubUpTo(n: int): seq<int>
    decreases n
  { if n <= 0 then [] else SubUpTo(n-1) + SubStep(n-1) }
  lemma SubUpToZero()
    ensures SubUpTo(0) == []
  { reveal SubUpTo(); }
  lemma SubUpToSucc(n: int) requires 0 <= n ensures SubUpTo(n+1) == SubUpTo(n) + SubStep(n) { reveal SubUpTo(); }
  ghost function SubTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(103,256) + ST.LoopBound(203,256)
    + SubUpTo(256) + ST.LoopCheck(203,false,256) }
  ghost function CopyStep(i: int): seq<int>
  { ST.LoopCheck(204,true,i) + ST.Read(508,0,i) + ST.Write(509,1,i) }
  ghost function {:opaque} CopyUpTo(n: int): seq<int>
    decreases n
  { if n <= 0 then [] else CopyUpTo(n-1) + CopyStep(n-1) }
  lemma CopyUpToZero()
    ensures CopyUpTo(0) == []
  { reveal CopyUpTo(); }
  lemma CopyUpToSucc(n: int) requires 0 <= n ensures CopyUpTo(n+1) == CopyUpTo(n) + CopyStep(n) { reveal CopyUpTo(); }
  ghost function CopyTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(104,256) + ST.LoopBound(204,256)
    + CopyUpTo(256) + ST.LoopCheck(204,false,256) }
  ghost function {:opaque} FwdInnerStep(l: int, block: int, offset: int): seq<int>
  {
    var i := 2*l*block+offset;
    ST.LoopCheck(206,true,offset)
    + ST.Read(510,0,i+l) + ST.Call(402,5,2) + FieldMulCallee()
    + ST.Read(511,0,i) + ST.Call(403,3,2) + FieldAddCallee()
    + ST.Write(514,1,i)
    + ST.Read(512,0,i) + ST.Call(404,4,2) + FieldSubCallee()
    + ST.Write(515,1,i+l)
  }
  ghost function {:opaque} FwdInnerUpTo(l: int, block: int, n: int): seq<int>
    requires l > 0
    requires 0 <= n <= l
    decreases n
  { if n <= 0 then [] else FwdInnerUpTo(l,block,n-1) + FwdInnerStep(l,block,n-1) }
  lemma FwdInnerUpToZero(l: int, block: int)
    requires l > 0
    ensures FwdInnerUpTo(l,block,0) == []
  { reveal FwdInnerUpTo(); reveal FwdInnerStep(); }
  lemma FwdInnerUpToSucc(l: int, block: int, n: int)
    requires l > 0
    requires 0 <= n < l
    requires 0 <= n
    ensures FwdInnerUpTo(l,block,n+1) == FwdInnerUpTo(l,block,n) + FwdInnerStep(l,block,n)
  { reveal FwdInnerUpTo(); reveal FwdInnerStep(); }
  ghost function {:opaque} FwdOuterHead(l: int, block: int): seq<int>
    requires l > 0
  { ST.LoopCheck(205,true,block) + ST.Read(513,2,128/l+block) + ST.LoopBound(206,l) }
  ghost function FwdOuterStep(l: int, block: int): seq<int>
    requires l > 0
  { FwdOuterHead(l,block) + FwdInnerUpTo(l,block,l) + ST.LoopCheck(206,false,l) }
  ghost function {:opaque} FwdOuterUpTo(l: int, n: int): seq<int>
    requires l > 0
    requires 0 <= n
    decreases n
  { if n <= 0 then [] else FwdOuterUpTo(l,n-1) + FwdOuterStep(l,n-1) }
  lemma FwdOuterUpToZero(l: int)
    requires l > 0
    ensures FwdOuterUpTo(l,0) == []
  { reveal FwdOuterUpTo(); reveal FwdOuterHead(); }
  lemma FwdOuterUpToSucc(l: int, n: int)
    requires l > 0
    requires 0 <= n
    requires 0 <= n
    ensures FwdOuterUpTo(l,n+1) == FwdOuterUpTo(l,n) + FwdOuterStep(l,n)
  { reveal FwdOuterUpTo(); reveal FwdOuterHead(); }
  ghost function ForwardStageTrace(s: int): seq<int>
    requires 0 <= s < 7
  { ST.Ops(8,0,4,2,0,0,0) + ST.Call(424,30,1) + Len(s as T.I).1
    + ST.LoopBound(205,(128/Len(s as T.I).0) as int)
    + FwdOuterUpTo(Len(s as T.I).0 as int,(128/Len(s as T.I).0) as int)
    + ST.LoopCheck(205,false,(128/Len(s as T.I).0) as int) }
  ghost function {:opaque} InvInnerStep(l: int, block: int, offset: int): seq<int>
  {
    var i := 2*l*block+offset;
    ST.LoopCheck(208,true,offset)
    + ST.Read(516,0,i) + ST.Read(517,0,i+l) + ST.Call(405,3,2) + FieldAddCallee()
    + ST.Write(521,1,i)
    + ST.Read(518,0,i+l) + ST.Read(519,0,i) + ST.Call(406,6,3) + FieldMulSubCallee()
    + ST.Write(522,1,i+l)
  }
  ghost function {:opaque} InvInnerUpTo(l: int, block: int, n: int): seq<int>
    requires l > 0
    requires 0 <= n <= l
    decreases n
  { if n <= 0 then [] else InvInnerUpTo(l,block,n-1) + InvInnerStep(l,block,n-1) }
  lemma InvInnerUpToZero(l: int, block: int)
    requires l > 0
    ensures InvInnerUpTo(l,block,0) == []
  { reveal InvInnerUpTo(); reveal InvInnerStep(); }
  lemma InvInnerUpToSucc(l: int, block: int, n: int)
    requires l > 0
    requires 0 <= n < l
    requires 0 <= n
    ensures InvInnerUpTo(l,block,n+1) == InvInnerUpTo(l,block,n) + InvInnerStep(l,block,n)
  { reveal InvInnerUpTo(); reveal InvInnerStep(); }
  ghost function {:opaque} InvOuterHead(l: int, block: int): seq<int>
    requires l > 0
  { ST.LoopCheck(207,true,block) + ST.Read(520,2,256/l-1-block) + ST.LoopBound(208,l) }
  ghost function InvOuterStep(l: int, block: int): seq<int>
    requires l > 0
  { InvOuterHead(l,block) + InvInnerUpTo(l,block,l) + ST.LoopCheck(208,false,l) }
  ghost function {:opaque} InvOuterUpTo(l: int, n: int): seq<int>
    requires l > 0
    requires 0 <= n
    decreases n
  { if n <= 0 then [] else InvOuterUpTo(l,n-1) + InvOuterStep(l,n-1) }
  lemma InvOuterUpToZero(l: int)
    requires l > 0
    ensures InvOuterUpTo(l,0) == []
  { reveal InvOuterUpTo(); reveal InvOuterHead(); }
  lemma InvOuterUpToSucc(l: int, n: int)
    requires l > 0
    requires 0 <= n
    requires 0 <= n
    ensures InvOuterUpTo(l,n+1) == InvOuterUpTo(l,n) + InvOuterStep(l,n)
  { reveal InvOuterUpTo(); reveal InvOuterHead(); }
  ghost function InverseStageTrace(s: int): seq<int>
    requires 0 <= s < 7
  { ST.Ops(8,5,4,2,0,0,0) + ST.Call(425,30,1) + Len((6-s) as T.I).1
    + ST.LoopBound(207,(128/Len((6-s) as T.I).0) as int)
    + InvOuterUpTo(Len((6-s) as T.I).0 as int,(128/Len((6-s) as T.I).0) as int)
    + ST.LoopCheck(207,false,(128/Len((6-s) as T.I).0) as int) }
  ghost function ScaleStep(i: int): seq<int>
  { ST.LoopCheck(209,true,i) + ST.Read(530,0,i) + ST.Call(407,5,2)
    + FieldMulCallee() + ST.Write(531,0,i) }
  ghost function {:opaque} ScaleUpTo(n: int): seq<int>
    decreases n
  { if n <= 0 then [] else ScaleUpTo(n-1) + ScaleStep(n-1) }
  lemma ScaleUpToZero()
    ensures ScaleUpTo(0) == []
  { reveal ScaleUpTo(); }
  lemma ScaleUpToSucc(n: int) requires 0 <= n ensures ScaleUpTo(n+1) == ScaleUpTo(n) + ScaleStep(n) { reveal ScaleUpTo(); }
  ghost function ScaleTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.LoopBound(209,256) + ScaleUpTo(256)
    + ST.LoopCheck(209,false,256) }
  ghost function NttStageStep(s: int): seq<int>
    requires 0 <= s < 7
  { ST.LoopCheck(210,true,s) + ST.Call(410,14,4) + ForwardStageTrace(s) }
  ghost function {:opaque} NttStageUpTo(n: int): seq<int>
    requires 0 <= n <= 7
    decreases n
  { if n <= 0 then [] else NttStageUpTo(n-1) + NttStageStep(n-1) }
  lemma NttStageUpToZero()
    ensures NttStageUpTo(0) == []
  { reveal NttStageUpTo(); }
  lemma NttStageUpToSucc(n: int)
    requires 0 <= n < 7
    ensures NttStageUpTo(n+1) == NttStageUpTo(n) + NttStageStep(n)
  { reveal NttStageUpTo(); }
  ghost function NttTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.Call(408,13,1) + CopyTrace() + ST.Alloc(105,256)
    + ST.Call(409,11,0) + NewZetasTrace() + ST.LoopBound(210,7)
    + NttStageUpTo(7) + ST.LoopCheck(210,false,7)
    + ST.Call(411,21,1) + WipeTrace(256) }
  ghost function InvNttStageStep(s: int): seq<int>
    requires 0 <= s < 7
  { ST.LoopCheck(211,true,s) + ST.Call(414,15,4) + InverseStageTrace(s) }
  ghost function {:opaque} InvNttStageUpTo(n: int): seq<int>
    requires 0 <= n <= 7
    decreases n
  { if n <= 0 then [] else InvNttStageUpTo(n-1) + InvNttStageStep(n-1) }
  lemma InvNttStageUpToZero()
    ensures InvNttStageUpTo(0) == []
  { reveal InvNttStageUpTo(); }
  lemma InvNttStageUpToSucc(n: int)
    requires 0 <= n < 7
    ensures InvNttStageUpTo(n+1) == InvNttStageUpTo(n) + InvNttStageStep(n)
  { reveal InvNttStageUpTo(); }
  ghost function InverseNttTrace(): seq<int>
  { ST.Ops(0,0,0,0,0,0,0) + ST.Call(412,13,1) + CopyTrace() + ST.Alloc(106,256)
    + ST.Call(413,11,0) + NewZetasTrace() + ST.LoopBound(211,7)
    + InvNttStageUpTo(7) + ST.LoopCheck(211,false,7)
    + ST.Call(415,21,1) + WipeTrace(256)
    + ST.Call(416,16,2) + ScaleTrace() }
  ghost function BaseCaseTrace(i: int): seq<int>
  { ST.Ops(1,0,0,0,0,0,0)
    + ST.Call(417,5,2) + FieldMulCallee()
    + ST.Call(418,7,4) + FieldAddMulCallee()
    + ST.Call(419,7,4) + FieldAddMulCallee()
    + ST.Write(540,5,i) + ST.Write(541,5,i+1) }
  ghost function NttMulStep(i: int): seq<int>
    requires 0 <= i < 128
  { ST.LoopCheck(212,true,i)
    + ST.Read(524,0,2*i) + ST.Read(525,0,2*i+1)
    + ST.Read(526,1,2*i) + ST.Read(527,1,2*i+1)
    + ST.Read(528,3,i)
    + ST.Call(421,19,7) + BaseCaseTrace(2*i) }
  ghost function {:opaque} NttMulUpTo(n: int): seq<int>
    requires 0 <= n <= 128
    decreases n
  { if n <= 0 then [] else NttMulUpTo(n-1) + NttMulStep(n-1) }
  lemma NttMulUpToZero()
    ensures NttMulUpTo(0) == []
  { reveal NttMulUpTo(); }
  lemma NttMulUpToSucc(n: int)
    requires 0 <= n < 128
    ensures NttMulUpTo(n+1) == NttMulUpTo(n) + NttMulStep(n)
  { reveal NttMulUpTo(); }
  ghost function NttMulTrace(): seq<int>
  { ST.Ops(2,0,6,0,0,0,0) + ST.Alloc(107,256)
    + ST.Call(420,12,0) + NewGammasTrace()
    + ST.LoopBound(212,128) + NttMulUpTo(128) + ST.LoopCheck(212,false,128) }
  ghost function WipeStep(i: int): seq<int>
  { ST.LoopCheck(213,true,i) + ST.Write(550,0,i) }
  ghost function {:opaque} WipeUpTo(n: int): seq<int>
    requires 0 <= n
    decreases n
  { if n <= 0 then [] else WipeUpTo(n-1) + WipeStep(n-1) }
  lemma WipeUpToZero()
    ensures WipeUpTo(0) == []
  { reveal WipeUpTo(); }
  lemma WipeUpToSucc(n: int) requires 0 <= n ensures WipeUpTo(n+1) == WipeUpTo(n) + WipeStep(n) { reveal WipeUpTo(); }
  ghost function WipeTrace(n: int): seq<int>
    requires 0 <= n
  { ST.Ops(0,0,0,0,0,0,0) + ST.LoopBound(213,n) + WipeUpTo(n) + ST.LoopCheck(213,false,n) }

  function Len(s: T.I): (T.I, ghost seq<int>)
    requires 0 <= s < 7
    ensures Len(s).0 as int == S.Len(s as int)
    ensures 2 <= Len(s).0 <= 128
    ensures Len(s).1 == (if s == 0 then BranchFalsePrefix(900,0) + ST.Branch(900,true) + ST.Ops(0,0,0,0,0,0,0)
      else if s == 1 then BranchFalsePrefix(900,1) + ST.Branch(901,true) + ST.Ops(0,0,0,0,0,0,0)
      else if s == 2 then BranchFalsePrefix(900,2) + ST.Branch(902,true) + ST.Ops(0,0,0,0,0,0,0)
      else if s == 3 then BranchFalsePrefix(900,3) + ST.Branch(903,true) + ST.Ops(0,0,0,0,0,0,0)
      else if s == 4 then BranchFalsePrefix(900,4) + ST.Branch(904,true) + ST.Ops(0,0,0,0,0,0,0)
      else if s == 5 then BranchFalsePrefix(900,5) + ST.Branch(905,true) + ST.Ops(0,0,0,0,0,0,0)
      else BranchFalsePrefix(900,6) + ST.Branch(906,true) + ST.Ops(0,0,0,0,0,0,0))
  {
    if s == 0 then (128, ghost BranchFalsePrefix(900,0) + ST.Branch(900,true) + ST.Ops(0,0,0,0,0,0,0))
    else if s == 1 then (64, ghost BranchFalsePrefix(900,1) + ST.Branch(901,true) + ST.Ops(0,0,0,0,0,0,0))
    else if s == 2 then (32, ghost BranchFalsePrefix(900,2) + ST.Branch(902,true) + ST.Ops(0,0,0,0,0,0,0))
    else if s == 3 then (16, ghost BranchFalsePrefix(900,3) + ST.Branch(903,true) + ST.Ops(0,0,0,0,0,0,0))
    else if s == 4 then (8, ghost BranchFalsePrefix(900,4) + ST.Branch(904,true) + ST.Ops(0,0,0,0,0,0,0))
    else if s == 5 then (4, ghost BranchFalsePrefix(900,5) + ST.Branch(905,true) + ST.Ops(0,0,0,0,0,0,0))
    else (2, ghost BranchFalsePrefix(900,6) + ST.Branch(906,true) + ST.Ops(0,0,0,0,0,0,0))
  }

  function ZetasChunk0(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk0(i).0 < 3329
    ensures ZetasChunk0(i).0 as int == S.Zetas()[0+(i as int)]
    ensures ZetasChunk0(i).1 == ChunkTrace(1000,i as int)
    ensures ZetasChunk0(i).1 == BranchFalsePrefix(1000,i as int) + ST.Branch(1000+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (1, ghost ChunkTrace(1000,0))
    else if i == 1 then (1729, ghost ChunkTrace(1000,1))
    else if i == 2 then (2580, ghost ChunkTrace(1000,2))
    else if i == 3 then (3289, ghost ChunkTrace(1000,3))
    else if i == 4 then (2642, ghost ChunkTrace(1000,4))
    else if i == 5 then (630, ghost ChunkTrace(1000,5))
    else if i == 6 then (1897, ghost ChunkTrace(1000,6))
    else if i == 7 then (848, ghost ChunkTrace(1000,7))
    else if i == 8 then (1062, ghost ChunkTrace(1000,8))
    else if i == 9 then (1919, ghost ChunkTrace(1000,9))
    else if i == 10 then (193, ghost ChunkTrace(1000,10))
    else if i == 11 then (797, ghost ChunkTrace(1000,11))
    else if i == 12 then (2786, ghost ChunkTrace(1000,12))
    else if i == 13 then (3260, ghost ChunkTrace(1000,13))
    else if i == 14 then (569, ghost ChunkTrace(1000,14))
    else (1746, ghost ChunkTrace(1000,15))
  }
  function ZetasChunk1(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk1(i).0 < 3329
    ensures ZetasChunk1(i).0 as int == S.Zetas()[16+(i as int)]
    ensures ZetasChunk1(i).1 == ChunkTrace(1032,i as int)
    ensures ZetasChunk1(i).1 == BranchFalsePrefix(1032,i as int) + ST.Branch(1032+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (296, ghost ChunkTrace(1032,0))
    else if i == 1 then (2447, ghost ChunkTrace(1032,1))
    else if i == 2 then (1339, ghost ChunkTrace(1032,2))
    else if i == 3 then (1476, ghost ChunkTrace(1032,3))
    else if i == 4 then (3046, ghost ChunkTrace(1032,4))
    else if i == 5 then (56, ghost ChunkTrace(1032,5))
    else if i == 6 then (2240, ghost ChunkTrace(1032,6))
    else if i == 7 then (1333, ghost ChunkTrace(1032,7))
    else if i == 8 then (1426, ghost ChunkTrace(1032,8))
    else if i == 9 then (2094, ghost ChunkTrace(1032,9))
    else if i == 10 then (535, ghost ChunkTrace(1032,10))
    else if i == 11 then (2882, ghost ChunkTrace(1032,11))
    else if i == 12 then (2393, ghost ChunkTrace(1032,12))
    else if i == 13 then (2879, ghost ChunkTrace(1032,13))
    else if i == 14 then (1974, ghost ChunkTrace(1032,14))
    else (821, ghost ChunkTrace(1032,15))
  }
  function ZetasChunk2(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk2(i).0 < 3329
    ensures ZetasChunk2(i).0 as int == S.Zetas()[32+(i as int)]
    ensures ZetasChunk2(i).1 == ChunkTrace(1064,i as int)
    ensures ZetasChunk2(i).1 == BranchFalsePrefix(1064,i as int) + ST.Branch(1064+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (289, ghost ChunkTrace(1064,0))
    else if i == 1 then (331, ghost ChunkTrace(1064,1))
    else if i == 2 then (3253, ghost ChunkTrace(1064,2))
    else if i == 3 then (1756, ghost ChunkTrace(1064,3))
    else if i == 4 then (1197, ghost ChunkTrace(1064,4))
    else if i == 5 then (2304, ghost ChunkTrace(1064,5))
    else if i == 6 then (2277, ghost ChunkTrace(1064,6))
    else if i == 7 then (2055, ghost ChunkTrace(1064,7))
    else if i == 8 then (650, ghost ChunkTrace(1064,8))
    else if i == 9 then (1977, ghost ChunkTrace(1064,9))
    else if i == 10 then (2513, ghost ChunkTrace(1064,10))
    else if i == 11 then (632, ghost ChunkTrace(1064,11))
    else if i == 12 then (2865, ghost ChunkTrace(1064,12))
    else if i == 13 then (33, ghost ChunkTrace(1064,13))
    else if i == 14 then (1320, ghost ChunkTrace(1064,14))
    else (1915, ghost ChunkTrace(1064,15))
  }
  function ZetasChunk3(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk3(i).0 < 3329
    ensures ZetasChunk3(i).0 as int == S.Zetas()[48+(i as int)]
    ensures ZetasChunk3(i).1 == ChunkTrace(1096,i as int)
    ensures ZetasChunk3(i).1 == BranchFalsePrefix(1096,i as int) + ST.Branch(1096+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (2319, ghost ChunkTrace(1096,0))
    else if i == 1 then (1435, ghost ChunkTrace(1096,1))
    else if i == 2 then (807, ghost ChunkTrace(1096,2))
    else if i == 3 then (452, ghost ChunkTrace(1096,3))
    else if i == 4 then (1438, ghost ChunkTrace(1096,4))
    else if i == 5 then (2868, ghost ChunkTrace(1096,5))
    else if i == 6 then (1534, ghost ChunkTrace(1096,6))
    else if i == 7 then (2402, ghost ChunkTrace(1096,7))
    else if i == 8 then (2647, ghost ChunkTrace(1096,8))
    else if i == 9 then (2617, ghost ChunkTrace(1096,9))
    else if i == 10 then (1481, ghost ChunkTrace(1096,10))
    else if i == 11 then (648, ghost ChunkTrace(1096,11))
    else if i == 12 then (2474, ghost ChunkTrace(1096,12))
    else if i == 13 then (3110, ghost ChunkTrace(1096,13))
    else if i == 14 then (1227, ghost ChunkTrace(1096,14))
    else (910, ghost ChunkTrace(1096,15))
  }
  function ZetasChunk4(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk4(i).0 < 3329
    ensures ZetasChunk4(i).0 as int == S.Zetas()[64+(i as int)]
    ensures ZetasChunk4(i).1 == ChunkTrace(1128,i as int)
    ensures ZetasChunk4(i).1 == BranchFalsePrefix(1128,i as int) + ST.Branch(1128+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (17, ghost ChunkTrace(1128,0))
    else if i == 1 then (2761, ghost ChunkTrace(1128,1))
    else if i == 2 then (583, ghost ChunkTrace(1128,2))
    else if i == 3 then (2649, ghost ChunkTrace(1128,3))
    else if i == 4 then (1637, ghost ChunkTrace(1128,4))
    else if i == 5 then (723, ghost ChunkTrace(1128,5))
    else if i == 6 then (2288, ghost ChunkTrace(1128,6))
    else if i == 7 then (1100, ghost ChunkTrace(1128,7))
    else if i == 8 then (1409, ghost ChunkTrace(1128,8))
    else if i == 9 then (2662, ghost ChunkTrace(1128,9))
    else if i == 10 then (3281, ghost ChunkTrace(1128,10))
    else if i == 11 then (233, ghost ChunkTrace(1128,11))
    else if i == 12 then (756, ghost ChunkTrace(1128,12))
    else if i == 13 then (2156, ghost ChunkTrace(1128,13))
    else if i == 14 then (3015, ghost ChunkTrace(1128,14))
    else (3050, ghost ChunkTrace(1128,15))
  }
  function ZetasChunk5(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk5(i).0 < 3329
    ensures ZetasChunk5(i).0 as int == S.Zetas()[80+(i as int)]
    ensures ZetasChunk5(i).1 == ChunkTrace(1160,i as int)
    ensures ZetasChunk5(i).1 == BranchFalsePrefix(1160,i as int) + ST.Branch(1160+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (1703, ghost ChunkTrace(1160,0))
    else if i == 1 then (1651, ghost ChunkTrace(1160,1))
    else if i == 2 then (2789, ghost ChunkTrace(1160,2))
    else if i == 3 then (1789, ghost ChunkTrace(1160,3))
    else if i == 4 then (1847, ghost ChunkTrace(1160,4))
    else if i == 5 then (952, ghost ChunkTrace(1160,5))
    else if i == 6 then (1461, ghost ChunkTrace(1160,6))
    else if i == 7 then (2687, ghost ChunkTrace(1160,7))
    else if i == 8 then (939, ghost ChunkTrace(1160,8))
    else if i == 9 then (2308, ghost ChunkTrace(1160,9))
    else if i == 10 then (2437, ghost ChunkTrace(1160,10))
    else if i == 11 then (2388, ghost ChunkTrace(1160,11))
    else if i == 12 then (733, ghost ChunkTrace(1160,12))
    else if i == 13 then (2337, ghost ChunkTrace(1160,13))
    else if i == 14 then (268, ghost ChunkTrace(1160,14))
    else (641, ghost ChunkTrace(1160,15))
  }
  function ZetasChunk6(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk6(i).0 < 3329
    ensures ZetasChunk6(i).0 as int == S.Zetas()[96+(i as int)]
    ensures ZetasChunk6(i).1 == ChunkTrace(1192,i as int)
    ensures ZetasChunk6(i).1 == BranchFalsePrefix(1192,i as int) + ST.Branch(1192+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (1584, ghost ChunkTrace(1192,0))
    else if i == 1 then (2298, ghost ChunkTrace(1192,1))
    else if i == 2 then (2037, ghost ChunkTrace(1192,2))
    else if i == 3 then (3220, ghost ChunkTrace(1192,3))
    else if i == 4 then (375, ghost ChunkTrace(1192,4))
    else if i == 5 then (2549, ghost ChunkTrace(1192,5))
    else if i == 6 then (2090, ghost ChunkTrace(1192,6))
    else if i == 7 then (1645, ghost ChunkTrace(1192,7))
    else if i == 8 then (1063, ghost ChunkTrace(1192,8))
    else if i == 9 then (319, ghost ChunkTrace(1192,9))
    else if i == 10 then (2773, ghost ChunkTrace(1192,10))
    else if i == 11 then (757, ghost ChunkTrace(1192,11))
    else if i == 12 then (2099, ghost ChunkTrace(1192,12))
    else if i == 13 then (561, ghost ChunkTrace(1192,13))
    else if i == 14 then (2466, ghost ChunkTrace(1192,14))
    else (2594, ghost ChunkTrace(1192,15))
  }
  function ZetasChunk7(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= ZetasChunk7(i).0 < 3329
    ensures ZetasChunk7(i).0 as int == S.Zetas()[112+(i as int)]
    ensures ZetasChunk7(i).1 == ChunkTrace(1224,i as int)
    ensures ZetasChunk7(i).1 == BranchFalsePrefix(1224,i as int) + ST.Branch(1224+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Zetas();
    if i == 0 then (2804, ghost ChunkTrace(1224,0))
    else if i == 1 then (1092, ghost ChunkTrace(1224,1))
    else if i == 2 then (403, ghost ChunkTrace(1224,2))
    else if i == 3 then (1026, ghost ChunkTrace(1224,3))
    else if i == 4 then (1143, ghost ChunkTrace(1224,4))
    else if i == 5 then (2150, ghost ChunkTrace(1224,5))
    else if i == 6 then (2775, ghost ChunkTrace(1224,6))
    else if i == 7 then (886, ghost ChunkTrace(1224,7))
    else if i == 8 then (1722, ghost ChunkTrace(1224,8))
    else if i == 9 then (1212, ghost ChunkTrace(1224,9))
    else if i == 10 then (1874, ghost ChunkTrace(1224,10))
    else if i == 11 then (1029, ghost ChunkTrace(1224,11))
    else if i == 12 then (2110, ghost ChunkTrace(1224,12))
    else if i == 13 then (2935, ghost ChunkTrace(1224,13))
    else if i == 14 then (885, ghost ChunkTrace(1224,14))
    else (2154, ghost ChunkTrace(1224,15))
  }
  function ZetasValue(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 128
    ensures 0 <= ZetasValue(i).0 < 3329
    ensures ZetasValue(i).0 as int == S.Zetas()[i as int]
    ensures ZetasValue(i).1 == (if i < 16 then BranchFalsePrefix(800,0) + ST.Branch(800,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(430,31,1) + ZetasChunk0(i-0).1
      else if i < 32 then BranchFalsePrefix(800,1) + ST.Branch(801,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(431,32,1) + ZetasChunk1(i-16).1
      else if i < 48 then BranchFalsePrefix(800,2) + ST.Branch(802,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(432,33,1) + ZetasChunk2(i-32).1
      else if i < 64 then BranchFalsePrefix(800,3) + ST.Branch(803,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(433,34,1) + ZetasChunk3(i-48).1
      else if i < 80 then BranchFalsePrefix(800,4) + ST.Branch(804,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(434,35,1) + ZetasChunk4(i-64).1
      else if i < 96 then BranchFalsePrefix(800,5) + ST.Branch(805,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(435,36,1) + ZetasChunk5(i-80).1
      else if i < 112 then BranchFalsePrefix(800,6) + ST.Branch(806,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(436,37,1) + ZetasChunk6(i-96).1
      else BranchFalsePrefix(800,7) + ST.Branch(807,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(437,38,1) + ZetasChunk7(i-112).1)
  {
    if i < 16 then (ZetasChunk0(i-0).0, ghost BranchFalsePrefix(800,0) + ST.Branch(800,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(430,31,1) + ZetasChunk0(i-0).1)
    else if i < 32 then (ZetasChunk1(i-16).0, ghost BranchFalsePrefix(800,1) + ST.Branch(801,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(431,32,1) + ZetasChunk1(i-16).1)
    else if i < 48 then (ZetasChunk2(i-32).0, ghost BranchFalsePrefix(800,2) + ST.Branch(802,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(432,33,1) + ZetasChunk2(i-32).1)
    else if i < 64 then (ZetasChunk3(i-48).0, ghost BranchFalsePrefix(800,3) + ST.Branch(803,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(433,34,1) + ZetasChunk3(i-48).1)
    else if i < 80 then (ZetasChunk4(i-64).0, ghost BranchFalsePrefix(800,4) + ST.Branch(804,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(434,35,1) + ZetasChunk4(i-64).1)
    else if i < 96 then (ZetasChunk5(i-80).0, ghost BranchFalsePrefix(800,5) + ST.Branch(805,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(435,36,1) + ZetasChunk5(i-80).1)
    else if i < 112 then (ZetasChunk6(i-96).0, ghost BranchFalsePrefix(800,6) + ST.Branch(806,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(436,37,1) + ZetasChunk6(i-96).1)
    else (ZetasChunk7(i-112).0, ghost BranchFalsePrefix(800,7) + ST.Branch(807,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(437,38,1) + ZetasChunk7(i-112).1)
  }

  method {:isolate_assertions} NewZetas() returns (r: array<T.I>, ghost trace: seq<int>)
    ensures fresh(r) && r.Length == 128
    ensures T.Ints(r) == S.Zetas()
    ensures forall i: int :: 0 <= i < 128 ==> 0 <= r[i] < 3329
    ensures trace == NewZetasTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    trace := trace + ST.Alloc(100,128);
    r := new T.I[128 as T.I];
    trace := trace + ST.LoopBound(200,128);
    ZetasUpToZero();
    for i: T.I := 0 to 128
      invariant 0 <= i <= 128
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Zetas()[j] && 0 <= r[j] < 3329
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(100,128) + ST.LoopBound(200,128)
        + ZetasUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(200,true,i as int) + ST.Call(422,39,1);
      r[i] := ZetasValue(i).0;
      trace := trace + ZetasValue(i).1 + ST.Write(500,0,i as int);
      ZetasUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(200,false,128);
  }

  function GammasChunk0(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk0(i).0 < 3329
    ensures GammasChunk0(i).0 as int == S.Gammas()[0+(i as int)]
    ensures GammasChunk0(i).1 == ChunkTrace(2000,i as int)
    ensures GammasChunk0(i).1 == BranchFalsePrefix(2000,i as int) + ST.Branch(2000+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (17, ghost ChunkTrace(2000,0))
    else if i == 1 then (3312, ghost ChunkTrace(2000,1))
    else if i == 2 then (2761, ghost ChunkTrace(2000,2))
    else if i == 3 then (568, ghost ChunkTrace(2000,3))
    else if i == 4 then (583, ghost ChunkTrace(2000,4))
    else if i == 5 then (2746, ghost ChunkTrace(2000,5))
    else if i == 6 then (2649, ghost ChunkTrace(2000,6))
    else if i == 7 then (680, ghost ChunkTrace(2000,7))
    else if i == 8 then (1637, ghost ChunkTrace(2000,8))
    else if i == 9 then (1692, ghost ChunkTrace(2000,9))
    else if i == 10 then (723, ghost ChunkTrace(2000,10))
    else if i == 11 then (2606, ghost ChunkTrace(2000,11))
    else if i == 12 then (2288, ghost ChunkTrace(2000,12))
    else if i == 13 then (1041, ghost ChunkTrace(2000,13))
    else if i == 14 then (1100, ghost ChunkTrace(2000,14))
    else (2229, ghost ChunkTrace(2000,15))
  }
  function GammasChunk1(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk1(i).0 < 3329
    ensures GammasChunk1(i).0 as int == S.Gammas()[16+(i as int)]
    ensures GammasChunk1(i).1 == ChunkTrace(2032,i as int)
    ensures GammasChunk1(i).1 == BranchFalsePrefix(2032,i as int) + ST.Branch(2032+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (1409, ghost ChunkTrace(2032,0))
    else if i == 1 then (1920, ghost ChunkTrace(2032,1))
    else if i == 2 then (2662, ghost ChunkTrace(2032,2))
    else if i == 3 then (667, ghost ChunkTrace(2032,3))
    else if i == 4 then (3281, ghost ChunkTrace(2032,4))
    else if i == 5 then (48, ghost ChunkTrace(2032,5))
    else if i == 6 then (233, ghost ChunkTrace(2032,6))
    else if i == 7 then (3096, ghost ChunkTrace(2032,7))
    else if i == 8 then (756, ghost ChunkTrace(2032,8))
    else if i == 9 then (2573, ghost ChunkTrace(2032,9))
    else if i == 10 then (2156, ghost ChunkTrace(2032,10))
    else if i == 11 then (1173, ghost ChunkTrace(2032,11))
    else if i == 12 then (3015, ghost ChunkTrace(2032,12))
    else if i == 13 then (314, ghost ChunkTrace(2032,13))
    else if i == 14 then (3050, ghost ChunkTrace(2032,14))
    else (279, ghost ChunkTrace(2032,15))
  }
  function GammasChunk2(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk2(i).0 < 3329
    ensures GammasChunk2(i).0 as int == S.Gammas()[32+(i as int)]
    ensures GammasChunk2(i).1 == ChunkTrace(2064,i as int)
    ensures GammasChunk2(i).1 == BranchFalsePrefix(2064,i as int) + ST.Branch(2064+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (1703, ghost ChunkTrace(2064,0))
    else if i == 1 then (1626, ghost ChunkTrace(2064,1))
    else if i == 2 then (1651, ghost ChunkTrace(2064,2))
    else if i == 3 then (1678, ghost ChunkTrace(2064,3))
    else if i == 4 then (2789, ghost ChunkTrace(2064,4))
    else if i == 5 then (540, ghost ChunkTrace(2064,5))
    else if i == 6 then (1789, ghost ChunkTrace(2064,6))
    else if i == 7 then (1540, ghost ChunkTrace(2064,7))
    else if i == 8 then (1847, ghost ChunkTrace(2064,8))
    else if i == 9 then (1482, ghost ChunkTrace(2064,9))
    else if i == 10 then (952, ghost ChunkTrace(2064,10))
    else if i == 11 then (2377, ghost ChunkTrace(2064,11))
    else if i == 12 then (1461, ghost ChunkTrace(2064,12))
    else if i == 13 then (1868, ghost ChunkTrace(2064,13))
    else if i == 14 then (2687, ghost ChunkTrace(2064,14))
    else (642, ghost ChunkTrace(2064,15))
  }
  function GammasChunk3(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk3(i).0 < 3329
    ensures GammasChunk3(i).0 as int == S.Gammas()[48+(i as int)]
    ensures GammasChunk3(i).1 == ChunkTrace(2096,i as int)
    ensures GammasChunk3(i).1 == BranchFalsePrefix(2096,i as int) + ST.Branch(2096+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (939, ghost ChunkTrace(2096,0))
    else if i == 1 then (2390, ghost ChunkTrace(2096,1))
    else if i == 2 then (2308, ghost ChunkTrace(2096,2))
    else if i == 3 then (1021, ghost ChunkTrace(2096,3))
    else if i == 4 then (2437, ghost ChunkTrace(2096,4))
    else if i == 5 then (892, ghost ChunkTrace(2096,5))
    else if i == 6 then (2388, ghost ChunkTrace(2096,6))
    else if i == 7 then (941, ghost ChunkTrace(2096,7))
    else if i == 8 then (733, ghost ChunkTrace(2096,8))
    else if i == 9 then (2596, ghost ChunkTrace(2096,9))
    else if i == 10 then (2337, ghost ChunkTrace(2096,10))
    else if i == 11 then (992, ghost ChunkTrace(2096,11))
    else if i == 12 then (268, ghost ChunkTrace(2096,12))
    else if i == 13 then (3061, ghost ChunkTrace(2096,13))
    else if i == 14 then (641, ghost ChunkTrace(2096,14))
    else (2688, ghost ChunkTrace(2096,15))
  }
  function GammasChunk4(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk4(i).0 < 3329
    ensures GammasChunk4(i).0 as int == S.Gammas()[64+(i as int)]
    ensures GammasChunk4(i).1 == ChunkTrace(2128,i as int)
    ensures GammasChunk4(i).1 == BranchFalsePrefix(2128,i as int) + ST.Branch(2128+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (1584, ghost ChunkTrace(2128,0))
    else if i == 1 then (1745, ghost ChunkTrace(2128,1))
    else if i == 2 then (2298, ghost ChunkTrace(2128,2))
    else if i == 3 then (1031, ghost ChunkTrace(2128,3))
    else if i == 4 then (2037, ghost ChunkTrace(2128,4))
    else if i == 5 then (1292, ghost ChunkTrace(2128,5))
    else if i == 6 then (3220, ghost ChunkTrace(2128,6))
    else if i == 7 then (109, ghost ChunkTrace(2128,7))
    else if i == 8 then (375, ghost ChunkTrace(2128,8))
    else if i == 9 then (2954, ghost ChunkTrace(2128,9))
    else if i == 10 then (2549, ghost ChunkTrace(2128,10))
    else if i == 11 then (780, ghost ChunkTrace(2128,11))
    else if i == 12 then (2090, ghost ChunkTrace(2128,12))
    else if i == 13 then (1239, ghost ChunkTrace(2128,13))
    else if i == 14 then (1645, ghost ChunkTrace(2128,14))
    else (1684, ghost ChunkTrace(2128,15))
  }
  function GammasChunk5(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk5(i).0 < 3329
    ensures GammasChunk5(i).0 as int == S.Gammas()[80+(i as int)]
    ensures GammasChunk5(i).1 == ChunkTrace(2160,i as int)
    ensures GammasChunk5(i).1 == BranchFalsePrefix(2160,i as int) + ST.Branch(2160+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (1063, ghost ChunkTrace(2160,0))
    else if i == 1 then (2266, ghost ChunkTrace(2160,1))
    else if i == 2 then (319, ghost ChunkTrace(2160,2))
    else if i == 3 then (3010, ghost ChunkTrace(2160,3))
    else if i == 4 then (2773, ghost ChunkTrace(2160,4))
    else if i == 5 then (556, ghost ChunkTrace(2160,5))
    else if i == 6 then (757, ghost ChunkTrace(2160,6))
    else if i == 7 then (2572, ghost ChunkTrace(2160,7))
    else if i == 8 then (2099, ghost ChunkTrace(2160,8))
    else if i == 9 then (1230, ghost ChunkTrace(2160,9))
    else if i == 10 then (561, ghost ChunkTrace(2160,10))
    else if i == 11 then (2768, ghost ChunkTrace(2160,11))
    else if i == 12 then (2466, ghost ChunkTrace(2160,12))
    else if i == 13 then (863, ghost ChunkTrace(2160,13))
    else if i == 14 then (2594, ghost ChunkTrace(2160,14))
    else (735, ghost ChunkTrace(2160,15))
  }
  function GammasChunk6(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk6(i).0 < 3329
    ensures GammasChunk6(i).0 as int == S.Gammas()[96+(i as int)]
    ensures GammasChunk6(i).1 == ChunkTrace(2192,i as int)
    ensures GammasChunk6(i).1 == BranchFalsePrefix(2192,i as int) + ST.Branch(2192+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (2804, ghost ChunkTrace(2192,0))
    else if i == 1 then (525, ghost ChunkTrace(2192,1))
    else if i == 2 then (1092, ghost ChunkTrace(2192,2))
    else if i == 3 then (2237, ghost ChunkTrace(2192,3))
    else if i == 4 then (403, ghost ChunkTrace(2192,4))
    else if i == 5 then (2926, ghost ChunkTrace(2192,5))
    else if i == 6 then (1026, ghost ChunkTrace(2192,6))
    else if i == 7 then (2303, ghost ChunkTrace(2192,7))
    else if i == 8 then (1143, ghost ChunkTrace(2192,8))
    else if i == 9 then (2186, ghost ChunkTrace(2192,9))
    else if i == 10 then (2150, ghost ChunkTrace(2192,10))
    else if i == 11 then (1179, ghost ChunkTrace(2192,11))
    else if i == 12 then (2775, ghost ChunkTrace(2192,12))
    else if i == 13 then (554, ghost ChunkTrace(2192,13))
    else if i == 14 then (886, ghost ChunkTrace(2192,14))
    else (2443, ghost ChunkTrace(2192,15))
  }
  function GammasChunk7(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 16
    ensures 0 <= GammasChunk7(i).0 < 3329
    ensures GammasChunk7(i).0 as int == S.Gammas()[112+(i as int)]
    ensures GammasChunk7(i).1 == ChunkTrace(2224,i as int)
    ensures GammasChunk7(i).1 == BranchFalsePrefix(2224,i as int) + ST.Branch(2224+(i as int),true) + ST.Ops(0,0,0,0,0,0,0)
  {
    reveal S.Gammas();
    if i == 0 then (1722, ghost ChunkTrace(2224,0))
    else if i == 1 then (1607, ghost ChunkTrace(2224,1))
    else if i == 2 then (1212, ghost ChunkTrace(2224,2))
    else if i == 3 then (2117, ghost ChunkTrace(2224,3))
    else if i == 4 then (1874, ghost ChunkTrace(2224,4))
    else if i == 5 then (1455, ghost ChunkTrace(2224,5))
    else if i == 6 then (1029, ghost ChunkTrace(2224,6))
    else if i == 7 then (2300, ghost ChunkTrace(2224,7))
    else if i == 8 then (2110, ghost ChunkTrace(2224,8))
    else if i == 9 then (1219, ghost ChunkTrace(2224,9))
    else if i == 10 then (2935, ghost ChunkTrace(2224,10))
    else if i == 11 then (394, ghost ChunkTrace(2224,11))
    else if i == 12 then (885, ghost ChunkTrace(2224,12))
    else if i == 13 then (2444, ghost ChunkTrace(2224,13))
    else if i == 14 then (2154, ghost ChunkTrace(2224,14))
    else (1175, ghost ChunkTrace(2224,15))
  }
  function GammasValue(i: T.I): (T.I, ghost seq<int>)
    requires 0 <= i < 128
    ensures 0 <= GammasValue(i).0 < 3329
    ensures GammasValue(i).0 as int == S.Gammas()[i as int]
    ensures GammasValue(i).1 == (if i < 16 then BranchFalsePrefix(850,0) + ST.Branch(850,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(440,41,1) + GammasChunk0(i-0).1
      else if i < 32 then BranchFalsePrefix(850,1) + ST.Branch(851,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(441,42,1) + GammasChunk1(i-16).1
      else if i < 48 then BranchFalsePrefix(850,2) + ST.Branch(852,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(442,43,1) + GammasChunk2(i-32).1
      else if i < 64 then BranchFalsePrefix(850,3) + ST.Branch(853,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(443,44,1) + GammasChunk3(i-48).1
      else if i < 80 then BranchFalsePrefix(850,4) + ST.Branch(854,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(444,45,1) + GammasChunk4(i-64).1
      else if i < 96 then BranchFalsePrefix(850,5) + ST.Branch(855,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(445,46,1) + GammasChunk5(i-80).1
      else if i < 112 then BranchFalsePrefix(850,6) + ST.Branch(856,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(446,47,1) + GammasChunk6(i-96).1
      else BranchFalsePrefix(850,7) + ST.Branch(857,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(447,48,1) + GammasChunk7(i-112).1)
  {
    if i < 16 then (GammasChunk0(i-0).0, ghost BranchFalsePrefix(850,0) + ST.Branch(850,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(440,41,1) + GammasChunk0(i-0).1)
    else if i < 32 then (GammasChunk1(i-16).0, ghost BranchFalsePrefix(850,1) + ST.Branch(851,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(441,42,1) + GammasChunk1(i-16).1)
    else if i < 48 then (GammasChunk2(i-32).0, ghost BranchFalsePrefix(850,2) + ST.Branch(852,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(442,43,1) + GammasChunk2(i-32).1)
    else if i < 64 then (GammasChunk3(i-48).0, ghost BranchFalsePrefix(850,3) + ST.Branch(853,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(443,44,1) + GammasChunk3(i-48).1)
    else if i < 80 then (GammasChunk4(i-64).0, ghost BranchFalsePrefix(850,4) + ST.Branch(854,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(444,45,1) + GammasChunk4(i-64).1)
    else if i < 96 then (GammasChunk5(i-80).0, ghost BranchFalsePrefix(850,5) + ST.Branch(855,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(445,46,1) + GammasChunk5(i-80).1)
    else if i < 112 then (GammasChunk6(i-96).0, ghost BranchFalsePrefix(850,6) + ST.Branch(856,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(446,47,1) + GammasChunk6(i-96).1)
    else (GammasChunk7(i-112).0, ghost BranchFalsePrefix(850,7) + ST.Branch(857,true) + ST.Ops(0,1,0,0,0,0,0) + ST.Call(447,48,1) + GammasChunk7(i-112).1)
  }

  method {:isolate_assertions} NewGammas() returns (r: array<T.I>, ghost trace: seq<int>)
    ensures fresh(r) && r.Length == 128
    ensures T.Ints(r) == S.Gammas()
    ensures forall i: int :: 0 <= i < 128 ==> 0 <= r[i] < 3329
    ensures trace == NewGammasTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    trace := trace + ST.Alloc(101,128);
    r := new T.I[128 as T.I];
    trace := trace + ST.LoopBound(201,128);
    GammasUpToZero();
    for i: T.I := 0 to 128
      invariant 0 <= i <= 128
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Gammas()[j] && 0 <= r[j] < 3329
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(101,128) + ST.LoopBound(201,128)
        + GammasUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(201,true,i as int) + ST.Call(423,49,1);
      r[i] := GammasValue(i).0;
      trace := trace + GammasValue(i).1 + ST.Write(501,0,i as int);
      GammasUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(201,false,128);
  }

  method {:isolate_assertions} Add(f: array<T.I>, g: array<T.I>) returns (r: array<T.I>, ghost trace: seq<int>)
    requires T.Canonical(f) && T.Canonical(g)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.Add(T.Ints(f),T.Ints(g))
    ensures trace == AddTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    trace := trace + ST.Alloc(102,256);
    r := new T.I[256 as T.I];
    trace := trace + ST.LoopBound(202,256);
    AddUpToZero();
    for i: T.I := 0 to 256
      invariant 0 <= i <= 256
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Add(T.Ints(f),T.Ints(g))[j]
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(102,256) + ST.LoopBound(202,256)
        + AddUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(202,true,i as int) + ST.Read(502,0,i as int)
        + ST.Read(503,1,i as int) + ST.Call(400,3,2);
      ghost var ft: seq<int>;
      r[i], ft := F.Add(f[i],g[i]);
      assert ft == FieldAddCallee();
      trace := trace + ft + ST.Write(504,2,i as int);
      AddUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(202,false,256);
  }

  method {:isolate_assertions} Sub(f: array<T.I>, g: array<T.I>) returns (r: array<T.I>, ghost trace: seq<int>)
    requires T.Canonical(f) && T.Canonical(g)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.Sub(T.Ints(f),T.Ints(g))
    ensures trace == SubTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    trace := trace + ST.Alloc(103,256);
    r := new T.I[256 as T.I];
    trace := trace + ST.LoopBound(203,256);
    SubUpToZero();
    for i: T.I := 0 to 256
      invariant 0 <= i <= 256
      invariant forall j: int :: 0 <= j < i as int ==> r[j] as int == S.Sub(T.Ints(f),T.Ints(g))[j]
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(103,256) + ST.LoopBound(203,256)
        + SubUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(203,true,i as int) + ST.Read(505,0,i as int)
        + ST.Read(506,1,i as int) + ST.Call(401,4,2);
      ghost var ft: seq<int>;
      r[i], ft := F.Sub(f[i],g[i]);
      assert ft == FieldSubCallee();
      trace := trace + ft + ST.Write(507,2,i as int);
      SubUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(203,false,256);
  }

  method Copy(f: array<T.I>) returns (r: array<T.I>, ghost trace: seq<int>)
    requires T.Canonical(f)
    ensures fresh(r) && T.Canonical(r) && T.Ints(r) == T.Ints(f)
    ensures trace == CopyTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    trace := trace + ST.Alloc(104,256);
    r := new T.I[256 as T.I];
    trace := trace + ST.LoopBound(204,256);
    CopyUpToZero();
    for i: T.I := 0 to 256
      invariant 0 <= i <= 256
      invariant forall j: int :: 0 <= j < i as int ==> r[j] == f[j]
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(104,256) + ST.LoopBound(204,256)
        + CopyUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(204,true,i as int) + ST.Read(508,0,i as int);
      r[i] := f[i];
      trace := trace + ST.Write(509,1,i as int);
      CopyUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(204,false,256);
  }

  method {:isolate_assertions} ForwardStage(f: array<T.I>, r: array<T.I>, roots: array<T.I>, s: T.I)
      returns (ghost trace: seq<int>)
    requires T.Canonical(f) && r.Length == 256 && 0 <= s < 7
    requires f != r && roots != r && T.Ints(roots) == S.Zetas()
    modifies r
    ensures T.Canonical(r) && T.Ints(r) == S.ForwardStage(T.Ints(f),s as int)
    ensures trace == ForwardStageTrace(s as int)
  {
    trace := ST.Ops(8,0,4,2,0,0,0);
    trace := trace + ST.Call(424,30,1);
    var l := Len(s).0;
    trace := trace + Len(s).1;
    var blocks: T.I := 128/l;
    trace := trace + ST.LoopBound(205,blocks as int);
    FwdOuterUpToZero(l as int);
    for block: T.I := 0 to blocks
      modifies r
      invariant 0 <= block <= blocks
      invariant forall j: int :: 0 <= j < 2*(l as int)*(block as int) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
      invariant trace == ST.Ops(8,0,4,2,0,0,0) + ST.Call(424,30,1) + Len(s).1
        + ST.LoopBound(205,blocks as int) + FwdOuterUpTo(l as int, block as int)
    {
      trace := trace + ST.LoopCheck(205,true,block as int);
      var start: T.I := 2*l*block;
      var k: T.I := 128/l+block;
      trace := trace + ST.Read(513,2,k as int);
      reveal FwdOuterHead();
      S.StageBounds((s) as int,start as int);
      S.RootTables(k as int);
      var z := roots[k];
      trace := trace + ST.LoopBound(206,l as int);
      FwdInnerUpToZero(l as int, block as int);
      for offset: T.I := 0 to l
        modifies r
        invariant 0 <= offset <= l
        invariant forall j: int :: 0 <= j < start as int ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
        invariant forall j: int :: start as int <= j < (start as int)+(offset as int) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
        invariant forall j: int :: (start as int)+(l as int) <= j < (start as int)+(l as int)+(offset as int) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j)
        invariant trace == ST.Ops(8,0,4,2,0,0,0) + ST.Call(424,30,1) + Len(s).1
          + ST.LoopBound(205,blocks as int) + FwdOuterUpTo(l as int, block as int)
          + FwdOuterHead(l as int, block as int) + FwdInnerUpTo(l as int, block as int, offset as int)
      {
        trace := trace + ST.LoopCheck(206,true,offset as int);
        var i: T.I := start+offset;
        S.StageBounds((s) as int,i as int);
        S.StagePartner((s) as int,i as int);
        assert i/(2*l) == block && i%(2*l) == offset;
        assert i as int == 2*(l as int)*(block as int)+(offset as int);
        trace := trace + ST.Read(510,0,(i+l) as int) + ST.Call(402,5,2);
        var t, ftMul := F.Mul(z,f[i+l]);
        assert ftMul == FieldMulCallee();
        trace := trace + ftMul
          + ST.Read(511,0,i as int) + ST.Call(403,3,2);
        ghost var ftAdd: seq<int>;
        r[i], ftAdd := F.Add(f[i],t);
        assert ftAdd == FieldAddCallee();
        trace := trace + ftAdd + ST.Write(514,1,i as int)
          + ST.Read(512,0,i as int) + ST.Call(404,4,2);
        ghost var ftSub: seq<int>;
        r[i+l], ftSub := F.Sub(f[i],t);
        assert ftSub == FieldSubCallee();
        trace := trace + ftSub + ST.Write(515,1,(i+l) as int);
        reveal FwdInnerStep();
        FwdInnerUpToSucc(l as int, block as int, offset as int);
      }
      trace := trace + ST.LoopCheck(206,false,l as int);
      assert forall j: int :: 0 <= j < 2*(l as int)*((block as int)+1) ==> r[j] as int == S.ForwardLane(T.Ints(f),s as int,j);
      FwdOuterUpToSucc(l as int, block as int);
    }
    trace := trace + ST.LoopCheck(205,false,blocks as int);
    assert T.Ints(r) == S.ForwardStage(T.Ints(f),s as int);
  }

  method {:isolate_assertions} InverseStage(f: array<T.I>, r: array<T.I>, roots: array<T.I>, s: T.I)
      returns (ghost trace: seq<int>)
    requires T.Canonical(f) && r.Length == 256 && 0 <= s < 7
    requires f != r && roots != r && T.Ints(roots) == S.Zetas()
    modifies r
    ensures T.Canonical(r) && T.Ints(r) == S.InverseStage(T.Ints(f),s as int)
    ensures trace == InverseStageTrace(s as int)
  {
    trace := ST.Ops(8,5,4,2,0,0,0);
    trace := trace + ST.Call(425,30,1);
    var l := Len(6-s).0;
    trace := trace + Len(6-s).1;
    var blocks: T.I := 128/l;
    trace := trace + ST.LoopBound(207,blocks as int);
    InvOuterUpToZero(l as int);
    for block: T.I := 0 to blocks
      modifies r
      invariant 0 <= block <= blocks
      invariant forall j: int :: 0 <= j < 2*(l as int)*(block as int) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
      invariant trace == ST.Ops(8,5,4,2,0,0,0) + ST.Call(425,30,1) + Len(6-s).1
        + ST.LoopBound(207,blocks as int) + InvOuterUpTo(l as int, block as int)
    {
      trace := trace + ST.LoopCheck(207,true,block as int);
      var start: T.I := 2*l*block;
      var k: T.I := 256/l-1-block;
      trace := trace + ST.Read(520,2,k as int);
      reveal InvOuterHead();
      S.StageBounds((6-s) as int,start as int);
      S.RootTables(k as int);
      var z := roots[k];
      trace := trace + ST.LoopBound(208,l as int);
      InvInnerUpToZero(l as int, block as int);
      for offset: T.I := 0 to l
        modifies r
        invariant 0 <= offset <= l
        invariant forall j: int :: 0 <= j < start as int ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
        invariant forall j: int :: start as int <= j < (start as int)+(offset as int) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
        invariant forall j: int :: (start as int)+(l as int) <= j < (start as int)+(l as int)+(offset as int) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j)
        invariant trace == ST.Ops(8,5,4,2,0,0,0) + ST.Call(425,30,1) + Len(6-s).1
          + ST.LoopBound(207,blocks as int) + InvOuterUpTo(l as int, block as int)
          + InvOuterHead(l as int, block as int) + InvInnerUpTo(l as int, block as int, offset as int)
      {
        trace := trace + ST.LoopCheck(208,true,offset as int);
        var i: T.I := start+offset;
        S.StageBounds((6-s) as int,i as int);
        S.StagePartner((6-s) as int,i as int);
        assert i/(2*l) == block && i%(2*l) == offset;
        assert i as int == 2*(l as int)*(block as int)+(offset as int);
        trace := trace + ST.Read(516,0,i as int) + ST.Read(517,0,(i+l) as int) + ST.Call(405,3,2);
        ghost var ftAdd: seq<int>;
        r[i], ftAdd := F.Add(f[i],f[i+l]);
        assert ftAdd == FieldAddCallee();
        trace := trace + ftAdd + ST.Write(521,1,i as int)
          + ST.Read(518,0,(i+l) as int) + ST.Read(519,0,i as int) + ST.Call(406,6,3);
        ghost var ftMulSub: seq<int>;
        r[i+l], ftMulSub := F.MulSub(z,f[i+l],f[i]);
        assert ftMulSub == FieldMulSubCallee();
        trace := trace + ftMulSub + ST.Write(522,1,(i+l) as int);
        reveal InvInnerStep();
        InvInnerUpToSucc(l as int, block as int, offset as int);
      }
      trace := trace + ST.LoopCheck(208,false,l as int);
      assert forall j: int :: 0 <= j < 2*(l as int)*((block as int)+1) ==> r[j] as int == S.InverseLane(T.Ints(f),s as int,j);
      InvOuterUpToSucc(l as int, block as int);
    }
    trace := trace + ST.LoopCheck(207,false,blocks as int);
    assert T.Ints(r) == S.InverseStage(T.Ints(f),s as int);
  }

  method Scale(a: array<T.I>, scalar: T.I) returns (ghost trace: seq<int>)
    requires T.Canonical(a) && 0 <= scalar < 3329
    modifies a
    ensures T.Canonical(a) && T.Ints(a) == S.Scale(old(T.Ints(a)),scalar as int)
    ensures trace == ScaleTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    ghost var before := T.Ints(a);
    trace := trace + ST.LoopBound(209,256);
    ScaleUpToZero();
    for i: T.I := 0 to 256
      invariant 0 <= i <= 256
      invariant forall j: int :: 0 <= j < i as int ==> a[j] as int == S.Scale(before,scalar as int)[j]
      invariant forall j: int :: i as int <= j < 256 ==> a[j] as int == before[j]
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.LoopBound(209,256) + ScaleUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(209,true,i as int) + ST.Read(530,0,i as int) + ST.Call(407,5,2);
      ghost var ft: seq<int>;
      a[i], ft := F.Mul(a[i],scalar);
      assert ft == FieldMulCallee();
      trace := trace + ft + ST.Write(531,0,i as int);
      ScaleUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(209,false,256);
  }

  method {:isolate_assertions} Ntt(f: array<T.I>) returns (r: array<T.I>, ghost trace: seq<int>)
    requires T.Canonical(f)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.Ntt(T.Ints(f))
    ensures T.Ints(r) == S.Representation(T.Ints(f))
    ensures trace == NttTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    ghost var before := T.Ints(f);
    trace := trace + ST.Call(408,13,1);
    ghost var ct: seq<int>;
    r, ct := Copy(f);
    trace := trace + ct;
    trace := trace + ST.Alloc(105,256);
    var scratch := new T.I[256 as T.I];
    trace := trace + ST.Call(409,11,0);
    var roots, zt := NewZetas();
    trace := trace + zt;
    ghost var a,b := r,scratch;
    S.NttPrefixZero(before);
    trace := trace + ST.LoopBound(210,7);
    NttStageUpToZero();
    for s: T.I := 0 to 7
      modifies a,b
      invariant 0 <= s <= 7
      invariant (r == a && scratch == b) || (r == b && scratch == a)
      invariant fresh(r) && fresh(scratch)
      invariant r != scratch && r != roots && scratch != roots
      invariant scratch.Length == 256
      invariant T.Canonical(r) && T.Ints(r) == S.NttPrefix(before,s as int)
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.Call(408,13,1) + CopyTrace()
        + ST.Alloc(105,256) + ST.Call(409,11,0) + NewZetasTrace()
        + ST.LoopBound(210,7) + NttStageUpTo(s as int)
    {
      S.NttPrefixStep(before,s as int);
      trace := trace + ST.LoopCheck(210,true,s as int) + ST.Call(410,14,4);
      ghost var st: seq<int>;
      st := ForwardStage(r,scratch,roots,s);
      assert st == ForwardStageTrace(s as int);
      trace := trace + st;
      r,scratch := scratch,r;
      NttStageUpToSucc(s as int);
    }
    trace := trace + ST.LoopCheck(210,false,7);
    trace := trace + ST.Call(411,21,1);
    ghost var wt: seq<int>;
    wt := Wipe(scratch);
    assert wt == WipeTrace(256);
    trace := trace + wt;
    S.NttRepresentation(before);
  }

  method {:isolate_assertions} InverseNtt(f: array<T.I>) returns (r: array<T.I>, ghost trace: seq<int>)
    requires T.Canonical(f)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.InverseNtt(T.Ints(f))
    ensures S.Representation(T.Ints(r)) == T.Ints(f)
    ensures trace == InverseNttTrace()
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    ghost var before := T.Ints(f);
    trace := trace + ST.Call(412,13,1);
    ghost var ct: seq<int>;
    r, ct := Copy(f);
    trace := trace + ct;
    trace := trace + ST.Alloc(106,256);
    var scratch := new T.I[256 as T.I];
    trace := trace + ST.Call(413,11,0);
    var roots, zt := NewZetas();
    trace := trace + zt;
    ghost var a,b := r,scratch;
    trace := trace + ST.LoopBound(211,7);
    InvNttStageUpToZero();
    for s: T.I := 0 to 7
      modifies a,b
      invariant 0 <= s <= 7
      invariant (r == a && scratch == b) || (r == b && scratch == a)
      invariant fresh(r) && fresh(scratch)
      invariant r != scratch && r != roots && scratch != roots
      invariant scratch.Length == 256
      invariant T.Canonical(r) && T.Ints(r) == S.InversePrefix(before,s as int)
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.Call(412,13,1) + CopyTrace()
        + ST.Alloc(106,256) + ST.Call(413,11,0) + NewZetasTrace()
        + ST.LoopBound(211,7) + InvNttStageUpTo(s as int)
    {
      trace := trace + ST.LoopCheck(211,true,s as int) + ST.Call(414,15,4);
      ghost var st: seq<int>;
      st := InverseStage(r,scratch,roots,s);
      assert st == InverseStageTrace(s as int);
      trace := trace + st;
      r,scratch := scratch,r;
      InvNttStageUpToSucc(s as int);
    }
    trace := trace + ST.LoopCheck(211,false,7);
    trace := trace + ST.Call(415,21,1);
    ghost var wt: seq<int>;
    wt := Wipe(scratch);
    assert wt == WipeTrace(256);
    trace := trace + wt;
    trace := trace + ST.Call(416,16,2);
    ghost var sct: seq<int>;
    sct := Scale(r,3303);
    assert sct == ScaleTrace();
    trace := trace + sct;
    R.NttInverseRoundTrip(before);
    S.NttRepresentation(T.Ints(r));
  }

  method BaseCase(a0: T.I, a1: T.I, b0: T.I, b1: T.I, gamma: T.I,
      r: array<T.I>, i: T.I) returns (ghost trace: seq<int>)
    requires r.Length == 256 && 0 <= i < 255
    modifies r
    requires 0 <= a0 < 3329 && 0 <= a1 < 3329
    requires 0 <= b0 < 3329 && 0 <= b1 < 3329 && 0 <= gamma < 3329
    ensures 0 <= r[i] < 3329 && 0 <= r[i+1] < 3329
    ensures r[i] as int == ((a0 as int)*(b0 as int)+(a1 as int)*(b1 as int)*(gamma as int))%3329
    ensures r[i+1] as int == ((a0 as int)*(b1 as int)+(a1 as int)*(b0 as int))%3329
    ensures forall j: int :: 0 <= j < 256 && j != i as int && j != (i as int)+1 ==> r[j] == old(r[j])
    ensures trace == BaseCaseTrace(i as int)
  {
    trace := ST.Ops(1,0,0,0,0,0,0);
    trace := trace + ST.Call(417,5,2);
    var t, ftMul := F.Mul(a1,b1);
    assert ftMul == FieldMulCallee();
    trace := trace + ftMul + ST.Call(418,7,4);
    var c0, ftC0 := F.AddMul(a0,b0,t,gamma);
    assert ftC0 == FieldAddMulCallee();
    trace := trace + ftC0 + ST.Call(419,7,4);
    var c1, ftC1 := F.AddMul(a0,b1,a1,b0);
    assert ftC1 == FieldAddMulCallee();
    trace := trace + ftC1;
    r[i],r[i+1] := c0,c1;
    trace := trace + ST.Write(540,5,i as int) + ST.Write(541,5,(i+1) as int);
    P.ModProduct((a1 as int)*(b1 as int),gamma as int);
  }

  method {:isolate_assertions} NttMul(f: array<T.I>, g: array<T.I>) returns (r: array<T.I>, ghost trace: seq<int>)
    requires T.Canonical(f) && T.Canonical(g)
    ensures fresh(r) && T.Canonical(r)
    ensures T.Ints(r) == S.NttMul(T.Ints(f),T.Ints(g))
    ensures trace == NttMulTrace()
  {
    trace := ST.Ops(2,0,6,0,0,0,0);
    trace := trace + ST.Alloc(107,256);
    r := new T.I[256 as T.I];
    trace := trace + ST.Call(420,12,0);
    var gammas, gt := NewGammas();
    trace := trace + gt;
    trace := trace + ST.LoopBound(212,128);
    NttMulUpToZero();
    for i: T.I := 0 to 128
      modifies r
      invariant 0 <= i <= 128
      invariant forall j: int :: 0 <= j < 2*(i as int) ==> r[j] as int == S.NttMul(T.Ints(f),T.Ints(g))[j]
      invariant trace == ST.Ops(2,0,6,0,0,0,0) + ST.Alloc(107,256)
        + ST.Call(420,12,0) + NewGammasTrace()
        + ST.LoopBound(212,128) + NttMulUpTo(i as int)
    {
      S.RootTables(i as int);
      trace := trace + ST.LoopCheck(212,true,i as int)
        + ST.Read(524,0,(2*i) as int) + ST.Read(525,0,(2*i+1) as int)
        + ST.Read(526,1,(2*i) as int) + ST.Read(527,1,(2*i+1) as int)
        + ST.Read(528,3,i as int)
        + ST.Call(421,19,7);
      ghost var bct: seq<int>;
      bct := BaseCase(f[2*i],f[2*i+1],g[2*i],g[2*i+1],gammas[i],r,2*i);
      assert bct == BaseCaseTrace(2*(i as int));
      trace := trace + bct;
      NttMulUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(212,false,128);
    assert T.Ints(r) == S.NttMul(T.Ints(f),T.Ints(g));
  }

  method Wipe(a: array<T.I>) returns (ghost trace: seq<int>)
    requires T.JavaLength(a.Length)
    modifies a
    ensures forall i: int :: 0 <= i < a.Length ==> a[i] == 0
    ensures trace == WipeTrace(a.Length as int)
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    var length: T.I := a.Length as T.I;
    trace := trace + ST.LoopBound(213,length as int);
    WipeUpToZero();
    for i: T.I := 0 to length
      invariant 0 <= i <= length
      invariant forall k: int :: 0 <= k < i as int ==> a[k] == 0
      invariant trace == ST.Ops(0,0,0,0,0,0,0) + ST.LoopBound(213,length as int) + WipeUpTo(i as int)
    {
      trace := trace + ST.LoopCheck(213,true,i as int);
      a[i] := 0;
      trace := trace + ST.Write(550,0,i as int);
      WipeUpToSucc(i as int);
    }
    trace := trace + ST.LoopCheck(213,false,length as int);
    assert length as int == a.Length;
  }

}