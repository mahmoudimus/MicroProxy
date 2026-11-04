include "NativeTypes.dfy"
include "../primitives/Field.dfy"
include "../source/SourceTrace.dfy"

// Native scalar refinement of the verified q=3329 field equations. Coefficients
// are Java ints, and the bounded Barrett product is a long. Reduction uses the
// Go-derived reciprocal and
// unsigned shifts only; mathematical division/remainder occur only in ghosts.
module NativeField {
  import T = NativeTypes
  import F = VerifiedField
  import ST = SourceTrace
  const Q: T.I := 3329
  const MaxReduce: T.I := 22154496

  lemma BarrettBounds(a: int)
    requires 0 <= a <= 22154496
    ensures 0 <= (a*5039)/16777216 <= 6654
    ensures 0 <= a-((a*5039)/16777216)*3329 < 6658
  {}

  // Bound covers every native Barrett product, including inputs above 2^24.
  // This standalone conversion proof avoids mixing bitvector division facts
  // with the caller's arithmetic context.
  lemma Shift24(x: bv64)
    requires x < 137438953472
    ensures (x >> 24) as int == (x as int)/16777216
  {}

  lemma NativeShift24(product: T.L)
    requires 0 <= product < 137438953472
    ensures ((product as bv64) >> 24) as int == (product as int)/16777216
  {
    var word: bv64 := product as bv64;
    assert word as int == product as int;
    assert word < 137438953472;
    Shift24(word);
  }

  // Observation ids: 1=ReduceOnce, 2=Reduce.  Ops records executable source
  // word-operation counts; primitive target-language cost is a separate trust
  // assumption.  Ghost-only proof branches contribute no runtime trace.
  method {:isolate_assertions} ReduceOnce(a: T.I) returns (r: T.I, ghost trace: seq<int>)
    requires 0 <= a < 6658
    ensures 0 <= r < Q && r as int == (a as int)%3329
    ensures trace == ST.Ops(1,2,1,0,0,1,1)
  {
    trace := ST.Ops(1,2,1,0,0,1,1);
    // The bias places a-Q around bit 15 without a signed-to-unsigned cast.
    // The sign case below is ghost; runtime uses only arithmetic and shifts.
    // bv64 avoids the delivered runtime's bv32 shift helper sign branch.
    var biased: T.I := a+32768-Q;
    var atLeastQ: bv64 := ((biased as bv64) >> (15 as T.I)) & 1;
    ghost var small := a < Q;
    if small {
      assert 0 <= biased < 32768;
      assert (biased as bv64) < 32768;
      assert atLeastQ == 0;
    } else {
      assert 32768 <= biased < 65536;
      assert 32768 <= (biased as bv64) < 65536;
      assert atLeastQ == 1;
    }
    r := a-(atLeastQ as T.I)*Q;
  }
  method {:isolate_assertions} Reduce(a: T.I) returns (r: T.I, ghost trace: seq<int>)
    requires 0 <= a <= MaxReduce
    ensures 0 <= r < Q && r as int == (a as int)%3329
    ensures trace == ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1)
  {
    trace := ST.Ops(0,1,2,0,0,0,1);
    var product: T.L := (a as T.L)*5039;
    assert 0 <= product < 137438953472;
    NativeShift24(product);
    var shifted: bv64 := (product as bv64) >> (24 as T.I);
    assert shifted as int == (product as int)/16777216;
    BarrettBounds(a as int);
    var quotient: T.I := shifted as T.I;
    var remainder: T.I := a-quotient*Q;
    ghost var callee: seq<int>;
    r, callee := ReduceOnce(remainder);
    trace := trace + ST.Call(1,1,1) + callee;
  }
  method Add(a: T.I, b: T.I) returns (r: T.I, ghost trace: seq<int>)
    requires 0 <= a < Q && 0 <= b < Q
    ensures 0 <= r < Q && r as int == ((a as int)+(b as int))%3329
    ensures trace == ST.Ops(1,0,0,0,0,0,0) + ST.Ops(1,2,1,0,0,1,1) + ST.Call(1,1,1)
  {
    trace := ST.Ops(1,0,0,0,0,0,0);
    ghost var callee: seq<int>;
    r, callee := ReduceOnce(a+b);
    trace := trace + callee + ST.Call(1,1,1);
  }
  method Sub(a: T.I, b: T.I) returns (r: T.I, ghost trace: seq<int>)
    requires 0 <= a < Q && 0 <= b < Q
    ensures 0 <= r < Q && r as int == ((a as int)-(b as int))%3329
    ensures trace == ST.Ops(1,1,0,0,0,0,0) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1)
  {
    trace := ST.Ops(1,1,0,0,0,0,0);
    ghost var callee: seq<int>;
    r, callee := ReduceOnce(a+Q-b);
    trace := trace + ST.Call(1,1,1) + callee;
  }
  method Mul(a: T.I, b: T.I) returns (r: T.I, ghost trace: seq<int>)
    requires 0 <= a < Q && 0 <= b < Q
    ensures 0 <= r < Q && r as int == ((a as int)*(b as int))%3329
    ensures trace == ST.Ops(0,0,1,0,0,0,0) + ST.Call(2,2,1)
      + ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1)
  {
    trace := ST.Ops(0,0,1,0,0,0,0);
    F.ProductBound(a as int,b as int,3328,3328);
    ghost var callee: seq<int>;
    r, callee := Reduce(a*b);
    trace := trace + ST.Call(2,2,1) + callee;
  }
  method MulSub(a: T.I, b: T.I, c: T.I) returns (r: T.I, ghost trace: seq<int>)
    requires 0 <= a < Q && 0 <= b < Q && 0 <= c < Q
    ensures 0 <= r < Q && r as int == ((a as int)*((b as int)-(c as int)))%3329
    ensures trace == ST.Ops(1,1,1,0,0,0,0) + ST.Call(3,2,1)
      + ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1)
  {
    trace := ST.Ops(1,1,1,0,0,0,0);
    var adjusted := b+Q-c;
    F.ProductBound(a as int,adjusted as int,3328,6657);
    ghost var callee: seq<int>;
    r, callee := Reduce(a*adjusted);
    trace := trace + ST.Call(3,2,1) + callee;
    assert (a as int)*(adjusted as int) == (a as int)*((b as int)-(c as int))+(a as int)*3329;
  }
  method AddMul(a: T.I, b: T.I, c: T.I, d: T.I) returns (r: T.I, ghost trace: seq<int>)
    requires 0 <= a < Q && 0 <= b < Q && 0 <= c < Q && 0 <= d < Q
    ensures 0 <= r < Q && r as int == ((a as int)*(b as int)+(c as int)*(d as int))%3329
    ensures trace == ST.Ops(1,0,2,0,0,0,0) + ST.Call(4,2,1)
      + ST.Ops(0,1,2,0,0,0,1) + ST.Call(1,1,1) + ST.Ops(1,2,1,0,0,1,1)
  {
    trace := ST.Ops(1,0,2,0,0,0,0);
    F.ProductBound(a as int,b as int,3328,3328);
    F.ProductBound(c as int,d as int,3328,3328);
    ghost var callee: seq<int>;
    r, callee := Reduce(a*b+c*d);
    trace := trace + ST.Call(4,2,1) + callee;
  }
}
