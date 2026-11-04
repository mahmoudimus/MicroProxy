include "../../../crypto/NativePolynomial.dfy"

module LemmaOutControl {
  import ST = SourceTrace
  lemma Produce() returns (x: seq<int>)
    ensures x == []
  { x := []; }
  method Use() returns (ghost trace: seq<int>) {
    trace := ST.Ops(0,0,0,0,0,0,0);
    ghost var x: seq<int>;
    x := Produce();
  }
}
