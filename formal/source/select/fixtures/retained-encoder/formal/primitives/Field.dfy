// Scalar field-helper contracts for q=3329. Arithmetic formulas are adapted
// from the existing Go-derived MlKem768.java (Go Authors, BSD-3-Clause).
// The contracts, range lemmas and Dafny proofs here are new work.
// Preconditions concern canonical coefficients; polynomial callers are separate.
module VerifiedField {
  const Q: int := 3329
  const MaxReduce: int := 22154496 // 3328*6657; includes inputs above 2^24.

  method ReduceOnce(a: int) returns (r: int)
    requires 0 <= a < 2*Q
    ensures 0 <= r < Q && r == a%Q
  {
    var x := (a-Q)%65536;
    r := (x+(x/32768)*Q)%65536;
    if a < Q { assert x == a-Q+65536; }
    else { assert x == a-Q; }
  }

  method Reduce(a: int) returns (r: int)
    requires 0 <= a <= MaxReduce
    ensures 0 <= r < Q && r == a%Q
  {
    var quotient := (a*5039)/16777216;
    var remainder := a - quotient*Q;
    r := ReduceOnce(remainder%65536);
  }
  method Add(a: int, b: int) returns (r: int)
    requires 0 <= a < Q && 0 <= b < Q
    ensures 0 <= r < Q && r == (a+b)%Q
  { r := ReduceOnce((a+b)%65536); }
  method Sub(a: int, b: int) returns (r: int)
    requires 0 <= a < Q && 0 <= b < Q
    ensures 0 <= r < Q && r == (a-b)%Q
  { r := ReduceOnce((a-b+Q)%65536); }
  method Mul(a: int, b: int) returns (r: int)
    requires 0 <= a < Q && 0 <= b < Q
    ensures 0 <= r < Q && r == (a*b)%Q
  {
    ProductBound(a, b, 3328, 3328);
    r := Reduce(a*b);
  }
  method MulSub(a: int, b: int, c: int) returns (r: int)
    requires 0 <= a < Q && 0 <= b < Q && 0 <= c < Q
    ensures 0 <= r < Q && r == (a*(b-c))%Q
  {
    var adjusted := (b-c+Q)%65536;
    assert adjusted == b-c+Q;
    ProductBound(a, adjusted, 3328, 6657);
    r := Reduce(a*adjusted);
    assert a*adjusted == a*(b-c)+a*Q;
    assert (a*(b-c)+a*Q)%Q == (a*(b-c))%Q;
  }
  method AddMul(a: int, b: int, c: int, d: int) returns (r: int)
    requires 0 <= a < Q && 0 <= b < Q && 0 <= c < Q && 0 <= d < Q
    ensures 0 <= r < Q && r == (a*b+c*d)%Q
  {
    ProductBound(a, b, 3328, 3328);
    ProductBound(c, d, 3328, 3328);
    r := Reduce(a*b+c*d);
  }

  lemma ProductBound(a: int, b: int, u: int, v: int)
    requires 0 <= a <= u && 0 <= b <= v
    ensures 0 <= a*b <= u*v
  {
    assert a*b <= u*b;
    assert u*b <= u*v;
  }
}
