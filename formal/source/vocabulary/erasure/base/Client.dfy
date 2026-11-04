// Runtime client used only for the finite ghost-erasure experiment.
module ErasureClient {
  function Twice(x: int): int { 2 * x }

  method Adder(a: int, b: int) returns (r: int)
    ensures r == a + b
  {
    r := a + b;
  }

  method Main() {
    var r := Adder(2, 3);
    print r, "\n";
  }
}
