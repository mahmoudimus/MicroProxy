include "../../../crypto/NativeKeccak.dfy"

// Binding regressions over a private candidate of the actual NativeKeccak
// source, not a second Rotate algorithm. The focused runner materializes the
// immutable baseline and reviewed tuple/ghost instrumentation before resolving.
module SnapshotBindingControls {
  import T = NativeTypes
  import K = NativeKeccak
  import ST = SourceTrace

  method Local(word: bv64, n: T.I) returns (value: bv64, ghost trace: seq<int>)
    requires 0 <= n < 64
  {
    trace := [];
    ghost var callWitness := K.Rotate(word,n);
    trace := trace + ST.Call(0,20,2) + callWitness.1;
    value := K.Rotate(word,n).0;
  }

  method ArrayRead(input: array<bv64>, output: array<bv64>, i: T.I, j: T.I, n: T.I)
      returns (ghost trace: seq<int>)
    requires 0 <= i as int < output.Length && 0 <= j as int < input.Length
    requires 0 <= n < 64
    modifies output
  {
    trace := [];
    ghost var callWitness := K.Rotate(input[j],n);
    trace := trace + ST.Read(0,0,j as int) + ST.Call(1,20,2)
      + callWitness.1 + ST.Write(2,1,i as int);
    output[i] := K.Rotate(input[j],n).0;
  }

  method Around(a: array<bv64>, n: T.I)
      returns (value: bv64, ghost trace: seq<int>)
    requires a.Length >= 2 && 0 <= n < 64
  {
    trace := [];
    ghost var callWitness := K.Rotate(a[1],n);
    trace := trace + ST.Read(0,0,0) + ST.Read(1,0,1)
      + ST.Call(2,20,2) + callWitness.1 + ST.Ops(0,0,0,0,0,1,0);
    value := a[0] ^ K.Rotate(a[1],n).0;
  }
}
