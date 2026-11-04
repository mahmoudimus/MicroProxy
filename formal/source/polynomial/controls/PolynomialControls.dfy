include "../../../crypto/NativePolynomial.dfy"

// Genuine source-level controls for the trusted checker.  They are not
// production code and are never translated.  `Control` exercises omission,
// shadowed callee identity, array-role substitution, event reset, marker
// interposition, unsupported control flow, and honest secret observations.
module Shadow {
  method Add(a: int, b: int) returns (r: int)
    ensures r == a+b
  { r := a+b; }
}

module Control {
  import ST = SourceTrace
  import SH = Shadow

  method SecretBranchObserved(x: int) returns (r: int, ghost trace: seq<int>)
    ensures r == (if x == 0 then 1 else 2)
    ensures trace == ST.Ops(0,0,0,0,0,0,0) + ST.Branch(1, x == 0)
  {
    trace := ST.Ops(0,0,0,0,0,0,0) + ST.Branch(1, x == 0);
    if x == 0 { r := 1; } else { r := 2; }
  }

  method SecretBranchUnmarked(x: int) returns (r: int, ghost trace: seq<int>)
    ensures r == (if x == 0 then 1 else 2)
    ensures trace == ST.Ops(0,0,0,0,0,0,0)
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    if x == 0 { r := 1; } else { r := 2; }
  }

  method SecretIndexObserved(i: int, a: array<int>) returns (r: int, ghost trace: seq<int>)
    requires 0 <= i < a.Length
    ensures r == a[i]
    ensures trace == ST.Ops(0,0,0,0,0,0,0) + ST.Read(1,1,i)
  {
    trace := ST.Ops(0,0,0,0,0,0,0) + ST.Read(1,1,i);
    r := a[i];
  }

  method SecretIndexUnmarked(i: int, a: array<int>) returns (r: int, ghost trace: seq<int>)
    requires 0 <= i < a.Length
    ensures r == a[i]
    ensures trace == ST.Ops(0,0,0,0,0,0,0)
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    r := a[i];
  }

  method ShadowCallee(a: int, b: int) returns (r: int, ghost trace: seq<int>)
    ensures r == a+b
  {
    trace := ST.Ops(0,0,0,0,0,0,0) + ST.Call(1,3,2) + ST.Ops(1,0,0,0,0,0,0);
    r := SH.Add(a,b);
  }

  method RoleShadow(f: array<int>, g: array<int>) returns (r: array<int>, ghost trace: seq<int>)
    requires f.Length == 1 && g.Length == 1
    ensures fresh(r) && r.Length == 1 && r[0] == g[0]
  {
    trace := ST.Ops(0,0,0,0,0,0,0) + ST.Alloc(1,1);
    r := new int[1];
    trace := trace + ST.Read(2,0,0);
    r[0] := g[0];
    trace := trace + ST.Write(3,1,0);
  }

  method EventReset(x: int) returns (r: int, ghost trace: seq<int>)
    ensures r == x
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    trace := ST.Branch(1, x == 0);
    r := x;
  }

  method Interposed(i: int, a: array<int>) returns (r: int, ghost trace: seq<int>)
    requires 0 <= i < a.Length
    ensures r == a[i]
    ensures trace == ST.Ops(0,0,0,0,0,0,0) + ST.Read(1,1,i) + ST.Branch(2, i == 0)
  {
    trace := ST.Ops(0,0,0,0,0,0,0) + ST.Read(1,1,i) + ST.Branch(2, i == 0);
    if i == 0 { r := a[i]; } else { r := a[i]; }
  }

  method Unsupported(n: int) returns (r: int, ghost trace: seq<int>)
    requires 0 <= n
    ensures r == n
    ensures trace == ST.Ops(0,0,0,0,0,0,0)
  {
    trace := ST.Ops(0,0,0,0,0,0,0);
    var i := 0;
    while i < n
      invariant 0 <= i <= n
      decreases n - i
    { i := i + 1; }
    r := n;
  }
}

// Actual executable-function tuple controls.  The real projection is used by
// the caller; the ghost projection is the trace returned by the same function.
module FunctionControl {
  import ST = SourceTrace

  function PrivateBranchObserved(v: int): (int, ghost seq<int>)
    requires 0 <= v < 2
    ensures PrivateBranchObserved(v).0 == (if v == 0 then 1 else 2)
  {
    if v == 0 then (1, ghost ST.Ops(0,0,0,0,0,0,0) + ST.Branch(1,true))
    else (2, ghost ST.Ops(0,0,0,0,0,0,0) + ST.Branch(1,false))
  }

  function PrivateBranchUnmarked(v: int): (int, ghost seq<int>)
    requires 0 <= v < 2
    ensures PrivateBranchUnmarked(v).0 == (if v == 0 then 1 else 2)
  {
    if v == 0 then (1, ghost ST.Ops(0,0,0,0,0,0,0))
    else (2, ghost ST.Ops(0,0,0,0,0,0,0))
  }

  function PrivateBranchReset(v: int): (int, ghost seq<int>)
    requires 0 <= v < 2
    ensures PrivateBranchReset(v).0 == (if v == 0 then 1 else 2)
  {
    if v == 0 then (1, ghost [])
    else (2, ghost [])
  }

  function PrivateIndexObserved(i: int, a: array<int>): (int, ghost seq<int>)
    requires 0 <= i < a.Length
    reads a
    ensures PrivateIndexObserved(i,a).0 == a[i]
  {
    (a[i], ghost ST.Ops(0,0,0,0,0,0,0) + ST.Read(1,1,i))
  }

  function PrivateIndexUnmarked(i: int, a: array<int>): (int, ghost seq<int>)
    requires 0 <= i < a.Length
    reads a
    ensures PrivateIndexUnmarked(i,a).0 == a[i]
  {
    (a[i], ghost ST.Ops(0,0,0,0,0,0,0))
  }
}
