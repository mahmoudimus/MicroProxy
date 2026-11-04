include "../../crypto/NativePolynomial.dfy"

// Universal two-run source-observation harnesses over the actual executable
// NativePolynomial methods.  Public configuration is identical between the two
// runs; coefficient contents are arbitrary and independently chosen.  The
// traces must be equal, and the functional result shapes must match the
// production postconditions.  These are proofs, not samples.
module NativePolynomialTraceHarness {
  import T = NativeTypes
  import NP = NativePolynomial
  import S = PolySpec
  import ST = SourceTrace

  method CheckNewZetas() {
    var r1, t1 := NP.NewZetas();
    var r2, t2 := NP.NewZetas();
    assert t1 == t2;
    assert t1 == NP.NewZetasTrace();
    assert fresh(r1) && fresh(r2) && r1.Length == 128 && r2.Length == 128;
    assert T.Ints(r1) == S.Zetas() && T.Ints(r2) == S.Zetas();
    ST.CallIsEncode(100,39,1); ST.OpsIsEncode(0,0,0,0,0,0,0);
  }

  method CheckNewGammas() {
    var r1, t1 := NP.NewGammas();
    var r2, t2 := NP.NewGammas();
    assert t1 == t2;
    assert t1 == NP.NewGammasTrace();
    assert fresh(r1) && fresh(r2) && r1.Length == 128 && r2.Length == 128;
    assert T.Ints(r1) == S.Gammas() && T.Ints(r2) == S.Gammas();
  }

  method CheckAdd(f1: array<T.I>, g1: array<T.I>, f2: array<T.I>, g2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(g1) && T.Canonical(f2) && T.Canonical(g2)
  {
    ghost var of1 := T.Ints(f1); ghost var og1 := T.Ints(g1);
    ghost var of2 := T.Ints(f2); ghost var og2 := T.Ints(g2);
    var r1, t1 := NP.Add(f1,g1);
    var r2, t2 := NP.Add(f2,g2);
    assert t1 == t2;
    assert t1 == NP.AddTrace();
    assert T.Ints(r1) == S.Add(of1,og1) && T.Ints(r2) == S.Add(of2,og2);
    assert T.Ints(f1) == of1 && T.Ints(g1) == og1 && T.Ints(f2) == of2 && T.Ints(g2) == og2;
  }

  method CheckAddAliased(f1: array<T.I>, f2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(f2)
  {
    var r1, t1 := NP.Add(f1,f1);
    var r2, t2 := NP.Add(f2,f2);
    assert t1 == t2;
    assert T.Ints(r1) == S.Add(T.Ints(f1),T.Ints(f1));
    assert T.Ints(r2) == S.Add(T.Ints(f2),T.Ints(f2));
  }

  method CheckSub(f1: array<T.I>, g1: array<T.I>, f2: array<T.I>, g2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(g1) && T.Canonical(f2) && T.Canonical(g2)
  {
    ghost var of1 := T.Ints(f1); ghost var og1 := T.Ints(g1);
    ghost var of2 := T.Ints(f2); ghost var og2 := T.Ints(g2);
    var r1, t1 := NP.Sub(f1,g1);
    var r2, t2 := NP.Sub(f2,g2);
    assert t1 == t2;
    assert t1 == NP.SubTrace();
    assert T.Ints(r1) == S.Sub(of1,og1) && T.Ints(r2) == S.Sub(of2,og2);
    assert T.Ints(f1) == of1 && T.Ints(g1) == og1 && T.Ints(f2) == of2 && T.Ints(g2) == og2;
  }

  method CheckSubAliased(f1: array<T.I>, f2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(f2)
  {
    var r1, t1 := NP.Sub(f1,f1);
    var r2, t2 := NP.Sub(f2,f2);
    assert t1 == t2;
    assert T.Ints(r1) == S.Sub(T.Ints(f1),T.Ints(f1));
    assert T.Ints(r2) == S.Sub(T.Ints(f2),T.Ints(f2));
  }

  method CheckCopy(f1: array<T.I>, f2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(f2)
  {
    ghost var of1 := T.Ints(f1); ghost var of2 := T.Ints(f2);
    var r1, t1 := NP.Copy(f1);
    var r2, t2 := NP.Copy(f2);
    assert t1 == t2;
    assert t1 == NP.CopyTrace();
    assert T.Ints(r1) == of1 && T.Ints(r2) == of2;
    assert T.Ints(f1) == of1 && T.Ints(f2) == of2;
  }

  method CheckScale(a1: array<T.I>, a2: array<T.I>, s: T.I)
    requires T.Canonical(a1) && T.Canonical(a2) && 0 <= s < 3329
    modifies a1, a2
  {
    ghost var o1 := T.Ints(a1); ghost var o2 := T.Ints(a2);
    var t1 := NP.Scale(a1,s);
    var t2 := NP.Scale(a2,s);
    assert t1 == t2;
    assert t1 == NP.ScaleTrace();
    assert T.Canonical(a1) && T.Canonical(a2);
  }

  method CheckForwardStage(f1: array<T.I>, r1: array<T.I>, roots1: array<T.I>,
                           f2: array<T.I>, r2: array<T.I>, roots2: array<T.I>, s: T.I)
    requires T.Canonical(f1) && T.Canonical(f2) && r1.Length == 256 && r2.Length == 256
    requires f1 != r1 && roots1 != r1 && T.Ints(roots1) == S.Zetas()
    requires f2 != r2 && roots2 != r2 && T.Ints(roots2) == S.Zetas()
    requires 0 <= s < 7
    requires r1 != r2 && f1 != r2 && f2 != r1
    modifies r1, r2
  {
    var t1 := NP.ForwardStage(f1,r1,roots1,s);
    var t2 := NP.ForwardStage(f2,r2,roots2,s);
    assert t1 == t2;
    assert t1 == NP.ForwardStageTrace(s as int);
    assert T.Ints(r1) == S.ForwardStage(T.Ints(f1),s as int);
    assert T.Ints(r2) == S.ForwardStage(T.Ints(f2),s as int);
  }

  method CheckInverseStage(f1: array<T.I>, r1: array<T.I>, roots1: array<T.I>,
                           f2: array<T.I>, r2: array<T.I>, roots2: array<T.I>, s: T.I)
    requires T.Canonical(f1) && T.Canonical(f2) && r1.Length == 256 && r2.Length == 256
    requires f1 != r1 && roots1 != r1 && T.Ints(roots1) == S.Zetas()
    requires f2 != r2 && roots2 != r2 && T.Ints(roots2) == S.Zetas()
    requires 0 <= s < 7
    requires r1 != r2 && f1 != r2 && f2 != r1
    modifies r1, r2
  {
    var t1 := NP.InverseStage(f1,r1,roots1,s);
    var t2 := NP.InverseStage(f2,r2,roots2,s);
    assert t1 == t2;
    assert t1 == NP.InverseStageTrace(s as int);
    assert T.Ints(r1) == S.InverseStage(T.Ints(f1),s as int);
    assert T.Ints(r2) == S.InverseStage(T.Ints(f2),s as int);
  }

  method CheckNtt(f1: array<T.I>, f2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(f2)
  {
    ghost var of1 := T.Ints(f1); ghost var of2 := T.Ints(f2);
    var r1, t1 := NP.Ntt(f1);
    var r2, t2 := NP.Ntt(f2);
    assert t1 == t2;
    assert t1 == NP.NttTrace();
    assert T.Ints(r1) == S.Ntt(of1) && T.Ints(r2) == S.Ntt(of2);
    assert T.Ints(r1) == S.Representation(of1) && T.Ints(r2) == S.Representation(of2);
    assert T.Ints(f1) == of1 && T.Ints(f2) == of2;
  }

  method CheckInverseNtt(f1: array<T.I>, f2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(f2)
  {
    ghost var of1 := T.Ints(f1); ghost var of2 := T.Ints(f2);
    var r1, t1 := NP.InverseNtt(f1);
    var r2, t2 := NP.InverseNtt(f2);
    assert t1 == t2;
    assert t1 == NP.InverseNttTrace();
    assert T.Ints(r1) == S.InverseNtt(of1) && T.Ints(r2) == S.InverseNtt(of2);
    assert S.Representation(T.Ints(r1)) == of1 && S.Representation(T.Ints(r2)) == of2;
    assert T.Ints(f1) == of1 && T.Ints(f2) == of2;
  }

  method CheckBaseCase(a0: T.I, a1: T.I, b0: T.I, b1: T.I, gamma: T.I,
                       a0p: T.I, a1p: T.I, b0p: T.I, b1p: T.I, gammap: T.I,
                       r1: array<T.I>, r2: array<T.I>, i: T.I)
    requires r1.Length == 256 && r2.Length == 256 && 0 <= i < 255
    requires 0 <= a0 < 3329 && 0 <= a1 < 3329 && 0 <= b0 < 3329 && 0 <= b1 < 3329 && 0 <= gamma < 3329
    requires 0 <= a0p < 3329 && 0 <= a1p < 3329 && 0 <= b0p < 3329 && 0 <= b1p < 3329 && 0 <= gammap < 3329
    modifies r1, r2
  {
    ghost var o1 := r1[..]; ghost var o2 := r2[..];
    var t1 := NP.BaseCase(a0,a1,b0,b1,gamma,r1,i);
    var t2 := NP.BaseCase(a0p,a1p,b0p,b1p,gammap,r2,i);
    assert t1 == t2;
    assert t1 == NP.BaseCaseTrace(i as int);
    assert forall j: int :: 0 <= j < 256 && j != i as int && j != (i as int)+1 ==> r1[j] == o1[j] && r2[j] == o2[j];
  }

  method CheckNttMul(f1: array<T.I>, g1: array<T.I>, f2: array<T.I>, g2: array<T.I>)
    requires T.Canonical(f1) && T.Canonical(g1) && T.Canonical(f2) && T.Canonical(g2)
  {
    ghost var of1 := T.Ints(f1); ghost var og1 := T.Ints(g1);
    ghost var of2 := T.Ints(f2); ghost var og2 := T.Ints(g2);
    var r1, t1 := NP.NttMul(f1,g1);
    var r2, t2 := NP.NttMul(f2,g2);
    assert t1 == t2;
    assert t1 == NP.NttMulTrace();
    assert T.Ints(r1) == S.NttMul(of1,og1) && T.Ints(r2) == S.NttMul(of2,og2);
    assert T.Ints(f1) == of1 && T.Ints(g1) == og1 && T.Ints(f2) == of2 && T.Ints(g2) == og2;
  }

  method CheckWipe(a1: array<T.I>, a2: array<T.I>)
    requires T.JavaLength(a1.Length) && T.JavaLength(a2.Length) && a1.Length == a2.Length
    modifies a1, a2
  {
    var t1 := NP.Wipe(a1);
    var t2 := NP.Wipe(a2);
    assert t1 == t2;
    assert t1 == NP.WipeTrace(a1.Length as int);
    assert forall j: int :: 0 <= j < a1.Length ==> a1[j] == 0;
    assert forall j: int :: 0 <= j < a2.Length ==> a2[j] == 0;
  }

  method CheckForwardStageSharedOutput(f1: array<T.I>, f2: array<T.I>, r: array<T.I>,
                                       roots1: array<T.I>, roots2: array<T.I>, s: T.I)
    requires T.Canonical(f1) && T.Canonical(f2) && r.Length == 256
    requires f1 != r && f2 != r && roots1 != r && roots2 != r
    requires T.Ints(roots1) == S.Zetas() && T.Ints(roots2) == S.Zetas() && 0 <= s < 7
    modifies r
  {
    var t1 := NP.ForwardStage(f1,r,roots1,s);
    var t2 := NP.ForwardStage(f2,r,roots2,s);
    assert t1 == t2;
    assert T.Ints(r) == S.ForwardStage(T.Ints(f2),s as int);
  }

  method CheckInverseStageSharedOutput(f1: array<T.I>, f2: array<T.I>, r: array<T.I>,
                                       roots1: array<T.I>, roots2: array<T.I>, s: T.I)
    requires T.Canonical(f1) && T.Canonical(f2) && r.Length == 256
    requires f1 != r && f2 != r && roots1 != r && roots2 != r
    requires T.Ints(roots1) == S.Zetas() && T.Ints(roots2) == S.Zetas() && 0 <= s < 7
    modifies r
  {
    var t1 := NP.InverseStage(f1,r,roots1,s);
    var t2 := NP.InverseStage(f2,r,roots2,s);
    assert t1 == t2;
    assert T.Ints(r) == S.InverseStage(T.Ints(f2),s as int);
  }

  method CheckForwardStageSharedRoots(f1: array<T.I>, f2: array<T.I>, r1: array<T.I>, r2: array<T.I>,
                                      roots: array<T.I>, s: T.I)
    requires T.Canonical(f1) && T.Canonical(f2) && r1.Length == 256 && r2.Length == 256
    requires r1 != r2 && f1 != r2 && f2 != r1
    requires f1 != r1 && f2 != r2 && roots != r1 && roots != r2
    requires T.Ints(roots) == S.Zetas() && 0 <= s < 7
    modifies r1, r2
  {
    var t1 := NP.ForwardStage(f1,r1,roots,s);
    var t2 := NP.ForwardStage(f2,r2,roots,s);
    assert t1 == t2;
    assert T.Ints(r1) == S.ForwardStage(T.Ints(f1),s as int);
    assert T.Ints(r2) == S.ForwardStage(T.Ints(f2),s as int);
  }
}
