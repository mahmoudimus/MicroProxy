include "../ApiStateHarness.dfy"

// Intentionally false claims after real calls with satisfiable public inputs.
// Replay selects each method separately and accepts only its named assertion
// failure; these are controls for the evidence, not production vulnerabilities.
module ShakeApiControls {
  import T = NativeTypes
  import S = SpongeSpec
  import N = NativeShake

  method WrongEmptyReadPhase(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var s := new N.Sponge(rate);
    var output := new bv8[0];
    s.Read(output);
    assert s.squeezing;
    assert !s.squeezing; // NEGATIVE empty-read-phase
  }

  method WrongPhaseBeforeBounds(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var s := new N.Sponge(rate);
    var input := new bv8[0];
    s.Start();
    var status := s.Update(input, -1, -1);
    assert status == 1;
    assert status == 2; // NEGATIVE phase-before-bounds
  }

  method WrongInvalidSlice(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var s := new N.Sponge(rate);
    var input := new bv8[0];
    var status := s.Update(input, 0, 1);
    assert status == 2;
    assert status == 0; // NEGATIVE invalid-slice
  }

  method WrongDestroyPhase(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var s := new N.Sponge(rate);
    s.Start();
    s.Destroy();
    assert !s.squeezing && s.position == 0;
    assert s.squeezing; // NEGATIVE destroy-phase
  }

  method WrongNextBoundaryPosition(rate: T.I)
    requires S.ValidRate(rate as int)
  {
    var s := new N.Sponge(rate);
    s.Start();
    // This is an arbitrary valid API state at the public rate boundary.
    s.position := rate;
    assert s.Valid();
    ghost var before := s.Model();
    var value := s.Next();
    S.NextEquation(before);
    assert s.position == 1;
    assert s.position == 0; // NEGATIVE next-boundary-position
  }
}
