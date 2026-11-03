// Genuine proof control: if the eight-int Ops count tuple loses one count
// (for example the shift count), distinct count tuples collapse.  The named
// assertion must fail; this control is not a positive proof.
include "../ObservationVocabulary.dfy"

module ControlOpsWidth {
  import opened SourceObservationVocabulary

  ghost function BadEncode(e: Event): seq<int> {
    match e
    case Ops(add, sub, mul, div, mod, bit, _) => [6, add, sub, mul, div, mod, bit]
    case _ => [0]
  }

  lemma EveryCountMustSurvive()
    ensures BadEncode(Ops(1, 2, 3, 4, 5, 6, 7)) !=
            BadEncode(Ops(1, 2, 3, 4, 5, 6, 8))
  {
    assert {:error "control-ops-width"}
      BadEncode(Ops(1, 2, 3, 4, 5, 6, 7)) !=
      BadEncode(Ops(1, 2, 3, 4, 5, 6, 8));
  }
}
