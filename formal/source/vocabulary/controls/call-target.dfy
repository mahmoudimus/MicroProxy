// Genuine proof control: if Call encoding discards the resolved target, two
// different callees collapse to the same wire value.  The named assertion must
// fail; this control is not a positive proof.
include "../ObservationVocabulary.dfy"

module ControlCallTarget {
  import opened SourceObservationVocabulary

  ghost function BadEncode(e: Event): seq<int> {
    match e
    case Call(site, _, arity) => [1, site, 0, arity]
    case _ => [0]
  }

  lemma CallTargetMustSurvive()
    ensures BadEncode(Call(1, 2, 3)) != BadEncode(Call(1, 4, 3))
  {
    assert {:error "control-call-target"} BadEncode(Call(1, 2, 3)) != BadEncode(Call(1, 4, 3));
  }
}
