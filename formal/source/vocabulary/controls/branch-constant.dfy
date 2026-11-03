// Genuine proof control: if a Branch encoding discards the Boolean payload,
// the required true/false distinguishability theorem is false.  The named
// assertion must fail; this control is not a positive proof.
include "../ObservationVocabulary.dfy"

module ControlBranchConstant {
  import opened SourceObservationVocabulary

  ghost function BadEncode(e: Event): seq<int> {
    match e
    case Branch(site, _) => [2, site, 0, 0]
    case _ => [0]
  }

  lemma BranchPayloadMustSurvive()
    ensures BadEncode(Branch(7, true)) != BadEncode(Branch(7, false))
  {
    assert {:error "control-branch-constant"} BadEncode(Branch(7, true)) != BadEncode(Branch(7, false));
  }
}
