// Genuine proof control: if Read encoding discards the resolved buffer role,
// two different roles collapse to the same wire value.  The named assertion
// must fail; this control is not a positive proof.
include "../ObservationVocabulary.dfy"

module ControlReadRole {
  import opened SourceObservationVocabulary

  ghost function BadEncode(e: Event): seq<int> {
    match e
    case Read(site, _, address) => [3, site, 0, address]
    case _ => [0]
  }

  lemma RoleMustSurvive()
    ensures BadEncode(Read(1, 10, 7)) != BadEncode(Read(1, 20, 7))
  {
    assert {:error "control-read-role"} BadEncode(Read(1, 10, 7)) != BadEncode(Read(1, 20, 7));
  }
}
