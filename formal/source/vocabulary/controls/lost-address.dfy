// Genuine proof control: if Read encoding discards the address, two different
// source indices collapse to the same wire value.  The named assertion must
// fail; this control is not a positive proof.
include "../ObservationVocabulary.dfy"

module ControlLostAddress {
  import opened SourceObservationVocabulary

  ghost function BadEncode(e: Event): seq<int> {
    match e
    case Read(site, role, _) => [3, site, role, 0]
    case _ => [0]
  }

  lemma AddressMustSurvive()
    ensures BadEncode(Read(1, 10, 7)) != BadEncode(Read(1, 10, 8))
  {
    assert {:error "control-lost-address"} BadEncode(Read(1, 10, 7)) != BadEncode(Read(1, 10, 8));
  }
}
