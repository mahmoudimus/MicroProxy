// Genuine proof control: dropping the tag creates a flattened payload encoding
// in which unrelated event kinds can be byte-identical.  The named assertion
// must fail; this control is not a positive proof.
include "../ObservationVocabulary.dfy"

module ControlFlattenedAmbiguous {
  import opened SourceObservationVocabulary

  ghost function BadEncode(e: Event): seq<int> {
    match e
    case Call(site, target, arity) => [site, target, arity]
    case Read(site, role, address) => [site, role, address]
    case _ => [0]
  }

  lemma EventKindMustNotFlatten()
    ensures BadEncode(Call(1, 2, 3)) != BadEncode(Read(1, 2, 3))
  {
    assert {:error "control-flattened-ambiguous"} BadEncode(Call(1, 2, 3)) != BadEncode(Read(1, 2, 3));
  }
}
