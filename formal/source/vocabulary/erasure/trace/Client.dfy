// Same runtime client as ../base/Client.dfy at the same source basename.  The
// only additions are ghost references to the {:compile false} vocabulary.
include "../../ObservationVocabulary.dfy"

module ErasureClient {
  import opened SourceObservationVocabulary

  ghost function ObservedEvents(): seq<Event> {
    [Call(1, 2, 3), Branch(4, true), Read(5, 6, 7), Write(8, 9, 10),
     LoopBound(11, 5), Ops(1, 0, 0, 0, 0, 0, 0), Alloc(12, 13),
     ProviderCall(14, 15, 16, 32, 32, 0, 32), LoopCheck(11, true, 0)]
  }

  ghost function ObservedTrace(): seq<int> { EncodeTrace(ObservedEvents()) }

  lemma ObservationRoundTrips()
    ensures DecodeTrace(ObservedTrace()) == SomeTrace(ObservedEvents())
  {
    DecodeTraceEncode(ObservedEvents());
  }

  function Twice(x: int): int { 2 * x }

  method Adder(a: int, b: int) returns (r: int)
    ensures r == a + b
  {
    r := a + b;
  }

  method Main() {
    var r := Adder(2, 3);
    print r, "\n";
  }
}
