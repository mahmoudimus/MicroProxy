// Adversarial canonical encoder body: exact function/constructor identities,
// but Encode returns the empty trace.
module {:compile false} SourceObservationVocabulary {
  datatype Event =
    | Call(site: int, target: int, arity: int)
    | Branch(site: int, taken: bool)
    | Read(site: int, role: int, address: int)
    | Write(site: int, role: int, address: int)
    | LoopCheck(site: int, guard: bool, iteration: int)
    | Ops(add: int, sub: int, mul: int, div: int, mod: int, bit: int, shift: int)
    | Alloc(site: int, size: int)
    | LoopBound(site: int, bound: int)
  ghost function Encode(e: Event): seq<int> { [1,0,0,0] }
}
