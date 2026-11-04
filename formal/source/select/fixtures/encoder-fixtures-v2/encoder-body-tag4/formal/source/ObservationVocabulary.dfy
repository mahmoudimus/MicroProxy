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
  ghost function Tag(e: Event): int {
    match e
    case Call(_,_,_) => 1
    case Branch(_,_) => 2
    case Read(_,_,_) => 3
    case Write(_,_,_) => 4
    case LoopCheck(_,_,_) => 9
    case Ops(_,_,_,_,_,_,_) => 6
    case Alloc(_,_) => 7
    case LoopBound(_,_) => 5
  }
  ghost function Encode(e: Event): seq<int> { [Tag(e), 0, 0, 0] }
}
