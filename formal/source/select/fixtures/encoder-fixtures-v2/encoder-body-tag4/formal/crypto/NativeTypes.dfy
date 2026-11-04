// Common native Java ABI types. Their restrictions are proved at each owned
// caller; mathematical snapshots below are ghost and disappear from runtime.
module NativeTypes {
  newtype {:nativeType "int"} I = x: int | -2147483648 <= x <= 2147483647 witness 0
  newtype {:nativeType "long"} L = x: int | -9223372036854775808 <= x <= 9223372036854775807 witness 0

  ghost function Ints(a: array<I>): seq<int>
    reads a
    ensures |Ints(a)| == a.Length
  { seq(a.Length,i requires 0 <= i < a.Length reads a => a[i] as int) }
  ghost function Bytes(a: array<bv8>): seq<bv8>
    reads a
    ensures |Bytes(a)| == a.Length
  { a[..] }
  ghost predicate Canonical(a: array<I>)
    reads a
  { a.Length == 256 && forall i :: 0 <= i < a.Length ==> 0 <= a[i] as int < 3329 }
  ghost predicate JavaLength(length: int) { 0 <= length <= 2147483647 }
}
