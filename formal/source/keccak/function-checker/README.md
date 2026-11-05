# Four pure-function observation bodies

`KeccakFunctionCoverage.cs` is the unchanged independently reviewed observer for
actual `NativeKeccak.Rotate`, `Constant`, `Offset` and `Source` bodies. Its C#
SHA256 is `fd2b09dc7ff564b821a18c9ae6ae5b7a1607a4f621ffff196c0cf50a5425b90b`.
The isolated project compiles only that file and the shared canonical policy.

Use `../coverage_replay.py` to build it from frozen inputs, require it together
with the eleven-method observer on one actual source graph, and replay all18
function controls. The public component remains `qualification: false` and does
not replace source value/noninterference proofs, Java or delivery qualification.
