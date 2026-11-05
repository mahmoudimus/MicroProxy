# Canonical encoder policy

`NativeCanonicalEncoderPolicy.cs` is byte-identical to the released
`baf0e693c7d4344c7232ea3c3b9d64e1fac03ab3` Select policy. Its SHA256 is
`27115848f259786cd928d9d477fe0b51d84c7fc21efb5f98d83f5182358c0734`.
Both isolated Keccak checker projects compile these shared bytes. The policy
checks the actual typed encoder match, constructor/binder identities, tags,
field order, Boolean values and padding. It does not infer encoder semantics
from a function name or a file hash. The observers separately bind actual
SourceTrace wrappers to their canonical constructors and positional formals.
