include "NativeTypes.dfy"
include "JdkHash.dfy"

// Two native ABI bindings for the same two JDK provider primitives used by
// JdkHash. Equality to H/G, byte preservation, allocation, digest length and
// normal completion are explicit trust assumptions. No owned algorithm is
// assumed here. Provider/JVM correctness and physical erasure are external.
module NativeJdkHash {
  import T = NativeTypes
  import H = JdkHash
  method {:extern "io.github.mahmoudimus.verifiedcrypto.native_kem_hash", "sha3_256"} {:axiom}
    Hash(input: array<bv8>) returns(output: array<bv8>)
    ensures fresh(output) && output.Length == 32
    ensures output[..] == H.H(input[..])
    ensures input[..] == old(input[..])
  method {:extern "io.github.mahmoudimus.verifiedcrypto.native_kem_hash", "sha3_512"} {:axiom}
    Expand(input: array<bv8>) returns(output: array<bv8>)
    ensures fresh(output) && output.Length == 64
    ensures output[..] == H.G(input[..])
    ensures input[..] == old(input[..])
}
