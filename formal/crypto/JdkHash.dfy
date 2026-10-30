// Named provider trust boundary, FIPS 202 SHA3-256 and SHA3-512 only.
// These two deterministic external functions are the only KEM axioms.
// The Java adapter must call the named JDK MessageDigest algorithm, preserve
// bytes exactly, and return the specified length. Provider correctness, failures,
// compiler/runtime correctness and timing are outside the owned Dafny proofs.
module JdkHash {
  function {:extern "io.github.mahmoudimus.verifiedcrypto.kem_hash", "sha3_256"} {:axiom}
    H(input: seq<bv8>): seq<bv8>
    ensures |H(input)| == 32
  function {:extern "io.github.mahmoudimus.verifiedcrypto.kem_hash", "sha3_512"} {:axiom}
    G(input: seq<bv8>): seq<bv8>
    ensures |G(input)| == 64
}
