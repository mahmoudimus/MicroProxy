# SHAKE and ML-KEM functional verification

This directory extends the verified Keccak and scalar-field foundations toward
generated production Java. The [completion plan](../../docs/project/2026-10-29-dafny-crypto-completion.md)
requires full component composition, checked native-array refinements,
compatibility tests and performance measurements before adoption.

## SHAKE sponge and segmented sequence API

`SpongeSpec.dfy` gives byte-oriented FIPS 202 absorption, SHAKE padding and
squeezing equations. `Shake.dfy` implements those equations with verified loops.
General concatenation and read-partition lemmas cover arbitrary finite lengths
at both rates, including empty input and zero-length output. A zero-length read
initiates squeezing, after which every update is rejected. Slice bounds use
subtraction to avoid overflowing an offset-plus-length check. Both padding XORs
are preserved when the suffix and final bit share the last rate byte.

`ByteLanes.dfy` proves the little-endian byte/lane mapping, pack/unpack round trips
and single-byte XOR behavior. The independent caller harness covers all legal
states, rates, slice arguments and finite output lengths. Fourteen semantic
controls include padding, phase, rate boundaries, byte order and five narrowed
caller domains; their actual proof failures are required for a successful replay.

```sh
python3 formal/crypto/shake_checks.py --output target/dafny-crypto-shake \
  --java-home /path/to/jdk21 --java-home /path/to/jdk25
```

The replay validates the pinned compiler distribution and all included sources,
audits every module, generates Java and checks independent Python hashlib vectors.
It verifies source, tool, JDK and generated-artifact identities before publishing
a receipt. [Recorded evidence](SHAKE-EVIDENCE.json) has zero proof errors and zero
audit findings: Shake 115 checks, SpongeSpec 159, ByteLanes 24, caller harness 11,
and the included Keccak foundation 122. Generated Java passes 47,663 assertions on
each JDK, including 198 vectors/partitions and 24 slice cases. An independent
review replayed the module proofs, both JDK tests and the hashlib vectors.

This stage uses immutable sequences. Its Java copying-helper assertions do not
prove ownership for a future mutable facade. Native-array refinement, production
adoption and performance remain separate gates; JVM timing stays open.

## Codec and finite sampling stage

`Codec.dfy` proves compression/decompression equations and the circular error
bound for widths 1 through 11, lossless packing/round trips for widths 1, 4, 10
and 12, and total validation results. Its 12-bit operation is **checked decoding**:
it rejects noncanonical coefficients rather than reducing raw 12-bit words modulo
3329. That combines FIPS 203 decoding with key validation, matching our existing
Java policy; it is not an equivalence claim for raw ByteDecode12 on invalid keys.

`Sampling.dfy` proves CBD2 and finite rejection-feed ordering, capacity and exact
three-byte consumption. Feed rejects incomplete triples and returns `Full` or
`NeedMore` over valid finite blocks. It does not assume an arbitrary XOF stream
eventually supplies 256 accepted coefficients. Termination/failure policy and
intermediate cleanup belong to KEM composition and production delivery.

The public-domain harnesses call these operations over their complete documented
domains. Ten semantic mutations test rounding, packing, canonicality, CBD sign,
sampling order, rejection at q, capacity, consumption and domain narrowing.
Resource exhaustion, syntax failures and timeouts do not count as rejection.

Run the focused replay with a pinned Dafny distribution and explicit JDK paths:

```sh
python3 formal/crypto/codec_sampling_checks.py \
  --dafny /path/to/dafny/dafny \
  --output target/dafny-crypto-codec \
  --java-home /path/to/jdk21 --java-home /path/to/jdk25
```

The repository's `formal/dafny/toolchain.py` installs and checks the official
checksum-pinned Dafny 4.9.1 distribution, including its bundled Z3 4.12.1 and
runtime. CI uses that installer before this replay. Each replay creates a unique
scratch directory and publishes its receipt only after every gate passes and
all source/reference inputs still match their starting hashes.

[Recorded evidence](CODEC-EVIDENCE.json): Codec 469 checks, Sampling 26, public
domain harnesses 7 and 2, and Java generation 70; all had zero errors. Both audits
reported zero findings. Generated Java passed 207,513 assertions on each of JDK
21 and 25. An independent replay/review approved this stage. These counts include
verification obligations, not independent security properties. Java differential
tests are finite compatibility evidence, not a universal bytecode proof.

No production primitive changes in this stage. Compiler/runtime/JDK assumptions,
cryptographic hardness, entropy and JVM timing remain separate from functional
proofs. The overall SHAKE/ML-KEM goal stays open through production acceptance.

## Polynomial and NTT algebra

`Polynomial.dfy` proves canonical field ranges throughout the executable
256-coefficient add/subtract, NTT, inverse NTT and NTT-domain multiplication
algorithms. The NTT result is connected to independent power-sum polynomial
remainders from FIPS 203 equations 4.12–4.13. Both inverse directions, all roots
and table entries, and the inverse scale are proved. A general ring theorem
derives negacyclic multiplication using `X^256 = -1` and residue evaluation;
the reference product is not defined through the NTT implementation.

These theorems quantify over every canonical coefficient vector, not a fixed
corpus. [Recorded evidence](POLYNOMIAL-EVIDENCE.json) includes 1,480 verified
obligations with zero errors, six genuine semantic controls, and generated Java
tests with 288 cases and 551,008 assertions on each JDK. The finite tests include
all 256 basis positions and 32 independent schoolbook products. An independent
review reran the full proof, zero-finding audit, caller harness, all controls and
both Java replays, and independently reconstructed both tables from powers of 17.

Use a fresh output directory for each scoped replay, and run its zero-finding
audit as CI does. `--phase` selects partial developer evidence; acceptance requires
`all`, matching input identities and every reported gate.

```sh
python3 formal/crypto/polynomial_checks.py --phase all \
  --dafny /path/to/dafny/dafny --output /fresh/output/directory \
  --java-home /path/to/jdk21 --runtime-home /path/to/jdk25
```

This closes the mathematical polynomial/NTT composition stage. Native-array
refinement, generated production delivery, performance and timing remain separate.
