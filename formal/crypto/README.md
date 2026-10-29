# SHAKE and ML-KEM functional verification

This directory extends the verified Keccak and scalar-field foundations toward
generated production Java. The [completion plan](../../docs/project/2026-10-29-dafny-crypto-completion.md)
requires full component composition, checked native-array refinements,
compatibility tests and performance measurements before adoption.

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
