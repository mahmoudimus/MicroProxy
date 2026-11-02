# PacketKey nonce bridge adoption

Status: **candidate functional integration in this worktree; root acceptance,
merge and Linux CI pending. Only the nonce math/generation is already accepted;
do not describe `main` as adopted.** The isolated nonce math/component was independently
reviewed and approved; this change wires the reviewed generated class into
`PacketKey.nonce(long)` and records it in the central delivery inventory, class
counts, bundle roots, ledger claim and CI job. It is not a declaration that a
fresh canonical stage, the actual production JAR/bundle or a live Linux CI run
has passed in this worktree. The historical SAW bytecode route remains blocked
and is not claimed.

Base: clean detached `30d7c3ca72b71e7ce337844a650998454bbdb157` in
`/Users/mahmoud/.codex/worktrees/crypto-nonce-dafny/microproxy`.

## Changed production surface

Only `quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java` was
edited in `src/main`:

- added a static import of `VerifiedNonce.__default.Nonce`;
- replaced the handwritten clone/XOR loop with
  `return Nonce(iv, packetNumber);`;
- corrected the Javadoc to say **all 64 bits** are XORed and that QUIC's
  62-bit packet-number limit is a protocol/caller policy, not a mask in this
  primitive.

The constructor is unchanged: it still rejects a non-12-byte IV and any wrong
key length with the historical messages, clones the IV, and adds no 62-bit
check. No other nonce-like methods (record/HPKE/TLS) were touched.

PacketKey source SHA-256:
`120f456959c3bdd2edd5916d8e9a76e9ed63dbb0ca84f886f31e8ea0814e2c2e`.

The generated class remains unchanged and is the candidate called by the
bridge:

- `quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce/__default.java`
  SHA-256 `aabace51edf58e4aefd398717b674ccbf8c138517f95fbb843139c8aea61cc06`;
- compiled class SHA-256
  `64ba6bbcccba2bc0f519b60ba090e11cf164544e98e24e73cd4699f9481c7069`.

## Artifact scope correction

This generated class is already under `quic/src/main/java`, so a normal Maven
build compiles and packages it even before this bridge. It is now **called** by
`PacketKey.nonce`, not merely present. The correct statement is:

> The generated `verifiednonce` class is an addition to the `quic` artifact;
> `PacketKey.nonce` now delegates to it; no POM dependency change was needed
> because `DafnyRuntime:4.9.1` is already present. Test/benchmark classes are
> under `src/test`/`formal` and must not ship in the production artifact.

Do not describe the artifact as unchanged. Root must inventory the new class,
run Maven/class/JAR acceptance on JDK 21 and 25, and decide adoption.

## Tests

New test-only file:
`quic/src/test/java/io/github/mahmoudimus/quic/crypto/PacketKeyNonceTest.java`
SHA-256 `c2f1b845b679bc86d1025d6c6b45d3f5ccbda80fe1c1e0382391ec280393fe57`.

It contains an independent frozen clone/XOR oracle (not the generated class)
and eight JUnit 5 tests covering:

- all 64 single-bit packet numbers across six varied IVs and all three suites;
- negative, high-bit, `Long.MIN_VALUE`/`MAX_VALUE` and endian byte placement;
- no masking of bit 62 or the sign bit;
- constructor IV-length errors with historical messages;
- constructor key-length errors with historical messages;
- IV cloning after construction, fresh output arrays, and mutation independence;
- actual `PacketKey.seal`/`open` round trips for 64- and 1200-byte payloads,
  every available suite, and high/negative packet numbers.

Targeted run (JUnit 5.11.4 / Platform 1.11.4 from the local Maven repository):

| JDK | Result |
|---|---|
| 21.0.12.1 | `PACKETKEY-TEST-OK tests=8 failed=0` |
| 25.0.5 | `PACKETKEY-TEST-OK tests=8 failed=0` |

This is a targeted test compile/run, not the full Maven test suite. Root owns
the full Maven 21/25 runs.

## Packet-protection benchmark

`formal/nonce/packet_bench.py` and `formal/nonce/bench/PacketKeyBenchmark.java`
compare:

- **baseline:** the frozen `baseline-main21/classes` tree, 467 classes,
  tree hash `e5781bc243596013b0a16946ab87b8eba3480987469e42b062503003f3c70340`;
- **candidate overlay:** exactly two classes compiled with JDK 21
  `--release 21 -g` from the reviewed `PacketKey.java` and the frozen
  `__default.java`; no other production class is overlaid.

Overlay hashes:

| Class | SHA-256 |
|---|---|
| candidate `PacketKey.class` | `1a9d607ff09ead4daa958ac23e31b90c235a8a3fe5a24e4765b7a647be8db68b` |
| baseline `PacketKey.class` | `61f7d592724838530ad4eeaead2d34c3b0eb055c5a1d878514904a2282694880` |
| generated `__default.class` | `64ba6bbcccba2bc0f519b60ba090e11cf164544e98e24e73cd4699f9481c7069` |

The candidate PacketKey bytecode contains
`.../VerifiedNonce/__default.Nonce`; the baseline bytecode does not. The
baseline tree hash and all source/runtime/JDK hashes are checked before and
after the run and were unchanged.

Workload: actual public `PacketKey.seal` then `PacketKey.open` round trips,
20-byte synthetic header/AAD, fixed synthetic key/IV per suite, packet numbers
increasing from `0x0102030405060708`, payload sizes 64 and 1200 bytes, all three
suites available. 100,000 iterations for 64 bytes, 10,000 for 1200 bytes, two
warmup rounds, seven measured rounds, five fresh JVMs per mode/configuration,
alternating mode order. Baseline and candidate runs are **separate JVMs**, so
no paired/fork-pair statistic is reported. CPU thread time is primary; wall and
thread allocation are recorded. Volatile sink every iteration and volatile
buffer escape every 64 iterations keep the packet path observable.

Before timing, 864 independent validation cases (suites × sizes × IVs ×
packet numbers × payload patterns) produced identical SHA-256 digests for
baseline and candidate on both JDKs:
`a5b1cff595367dd6eaca7d28c4c1bfaaf02d95b9ba20910a3cb9a5901a86a227`
on JDK 21 and JDK 25, with all three suites and no skipped suites.

### CPU results

`delta` = candidate median − baseline median; `ratio` = candidate median /
baseline median. Values are per seal+open round trip (two nonce constructions
plus two AEAD operations), not per nonce.

| JDK | Suite | Bytes | Baseline ns | Candidate ns | Delta ns | Ratio |
|---|---|---:|---:|---:|---:|---:|
| 21 | AES-128-GCM | 64 | 389.8 | 404.7 | +14.9 | 1.038 |
| 21 | AES-128-GCM | 1200 | 1028.3 | 1029.5 | +1.2 | 1.001 |
| 21 | AES-256-GCM | 64 | 412.1 | 434.8 | +22.7 | 1.055 |
| 21 | AES-256-GCM | 1200 | 1110.2 | 1119.3 | +9.1 | 1.008 |
| 21 | ChaCha20-Poly1305 | 64 | 945.6 | 971.4 | +25.7 | 1.027 |
| 21 | ChaCha20-Poly1305 | 1200 | 3335.0 | 3355.9 | +20.9 | 1.006 |
| 25 | AES-128-GCM | 64 | 364.1 | 415.9 | +51.8 | 1.142 |
| 25 | AES-128-GCM | 1200 | 1027.2 | 1060.8 | +33.6 | 1.033 |
| 25 | AES-256-GCM | 64 | 366.7 | 417.8 | +51.0 | 1.139 |
| 25 | AES-256-GCM | 1200 | 1099.3 | 1141.9 | +42.6 | 1.039 |
| 25 | ChaCha20-Poly1305 | 64 | 930.8 | 939.4 | +8.6 | 1.009 |
| 25 | ChaCha20-Poly1305 | 1200 | 2988.9 | 3006.7 | +17.8 | 1.006 |

The isolated primitive measured about 11–15 ns extra per nonce and the same
32 B allocation. In actual packet protection the observed deltas range from
about +1 to +52 ns per round trip, and the ratio is 1.001–1.142 depending on
JDK/suite/size. At 1200 bytes the AEAD cost dominates and the nonce difference
is near measurement noise; at 64 bytes the delta is more visible. The 3.73x
isolated primitive ratio is **not** a full packet cost. No absolute overhead
cap or adoption verdict is expressed; root must weigh these numbers together
with the full handshake/CI results.

Allocation is recorded per configuration in the raw receipt. Packet round-trip
allocation includes `PacketKey.seal/open`'s duplicated `ByteBuffer` and
provider internals, so it is not a pure 32 B nonce comparison; most medians are
equal, with small run-to-run differences. The isolated component receipt remains
the direct evidence for equal 32 B nonce allocation.

### Benchmark limitations

- Shared host: load averages were ~6.5/7.3/11.2 before and ~5.2/6.8/10.7 after;
  JIT/GC/CPU frequency are uncontrolled. Absolute numbers are diagnostic.
- Baseline classes were compiled earlier by the frozen Maven build; the
  candidate overlay was compiled with the pinned JDK 21 in this run.
- Separate JVMs mean no contemporaneous pairing; no confidence interval or
  paired significance claim is made.
- The workload includes two AEAD operations per iteration; it is a packet
  hot-path measurement, not a pure nonce microbenchmark.
- No constant-time, side-channel, security, throughput, capacity, production
  JAR or full-handshake claim follows.

Raw receipt:
`/Users/mahmoud/.cache/microproxy-formal/issue117-20261101/nonce/packet-integration/report.json`
SHA-256 `60297ae65484c8c89939f4b2c8b8d48d69caa0dd5d3a5241464f2d6121a9df5e`;
workspace with 120 raw records and all logs:
`.../nonce/packet-integration/packet-benchmark-qoy2_agg/`.

## Adoption record and remaining gates

1. **Delivery/ledger/boundary.** `formal/crypto/delivery.json` pins the generated
   `verifiednonce` source as an existing generated source. The production class
   counts are 468 library / 84 crypto-scoped / 468 retained-bundle classes;
   the bundle prefixes and required roots include `PacketKey` and the generated
   nonce. V3 is `partial`: the SAW bytecode route stays blocked, while the new
   narrow `packet-nonce-functional-production` claim is supported by the typed
   receipt validator. The historical SAW `PacketKey.java` pin is frozen under
   `formal/saw/historical`; the live `PacketKey.java` is separately pinned.
2. **Canonical stage and artifacts.** A fresh full stage against the updated
   delivery manifest, the real Maven JDK21/25 builds and the actual library/JAR/
   bundle checks are still required. No stage or artifact receipt in this
   worktree is reused as current evidence.
   The fresh bundle check also compiles and runs
   `formal/nonce/BundleNonceSmoke.java` against the actual minimized bundle: it
   executes `PacketKey.nonce`/`seal`/`open` for all three suites and packet
   numbers 0, 1 and -1, compares the nonce and ciphertext to independent oracles,
   and records the actual bundle/runtime/harness class-load origins. The existing
   TLS-only hybrid handshake smoke remains unchanged and does not assert nonce
   origins by name.
3. **CI.** The `dafny-nonce-functional` job runs the portable proof, negative
   controls, bounded `--no-verify` generation and JDK21/25 differential tests on
   Linux with the pinned official archive and `libicu74`. No Linux live pass is
   claimed until that job actually runs.
4. **Performance decision.** The packet round-trip and isolated primitive
   measurements are diagnostic shared-host evidence; they are not a capacity,
   constant-time or absolute-overhead claim. The adoption decision is recorded
   by the user-authorized, evidence-based review, not by the benchmark alone.
5. **Trust.** The Dafny proof covers the generated nonce primitive, not
   `PacketKey`'s Cipher, provider, JVM or timing. The bridge Java change is
   reviewed/tested, not proved by Dafny. `javac`, JVM/JIT/GC/CPU, JCE
   providers and Maven/JAR tooling remain trusted.

## Benchmark provenance renewal

The recorded 120-sample experiment above predates the portable tool-config
change and subsequent benchmark-IO hardening. Its input tree and class hashes
were independently checked, but the old receipt did not bind its runner script.
New runs accept explicit `--baseline-classes` and `--runtime`, enforce the frozen
baseline tree and PacketKey class identities, and record runner/tool-config hashes
before and after. The historical CPU values are not represented as a rerun of the
new script. This changes neither the bridge nor its functional proof.
