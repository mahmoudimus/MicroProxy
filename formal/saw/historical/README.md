# Frozen pre-adoption source for the historical SAW receipt

`formal/saw/evidence/report.json` proves the historical Java 21
`MlKem768.reduceOnce` bytecode (production commit `f5f931f...`) and records that
the `PacketKey.nonce` experiment is blocked by unsupported primitive-array
`clone` translation. That receipt is a **historical snapshot**. It is not a
proof of the current `PacketKey.java` or of the generated `VerifiedNonce`
helper.

`formal/saw/inputs.json` is preserved verbatim: its original `inputs` map still
contains the pre-adoption
`quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java` entry at
`501999d8871707497f9f1c6a4765524384551bb3383484045a7ca2aabe40130d`. The
production bridge changed that file, so re-pinning the historical map to the new
hash would silently extend the historical claim to unreviewed bytecode.

This directory preserves the exact pre-adoption blob for the historical pin:

| Frozen file | SHA-256 | Source |
|---|---|---|
| `quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java` | `501999d8871707497f9f1c6a4765524384551bb3383484045a7ca2aabe40130d` | `/usr/bin/git show 30d7c3ca72b71e7ce337844a650998454bbdb157:quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java` |

The checked-in file is byte-identical to that git blob and to the original
manifest entry. The ledger splits the **same** original `inputs` map into two
reviewed hash-map signatures:

- `include_prefixes: ["formal/"]`, no prefix: the live formal reference pins,
  validated at the repository root;
- `include_prefixes: ["quic/src/"]`, `path_prefix: "formal/saw/historical"`:
  the historical `PacketKey.java` key, validated against the frozen copy here.

The original manifest is not rewritten and no new runner path was added.
`formal/saw/run.py` remains the reviewed historical runner, and it still
validates its `inputs` map against the checkout. That means a replay on the
current tree **must fail** at the `PacketKey.java` input check, because the live
file is the new bridge `120f4569...`, not the frozen pre-adoption
`501999d8...`. That failure is accurate and intentional: a faithful replay needs
the pinned historical checkout (or a byte-identical historical build), not a
current build. Do not relax that check to make a current-tree replay pass.

The original receipt also pins the historical Java 21 class files
`quic/target/classes/io/github/mahmoudimus/quic/tls/MlKem768.class`
(`65f1d21d...`) and
`quic/target/classes/io/github/mahmoudimus/quic/crypto/PacketKey.class`
(`61f7d592...`). Those entries also stay in `inputs`. A current Maven build
compiles the new bridge, so it cannot satisfy the `61f7d592...` class pin. The
repository does not claim that a current compiler reproduces the historical
class bytes from the frozen source; the class pins and the frozen source are
both provenance for the recorded run. The whole historical class tree is
intentionally not checked in because it is a build artifact. The raw receipt
retains its workspace record.

The frozen source is explicit receipt evidence, not a live or current nonce
proof. Do not repin it to the current bridge. The generated nonce has its own
reviewed Dafny/generated functional route in `formal/nonce/` and its own narrow
receipt; that route is not a SAW bytecode proof and does not change this
historical receipt.
