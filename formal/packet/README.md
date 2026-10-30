# QUIC scalar functional and trace verification

This component replaces protected-header-dependent work in packet-number recovery
and header unprotection. Production uses a Dafny-generated scalar kernel and fixed
four-octet buffer access adapters. Public APIs, standards bytes and browser
fingerprint fixtures remain covered by regression tests; no runtime dependency is
added. Generic `PacketNumber.read` remains available for exactly-sized buffers.

From the repository root, with Python 3.11+, Maven and `JAVA_HOME` pointing to JDK 21+:

```sh
python3 -m unittest discover -s formal/packet -p 'test_*.py' -v
python3 formal/packet/run.py
```

Ubuntu 24.04 needs `libicu74` for Dafny's bundled .NET runtime. The replay reuses the
pinned Dafny 4.9.1 distribution installer in `formal/dafny/toolchain.py`; it explicitly
selects bundled Z3-4.12.1 and `smt.case_split=0`. The complete official archive and
extracted files are checksum-checked, including the solver. Archive pins identify
the official HTTPS download, not independently signed release attestations.
No global toolchain is changed. Cache overrides are `--cache` and
`MICROPROXY_FORMAL_CACHE`; tools and local OS execution remain trusted.

## What is proved

`PacketKernel.dfy` has independent conditional reference equations and executable
mask-based implementations. Decode covers **all 64-bit** largest/truncated bit
patterns and lengths 1..4, retaining the original Java signed-overflow arithmetic
and add-before-sub decision priority. Its meaningful QUIC largest-number domain
is -1..2^62-1; a reconstructed number is not automatically accepted by the protocol.
The proofs include unsigned/signed comparison, prefix byte order, exact first-byte
protection and preservation of octets beyond the actual packet-number length.

`TraceMachine.dfy` proves two-run observation equality for arbitrary finite valid
straight-line register programs and arbitrary secret word inputs. Values/outputs
may differ. The observer sees operation kind and register-slot accesses, treating
word operations as atomic with operand-independent cost. This is an explicit
idealization; it does not establish physical instruction latency or JIT behavior.

The trusted bytecode checker disassembles the **actual built production classes**,
expands the exact scalar helper call closure and rejects jumps, arrays, division,
allocation, synchronization and unlisted calls in the scalar language. It extracts
concrete SSA programs, then Dafny verifies their validity and applies the universal
two-run theorem. The I/O checker tracks secrecy through adapter bytecode and rejects
secret-derived addresses or branches, binding scalar calls to the exact class and
signature. A range checker follows `checkLength` over the complete legal 1..4 input
interval and requires a common, effect-free normal path. Fixed buffer accesses are
relative to public packet/start offsets; heap roles correspond between executions.

These checkers and `javap` are **trusted implementation bridges**, tested with
negative fixtures; they are not themselves formally verified. The result is a
conditional source/bytecode trace claim, not a verified whole-JVM theorem.
Functional equations apply to the scalar word representation. Handwritten Java
buffer value packing/unpacking and domain propagation are reviewed and tested;
they do not yet have a full Dafny value-refinement proof. The adapter checker
establishes the structural address/call policy, not their complete returned values.

## Compiler adaptation and runtime closure

Dafny's Java backend emits runtime helper calls because its shifts allow count64,
whereas JVM shifts mask counts to six bits. Our only executable Dafny shifts live
in `ShiftLeft/ShiftRight`, each with `count<64`, full value equations and the proved
JVM count-mask equivalence; Dafny checks every call-site precondition.

`lowering.py` is an explicit trusted compiler adaptation. It accepts exactly two
backend intrinsics, only inside the corresponding verified helper methods, with
unchanged `value`/`count` arguments. It lowers those calls to Java `<<`/`>>>` and
removes the unused proof-module import. Unexpected runtime calls, extra shifts or
changed argument shapes fail closed. Raw and packaged source hashes are recorded.
The packaged class is generated reproducibly and must never be hand-edited. This
is **Dafny output plus the documented lowering pass**, not unmodified backend output.
The replay compiles it without a Dafny runtime JAR or other classpath and checks
its actual bytecode closure. Compiler/lowering correctness remains trusted.

## Integration and exclusions

`HeaderKey.unprotect` samples before writes, then accesses five fixed packet
locations for reading and writing: first byte and all four possible PN octets.
Masks preserve ciphertext after the actual PN. Well-formed header layouts have
`start<packetNumberOffset`, sufficient sample space and exclusive mutable-buffer
ownership. Tests cover heap/direct/sliced buffers, either byte order, state/mark
preservation, read-only/short-packet rejection, full signed reconstruction edges,
independent old-algorithm comparisons and published QUIC v1/v2 AES/ChaCha vectors.

JDK `ByteBuffer` operations and provider sampling remain trusted opaque boundaries.
Returned header/number/length metadata, `ProtectedPacket`'s subsequent object/state
handling, AEAD lengths/errors, key-phase processing and outgoing `protect` are
outside this trace theorem. Constant-time equality elsewhere does not close these
obligations. No whole-record, whole-connection, CPU/JIT/provider/GC timing guarantee,
cryptographic security reduction or completed ML-KEM/SHAKE verification is claimed.

## Replay and provenance

`inputs.json` pins the kernel/model, runner/checkers/lowerer, shared tool/cleanup
code and canonical production/test sources. Pins are drift gates, not semantic
proofs or review signatures; renew only after reviewing changed obligations.
The runner invalidates old success before setup, rejects partial proof/audit output,
checks positive domains and negative controls, generates/packages Java, compares
the canonical source, builds/tests production and certifies copied class artifacts.
The report is published atomically only after final source/class identity checks.
Cancellation/timeout cleanup reuses the previously reviewed bounded process runner.

Evidence goes to `target/packet-verification/report.json` and a fresh `replay-*`
directory containing logs, raw generated Java, copied actual classes, SSA programs
and the concrete trace proof harness. `--output` selects a separate evidence root.
CI repeats on JDK 21/25 and uploads artifacts. Tests/measurements and formal proofs
are separate evidence; a timeout cannot count as a rejected mutant.

The threat model is informed by [EverQUIC's paper](https://www.andrew.cmu.edu/user/bparno/papers/quic-record.pdf)
and [pinned Dafny reference](https://github.com/secure-foundations/everquic-dafny/tree/8db9698ef5e1b2db54cb035316362447bb568b9a).
Our new standards-based Dafny code does not inherit their F*/C theorems. The current
[RFC9000 PN algorithm](https://www.rfc-editor.org/rfc/rfc9000.html#appendix-A.3)
and [RFC9001 header protection](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4)
govern interoperability; earlier draft-era proofs require separate standards review.
