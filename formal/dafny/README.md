# Verified HKDF with generated Java

This is the first isolated implementation of the selected Dafny-to-Java route.
The verified implementation is `hkdf/Hkdf.dfy`; the runner verifies it, generates
Java with verification enabled, compiles that output and tests it with real JCE.
The default Maven reactor and production `quic.Hkdf` remain unchanged. The latter
is compiled from its canonical source only as an independent test reference.

From the repository root, with Python 3.11+ and `JAVA_HOME` set to JDK 21+:

On Ubuntu 24.04, install `libicu74` for the bundled .NET runtime first. The runner
requires the standard POSIX `ps` utility for cancellation cleanup.

```sh
python3 -m unittest discover -s formal/dafny -p 'test_run.py' -v
python3 formal/dafny/run.py
# Optionally exercise the same Java 21 classes on another installed runtime:
python3 formal/dafny/run.py --java-home /absolute/path/to/another/jdk
```

The runner caches pinned Dafny 4.9.1 outside the checkout. Linux x86-64 and macOS
arm64 are supported; `--cache` or `MICROPROXY_FORMAL_CACHE` overrides the location.
Archive and per-platform runtime SHA256 values are in `tools.json`. The official
release API supplied no digest: these pins identify the official HTTPS downloads
used here, not independently signed release attestations. Every extracted file
is checked against the pinned archive before replay; local OS/tool execution is
still trusted. No global toolchain is changed.

`target/dafny-hkdf/report.json` records current status, exact inputs, generated
Java/class hashes, compiler/JDK/provider identities, logs and byte/class footprint.
Each invocation first invalidates old success. A failed setup/control/test cannot
leave a complete report. A lock prevents simultaneous writers; interrupted runs
remain incomplete. Commands have bounded timeouts and cancellation cleanup.
Generated code is recreated in a fresh replay directory, never hand-edited or
checked in as an alternative source. CI uploads it with the report for inspection.
Source pins are drift gates, not semantic proofs or review signatures; review
changes before deliberately renewing `inputs.json`.

## Functional proof and domain

All four public methods have no caller preconditions. They return `Success` or a
named validation failure, with exact equality to total result specifications.
The positive-domain harness invokes every method on unconstrained mathematical
inputs and proves these equations. Adding a reject-all precondition breaks that
check. Verification includes termination and loop invariants.

| Operation | Proved behavior relative to abstract HMAC |
|---|---|
| Extract | SHA-256/384/512 selection; empty salt becomes HashLen zero octets; exact HMAC result, including empty IKM |
| Expand | Every nonempty PRK; exact RFC 5869 feedback, one-byte counters 1..255, concatenation and truncation; output length 0..255*HashLen |
| LabelInfo | Exact TLS label serialization; uint16 length 0..65535; label up to 249 UTF-16 units, each ASCII; context up to 255 octets |
| ExpandLabel | Composition of label validation/serialization and Expand, including error precedence and bounds |

Two compatibility extensions match the existing Java helper: Expand accepts
nonempty PRKs shorter than HashLen (RFC 5869 specifies at least HashLen), and
LabelInfo accepts an empty suffix label (RFC 8446 requires a nonempty suffix).
These API contracts do not assert that every accepted input is a valid protocol
call. Sequences/integers are mathematical: finite Java heap, allocation failure,
JVM limits and concurrent mutation of caller input arrays are outside the proof.

Negative controls alter feedback, counter, truncation and label prefix. They must
fail actual proof obligations; parsing failures, resource limits, timeouts and
crashes are rejected as evidence. Additional controls narrow a public precondition,
add a trusted axiom, or skip a method proof. The separate Dafny audit must report
exactly the permitted `VerifiedHkdf.Mac` axiom. The auditor itself does not verify
programs; the runner separately requires completed proof summaries.

The recurrence/invariant approach is credited to the pinned
[AWS HKDF reference](https://github.com/aws/aws-cryptographic-material-providers-library/blob/c787ad12612ac0f35975afe9209e5dbe6b546654/AwsCryptographyPrimitives/src/HKDF/HKDF.dfy).
Our standalone proof has no AWS includes. We have verified the complete local
kernel; we have not replayed the full upstream MPL dependency/submodule graph.
AWS provenance applies to reused HKDF structure; it does not limit the wider
Dafny program to AWS algorithms. See `NOTICE`.

## Java boundary and trust

The sole Dafny assumption is a deterministic external `Mac` implementing the
requested HMAC and returning HashLen bytes for a nonempty key. The Java binding
uses fresh `javax.crypto.Mac` instances for HmacSHA256/384/512. The small handwritten
facade copies octets without signed-byte loss, preserves all UTF-16 bits before
ASCII validation, translates validation results, and returns fresh arrays.
These Java adapters are tested, not proved by Dafny.

The suite contains RFC 5869/9001 answers, independently derived SHA-384/512 answers,
deterministic comparison with canonical handwritten HKDF, boundary/invalid inputs,
high-bit octets, Unicode/surrogate rejection, ownership and concurrent calls.
Those finite checks help detect translation/adapter bugs; they do not prove the
compiler, JDK, JCE provider, all Java input lengths or concurrency semantics.

Trust includes Dafny/Boogie/Z3, source specifications and their standards review,
Dafny's Java compiler/runtime, `javac`, JVM and the JCE/provider implementation.
See the [Dafny reference](https://dafny.org/v4.9.1/DafnyRef/DafnyRef).
No PRF/entropy security reduction, constant-time trace proof, HotSpot/GC/CPU timing
proof, secret-erasure guarantee or complete ML-KEM/SHAKE proof follows from this.
The generated runtime may allocate and copy secret-bearing values; footprint and
runtime behavior need review before a production switch. The next adoption gate
is packaging/runtime/performance review plus integration at real key-schedule call
sites. Existing fingerprints and APIs must remain covered there.
