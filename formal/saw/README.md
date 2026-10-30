# Direct Java bytecode verification with SAW

SAW 1.6 verifies the checksum-pinned Java 21 bytecode of the pre-adoption
`MlKem768.reduceOnce(int)`:

```text
forall a : int, 0 <= a < 6658:
    reduceOnce(a) = a mod 3329
```

The independent Cryptol specification uses integer remainder on a 32-bit bitvector.
The Java implementation uses subtraction, shifts, multiplication and masks. The
proof loads `MlKem768.class` (class-file major version 65), byte-identical to the
production artifact at the commit recorded in `inputs.json`, without copying the
method into a Java model or assuming its result. After Dafny adoption this is a
historical reference proof, not a proof of the current generated `NativeField`.
The `jvm_verify` override list is empty. SAW's summary records one verified method,
one verified return-value obligation, and no admitted dependencies.

This is a functional proof of one private scalar arithmetic method. Callers must
satisfy its range precondition. Their compliance, the rest of ML-KEM, full protocol
security, JCA providers, JIT behavior and timing are outside this proof.

## Replay

First obtain SAW's official 1.6 release with its solvers and a JDK 21. The tested
macOS arm64 archive and input hashes are pinned in `inputs.json`. This runner does
not install tools or build Java. Existing reference class files must match the
pinned hashes; changed inputs require review before updating the pins.

From the repository root:

```sh
mkdir -p target/saw-reference-classes
cp -R quic/target/classes/. target/saw-reference-classes/
"$JAVA_HOME/bin/javac" --release 21 -g -d target/saw-reference-classes \
  formal/crypto/reference/Shake.java formal/crypto/reference/MlKem768.java
python3 formal/saw/run.py \
  --saw "$HOME/.cache/microproxy-formal/saw-1.6-macos-15-ARM64-with-solvers/bin/saw" \
  --java-home /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
```

The preparation compiles the unchanged whole reference classes, then the runner
requires the original production class hash before proving anything. With the
pinned JDK21 options above, the resulting class is byte-identical to that artifact.
The copied `PacketKey` class remains subject to its separate source/class pins.

Use `--classes /absolute/path/to/an/existing/classes/snapshot` when another build
is active, and `--output /absolute/path` to relocate evidence. The runner snapshots
class files, validates the pinned source/class hashes before and after the copy,
and proves against that isolated copy. It extracts the selected JDK's unchanged
module class files into the external tool cache, avoiding thousands of separate
`jimage` invocations in SAW's class loader. It never lowers the production class
version or substitutes an older JDK model.

`evidence/report.json` records exact SAW commands, input and runtime hashes,
per-process exit status, logs and SAW's JSON verification summaries. SAW is invoked
with path satisfiability enabled and `--detect-vacuity`. `summarize_verification`
also prints the verified/assumed distinction. The runner requires a nonempty set
of verified obligations and an empty dependency list for the successful method.
The report is atomically replaced with `status: incomplete` before any input or
tool validation. Only `status: complete` means the proof, all controls and final
input/runtime hash checks passed. A failed or interrupted replay records that
status and its error, even when an individual earlier proof succeeded. Each
subprocess owns a process group; timeout or interruption sends TERM, allows a
one-second grace period, then kills remaining group members and reaps the leader.

Run the runner regression tests without SAW, Java compilation or network access:

```sh
python3 -m unittest discover -s formal/saw -p 'test_*.py' -v
```

The three replay controls are separate from the successful proof:

| Run | Required result |
| --- | --- |
| Wrong modulus, `3328` | Genuine proof counterexample, exit 2; the observed witness is `a = 4095`, where the actual result is `766` and the false specification expects `767`. |
| Contradictory preconditions | SAW reports the contradictory assumptions. SAW itself can exit 0 and label this method verified, so the runner explicitly rejects this as a vacuous specification. |
| Actual `PacketKey.nonce(long)` | Reaches symbolic execution, then reports the known array `clone` translation blocker. This is recorded as blocked, never verified. |

The successful proof also explicitly finds a satisfiable input to its precondition
(`a = 1` in the recorded run). A parse failure, solver error, timeout or unexpected
failure does not satisfy the wrong-modulus control.

## Unproved experiments

`blocked/packet-key-nonce.saw` loads the actual production `PacketKey.class`, makes
the IV and all 64 packet-number bits symbolic, and specifies big-endian XOR plus
preservation of the input IV and a returned allocation. It cannot reach its proof
obligations with this SAW release:

```text
TODO: invoke virtual "clone" unsupported for arrays
```

The precise cause is the array receiver branch of `Invokevirtual` in the pinned
[Crucible translator](https://github.com/GaloisInc/crucible/blob/c4ef4ff10807d414f39b7cd5046f76907340fce3/crucible-jvm/src/Lang/Crucible/JVM/Translation.hs#L873).
This fails before method-override dispatch, so an assumed `Object.clone` contract
does not repair the missing translation. No clone contract or nonce result was
admitted here. Nonce output, IV preservation and allocation freshness remain
unproved; its wrong-endian specification cannot provide a proof-level negative
control until this backend limitation is repaired.

The smallest next experiment is to implement and independently review primitive
array `clone` translation in Crucible, checking copied bytes, preserved input and
fresh reference, then replay this script against the same production class hash.
Changing production code or its class file to avoid `clone` changes the target.

`blocked/mlkem-reduce.saw` is a separate, unproved attempt to show Barrett reduction
equals mathematical remainder for all inputs below `2^24`. Both an initial 64-bit
preconditioned form and a smaller 24-bit input circuit hit a 90-second solver
budget. It is excluded from the successful proof count and the default replay.

The trust boundary includes SAW/Crucible's bytecode semantics and translation,
Cryptol, the bundled solver, the selected local JDK classes and the build that
produced the pinned production class files. Source hashes establish snapshot
identity; Java compilation itself is not proved. The
[SAW JVM manual](https://github.com/GaloisInc/saw-script/blob/v1.6/doc/saw-user-manual/verifying-code.md#loading-jvm-code)
labels support for JDK 9 and later experimental.
