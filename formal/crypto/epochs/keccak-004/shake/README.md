# Epoch 004 native SHAKE functional consumer

This successor replays the unchanged native SHAKE policy against the authenticated current
source view. It preserves all eight proof/audit roots, all 22 semantic controls, the independent
hashlib vector inventory, and the original Java harness and runtime discipline checks. The only
mutation changes are the five reviewed tuple/ghost-result anchor ports in `inputs.json`.

`qualification` stays `false`: parent epoch integration and delivery are separate gates. This
consumer makes no timing, physical erasure, or production adoption claim.

## Inputs and execution

Run `python3 replay.py --help` for the required arguments. Supply explicit absolute paths for:

- The reviewed successor `inputs.json` and its externally selected SHA256.
- The source-view constructor's current view, its epoch manifest and externally selected SHA256.
- The checkout containing the unchanged legacy helpers.
- A separately prepared tool manifest and externally selected SHA256, outside the fresh output.
- The official Dafny cache, delivered Maven runtime and selected SHA256, and JDK 21/25 homes.
- A fresh output path outside all protected inputs.

The runner authenticates bytes before executing helper source, freezes the complete current
view and helper inputs, and translates the same frozen source used by the proofs. Historical
manifests in the view are retained as data and grant no current-source authority. No legacy
guard globals or old files are changed.

Child commands receive only host locale/time-zone values, a fixed system PATH, and fresh private
HOME/temp directories. Java, javac and javap also receive explicit `user.home` and
`java.io.tmpdir` properties because the JDK does not derive these properties from the HOME and
TMPDIR environment variables on every platform. Helper source is compiled from the same
in-memory bytes checked against its selected pin, bypassing `.pyc` caches. The host OS and the
original Python/tool runtime boundary remain trusted; this is not hermetic host execution.

The final `receipt.json` appears only after every gate and all before/after stability checks
pass. Individual commands retain raw logs, exact arguments, exits and log hashes. A progress
file is not a completion receipt.

## Boundary tests

These tests require an explicitly selected JDK for their real compiler/property probes:

```sh
python3 test_replay.py --java-home "$JDK21_HOME"
python3 test_replay.py --java-home "$JDK25_HOME"
```

An explicitly set `JAVA_HOME` is also accepted. Unittest discovery without either selection
reports the Java integration prerequisite as skipped; it is not a complete integration run.
The tests include actual poisoned-bytecode-cache and compiler-option controls. Each complete
functional replay separately requires both JDKs to pass the original 198 vectors, 198 partitions,
1728 permutations, 24 slices and 25218 assertions per JDK.
