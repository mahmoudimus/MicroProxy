# Scoped security verification

The governing claims and gaps are in [Security assurance](../docs/formal-security.md).
These artifacts prove properties of explicit models, not whole-stack Java security.

The separate, opt-in [SAW experiment](saw/README.md) verifies one bounded arithmetic
method from actual Java 21 bytecode. It has its own pinned inputs, negative controls
and trust boundary; it is not part of the Lean/TLC replay described below.

From the repository root, with JDK 21+, Maven, Python 3.11+ and zstd:

```bash
python3 -m unittest discover -s scripts/security -p 'test_formal_tools.py' -v
python3 scripts/security/install_formal_tools.py
python3 scripts/security/formal_check.py
```

The installer caches checksum-pinned Lean 4.35.0 and TLC 1.7.4 outside the checkout, under
`~/.cache/microproxy-formal`. Use `MICROPROXY_FORMAL_CACHE` or `--cache` to override it.
It does not change global toolchains. `formal/tools.json` supports Linux x86-64 and macOS arm64;
another platform requires a reviewed official release asset and SHA256. Lean archive hashes
come from the official release API; TLC's release has no API digest, so its hash records the
official HTTPS download used here. The local cache, OS and tool binaries remain trusted.

The runner writes logs, actual Java observations and a JSON report to `target/formal-security`
(override with `--output`). Observations are regenerated into an empty observation directory.
Generated Lean examples are kernel-checked with `decide`, not native proof evaluation. This
checks only the finite observed cases. The runner audits all listed theorem dependencies,
rejecting proof holes/custom axioms/compiler-trust axioms; standard logical axioms are allowed.
Deliberately faulty models must fail proof obligations or produce named TLC counterexamples.

`formal/assurance.json` maps model theorems to source snapshots. A changed Java source fails the
hash check until deliberately renewed after reviewing the code, model, theorem, assumptions
and observation tests. Do not regenerate hashes merely to get a green check. Matching hashes
are a drift reminder, not semantic equivalence or a review signature.

The CI workflow replays these steps alongside normal Maven, standards-vector and interop tests.
Browser profiles and captured fixtures are unchanged.
