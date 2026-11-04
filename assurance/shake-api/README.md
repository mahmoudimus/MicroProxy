# SHAKE public API state/status coupling

This independent proof root proves a **public state/status coupling** property for
the existing executable `NativeShake.Sponge` API. It calls the actual unchanged
`constructor`, `Update`, `Start`, `Next`, `Read` and `Destroy` methods and verifies
all included implementation bodies; it does not modify production Dafny/Java,
add assumptions, axioms or new algorithms, and it is not a logical-trace,
observation-completeness or JVM-timing claim.

## Property

For two **arbitrary valid** sponges with equal public `(rate, position, squeezing)`
fields and independently chosen secret `lanes`/`scratch` contents, corresponding
calls with equal public input lengths, slice arguments and requested output lengths
return the **same status** and preserve equality of those public fields. Secret
output bytes are never compared.

Covered operations and boundaries:

- `Update` on arbitrary slices, including zero-length, in-bounds, out-of-bounds and
  arbitrary segmented input; statuses `0` (updated), `2` (invalid slice) and `1`
  (phase error after output started). The phase error precedes slice bounds.
- Exact absorb rollover at `position + 1 == rate` (`PairAbsorbBoundary`), derived
  locally from `SpongeSpec.AbsorbOneEquation` (no closed-form arithmetic).
- `Start` from arbitrary valid non-squeezing or already-squeezing states.
- `Next` at arbitrary positions and the exact `position == rate` rollover to `1`
  (`PairNextBoundary`), from `SpongeSpec.NextEquation`.
- `Read` with zero length (still starts squeezing), arbitrary lengths and
  segmentation; `Read` composition uses the existing `SpongeSpec` read laws.
- `Destroy` followed by reuse (`Update`, then `Start`).
- A **shared external output buffer** (`PairReadSharedOutput`, `oa == ob`) is
  admitted: both reads write the same buffer and the proof claims only public
  state coupling, never secret-byte equality. Within-call aliasing that the
  production contracts admit is preserved (an output buffer may alias the *own*
  instance's arrays, but not its `sources`/`offsets`).

States are arbitrary: the pair methods take any objects satisfying the production
`Valid()` contract and the stated public equality; constructor scenarios are
supplementary, not the only instances.

## Explicit cross-run alias domain

`Separated(a, b)` requires the two instances' objects and all of their
`lanes`/`scratch`/`parity`/`offsets`/`sources` arrays to be disjoint. This models
two independent executions and prevents a call on one run from writing the other
run's state or lookup tables. Output buffers must additionally lie outside the
**other** instance's footprint (`SeparatedWithOutputs`), while the own-instance
aliases permitted by `Read` remain. These alias restrictions relate the two runs;
the native per-call exclusions are retained. Equality of public metadata is a
premise of the relational theorem, not a restriction added to production callers.

## Verification

```sh
python3 -m unittest discover -s assurance/shake-api -p 'test_*.py' -v
python3 assurance/shake-api/replay.py --output /fresh/shake-api-replay
```

Parser-discovered closure (all bodies verified): `ApiStateHarness.dfy`,
`formal/crypto/NativeShake.dfy`, `NativeKeccak.dfy`, `NativeTypes.dfy`,
`SpongeSpec.dfy`, `formal/primitives/Keccak.dfy`. The replay requires exactly
1,558 included-body checks and, separately, 51 root-only checks; these counts
overlap. It uses checksum-pinned Dafny 4.9.1 / Z3 4.12.1 with the existing
30-second / 50,000,000-resource policy, `O:smt.case_split=0`, two cores and no
`--allow-external-contracts` flag. No ambient Dafny executable is selected.

The six positive-source files and the separately discovered negative-control
root are each audited with `dafny audit` (zero findings). Five deliberately false
claims after real API calls must each fail at its exact assertion location with
exit 4, zero verified checks and one assertion error. Parser/type/precondition
failures, warnings, crashes and timeouts cannot satisfy those controls. An
injected included-body axiom must produce the expected audit finding.

The fresh output directory must not exist. Replay freezes the exact source/tool
input maps, discovers both roots' includes with the pinned compiler parser, checks
inputs again after all work and retains raw commands and logs. Fifteen unit tests
exercise the evidence gate; those tests are not additional crypto theorems. The
Python orchestration, input checks and diagnostic classifiers remain trusted
tools. This component enables no additional whole-SHAKE trace or release claim in
the obligation ledger; V7 remains partial.

`SpongeSpec` supplies the public relational lemmas (`AbsorbStep`/`AbsorbEmpty`/
`AbsorbOneEquation`/`PadEquation`/`NextEquation`/`RawRead*`); the harness adds only
ghost relational lemmas and paired callers of the executable API. No closed-form
position arithmetic is used.

## Not proven here

Operation/address/call/alloc trace independence, observation completeness, Keccak
child traces, Java/JVM refinement, physical timing/erasure, compiler/runtime/
provider correctness, cryptographic hardness, adapter/error composition and
external expert review remain outstanding. Physical JVM/JIT/CPU/GC/provider timing
is not claimed.

An internal secret-dependent branch could preserve all of these public fields.
This theorem does not exclude it: that requires operation observations, checked
coverage and transitive Keccak trace composition.

The independent root lives outside `formal/` because it is not an input of the
frozen Select package. No old source root imports it; all 85 original candidate
Dafny inputs and eight explicit helpers remain byte-identical. Its own exact
manifest and CI replay qualify the new proof, without excluding or repinning any
dependency of the existing Select claim.
