# Direct executable-Dafny assurance

This is the primary source-level continuation for issue #117. It consumes the
actual executable Dafny implementation used to generate Java. The existing
[`formal/timing`](../timing/README.md) bytecode models remain supplementary.

## SHAKE ownership and frames

`ShakeOwnership.dfy` calls the actual `NativeShake.Xof` and `Sponge` constructor,
`Update`, `Read`, `Destroy` and other public Sponge methods. It introduces no
second implementation and changes no production method body or precondition.
The replay verifies every included source body, the existing complete public
domain harness and the new ownership harness.

The direct proofs cover arbitrary permitted byte contents, both rates 136/168,
all permitted lengths and slices, fresh outputs, the six-object factory
footprint, disjoint internal arrays, unchanged external inputs, const footprint
and rate preservation, output survival through destruction, and permitted
external input/output aliasing. Distinct-buffer input preservation and
same-buffer read/write behavior have separate contracts.

`FactoryOwned` names a local validity/disjointness property. It does not establish
global exclusive access by Java callers. The public table arrays are distinct
already under the production `Valid()` contract: at index 1 their required
values are 1 and 6. The harness proves this fact instead of narrowing `Valid()`
or adding constructor assumptions.

From the repository root:

```sh
python3 -m unittest discover -s formal/source -p 'test_*.py' -v
python3 formal/source/replay.py --output /fresh/source-ownership-replay
```

The output directory must not exist. The runner checks the complete source and
replay/tool input inventories, freezes the source graph, uses the checksum-pinned
Dafny 4.9.1 distribution and Z3, verifies included bodies with the existing
30-second / 50,000,000-resource / `O:smt.case_split=0` policy, audits assumptions,
and rejects three intentionally false alias/freshness assertions. It explicitly
audits every included source file, since Dafny's auditor does not automatically
traverse includes. A separate control injects `assume {:axiom} false` into the
included production `Xof` body and requires that audit to report the assumption.
A failed
control must be a named assertion failure; CLI, parser, timeout, resource and
internal errors do not count. Source and tool checks run again before success.

The included-body/domain graph has 1,552 verified checks and the new harness has
20. The runner requires both reviewed counts; contract-only verification
produces 45 checks and must not qualify. Legitimate source changes require
replaying and reviewing the new obligations before these expectations change.
The three negative assertions must each yield exactly one failed obligation.
These are universal proofs under the
preconditions, not twenty sampled inputs. Negative controls are regression
evidence for the replay and its proof dependencies, not discovered runtime
vulnerabilities. The Python inventory/diagnostic gate remains trusted code.

## Source traces and delivery

Ownership/frame proofs do not establish secret-trace independence. Same-body
observation, instrumentation completeness and composed crypto trace coverage
remain unfinished. A ghost trace needs a justified connection to real source
operations before a stronger claim is made. See the
[source-assurance design](../../docs/project/2026-11-03-dafny-source-assurance.md).

These additions do not change executable Dafny or production generated Java.
The existing generation, canonical-class and supplied-artifact gates provide
the separate source-to-delivery evidence. Compilers/runtimes, reviewed Java
adapters and selected primitives retain their documented assumptions. No Java
refinement, whole-crypto trace closure, cryptographic-hardness, physical erasure,
physical timing or independent expert-review claim is made by this component.
