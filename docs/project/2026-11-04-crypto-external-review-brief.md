# External cryptography and formal-methods review brief

Issue [#117](https://github.com/mahmoudimus/MicroProxy/issues/117) remains open.
This brief prepares a review of the cryptographic implementation, specifications,
proofs, integration and trusted tooling. No external reviewer has been engaged or
endorsed the implementation through this document. Development-agent review does
not satisfy independent expert review.

## Baseline and claims

The starting baseline is main commit
`0fa9d878a9bee666ada04e18c7c87b71ce273214`, which merged
[#140](https://github.com/mahmoudimus/MicroProxy/pull/140). A review must record its
own exact commit, tool identities and supplied artifact hashes. Later changes and
releases need separate qualification.

The supported headline is **functionally verified cryptographic implementations
with documented trust assumptions**. Production HKDF, SHAKE and ML-KEM use Java
generated from executable Dafny. Functional correctness means refinement to the
stated specifications over the accepted domains; it is not a security reduction,
a complete TLS/QUIC proof or a universal JVM constant-time guarantee.

Logical trace results are component claims. Same-body HKDF observations, scoped
polynomial/NTT observations and Select's choice/ownership/trace properties do not
establish whole-call-graph secret independence. The
[assurance page](../formal-security.md) and
[ledger guide](https://github.com/mahmoudimus/MicroProxy/blob/main/formal/obligations.md)
state their individual scopes. Use the ledger's claim records and validation
contracts rather than treating proof counts as a security score.

## Review questions and primary sources

| Area | Questions to resolve | Primary inputs |
|---|---|---|
| Specifications and domains | Do the equations match the intended standards, including lengths, malformed input and implicit rejection? Are any preconditions stronger than the production callers establish? | `formal/dafny/hkdf/`, `formal/crypto/`, `formal/primitives/`, the public-domain harnesses and `formal/crypto-obligations.json` |
| Executable-source proofs | Are functional postconditions, mutable-buffer ownership, freshness, permitted aliases and frames sufficient? Do the proofs depend on an axiom or external contract that the claims omit? | Actual executable Dafny, `formal/source/ShakeOwnership.dfy`, `formal/source/hkdf/`, `formal/source/polynomial/` and `formal/source/select/` |
| Source observations | Are branches, short-circuit evaluation, loops, accesses, allocations, calls and child traces represented faithfully? Are public/secret classifications and output declassifications justified? | `formal/source/vocabulary/`, `formal/source/SourceTrace.dfy`, component harnesses, resolved-AST C# checkers and their negative controls |
| Java integration | Does the generated source come from the verified body? Do facade adapters establish its preconditions, preserve ownership and handle provider errors without adding an oracle? | `quic/src/main/java/`, generation/delivery manifests, provider adapters, integration tests and `formal/crypto/delivery.py` |
| Evidence consumers | Can an omitted input, shadow declaration, forged report, truncated diagnostic, unsupported operation or stale artifact pass a gate? | `scripts/security/check_crypto_obligations.py`, `check_crypto_release.py`, `check_select_source.py`, their tests and the component replay runners |
| Delivered artifacts | Do the supplied library/bundle classes match the canonical generated stage, and are the loaded classes from the expected origins? | Supplied-artifact validator, actual JAR/bundle inputs, loaded-origin checks and invocation-specific receipts |

These paths are relative to the recorded repository commit. Review the real
callers and dependencies, not only the entry-point contracts or receipt JSON.

## Boundaries that require explicit treatment

- Dafny/Boogie/Z3 and the Java compiler/runtime remain trusted. Hash identity and
  ghost-erasure checks do not prove a compiler or the JVM correct.
- Resolved-AST C# observation checkers and Python orchestration/claim gates are
  trusted reviewed tools. Their tests and semantic negative controls provide
  evidence, not proofs of their implementations.
- Logical buffer roles and indices are source observations, not physical heap
  addresses. A callee-name event alone does not establish its child trace.
- JDK HMAC/SHA3 and entropy/security assumptions retain their declared boundaries.
  Our own helpers and adapters must not be hidden as opaque provider assumptions.
- Physical JVM/JIT/CPU/GC/provider timing remains **outstanding**. Measurements or
  disassembly are bounded deployment evidence; neither closes a universal
  constant-time claim. Physical erasure is also outside the source wipe theorem.
- The full upstream AWS HKDF reference-graph replay and alternate SAW array-clone
  route remain separately recorded residuals. Neither is additional proved
  evidence for the selected standalone/generated implementation.

## Reproduction and acceptance

Start with the [ledger guide](https://github.com/mahmoudimus/MicroProxy/blob/main/formal/obligations.md)
and each component's replay README. Run the normal ledger gate and require the
specific scoped claims being assessed. The aggregate `--require-all` gate must
fail while stronger required obligations remain open. A green component gate
does not imply that aggregate completion.

For a release review, run the supplied-artifact validator on the actual new
library and bundle. A previous release's successful invocation cannot certify
different artifacts. Record failures, timeouts and unsupported operations as
such; they are not semantic counterexamples or successful proofs.

The external review record should identify the reviewers and expertise, exact
scope/exclusions, commit/artifacts/tools, reproduced commands, findings and their
severity, fixes and retests, and unresolved limitations. Findings against a
specification or trusted tool require reassessing dependent claims. Close the
independent-review checklist item only after that review and disposition of its
findings; this preparation document is not its completion evidence.
