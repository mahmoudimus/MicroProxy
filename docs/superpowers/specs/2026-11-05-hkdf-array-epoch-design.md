# HKDF array-input delivery epoch

Checkpoint: implementation and DATA checks are present; new artifact qualification
is not complete. Later reviewed refinements are recorded in
`formal/crypto/epochs/hkdf-array-001/README.md` and `CI-CONTRACT.md`: complete
current-branch construction, an explicitly frozen dependency cache with offline
packaging, and separate retained-Darwin/local/Python-spelling authorities. The
design below records the original decision; its commands are not a completed
execution receipt.

This is an implementation decision within the approved #117 delivery goal. It
applies the existing source-epoch pattern to the new HKDF input boundary. It does
not change the approved cryptographic specifications or extend the security claim.

The current `keccak-004` CI gate seals 467 inputs and 468 library classes from its
selected subject. The new generated HKDF input entries change that subject. The
old Keccak parent, its receipts and the published 0.8.1 files remain immutable.

## Selected approach

Add `formal/crypto/epochs/hkdf-array-001/`, with an independently selected policy,
an exact delivery-configuration successor, an orchestrator and admission tests.
Its result has three explicit layers:

1. Retained Keccak and NativeCrypto component evidence on its authenticated
   original subject, with exact unchanged native dependencies bound to the new
   project. Preserve the parent's seven-Poly-theorem-closure rule. Reusing old
   whole-Poly composition, package linkage or erasure qualification is forbidden.
2. Fresh completed HKDF v2 evidence for executable Dafny, observation coverage,
   generated Java, reviewed adapters, both JDKs and the current producer authority.
3. Fresh whole-library and bundle validation on the candidate artifacts, with
   exact predecessor-to-candidate input and class deltas.

The unchanged artifact validator remains the authority for actual JAR contents,
runtime/notices, duplicate and multi-release entries, handshake/nonce behavior,
and loaded origins. The HKDF 12-class JAR hook supplements its whole-artifact
checks. It cannot replace them.

Changing the old Keccak selection would blur artifact provenance. An HKDF-only
JAR check would omit the rest of the delivered library and bundle. Neither meets
the approved delivery goal. The new epoch preserves both evidence scopes.

## Boundaries

- `inputs.json` is an externally selected policy, authenticated by an explicit
  expected SHA-256 argument. It pins predecessor authorities, complete candidate
  maps, exact allowed deltas, the completed HKDF evidence and its producer/tool
  bindings. It must not authorize broad path prefixes or accept whatever changed.
- Measure all candidate classes before selecting a delta. The expected changes
  appear to be `VerifiedHkdf/__default.class` and `HkdfBridge.class`; that remains
  a hypothesis until the entire class map is compared. Every unaffected entry
  must match. Added or removed inputs/classes require individual entries.
- `delivery.json` preserves native proof, control, compiler and runtime policy.
  Only reviewed HKDF-generated-source entries may differ from its predecessor.
- The project passed as repository root and tool root to the artifact API must be
  the same new isolated project. Construct it from authenticated predecessor and
  candidate inputs; do not use unrelated dirty files or mutable working outputs.
- Missing, partial or stale HKDF v2 output cannot qualify. Required canonical
  counts are 257 body, 11 sequence NI and 13 array NI conditions. Mixed proofs
  have 257 each. Domain, audit, controls and runtime suites remain separately
  required; these numbers are not interchangeable or independent theorems.
- Preserve all original input domains, aliases, error behavior and fingerprints.
  Do not introduce new primitive or opaque owned-code assumptions.
- Outputs must be new and disjoint from input/tool roots. Authenticate source and
  tool maps before and after; save actual child stdout, exit and ownership records
  before parsing. Use the existing reviewed process supervisor and loaders.

## Required execution

The artifact API requires a complete stage receipt matching the current delivery
configuration. Its `delivery.py check` then reproduces that stage. Therefore the
unchanged API requires initial new-config stage creation and its own mandated
reproduction. Do not substitute an old receipt with a rewritten configuration
hash, or add a third manual replay.

Run the new admission tests and the existing artifact-validator tests first.
Then create the selected stage, package with JDK 21 using
`mvn -q -pl microproxy-starlark -am -DskipTests package`, check the HKDF JAR subset
and native runtime guard, and invoke the full artifact API on JDK 21 and 25.
Packaging is private; never install, deploy or replace published 0.8.1 artifacts.

The result must distinguish retained proofs, fresh HKDF evidence and fresh finite
artifact checks. Full source trace/adapter composition, physical JVM timing and
external expert review do not become complete through this delivery result.

## Review and failure controls

Reject an unauthorized third class or input change, missing/extra classes, an old
HKDF subject, coherently repinned false evidence, stale stage configuration,
changed native/provider closure, wrong tools/runtime/JDK, alternate loaded
origins, artifact mutation during validation, and treating the old 468-class
identity as the new subject. Keep the historical stale-context rejection tests.
The global V7 obligation remains partial.
