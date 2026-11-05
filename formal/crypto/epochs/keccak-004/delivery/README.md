# Explicit Keccak delivery successor

The current source emits five additional grouping-parenthesis pairs in one
generated Java file. The native runtime caller inventory records four of those
lines literally, so the released delivery contract correctly rejects the new
inventory. Its historical manifest and receipts remain unchanged.

`predecessor-delivery.json` is the exact released configuration.
`delivery.json` is a separately selected successor with only three data changes:

- The inventory digest changes from `7dbe4d9f...` to `3b0066f6...`.
- NativeKeccak's exact current source hash becomes an additional required pin.
- NativeShake's exact current source hash becomes an additional required pin.

The 193-site count, file set, caller review, helper and boxing policy, proof
phases, semantic controls, supported JDKs, compiler flags, provider assumptions
and approval requirements are unchanged. `runtime-inventory-delta.json` records
all four changed entries. An independent engineering review reconstructed both inventories
from actual Java and rehashed the complete generated sources and compiled
classes: only grouping parentheses changed, with identical class bytes on the
qualified profiles. The fifth parentheses-only line is outside that inventory.

`manifest.json` binds both configurations, the exact current source epoch,
unchanged helper code and this reviewed delta. It is candidate data, with
`qualification:false`. It does not itself establish a canonical stage, Maven
identity, production adoption or physical timing.

The unchanged delivery helper selects its configuration through its physical
`formal/crypto/delivery.json` path. Therefore use this successor only in a NEW
authenticated epoch delivery view, installing the selected configuration at
that canonical path inside the view. Bind the same view and manifest through
assembly, staging, receipt hashing, stage loading and final artifact checks.
Do not patch helper globals, normalize arbitrary source strings, accept both
inventory digests indiscriminately, or change historical evidence.

Fresh full-source canonical proofs, exact source/class regeneration, actual
Maven/library/bundle checks and the existing approval gates remain mandatory.
The default released configuration remains at `formal/crypto/delivery.json`;
it continues to reject this source candidate until an explicit successor is used.
