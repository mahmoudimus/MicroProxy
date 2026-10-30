# QUIC Feature Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete and demonstrate the named protocol/application feature baseline without changing captured browser behavior by default.

**Architecture:** Extend the existing sans-I/O connection and stream state machines, then expose tested behavior through the blocking facade and optional runner endpoint. Reuse working migration, version-follow and scheduler code.

**Tech Stack:** JDK 21+, Maven, JUnit, pinned QUIC Interop Runner containers, Lean and TLA+/TLC for selected invariants.

**Spec:** [QUIC completion and Java cryptography assurance](2026-10-28-quic-crypto-assurance-design.md).

## Global Constraints

- JDK 21 floor; JDK 21/25 compatibility checks; no new default runtime dependency.
- Browser profiles/fixtures remain unchanged unless a separately reviewed profile update is intended.
- Interop support requires actual feature exercise and packet/file validation; unsupported inputs return 127.
- Scope is the spec's named RFC/draft baseline. Record extra optional capabilities separately.
- Every implementation task ends with focused regression checks, relevant fingerprint checks, independent review and a scoped commit.

## Review Focus

1. Forged or reordered version packets must not authenticate a downgrade: F1/F2.
2. Preferred IPv4/IPv6 addresses may be unreachable or validate late: F3.
3. Reprioritization racing a blocked write must preserve scheduling/close behavior: F4.
4. A reset received before missing prefix bytes must not become premature EOF: F6.
5. Malformed extension/remembered 0-RTT state must fail before partial state mutation: F5/F6.

## F0: Establish the requirement and release ledger

**Files:** Create `docs/reference/quic-feature-matrix.md` and `quic-interop/coverage.json`; update `quic-interop/README.md`, `quic/README.md`, `mkdocs.yml`, `docs/llms.txt`.

**Interfaces:** Each coverage row has `id`, `standard_section`, `role`, `requirement_level`, `implementation`, `tests`, `status`, and `issue`. Implementation/test references name actual methods. Status is supported, partial, unsupported, or unverified.

- [ ] Inventory transport, TLS acceptance, recovery, streams, limits, CID lifecycle, Retry, migration, MTU, DATAGRAM, resumption and all quoted features against the named standards.
- [ ] Separate client-side version following from server selection and incompatible VN restart. Preserve the existing partial implementation in the ledger.
- [ ] Record the socket ECN limitation at `Connection`'s `setSendingEcn(false)` and `EndpointDriver`. A native/FFM transport decision is a separate reviewed task, not an implied new dependency.
- [ ] Turn every mandatory gap and every promised optional gap into an owned work item. Add a coverage validator that rejects missing status/test/issue evidence; its negative fixture must fail.
- [ ] Verify `python3 scripts/security/check_quic_coverage.py` (to create), docs checks, current-main/PR #114 status and immutable image provenance. Commit the baseline ledger before feature changes.

## F1: Complete client version-negotiation validation

**Files:** `connection/Connection.java`, `connection/ClientConfig.java`, `params/TransportParameters.java`, `params/VersionInformation.java`, `params/TransportParameterProfile.java`, `QuicClient.java` under `quic/src/main/java/io/github/mahmoudimus/quic/`; create `connection/CompatibleVersionNegotiationTest.java` in the corresponding test tree.

**Interfaces:** Preserve `followVersion(QuicVersion)` as the current transition entry. Add explicit version-negotiation policy/state that separates original, active and authenticated chosen version and records whether ordinary VN caused a new attempt. Initial policy compatibility is v1/v2 only. Raw VN failure remains observable when restart policy is disabled.

- [ ] Add named tests for offered v1-to-v2 switching, missing/mismatched authenticated information, incompatible/unoffered versions, repeated switches and forged packets before/after authentication. Assert the final version and relevant close code, not merely that any exception occurred.
- [ ] Demonstrate the current partial implementation fails the missing conformance cases; retain its passing Firefox-profile tests.
- [ ] Complete policy/state and validation according to RFC 9368, including a bounded ordinary-VN restart when enabled and remembered negotiation evidence across the attempt.
- [ ] Run `mvn -pl quic -am -Dtest=CompatibleVersionNegotiationTest,FirefoxInitialPacketsTest,Firefox159QuicProfileTest -Dsurefire.failIfNoSpecifiedTests=false test`. Expect all selected tests to execute and pass. Commit after review.

## F2: Server compatible selection and runner v2

**Files:** Under the same QUIC package roots as F1: `connection/Endpoint.java`, `connection/Connection.java`, `connection/ServerConfig.java`, `connection/EndpointConfig.java`, `crypto/Keys.java`, `params/TransportParameters.java`; adapter `quic-interop/src/main/java/io/github/mahmoudimus/quic/interop/InteropEndpoint.java`, `quic-interop/run_endpoint.sh`, endpoint tests and `quic-interop/test_endpoint_contract.py`.

**Interfaces:** Add explicit server version preference/fully-deployed policy to `ServerConfig.Builder`; default preserves present version behavior. The server chooses only a compatible offered version. Actual packet protection follows the chosen version. Enable adapter `v2` only after both roles work.

- [ ] Add server/client round-trip tests with a v1 first flight and v2 outcome; cover the authenticated client choice, Retry, ALPN compatibility, 0-RTT acceptance/rejection and deployment preference changes.
- [ ] Run the new tests against the existing code and save the failing case classification.
- [ ] Implement selection and version-dependent key/packet transitions; extend TLS version-information validation for both roles. Add a bounded TLA model for selection/authentication states with a weakened-validation counterexample.
- [ ] Run focused version/TLS/packet-vector tests and the upstream runner `v2` case in both directions against two supporting peers. Store immutable image/peer IDs and packet evidence proving negotiation occurred. A directly forced v2 connection does not close this task. Review and commit.

## F3: Preferred-address migration in the interop adapter

**Files:** `quic-interop/src/main/java/io/github/mahmoudimus/quic/interop/InteropEndpoint.java`, `quic-interop/src/test/java/io/github/mahmoudimus/quic/interop/InteropEndpointTest.java`, `quic-interop/run_endpoint.sh`, `quic-interop/test_endpoint_contract.py`; reuse `ServerConfig.Builder.preferredAddress` and `EndpointDriver` socket binding. Core migration changes need a separate reproduced defect.

**Interfaces:** For server `connectionmigration`, advertise a distinct bound preferred IPv4/IPv6 endpoint on the runner's existing server addresses, using an available distinct port. Client-side runner mapping remains `transfer`; existing `ClientConfig.Builder.preferredAddress(true)` applies.

- [ ] Add an adapter integration fixture asserting a different post-handshake remote path, expected CID, PATH_CHALLENGE/RESPONSE and correct downloaded bytes. Add unreachable-path fallback and late-validation cases.
- [ ] Verify the current wrapper rejects this case with 127.
- [ ] Wire existing socket/configuration support and update the whitelist only after the fixture passes.
- [ ] Run `MigrationTest`, `MigrationLoopbackTest`, adapter tests and runner `connectionmigration` in both applicable roles. Require trace-observed path change, not only completed transfer. Review and commit.

## F4: Blocking stream priorities

**Files:** `QuicStream.java`, existing `Connection.setPriority`/`StreamsState.setPriority`/`PendingStreamsQueue`, `connection/StreamsStateTest.java`; create `StreamPriorityLoopbackTest.java`.

**Interfaces:** Add `public void QuicStream.setPriority(int priority) throws IOException`. Use the connection-driver lock, validate a send-capable live stream, call the existing scheduler and wake transmission. Higher values keep their existing ordering. Document next scheduling/requeue semantics and the current fairness policy.

- [ ] Write tests for blocked concurrent streams, reprioritization after enqueue, equal priorities, fairness, receive-only streams and connection closure during a setter call.
- [ ] Verify missing API/scheduling assertions fail before implementation.
- [ ] Implement the facade without changing default priorities or claiming HTTP/3 PRIORITY_UPDATE support.
- [ ] Run `StreamsStateTest` and `StreamPriorityLoopbackTest`; verify actual transmitted stream order under constrained flow/congestion capacity. Review and commit.

## F5: Partial-reset wire format and negotiation

**Files:** `frame/Frame.java`, `frame/FrameType.java`, `frame/FrameDecoder.java`, `params/TransportParameters.java`, `connection/TransportConfig.java`, ticket/0-RTT parameter validation; extend decoder/parameter tests.

**Interfaces:** Add `Frame.ResetStreamAt(long streamId, long errorCode, long finalSize, long reliableSize)` consistent with existing frame types. Baseline is draft -11: frame `0x24`, empty transport parameter `0x1d`. Recheck assigned values at implementation time. Default advertisement remains off until F6.

- [ ] Add codec, malformed-size, packet-space, negotiation and remembered-0-RTT regressions with precise errors.
- [ ] Show old code lacks the required behavior.
- [ ] Implement codecs/validation and configuration plumbing with bounded allocation and immutable final-size accounting. Do not advertise an incomplete receive path.
- [ ] Run decoder, transport-parameter, ticket and 0-RTT tests; review normative revision changes and commit.

## F6: Partial-reset delivery, retransmission and API

**Files:** `connection/Send.java`, `Recv.java`, `SendBuffer.java`, `StreamsState.java`, stream state/event types, `Connection.java`, `QuicStream.java`; create `PartialResetTest.java`, `PartialResetLoopbackTest.java`, and `formal/tla/PartialReset.tla` with configs.

**Interfaces:** Add `public void QuicStream.resetAt(long errorCode, long reliableSize) throws IOException`. Accept only a send-capable stream and a prefix already submitted; rejected input leaves state intact. Reuse `QuicStreamException` to signal reset after required delivery. Sending support requires peer negotiation.

- [ ] Add loss/reorder/duplicate/FIN/STOP_SENDING fixtures: preserve the required prefix, avoid premature EOF, account final size, handle zero/decreasing reliable sizes, and enforce consistent error/final-size values. Exercise simultaneous application reads/writes and close.
- [ ] Verify ordinary-reset behavior fails retained-prefix delivery.
- [ ] Implement minimal retained-range state and recovery; add bounded-state invariants and a deliberately unsafe early-release model. Liveness assertions require stated network/scheduler fairness.
- [ ] Run state and UDP integration tests, a draft-compatible independent peer when available, and the new TLC configs. Default advertisement can turn on only after reviewed behavior is complete; leave captured profiles unchanged. Review and commit.

## F7: Matrix, release and claim gate

**Files:** `quic-interop/results/`, coverage ledger, endpoint/docs workflows, README/assurance references; create `scripts/security/check_quic_release.py` and its gate tests.

**Interfaces:** A release manifest binds code/image digests, standards revisions, case/role/peer results and unresolved issues. Expected unsupported states must be explicit. Missing tools/peers fail required jobs.

- [ ] Test the gate with missing/stale results, a failure mislabeled unsupported, source drift and a wrong image digest; all must fail.
- [ ] Run the runner's pinned full functional matrix, including multiplexing, amplification, loss/corruption, key updates, rebinding and new v2/migration cases. Run DATAGRAM and partial-reset independent-peer fixtures separately where the runner has no case. Record measurements separately from functional pass gates.
- [ ] Diagnose every failure and repeat nondeterministic cases with a documented seed/run policy; report every repetition and failure rate. Do not replace a failing case with a passing subset.
- [ ] Run full Maven verification on JDK 21/25, captured fingerprint regressions, proof/source-drift gates and independent review. Publish a new immutable image and update registration only for the tested artifact.
- [ ] Close this track only when F0's mandatory/promised rows are resolved. Public matrix acceptance is external state and remains separately tracked.
