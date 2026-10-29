# QUIC packet-number and header trace verification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Replace the identified protected-header-dependent loops/branches in QUIC packet-number recovery and header unprotection with verified Dafny-generated Java, preserving wire bytes, APIs and browser fingerprints.

**Architecture:** Generate a primitive-only scalar kernel from Dafny for header unmasking, prefix reading and RFC 9000 packet-number reconstruction. A transparent lowering pass for exactly two proved bounded-shift helpers removes Dafny runtime intrinsics; the pass is part of compiler trust. Integrate with fixed-address four-octet Java buffer accesses. Prove functional equations and paired execution traces under an explicit idealized primitive-operation observer, then check actual generated Java/class code against its restricted straight-line instruction/call policy. This checker, the compiler, JVM/JDK and JCE remain trusted. Caller metadata after return, AEAD/key-phase processing and general JVM timing remain separate obligations.

**Tech Stack:** Pinned Dafny 4.9.1/Boogie/Z3 already cached by `formal/dafny/toolchain.py`, JDK 21/25, Python 3.11+, JUnit. No new production runtime dependency: compile generated scalar Java without DafnyRuntime.jar and verify its class closure.

**Spec:** This document records the user-selected approach from the preceding EverQUIC assessment; the user explicitly requested setting a goal and executing it. Their execution instruction opts out of another question/approval cycle. It is a scoped extension of the existing Java crypto verification plan.

## Intent, prior art and alternatives

EverQUIC's 2021 paper separates safe Dafny protocol logic from F*/Low* record-layer functional/security/secret-independence proofs. Use the packet-number/header specifications and observer as research references; porting does not transfer their theorems. The pinned reference is secure-foundations/everquic-dafny commit8db9698ef5e1b2db54cb035316362447bb568b9a and its linked paper. Current RFC9000/9001/9369 and existing vectors govern our bytes.

Alternatives: (1) retain handwritten Java and prove a full bytecode refinement, which adds the existing backend blockers; (2) selected verified Dafny kernel -> Java, with compiler trust; (3) native F*/EverCrypt integration, which adds native deployment/FFI and is outside the selected pure-Java route. The implementation choice is ours within the user's authorized route.

## Global Constraints

- Worktree `/Users/mahmoud/.codex/worktrees/security-review/microproxy`, branch `diff/quic-packet-traces`, base `00d46a1a5048df7ac157c9373320ceca03f72781`; stack on PR120. Leave unrelated work alone.
- Keep public API behavior, byte order independence, ByteBuffer position/limit semantics, wire bytes, browser fingerprints and default dependency-free runtime.
- Pure primitive kernel: no external axioms/assumes, allocation, arrays, data-dependent jumps, division or unlisted library/helper calls in compiled scalar methods.
- Functional contract matches the existing signed-Java-overflow recurrence for lengths 1..4; the RFC meaningful largest-number domain is -1..2^62-1. Do not silently narrow the actual algorithm or assert all reconstructed results lie below2^62.
- Header unprotection writes the first octet plus exactly four fixed packet-number-area addresses, preserving bytes beyond the actual packet-number length. This is safe only after the existing public sample-length check.
- Ordinary generic PacketNumber.read remains usable on buffers containing exactly1..4bytes; only the protected-packet path switches to fixed-four-byte reads.
- The trace observer treats primitive word operations as operand-independent. It observes branches, call shape and buffer addresses; excludes returned metadata after the boundary, allocation/runtime/JIT/CPU effects and provider internals. Functional proof alone is not a timing proof.
- Negative controls must fail semantic/trace obligations or the actual code gate; timeout/parser/crash cannot count as proof rejection. Pin all inputs/generated code, invalidate stale reports, reuse reviewed runner cleanup.

## Review Focus

1. Packet-number boundaries at half-window, 2^62, -1, high truncated bits and signed overflow must retain reference results: Task1/3 tests.
2. Four-byte touches must preserve following ciphertext, buffer order, slices/direct buffers, positions/limits, and short/read-only rejection: Task3 tests.
3. Compiler-introduced comparisons/helper calls may reintroduce secret work: Task2 recursive bytecode gate and mutations.
4. A self-reported constant trace with no connection to emitted code is insufficient: Task1 operational trace model plus Task2 generated-code policy bridge; document checker/compiler trust.
5. Header/PN success does not make provider AEAD lengths or key-phase handling constant time: Task4 scope and integration review.

## Task 1: Scalar algorithm and trace contracts

**Files:** create `formal/packet/PacketKernel.dfy` and isolated proof controls. No production edits before regression RED.

**Interfaces:** scalar `Decode(largest:bv64,truncated:bv64,length:bv64):bv64`, `ReadPrefix(word:bv64,length:bv64):bv64`, `Unprotect(headerAndFourOctets:bv64,mask:bv64):bv64`. Header octet occupies bits32..39; following four octets occupy bits0..31 in network order. All kernel methods use only fixed-width primitives. Lengths1..4 are explicit preconditions; unprotection derives length internally. Stable independent reference equations use conditional mathematical specifications. Trace contracts have no secret-dependent observation.

- [x] Prove expected wrong recurrence/byte mask fails before implementation acceptance.
- [x] Implement and prove signed comparison/selection helpers, exact reconstruction with original add-before-sub priority, prefix truncation and header mask scope.
- [x] Add paired-run trace obligations and satisfiable-domain harness; clarify their observer and code-bridge requirements.
- [x] Run pinned Dafny proof, audit with zero findings and functional/trace negative controls. Record actual count/domain.

## Task 2: Reproducible dependency-free Java and trace gate

**Files:** create `formal/packet/{run.py,test_run.py,inputs.json,README.md}`; generate `quic/src/main/java/io/github/mahmoudimus/quic/internal/verified/__default.java` (or final namespace established by the verified backend spike). Reuse pinned tools and safe runner primitives without widening old HKDF's source inventory.

**Interfaces:** replay verifies/audits/generates, compares exact production generated source, compiles canonical Java classes and checks actual class instructions/call closure. Source/hash matching records identity; the restrictive generated-code observer gate is an explicitly trusted checker, not a verified JVM implementation.

- [x] Write/run RED runner tests for branch/lookup/unexpected-call/allocation/helper/runtime dependency, stale success, changed source/generated/class and vacuous domains.
- [x] Implement fail-closed replay and actual emitted-code policy checking; reject unknown opcodes/targets and unverified procedures.
- [x] Run generated Java compilation without Dafny runtime, then positive and negative gate tests. Cache tools externally; keep old HKDF replay pins intact.

## Task 3: Integrate fixed-work header and packet-number paths

**Files:** modify `crypto/HeaderKey.java`, `packet/PacketNumber.java`, `packet/ProtectedPacket.java`; add focused JUnit tests to existing packet tests/new header tests. Update only affected proof source pins after reviewing their semantic relation.

**Interfaces:** retain HeaderKey.unprotect/protect and PacketNumber.decode public signatures. Keep protect/reference bytes identical. ProtectedPacket uses fixed-four-byte prefix reading only after sample validation. Buffer indexes depend only on public start/packet-number offset; data selections are scalar masks.

- [x] Add failing protected-path access/branch policy checks and edge regression cases; preserve existing standards assertions.
- [x] Integrate generated methods with fixed-four-octet reads/writes. Keep plaintext bytes beyond actual PN untouched and all buffer state expectations stable.
- [x] Run old/new reference differential cases for all4lengths and boundary classes, standards vectors v1/v2/AES/ChaCha, heap/direct/sliced/endian/read-only/short-buffer cases and fingerprint tests.
- [x] Inspect/class-check actual built methods and canonical generated identity; record remaining Java wrapper/provider assumptions.

## Task 4: Compatibility, independent review and evidence

**Files:** docs formal-security/timing audit/plan, formal packet README/evidence, formal CI JDK 21/25, relevant source manifests.

- [x] Run appropriate Maven suites on JDK 21/25, both pinned-platform replays and controls, and all changed-input proof checks. Preserve test/vector/fingerprint fixtures.
- [x] Update exact claims, trace boundary, source/tool/generated/class provenance, runtime-dependency result and excluded downstream paths.
- [x] Obtain fresh whole-branch review under requesting-code-review, fix Important findings RED->GREEN, rerun affected checks.
- Publication/handoff: commit/push the isolated branch, create/attach a draft PR stacked on120 and update crypto track117 with achieved scope. Leave whole-stack timing and remaining algorithm work open. The task ledger and goal status record final publication and lifecycle completion.

Implementation and local evidence: `7be2a23`; see `formal/packet/EVIDENCE.md`. Publication and final goal handoff are recorded in the task ledger. Whole-stack timing and other crypto roadmap milestones remain open.
