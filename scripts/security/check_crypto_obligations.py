#!/usr/bin/env python3
"""Validate the fail-closed MicroProxy crypto obligation ledger.

This is a provenance and declared-claim gate, not a theorem prover.  It checks
that the fixed V0-V8 inventory is present, that every cited input is a pinned
relative repository file, that component receipts still contain their reviewed
positive/negative controls, that the dependency graph is acyclic and root
reachable, and that claims do not exceed their evidence.  It never promotes a
matching hash to a semantic proof or an expert review.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
LEDGER_SCHEMA = "microproxy.crypto-obligations/v1"
STATUS_SCHEMA = "microproxy.crypto-obligation-status/v1"

REQUIRED_OBLIGATIONS = ("V0", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8")
ROOT_OBLIGATION = "V8"

ALLOWED_STATUSES = {
    "model-proof",
    "implementation-proof",
    "bytecode-proof",
    "finite-tests",
    "partial",
    "blocked",
    "deferred",
    "not-selected",
    "unsupported",
}
PROOF_STATUSES = {"model-proof", "implementation-proof", "bytecode-proof"}
CLAIM_STATUSES = {"supported", "deferred", "blocked", "snapshot", "not-selected", "unsupported"}
CLAIM_STRENGTHS = {"implementation", "model", "bytecode", "finite", "none"}

# These identifiers are intentionally pinned here.  Adding or renaming trust
# assumptions requires an explicit checker change and review, so a ledger edit
# cannot silently expand the trusted base.
ALLOWED_ASSUMPTIONS = {
    "dafny-toolchain",
    "dafny-runtime",
    "javac-jvm",
    "jdk-primitives",
    "generated-runtime-discipline",
    "reviewed-java-facades",
    "packet-compiler-lowering",
    "saw-toolchain",
    "lean-toolchain",
    "tlc-finite-model",
    "crypto-hardness-entropy",
    "jvm-timing-jit-cpu-gc",
    "trusted-bytecode-mapper-policy",
    "trusted-source-observation-coverage",
    "assumed-owned-helper-trace-contracts",
}

ALLOWED_EVIDENCE_KINDS = {
    "model-source",
    "spec-source",
    "proof-receipt",
    "component-receipt",
    "bytecode-report",
    "proof-log",
    "delivery-receipt",
    "source-inventory",
    "production-source",
    "generated-source",
    "finite-test",
    "test-source",
    "input-manifest",
    "tool-manifest",
    "snapshot-receipt",
    "current-jar-receipt",
    "expert-review-receipt",
    "security-reduction-receipt",
    "timing-proof-receipt",
    "whole-system-proof-receipt",
    "upstream-closure-receipt",
    "documentation",
}
PROOF_EVIDENCE_KINDS = {
    "model-source",
    "spec-source",
    "proof-receipt",
    "component-receipt",
    "bytecode-report",
    "proof-log",
    "delivery-receipt",
    "source-inventory",
}

# --- Poly source-trace NI (V7 scoped claim) -------------------------------
# A separate, scoped V7 contribution: NativeField/NativePolynomial source
# observation proofs bound by a separately trusted resolved-AST checker.  The
# receipt is the actual full portable-package report (not a summary), so every
# load-bearing fact below is cross-checked against the repository bytes and the
# report's own before/after input guards.  All reviewable literals live here:
# a ledger edit or a renewed receipt JSON cannot add a supportable claim.
POLY_SOURCE_CLAIM = "poly-source-trace-ni"
POLY_SOURCE_RECEIPT = "formal/source/polynomial/SOURCE-EVIDENCE.json"
POLY_SOURCE_INPUTS = "formal/source/polynomial/inputs.json"
POLY_SOURCE_BASELINE_TEMPLATE = "formal/source/polynomial-baseline.json"
POLY_SOURCE_BASELINE_HELPER = "scripts/security/prepare_poly_baseline.py"
POLY_SOURCE_BASELINE_TEST = "scripts/security/test_crypto_poly_baseline.py"
POLY_SOURCE_TRACKED_INDEX = "formal/crypto/evidence/2026-11-04-poly/source/log-index.json"
POLY_SOURCE_TRACKED_REPORT = "formal/crypto/evidence/2026-11-04-poly/source/SOURCE-EVIDENCE.json"
POLY_SOURCE_SCHEMA = "microproxy.native-polynomial-central-port/v1"
POLY_SOURCE_INPUTS_SCHEMA = "microproxy.native-polynomial-central-port-inputs/v2"
POLY_SOURCE_BASELINE = {
    "commit": "5ce660a69a1dd496dda02705bf1e2b1aa7a2be1d",
    "tree": "df8b49bc8d181be18d78a9db7ab0233f23f7346f",
    "files": 20,
    "manifest_sha256": "77daf19d88d147086717d86f06cda280e9f16d0e7b2ef769472745a77f256ff0",
}
# Immutable pre-adoption hashes of the four baseline component files (the
# immutable main closure carries these; the poly domain harness is package-owned
# and is not part of the 20-file main closure).  The baseline manifest must carry
# these, which rules out using the post-adoption candidate (or any mutable A
# state) as its own erasure baseline.
POLY_SOURCE_BASELINE_COMPONENT_PINS = {
    "formal/crypto/NativeField.dfy": "f6fb7911a9be3559d06b241cc2ca7ebb2acc98e0ff5444979f8459ff503eaa92",
    "formal/crypto/NativePolynomial.dfy": "4740bdb1deb10a6cb4855c279e441f77b2e541b36804c06dc0b896b9fc9dbee1",
    "formal/crypto/NativeSampling.dfy": "a02194e6e2e6803496852365d0ff5ba9ef0b4e73937f6265ab689c70abe1823b",
    "formal/crypto/NativeMlKem.dfy": "4dabda21e130be283ac2ab78e74414019a0f74dc04ea7ca92af361825898c2d8",
}
POLY_SOURCE_POLICY = {
    "composition_case_split": 3,
    "cores": 2,
    "native_case_split": 0,
    "resource": 50000000,
    "time": 30,
}
POLY_SOURCE_PROOFS = (
    ("field", "formal/crypto/NativeField.dfy", 86),
    ("polynomial", "formal/crypto/NativePolynomial.dfy", 1001),
    ("paired-harness", "formal/source/polynomial/NativePolynomialTraceHarness.dfy", 26),
    ("mlkem-composition", "formal/crypto/NativeMlKem.dfy", 2767),
    ("field-compatibility", "formal/source/polynomial/FieldTraceCompatibility.dfy", 14),
    ("source-trace", "formal/source/SourceTrace.dfy", 17),
    ("observation-vocabulary", "formal/source/vocabulary/ObservationVocabulary.dfy", 29),
    ("checker-controls", "formal/source/polynomial/controls/PolynomialControls.dfy", 19),
)
POLY_SOURCE_AUDIT_FILES = (
    "formal/source/vocabulary/ObservationVocabulary.dfy",
    "formal/source/SourceTrace.dfy",
    "formal/crypto/NativeField.dfy",
    "formal/crypto/NativePolynomial.dfy",
    "formal/crypto/NativeMlKem.dfy",
    "formal/source/polynomial/NativePolynomialTraceHarness.dfy",
    "formal/source/polynomial/FieldTraceCompatibility.dfy",
    "formal/source/polynomial/AllPolynomialTraceRoots.dfy",
)
POLY_SOURCE_CANONICAL_CONTROLS = (
    "canonical-branch-flip", "canonical-erase-address", "canonical-erase-ops",
    "canonical-dead-branch",
)
# Reviewed load-bearing distinction per mutation: a genuine Dafny proof failure, a
# checker-only rejection whose Dafny proof still verifies (stronger: the checker is
# doing the work), or the OOR observation that is explicitly not usable as evidence.
POLY_SOURCE_MUTATIONS = {
    "leaf-branch-mutation": "observed-not-used-as-proof",
    "real-path-mutation": "dafny-proof-failure",
    "child-ghost-mutation": "dafny-proof-failure",
    "caller-arg-mutation": "dafny-proof-failure",
    "chunktrace-helper-mutation": "dafny-proof-failure",
    "branchfalseprefix-helper-mutation": "dafny-proof-failure",
    "missing-false-prefix": "dafny-proof-failure",
    "ghost-reorder": "dafny-proof-failure",
    "fake-ops": "dafny-proof-failure",
    "synthetic-callee": "checker-only-rejection",
    "drop-callee-trace": "dafny-proof-failure",
    "duplicate-projection": "dafny-proof-failure",
    "wrong-local": "dafny-proof-failure",
    "rebind-local": "dafny-proof-failure",
    "rebind-same-model": "checker-only-rejection",
    "rebind-suchthat": "checker-only-rejection",
}
POLY_SOURCE_FOCUSED_CONTROL = "missing-false-prefix"
POLY_SOURCE_FOCUSED_SYMBOL = "NativePolynomial.ZetasValue"
POLY_SOURCE_FOCUSED_ANCHOR = "ensures ZetasValue(i).1"
POLY_SOURCE_FOCUSED_ORIGINAL_LOG = "logs/controls/missing-false-prefix-original-focused.log"
POLY_SOURCE_FOCUSED_POLICY = (
    "--verification-time-limit", "30", "--resource-limit", "50000000",
    "--cores", "2", "--solver-option", "O:smt.case_split=0",
)
POLY_SOURCE_CANONICAL_NEEDLES = {
    'canonical-branch-flip': 'positional formal 1: SourceTrace._default.Branch',
    'canonical-erase-address': 'positional formal 2: SourceTrace._default.Read',
    'canonical-erase-ops': 'positional formal 4: SourceTrace._default.Ops',
    'canonical-dead-branch': 'not exact canonical Encode(constructor(positional formals)): SourceTrace._default.Branch',
}
POLY_SOURCE_CANONICAL_DIAGNOSTICS = {
    'canonical-branch-flip': ((50, 2, 'a postcondition could not be proved on this return path'), (49, 12, 'this is the postcondition that could not be proved')),
    'canonical-erase-address': ((53, 2, 'a postcondition could not be proved on this return path'), (52, 12, 'this is the postcondition that could not be proved')),
    'canonical-erase-ops': ((65, 2, 'a postcondition could not be proved on this return path'), (64, 12, 'this is the postcondition that could not be proved')),
    'canonical-dead-branch': ((50, 2, 'a postcondition could not be proved on this return path'), (49, 12, 'this is the postcondition that could not be proved'), (70, 78, 'a postcondition could not be proved on this return path'), (70, 52, 'this is the postcondition that could not be proved'), (71, 86, 'a postcondition could not be proved on this return path'), (71, 46, 'this is the postcondition that could not be proved')),
}
POLY_SOURCE_MUTATION_NEEDLES = {
    'leaf-branch-mutation': 'arm 0 guard is not exact index<literal',
    'real-path-mutation': 'real result is not a .0 projection',
    'child-ghost-mutation': 'ghost is not exactly five ordered leaves',
    'caller-arg-mutation': 'ghost projection ZetasValue is not immediately after an actual call with the same arguments',
    'chunktrace-helper-mutation': 'ChunkTrace body is not three leaves',
    'branchfalseprefix-helper-mutation': 'BranchFalsePrefix else is not two leaves',
    'missing-false-prefix': 'arm 3 ghost is not exactly five ordered leaves',
    'ghost-reorder': 'arm 0 true event is not exact',
    'fake-ops': 'Ops payload is not exact',
    'synthetic-callee': 'non-approved suffix expression',
    'drop-callee-trace': 'actual pure call GammasValue has 0 immediate ghost projections',
    'duplicate-projection': 'actual pure call ZetasValue has 2 immediate ghost projections',
    'wrong-local': 'callee trace local is not appended immediately after its defining call',
    'rebind-local': 'ghost trace local has 2 assignments; exactly one exact ghost-out call is required (rebinding)',
    'rebind-same-model': 'ghost trace local has 2 assignments; exactly one exact ghost-out call is required (rebinding)',
    'rebind-suchthat': 'AssignSuchThatStmt',
}
POLY_SOURCE_MUTATION_DIAGNOSTICS = {
    'real-path-mutation': ((566, 19, 'a postcondition could not be proved on this return path'), (556, 12, 'this is the postcondition that could not be proved')),
    'child-ghost-mutation': ((566, 19, 'a postcondition could not be proved on this return path'), (557, 12, 'this is the postcondition that could not be proved')),
    'caller-arg-mutation': ((590, 16, 'this invariant could not be proved to be maintained by the loop'), (595, 23, 'function precondition could not be proved'), (554, 18, 'this proposition could not be proved')),
    'chunktrace-helper-mutation': ((26, 7, 'a postcondition could not be proved on this return path'), (25, 12, 'this is the postcondition that could not be proved')),
    'branchfalseprefix-helper-mutation': ((22, 27, 'a postcondition could not be proved on this return path'), (20, 12, 'this is the postcondition that could not be proved')),
    'missing-false-prefix': ((569, 24, 'a postcondition could not be proved on this return path'), (557, 12, 'this is the postcondition that could not be proved')),
    'ghost-reorder': ((566, 19, 'a postcondition could not be proved on this return path'), (557, 12, 'this is the postcondition that could not be proved')),
    'fake-ops': ((566, 19, 'a postcondition could not be proved on this return path'), (557, 12, 'this is the postcondition that could not be proved')),
    'drop-callee-trace': ((838, 16, 'this invariant could not be proved to be maintained by the loop'),),
    'duplicate-projection': ((590, 16, 'this invariant could not be proved to be maintained by the loop'),),
    'wrong-local': ((1127, 16, 'this loop invariant could not be proved on entry'),),
    'rebind-local': ((863, 16, 'this invariant could not be proved to be maintained by the loop'),),
}
POLY_SOURCE_DECOY_REJECTION = 'unregistered executable callee NativePolynomial.Decoy._ctor'
POLY_SOURCE_PROBE_REASON = 'checker-scope-probe-repeated: checker reported duplicate resolved roots'
POLY_SOURCE_CANONICAL_ANCHORS = {
    'canonical-branch-flip': 'Branch(site,taken) == O.Encode(O.Branch(site,taken))',
    'canonical-erase-address': 'Read(site,role,address) == O.Encode(O.Read(site,role,address))',
    'canonical-erase-ops': 'Ops(a,b,c,d,e,f,g) == O.Encode(O.Ops(a,b,c,d,e,f,g))',
    'canonical-dead-branch': 'Branch(site,taken) == O.Encode(O.Branch(site,taken))',
}
POLY_SOURCE_METHOD_ROOTS = (
    "NativePolynomial.NewZetas", "NativePolynomial.NewGammas", "NativePolynomial.Add",
    "NativePolynomial.Sub", "NativePolynomial.Copy", "NativePolynomial.ForwardStage",
    "NativePolynomial.InverseStage", "NativePolynomial.Scale", "NativePolynomial.Ntt",
    "NativePolynomial.InverseNtt", "NativePolynomial.BaseCase", "NativePolynomial.NttMul",
    "NativePolynomial.Wipe", "NativeField.ReduceOnce", "NativeField.Reduce",
    "NativeField.Add", "NativeField.Sub", "NativeField.Mul", "NativeField.MulSub",
    "NativeField.AddMul",
)
POLY_SOURCE_PURE_FUNCTIONS = (
    "NativePolynomial.Len", "NativePolynomial.ZetasChunk0", "NativePolynomial.ZetasChunk1",
    "NativePolynomial.ZetasChunk2", "NativePolynomial.ZetasChunk3", "NativePolynomial.ZetasChunk4",
    "NativePolynomial.ZetasChunk5", "NativePolynomial.ZetasChunk6", "NativePolynomial.ZetasChunk7",
    "NativePolynomial.ZetasValue", "NativePolynomial.GammasChunk0", "NativePolynomial.GammasChunk1",
    "NativePolynomial.GammasChunk2", "NativePolynomial.GammasChunk3", "NativePolynomial.GammasChunk4",
    "NativePolynomial.GammasChunk5", "NativePolynomial.GammasChunk6", "NativePolynomial.GammasChunk7",
    "NativePolynomial.GammasValue",
)
POLY_SOURCE_CLOSURE_COUNTS = {
    "field-compatibility": 6,
    "mlkem": 20,
    "native-field": 5,
    "native-polynomial": 7,
    "paired-harness": 8,
    "polynomial-domain": 8,
    "roots": 8,
}
POLY_SOURCE_PACKAGE_SCOPE = {
    "component_overrides": (
        "formal/crypto/NativeField.dfy", "formal/crypto/NativePolynomial.dfy",
        "formal/crypto/NativeSampling.dfy", "formal/crypto/NativeMlKem.dfy",
        "formal/crypto/native_polynomial_domain.dfy"),
    "helper_dfy": (
        "formal/crypto/Codec.dfy", "formal/crypto/JdkHash.dfy", "formal/crypto/KemSpec.dfy",
        "formal/crypto/NativeCodec.dfy", "formal/crypto/NativeJdkHash.dfy",
        "formal/crypto/NativeKeccak.dfy", "formal/crypto/NativeShake.dfy",
        "formal/crypto/NativeTypes.dfy", "formal/crypto/Polynomial.dfy",
        "formal/crypto/Sampling.dfy", "formal/crypto/Shake.dfy", "formal/crypto/SpongeSpec.dfy"),
    "primitive_files": ("formal/primitives/Field.dfy", "formal/primitives/Keccak.dfy"),
    "provider_java": ("formal/crypto/kem_hash.java", "formal/crypto/native_kem_hash.java"),
    "shared_source": ("formal/source/SourceTrace.dfy",
                      "formal/source/vocabulary/ObservationVocabulary.dfy"),
    "tool_files": ("formal/dafny/toolchain.py", "formal/dafny/tools.json",
                   "formal/crypto/delivery.py"),
}
POLY_SOURCE_INPUT_KEYS = (
    "formal/crypto/Codec.dfy", "formal/crypto/JdkHash.dfy", "formal/crypto/KemSpec.dfy",
    "formal/crypto/NativeCodec.dfy", "formal/crypto/NativeField.dfy",
    "formal/crypto/NativeJdkHash.dfy", "formal/crypto/NativeKeccak.dfy",
    "formal/crypto/NativeMlKem.dfy", "formal/crypto/NativePolynomial.dfy",
    "formal/crypto/NativeSampling.dfy", "formal/crypto/NativeShake.dfy",
    "formal/crypto/NativeTypes.dfy", "formal/crypto/Polynomial.dfy",
    "formal/crypto/Sampling.dfy", "formal/crypto/Shake.dfy", "formal/crypto/SpongeSpec.dfy",
    "formal/crypto/delivery.py", "formal/crypto/kem_hash.java",
    "formal/crypto/native_kem_hash.java", "formal/crypto/native_polynomial_domain.dfy",
    "formal/dafny/toolchain.py", "formal/dafny/tools.json", "formal/primitives/Field.dfy",
    "formal/primitives/Keccak.dfy", "formal/source/SourceTrace.dfy",
    "formal/source/polynomial/AllPolynomialTraceRoots.dfy",
    "formal/source/polynomial/FieldTraceCompatibility.dfy",
    "formal/source/polynomial/NativePolynomialTraceHarness.dfy",
    "formal/source/polynomial/README.md",
    "formal/source/polynomial/checker/PolynomialSourceCoverage.cs",
    "formal/source/polynomial/checker/PolynomialSourceCoverage.csproj",
    "formal/source/polynomial/controls/BranchObservedHarness.dfy",
    "formal/source/polynomial/controls/ByMethodControl.dfy",
    "formal/source/polynomial/controls/ControlHarnesses.dfy",
    "formal/source/polynomial/controls/FunctionBranchHarness.dfy",
    "formal/source/polynomial/controls/FunctionIndexHarness.dfy",
    "formal/source/polynomial/controls/FunctionUnmarkedHarnesses.dfy",
    "formal/source/polynomial/controls/IndexObservedHarness.dfy",
    "formal/source/polynomial/controls/LemmaOutControl.dfy",
    "formal/source/polynomial/controls/PolynomialControls.dfy",
    "formal/source/polynomial/controls/UnmarkedHarnesses.dfy",
    "formal/source/polynomial/inputs.json", "formal/source/polynomial/replay.py",
    "formal/source/polynomial/test_replay.py",
    "formal/source/vocabulary/ObservationVocabulary.dfy",
)
POLY_SOURCE_CHECKER_SOURCE_PIN = "fc67e059f500a10bf52f978040db92d56edd4c6475a6a21d581e4956dd406910"
POLY_SOURCE_CHECKER_PROJECT_PIN = "b37f0a8aadee87bc0c0191352311cc656b21e0e0fbc61cf0e71e4d4e49dfb2c0"
POLY_SOURCE_CHECKER_SDK = "10.0.400"
POLY_SOURCE_TOOL = {
    "version": "4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2",
    "asset_sha256": "3209da6998c98c10e15970b85f6aa27925682c3273cd41539348ab8f7941553e",
    "toolchain_sha256": "4ff94e948692ed9d358d06c58add5362c084880124d058d906d4d381cf15b5a8",
    "tools_manifest_sha256": "d0400f892192bd2e603651aa36c9fed32394b5d0600955d4854c852df729f1c6",
}
POLY_SOURCE_RUNTIME = {
    "explicit_sha256": "dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6",
    "toolchain_sha256": "2c028565d81751f5f659d962c98613b118e45bfae6a295fb140f5e07f4b82b2f",
}
POLY_SOURCE_TRUST_BOUNDARIES = (
    "Dafny verifier and ghost erasure",
    "trusted resolved-AST C# checker",
    "javac/JVM and DafnyRuntime",
    "JCE/provider runtime",
    "read/write roles are method-local resolved identities",
)
POLY_SOURCE_GENERATED_FILES = 66
POLY_SOURCE_CLASS_COUNT = 65
POLY_SOURCE_ERASED_JAVA = (
    "NativeCrypto-java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativePolynomial/__default.java",
)
POLY_SOURCE_CLAIM_EVIDENCE = (
    (POLY_SOURCE_RECEIPT, "component-receipt"),
    (POLY_SOURCE_INPUTS, "input-manifest"),
    ("formal/source/polynomial/README.md", "documentation"),
    ("formal/source/polynomial/replay.py", "tool-manifest"),
    ("formal/source/polynomial/test_replay.py", "test-source"),
    ("formal/source/polynomial/NativePolynomialTraceHarness.dfy", "proof-receipt"),
    ("formal/source/polynomial/FieldTraceCompatibility.dfy", "proof-receipt"),
    ("formal/source/polynomial/AllPolynomialTraceRoots.dfy", "proof-receipt"),
    ("formal/source/polynomial/controls/PolynomialControls.dfy", "proof-receipt"),
    ("formal/source/polynomial/controls/ControlHarnesses.dfy", "proof-receipt"),
    ("formal/source/polynomial/controls/BranchObservedHarness.dfy", "proof-receipt"),
    ("formal/source/polynomial/controls/IndexObservedHarness.dfy", "proof-receipt"),
    ("formal/source/polynomial/controls/ByMethodControl.dfy", "proof-receipt"),
    ("formal/source/polynomial/controls/LemmaOutControl.dfy", "proof-receipt"),
    ("formal/source/polynomial/checker/PolynomialSourceCoverage.cs", "tool-manifest"),
    ("formal/source/polynomial/checker/PolynomialSourceCoverage.csproj", "tool-manifest"),
    (POLY_SOURCE_BASELINE_TEMPLATE, "input-manifest"),
    (POLY_SOURCE_BASELINE_HELPER, "tool-manifest"),
    (POLY_SOURCE_BASELINE_TEST, "test-source"),
    ("formal/source/SourceTrace.dfy", "proof-receipt"),
    ("formal/source/vocabulary/ObservationVocabulary.dfy", "spec-source"),
    ("formal/crypto/NativeField.dfy", "proof-receipt"),
    ("formal/crypto/NativePolynomial.dfy", "proof-receipt"),
    ("formal/crypto/NativeSampling.dfy", "proof-receipt"),
    ("formal/crypto/NativeMlKem.dfy", "proof-receipt"),
    ("formal/crypto/native_polynomial_domain.dfy", "spec-source"),
)


POLY_SOURCE_LOG_PATHS = (
    'logs/audit-formal-crypto-NativeField.dfy.log',
    'logs/audit-formal-crypto-NativeMlKem.dfy.log',
    'logs/audit-formal-crypto-NativePolynomial.dfy.log',
    'logs/audit-formal-source-SourceTrace.dfy.log',
    'logs/audit-formal-source-polynomial-AllPolynomialTraceRoots.dfy.log',
    'logs/audit-formal-source-polynomial-FieldTraceCompatibility.dfy.log',
    'logs/audit-formal-source-polynomial-NativePolynomialTraceHarness.dfy.log',
    'logs/audit-formal-source-vocabulary-ObservationVocabulary.dfy.log',
    'checker-build/build.log',
    'logs/checker-positive.log',
    'logs/checker-scope-probe-repeated.log',
    'logs/closure-field-compatibility-dependencies-0.log',
    'logs/closure-field-compatibility-dependencies-1.log',
    'logs/closure-field-compatibility-dependencies-2.log',
    'logs/closure-field-compatibility-dependencies-3.log',
    'logs/closure-mlkem-dependencies-0.log',
    'logs/closure-mlkem-dependencies-1.log',
    'logs/closure-mlkem-dependencies-2.log',
    'logs/closure-mlkem-dependencies-3.log',
    'logs/closure-native-field-dependencies-0.log',
    'logs/closure-native-field-dependencies-1.log',
    'logs/closure-native-field-dependencies-2.log',
    'logs/closure-native-polynomial-dependencies-0.log',
    'logs/closure-native-polynomial-dependencies-1.log',
    'logs/closure-native-polynomial-dependencies-2.log',
    'logs/closure-paired-harness-dependencies-0.log',
    'logs/closure-paired-harness-dependencies-1.log',
    'logs/closure-paired-harness-dependencies-2.log',
    'logs/closure-paired-harness-dependencies-3.log',
    'logs/closure-polynomial-domain-dependencies-0.log',
    'logs/closure-polynomial-domain-dependencies-1.log',
    'logs/closure-polynomial-domain-dependencies-2.log',
    'logs/closure-polynomial-domain-dependencies-3.log',
    'logs/closure-roots-dependencies-0.log',
    'logs/closure-roots-dependencies-1.log',
    'logs/closure-roots-dependencies-2.log',
    'logs/closure-roots-dependencies-3.log',
    'logs/controls-BranchObservedHarness.dfy.log',
    'logs/controls-FunctionBranchHarness.dfy.log',
    'logs/controls-FunctionIndexHarness.dfy.log',
    'logs/controls-FunctionUnmarkedHarnesses.dfy.log',
    'logs/controls-IndexObservedHarness.dfy.log',
    'logs/controls-UnmarkedHarnesses.dfy.log',
    'logs/controls/branchfalseprefix-helper-mutation-dafny.log',
    'logs/controls/branchfalseprefix-helper-mutation.log',
    'logs/controls/caller-arg-mutation-dafny.log',
    'logs/controls/caller-arg-mutation.log',
    'logs/controls/canonical-branch-flip-checker.log',
    'logs/controls/canonical-branch-flip-verify.log',
    'logs/controls/canonical-dead-branch-checker.log',
    'logs/controls/canonical-dead-branch-verify.log',
    'logs/controls/canonical-erase-address-checker.log',
    'logs/controls/canonical-erase-address-verify.log',
    'logs/controls/canonical-erase-ops-checker.log',
    'logs/controls/canonical-erase-ops-verify.log',
    'logs/controls/checker-ByMethodProbe-Identity.log',
    'logs/controls/checker-EventReset.log',
    'logs/controls/checker-FunctionControl-PrivateBranchObserved.log',
    'logs/controls/checker-FunctionControl-PrivateBranchReset.log',
    'logs/controls/checker-FunctionControl-PrivateBranchUnmarked.log',
    'logs/controls/checker-FunctionControl-PrivateIndexObserved.log',
    'logs/controls/checker-FunctionControl-PrivateIndexUnmarked.log',
    'logs/controls/checker-Interposed.log',
    'logs/controls/checker-LemmaOutControl.log',
    'logs/controls/checker-RoleShadow.log',
    'logs/controls/checker-SecretBranchObserved.log',
    'logs/controls/checker-SecretBranchUnmarked.log',
    'logs/controls/checker-SecretIndexObserved.log',
    'logs/controls/checker-SecretIndexUnmarked.log',
    'logs/controls/checker-ShadowCallee.log',
    'logs/controls/checker-Unsupported.log',
    'logs/controls/child-ghost-mutation-dafny.log',
    'logs/controls/child-ghost-mutation.log',
    'logs/controls/chunktrace-helper-mutation-dafny.log',
    'logs/controls/chunktrace-helper-mutation.log',
    'logs/controls/decoy-class.log',
    'logs/controls/drop-callee-trace-dafny.log',
    'logs/controls/drop-callee-trace.log',
    'logs/controls/duplicate-projection-dafny.log',
    'logs/controls/duplicate-projection.log',
    'logs/controls/fake-ops-dafny.log',
    'logs/controls/fake-ops.log',
    'logs/controls/ghost-reorder-dafny.log',
    'logs/controls/ghost-reorder.log',
    'logs/controls/leaf-branch-mutation-dafny.log',
    'logs/controls/leaf-branch-mutation.log',
    'logs/controls/missing-false-prefix-dafny.log',
    'logs/controls/missing-false-prefix-original-focused.log',
    'logs/controls/missing-false-prefix.log',
    'logs/controls/real-path-mutation-dafny.log',
    'logs/controls/real-path-mutation.log',
    'logs/controls/rebind-and-model-swap-body.log',
    'logs/controls/rebind-and-model-swap-checker.log',
    'logs/controls/rebind-and-model-swap-generate.log',
    'logs/controls/rebind-and-model-swap-harness.log',
    'logs/controls/rebind-local-dafny.log',
    'logs/controls/rebind-local.log',
    'logs/controls/rebind-same-model-dafny.log',
    'logs/controls/rebind-same-model.log',
    'logs/controls/rebind-suchthat-dafny.log',
    'logs/controls/rebind-suchthat-model-swap-body.log',
    'logs/controls/rebind-suchthat-model-swap-checker.log',
    'logs/controls/rebind-suchthat-model-swap-generate.log',
    'logs/controls/rebind-suchthat-model-swap-harness.log',
    'logs/controls/rebind-suchthat.log',
    'logs/controls/synthetic-callee-dafny.log',
    'logs/controls/synthetic-callee.log',
    'logs/controls/verify-LemmaOutControl.log',
    'logs/controls/wrong-local-dafny.log',
    'logs/controls/wrong-local.log',
    'logs/dafny-version.log',
    'logs/generate-baseline.log',
    'logs/generate-trace.log',
    'logs/javac-21-base.argfile',
    'logs/javac-21-base.log',
    'logs/javac-21-trace.argfile',
    'logs/javac-21-trace.log',
    'logs/javac-25-base.argfile',
    'logs/javac-25-base.log',
    'logs/javac-25-trace.argfile',
    'logs/javac-25-trace.log',
    'logs/verify-checker-controls.log',
    'logs/verify-field-compatibility.log',
    'logs/verify-field.log',
    'logs/verify-mlkem-composition.log',
    'logs/verify-observation-vocabulary.log',
    'logs/verify-paired-harness.log',
    'logs/verify-polynomial.log',
    'logs/verify-source-trace.log',
)

POLY_SOURCE_PROOF_LOGS = {
    'field': 'logs/verify-field.log',
    'polynomial': 'logs/verify-polynomial.log',
    'paired-harness': 'logs/verify-paired-harness.log',
    'mlkem-composition': 'logs/verify-mlkem-composition.log',
    'field-compatibility': 'logs/verify-field-compatibility.log',
    'source-trace': 'logs/verify-source-trace.log',
    'observation-vocabulary': 'logs/verify-observation-vocabulary.log',
    'checker-controls': 'logs/verify-checker-controls.log',
}

POLY_SOURCE_AUDIT_LOGS = {
    'formal/source/vocabulary/ObservationVocabulary.dfy': 'logs/audit-formal-source-vocabulary-ObservationVocabulary.dfy.log',
    'formal/source/SourceTrace.dfy': 'logs/audit-formal-source-SourceTrace.dfy.log',
    'formal/crypto/NativeField.dfy': 'logs/audit-formal-crypto-NativeField.dfy.log',
    'formal/crypto/NativePolynomial.dfy': 'logs/audit-formal-crypto-NativePolynomial.dfy.log',
    'formal/crypto/NativeMlKem.dfy': 'logs/audit-formal-crypto-NativeMlKem.dfy.log',
    'formal/source/polynomial/NativePolynomialTraceHarness.dfy': 'logs/audit-formal-source-polynomial-NativePolynomialTraceHarness.dfy.log',
    'formal/source/polynomial/FieldTraceCompatibility.dfy': 'logs/audit-formal-source-polynomial-FieldTraceCompatibility.dfy.log',
    'formal/source/polynomial/AllPolynomialTraceRoots.dfy': 'logs/audit-formal-source-polynomial-AllPolynomialTraceRoots.dfy.log',
}

POLY_SOURCE_CANONICAL_LOGS = {
    'canonical-branch-flip': ('logs/controls/canonical-branch-flip-checker.log', 'logs/controls/canonical-branch-flip-verify.log'),
    'canonical-erase-address': ('logs/controls/canonical-erase-address-checker.log', 'logs/controls/canonical-erase-address-verify.log'),
    'canonical-erase-ops': ('logs/controls/canonical-erase-ops-checker.log', 'logs/controls/canonical-erase-ops-verify.log'),
    'canonical-dead-branch': ('logs/controls/canonical-dead-branch-checker.log', 'logs/controls/canonical-dead-branch-verify.log'),
}

POLY_SOURCE_MUTATION_LOGS = {
    'leaf-branch-mutation': ('logs/controls/leaf-branch-mutation.log', 'logs/controls/leaf-branch-mutation-dafny.log'),
    'real-path-mutation': ('logs/controls/real-path-mutation.log', 'logs/controls/real-path-mutation-dafny.log'),
    'child-ghost-mutation': ('logs/controls/child-ghost-mutation.log', 'logs/controls/child-ghost-mutation-dafny.log'),
    'caller-arg-mutation': ('logs/controls/caller-arg-mutation.log', 'logs/controls/caller-arg-mutation-dafny.log'),
    'chunktrace-helper-mutation': ('logs/controls/chunktrace-helper-mutation.log', 'logs/controls/chunktrace-helper-mutation-dafny.log'),
    'branchfalseprefix-helper-mutation': ('logs/controls/branchfalseprefix-helper-mutation.log', 'logs/controls/branchfalseprefix-helper-mutation-dafny.log'),
    'missing-false-prefix': ('logs/controls/missing-false-prefix.log', 'logs/controls/missing-false-prefix-dafny.log'),
    'ghost-reorder': ('logs/controls/ghost-reorder.log', 'logs/controls/ghost-reorder-dafny.log'),
    'fake-ops': ('logs/controls/fake-ops.log', 'logs/controls/fake-ops-dafny.log'),
    'synthetic-callee': ('logs/controls/synthetic-callee.log', 'logs/controls/synthetic-callee-dafny.log'),
    'drop-callee-trace': ('logs/controls/drop-callee-trace.log', 'logs/controls/drop-callee-trace-dafny.log'),
    'duplicate-projection': ('logs/controls/duplicate-projection.log', 'logs/controls/duplicate-projection-dafny.log'),
    'wrong-local': ('logs/controls/wrong-local.log', 'logs/controls/wrong-local-dafny.log'),
    'rebind-local': ('logs/controls/rebind-local.log', 'logs/controls/rebind-local-dafny.log'),
    'rebind-same-model': ('logs/controls/rebind-same-model.log', 'logs/controls/rebind-same-model-dafny.log'),
    'rebind-suchthat': ('logs/controls/rebind-suchthat.log', 'logs/controls/rebind-suchthat-dafny.log'),
}

POLY_SOURCE_N1B_LOGS = {
    'rebind-and-model-swap': {'body': 'logs/controls/rebind-and-model-swap-body.log', 'checker': 'logs/controls/rebind-and-model-swap-checker.log', 'harness': 'logs/controls/rebind-and-model-swap-harness.log', 'generate': 'logs/controls/rebind-and-model-swap-generate.log'},
    'rebind-suchthat-model-swap': {'body': 'logs/controls/rebind-suchthat-model-swap-body.log', 'checker': 'logs/controls/rebind-suchthat-model-swap-checker.log', 'harness': 'logs/controls/rebind-suchthat-model-swap-harness.log', 'generate': 'logs/controls/rebind-suchthat-model-swap-generate.log'},
}

POLY_SOURCE_DECOY_LOG = 'logs/controls/decoy-class.log'
POLY_SOURCE_PROBE_LOG = 'logs/checker-scope-probe-repeated.log'
POLY_SOURCE_DEFAULT_CHECKER_LOG = 'logs/checker-positive.log'

POLY_SOURCE_POSITIVE_SCOPES = (
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.SecretBranchObserved"}', ('Control.SecretBranchObserved',), 1, 'logs/controls/checker-SecretBranchObserved.log', 'POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots [Control.SecretBranchObserved]; actual (real,ghost) function tuple paths; ordered flat markers; fail-closed'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.SecretIndexObserved"}', ('Control.SecretIndexObserved',), 1, 'logs/controls/checker-SecretIndexObserved.log', 'POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots [Control.SecretIndexObserved]; actual (real,ghost) function tuple paths; ordered flat markers; fail-closed'),
    ('{"POLY_TRACE_FUNCS": "FunctionControl.PrivateBranchObserved", "POLY_TRACE_ROOTS": null}', ('NativePolynomial.NewZetas', 'NativePolynomial.NewGammas', 'NativePolynomial.Add', 'NativePolynomial.Sub', 'NativePolynomial.Copy', 'NativePolynomial.ForwardStage', 'NativePolynomial.InverseStage', 'NativePolynomial.Scale', 'NativePolynomial.Ntt', 'NativePolynomial.InverseNtt', 'NativePolynomial.BaseCase', 'NativePolynomial.NttMul', 'NativePolynomial.Wipe', 'NativeField.ReduceOnce', 'NativeField.Reduce', 'NativeField.Add', 'NativeField.Sub', 'NativeField.Mul', 'NativeField.MulSub', 'NativeField.AddMul'), 20, 'logs/controls/checker-FunctionControl-PrivateBranchObserved.log', 'POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots [NativePolynomial.NewZetas,NativePolynomial.NewGammas,NativePolynomial.Add,NativePolynomial.Sub,NativePolynomial.Copy,NativePolynomial.ForwardStage,NativePolynomial.InverseStage,NativePolynomial.Scale,NativePolynomial.Ntt,NativePolynomial.InverseNtt,NativePolynomial.BaseCase,NativePolynomial.NttMul,NativePolynomial.Wipe,NativeField.ReduceOnce,NativeField.Reduce,NativeField.Add,NativeField.Sub,NativeField.Mul,NativeField.MulSub,NativeField.AddMul]; actual (real,ghost) function tuple paths; ordered flat markers; fail-closed'),
    ('{"POLY_TRACE_FUNCS": "FunctionControl.PrivateIndexObserved", "POLY_TRACE_ROOTS": null}', ('NativePolynomial.NewZetas', 'NativePolynomial.NewGammas', 'NativePolynomial.Add', 'NativePolynomial.Sub', 'NativePolynomial.Copy', 'NativePolynomial.ForwardStage', 'NativePolynomial.InverseStage', 'NativePolynomial.Scale', 'NativePolynomial.Ntt', 'NativePolynomial.InverseNtt', 'NativePolynomial.BaseCase', 'NativePolynomial.NttMul', 'NativePolynomial.Wipe', 'NativeField.ReduceOnce', 'NativeField.Reduce', 'NativeField.Add', 'NativeField.Sub', 'NativeField.Mul', 'NativeField.MulSub', 'NativeField.AddMul'), 20, 'logs/controls/checker-FunctionControl-PrivateIndexObserved.log', 'POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots [NativePolynomial.NewZetas,NativePolynomial.NewGammas,NativePolynomial.Add,NativePolynomial.Sub,NativePolynomial.Copy,NativePolynomial.ForwardStage,NativePolynomial.InverseStage,NativePolynomial.Scale,NativePolynomial.Ntt,NativePolynomial.InverseNtt,NativePolynomial.BaseCase,NativePolynomial.NttMul,NativePolynomial.Wipe,NativeField.ReduceOnce,NativeField.Reduce,NativeField.Add,NativeField.Sub,NativeField.Mul,NativeField.MulSub,NativeField.AddMul]; actual (real,ghost) function tuple paths; ordered flat markers; fail-closed'),
)

POLY_SOURCE_REJECTIONS = (
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.SecretBranchUnmarked"}', 'missing Branch observation for branch guard', 'logs/controls/checker-SecretBranchUnmarked.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(30,4): Error: missing Branch observation for branch guard'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.SecretIndexUnmarked"}', 'missing Read observation for array read', 'logs/controls/checker-SecretIndexUnmarked.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(48,10): Error: missing Read observation for array read'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.ShadowCallee"}', 'unregistered executable callee Shadow._default.Add', 'logs/controls/checker-ShadowCallee.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(55,9): Error: unregistered executable callee Shadow._default.Add'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.RoleShadow"}', 'mismatched Read observation for array read', 'logs/controls/checker-RoleShadow.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(64,24): Error: mismatched Read observation for array read'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.EventReset"}', 'later trace update must append to the same trace', 'logs/controls/checker-EventReset.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(73,10): Error: EventReset: later trace update must append to the same trace'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.Interposed"}', 'expected exact SourceTrace.Branch for branch guard, found Read', 'logs/controls/checker-Interposed.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(82,40): Error: expected exact SourceTrace.Branch for branch guard, found Read'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "Control.Unsupported"}', 'Ops arg 0=0, source executable count=1', 'logs/controls/checker-Unsupported.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(91,20): Error: Unsupported: Ops arg 0=0, source executable count=1'),
    ('{"POLY_TRACE_FUNCS": "FunctionControl.PrivateBranchUnmarked", "POLY_TRACE_ROOTS": null}', 'arm 0 is missing Branch observation', 'logs/controls/checker-FunctionControl-PrivateBranchUnmarked.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(118,35): Error: PrivateBranchUnmarked: arm 0 is missing Branch observation'),
    ('{"POLY_TRACE_FUNCS": "FunctionControl.PrivateBranchReset", "POLY_TRACE_ROOTS": null}', 'arm 0 is missing Branch observation', 'logs/controls/checker-FunctionControl-PrivateBranchReset.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(126,29): Error: PrivateBranchReset: arm 0 is missing Branch observation'),
    ('{"POLY_TRACE_FUNCS": "FunctionControl.PrivateIndexUnmarked", "POLY_TRACE_ROOTS": null}', 'arm 0 is missing exact Read for array address', 'logs/controls/checker-FunctionControl-PrivateIndexUnmarked.log', 'formal/source/polynomial/controls/PolynomialControls.dfy(143,23): Error: PrivateIndexUnmarked: arm 0 is missing exact Read for array address'),
    ('{"POLY_TRACE_FUNCS": "ByMethodProbe.Identity", "POLY_TRACE_ROOTS": null}', 'function-by-method is unsupported', 'logs/controls/checker-ByMethodProbe-Identity.log', 'formal/source/polynomial/controls/ByMethodControl.dfy(3,11): Error: Identity: function-by-method is unsupported; the actual imperative body is not checked'),
    ('{"POLY_TRACE_FUNCS": null, "POLY_TRACE_ROOTS": "LemmaOutControl.Use"}', 'ghost lemma-out binding is unsupported', 'logs/controls/checker-LemmaOutControl.log', 'formal/source/polynomial/controls/LemmaOutControl.dfy(11,6): Error: Use: ghost lemma-out binding is unsupported'),
)

POLY_SOURCE_DAFNY_NEGATIVES = (
    ('logs/controls-BranchObservedHarness.dfy.log', 'formal/source/polynomial/controls/BranchObservedHarness.dfy(9,11): Error: assertion might not hold', 0, 'assert t1 == t2'),
    ('logs/controls-IndexObservedHarness.dfy.log', 'formal/source/polynomial/controls/IndexObservedHarness.dfy(9,11): Error: assertion might not hold', 1, 'assert t1 == t2'),
    ('logs/controls-FunctionBranchHarness.dfy.log', 'formal/source/polynomial/controls/FunctionBranchHarness.dfy(11,11): Error: assertion might not hold', 0, 'assert t1 == t2'),
    ('logs/controls-FunctionIndexHarness.dfy.log', 'formal/source/polynomial/controls/FunctionIndexHarness.dfy(11,11): Error: assertion might not hold', 1, 'assert t1 == t2'),
)

POLY_SOURCE_GREEN_CHECKS = (
    ('logs/controls-UnmarkedHarnesses.dfy.log', 3),
    ('logs/controls-FunctionUnmarkedHarnesses.dfy.log', 3),
    ('logs/controls/verify-LemmaOutControl.log', 2),
)

POLY_SOURCE_DEFAULT_SELECTOR = 'default (both POLY_TRACE_* cleared)'
POLY_SOURCE_TRACKED_PREFIX = "formal/crypto/evidence/2026-11-04-poly/source/"
POLY_SOURCE_DEFAULT_FIRST_LINE = (
    "POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots ["
    + ",".join(POLY_SOURCE_METHOD_ROOTS)
    + "]; actual (real,ghost) function tuple paths; ordered flat markers; fail-closed")
POLY_SOURCE_POSITIVE_MARKERS = "actual (real,ghost) function tuple paths; ordered flat markers; fail-closed"
POLY_SOURCE_LOG_SUMMARY = re.compile(
    r"Dafny program verifier finished with (\d+) verified, (\d+) errors?"
    r"(?:, (\d+) out of resource)?")
POLY_SOURCE_AUDIT_SUMMARY = re.compile(r"Dafny auditor completed with (\d+) findings")
POLY_SOURCE_DIAGNOSTIC = re.compile(r"\(\d+,\d+\): (?:Error|Warning): ")
POLY_SOURCE_RESOLUTION = re.compile(r"^(\d+) resolution/type errors detected in ", re.M)
POLY_SOURCE_CHECKER_OK = re.compile(
    r"^POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots \[(.*?)\]; "
    + re.escape(POLY_SOURCE_POSITIVE_MARKERS) + r"$", re.M)
POLY_SOURCE_BAD_LOG = re.compile(
    r"timeout|timed out|out of resource|resource limit|resource exhaustion|"
    r"out of memory|OutOfMemory|Unhandled exception|Stack overflow|"
    r"parse error|Parser error|crashed|Segmentation fault", re.IGNORECASE)


REQUIRED_COMPONENT_EVIDENCE = {
    'V0': (
        ('formal/assurance.json', 'component-receipt'),
        ('formal/lean/RecordBounds.lean', 'model-source'),
        ('formal/lean/ResourceBounds.lean', 'model-source'),
        ('formal/lean/CryptoEncoding.lean', 'model-source'),
        ('formal/tla/TrafficKeys.tla', 'model-source'),
        ('formal/tla/TrafficKeys-cap2.cfg', 'model-source'),
        ('formal/tla/TrafficKeys-unsafe-reuse.cfg', 'model-source'),
        ('formal/saw/evidence/report.json', 'bytecode-report'),
        ('formal/saw/evidence/proof.log', 'proof-log'),
        ('formal/packet/inputs.json', 'input-manifest'),
        ('formal/packet/EVIDENCE.md', 'component-receipt'),
        ('formal/primitives/inputs.json', 'input-manifest'),
        ('formal/primitives/EVIDENCE.md', 'component-receipt'),
        ('scripts/security/formal_check.py', 'tool-manifest'),
    ),
    'V4': (
        ('formal/crypto/SHAKE-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/ByteLanes.dfy', 'spec-source'),
        ('formal/crypto/Shake.dfy', 'spec-source'),
        ('formal/crypto/SpongeSpec.dfy', 'spec-source'),
        ('formal/crypto/shake_domain.dfy', 'spec-source'),
        ('formal/primitives/Keccak.dfy', 'proof-receipt'),
        ('formal/crypto/shake_checks.py', 'tool-manifest'),
        ('formal/crypto/shake_java/io/github/mahmoudimus/quic/tls/GeneratedShakeTest.java', 'test-source'),
        ('formal/crypto/delivery.json', 'delivery-receipt'),
        ('formal/crypto/adoption/stage-receipt.json', 'delivery-receipt'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/tls/Shake.java', 'production-source'),
    ),
    'V5': (
        ('formal/crypto/CODEC-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/POLYNOMIAL-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/Codec.dfy', 'spec-source'),
        ('formal/crypto/Sampling.dfy', 'spec-source'),
        ('formal/crypto/Polynomial.dfy', 'spec-source'),
        ('formal/crypto/NativeCodec.dfy', 'proof-receipt'),
        ('formal/crypto/NativeSampling.dfy', 'proof-receipt'),
        ('formal/crypto/NativePolynomial.dfy', 'proof-receipt'),
        ('formal/crypto/NativeField.dfy', 'proof-receipt'),
        ('formal/crypto/native_codec_domain.dfy', 'spec-source'),
        ('formal/crypto/native_polynomial_domain.dfy', 'spec-source'),
        ('formal/primitives/Field.dfy', 'proof-receipt'),
        ('formal/crypto/adoption/stage-receipt.json', 'delivery-receipt'),
    ),
    'V6': (
        ('formal/crypto/KEM-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/NATIVE-KEM-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'component-receipt'),
        ('formal/crypto/MlKem.dfy', 'spec-source'),
        ('formal/crypto/KemSpec.dfy', 'spec-source'),
        ('formal/crypto/NativeMlKem.dfy', 'proof-receipt'),
        ('formal/crypto/native_kem_domain.dfy', 'spec-source'),
        ('formal/crypto/native_kem_hash.java', 'production-source'),
        ('formal/crypto/kem_hash.java', 'production-source'),
        ('formal/crypto/adoption/stage-receipt.json', 'delivery-receipt'),
        ('formal/crypto/adoption/ACCEPTANCE.json', 'snapshot-receipt'),
        ('formal/crypto/adoption/approval.json', 'snapshot-receipt'),
        ('formal/crypto/adoption/final-bundle.json', 'snapshot-receipt'),
        ('formal/crypto/adoption/publication.json', 'snapshot-receipt'),
        ('formal/crypto/delivery.json', 'delivery-receipt'),
        ('formal/crypto/adoption/Shake.java', 'production-source'),
        ('formal/crypto/adoption/MlKem768.java', 'production-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/tls/MlKem768.java', 'production-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/tls/Shake.java', 'production-source'),
    ),
    'V7': (
        ('docs/security-timing-audit.md', 'documentation'),
        ('scripts/security/assess-local-timing.sh', 'tool-manifest'),
        ('formal/packet/EVIDENCE.md', 'component-receipt'),
        ('formal/packet/inputs.json', 'input-manifest'),
        ('formal/packet/README.md', 'documentation'),
        ('formal/packet/TraceMachine.dfy', 'model-source'),
        ('formal/packet/bytecode_guard.py', 'tool-manifest'),
        ('formal/saw/evidence/report.json', 'bytecode-report'),
        ('docs/formal-security.md', 'documentation'),
        ('docs/project/2026-10-28-java-crypto-verification.md', 'documentation'),
    ),
    'V8': (
        ('scripts/security/check_crypto_obligations.py', 'tool-manifest'),
        ('scripts/security/check_crypto_release.py', 'tool-manifest'),
        ('scripts/security/crypto_current_release.py', 'tool-manifest'),
        ('scripts/security/test_crypto_obligations.py', 'test-source'),
        ('scripts/security/test_crypto_current_release.py', 'test-source'),
        ('formal/obligations.md', 'documentation'),
        ('scripts/security/assess-local-timing.sh', 'tool-manifest'),
        ('docs/security-timing-audit.md', 'documentation'),
        ('docs/formal-security.md', 'documentation'),
        ('formal/crypto/adoption/ACCEPTANCE.json', 'snapshot-receipt'),
        ('formal/crypto/adoption/final-bundle.json', 'snapshot-receipt'),
        ('formal/crypto/delivery.json', 'delivery-receipt'),
        ('formal/crypto/adoption/stage-receipt.json', 'delivery-receipt'),
    ),
}

REQUIRED_COMPONENT_CHECKS = {
    'V0': {
        "control_groups": (
            ('saw-scoped-replay', 'formal/saw/evidence/report.json', 'runs'),
        ),
        "receipt_checks": (
            ('formal/assurance.json', ('schema', 'minimum_observations.record', 'minimum_observations.nonce', 'minimum_observations.budget', 'minimum_observations.cache', 'minimum_observations.label')),
            ('formal/saw/evidence/report.json', ('status', 'runs.proof.result', 'runs.wrong_modulus.result', 'runs.wrong_modulus.exit_code', 'runs.vacuous.result', 'runs.nonce.result')),
        ),
        "hash_maps": (
            ('formal/assurance.json', 'java_sources', (), ()),
            ('formal/packet/inputs.json', 'inputs', ('formal/packet/', 'quic/src/'), ()),
            ('formal/primitives/inputs.json', 'inputs', ('formal/primitives/', 'formal/crypto/reference/'), ()),
        ),
        "entry_hash_checks": (
        ),
        "inventory_checks": (
        ),
        "nonvacuity": (
            'formal/saw/evidence/proof.log',
            ('a = 1', 'Proof succeeded'),
        ),
        "text_checks": (
        ),
    },
    'V4': {
        "control_groups": (
            ('shake-semantic-controls', 'formal/crypto/SHAKE-EVIDENCE.json', 'controls'),
        ),
        "receipt_checks": (
            ('formal/crypto/SHAKE-EVIDENCE.json', ('proofs', 'audits', 'generation', 'vectors.count')),
        ),
        "hash_maps": (
            ('formal/crypto/adoption/stage-receipt.json', 'sources', (), ()),
        ),
        "entry_hash_checks": (
        ),
        "inventory_checks": (
        ),
        "nonvacuity": (
            'formal/crypto/shake_domain.dfy',
            ('No message, partition, lane value, or finite output is sampled', 'method AllXofs'),
        ),
        "text_checks": (
        ),
    },
    'V5': {
        "control_groups": (
            ('codec-semantic-controls', 'formal/crypto/CODEC-EVIDENCE.json', 'controls'),
            ('polynomial-semantic-controls', 'formal/crypto/POLYNOMIAL-EVIDENCE.json', 'controls'),
            ('native-codec-semantic-controls', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'controls'),
            ('native-codec-bytecode-controls', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'bytecode_controls'),
            ('native-polynomial-mac-controls', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.controls'),
            ('native-polynomial-linux-controls', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'linux_controls.receipt.controls'),
        ),
        "receipt_checks": (
            ('formal/crypto/CODEC-EVIDENCE.json', ('proofs.proof-Codec', 'proofs.proof-Sampling', 'proofs.codec_domain', 'proofs.sampling_domain')),
            ('formal/crypto/POLYNOMIAL-EVIDENCE.json', ('status', 'phase', 'verified', 'dafny_version', 'solver_version')),
            ('formal/crypto/NATIVE-CODEC-EVIDENCE.json', ('proofs.proof-NativeField', 'proofs.proof-NativeCodec', 'proofs.proof-NativeSampling', 'proofs.native_codec_domain', 'proofs.native_sampling_domain')),
            ('formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', ('status', 'scope', 'unchanged_policy.negative_control_count', 'unchanged_policy.required_semantic_exit', 'mac_full.receipt.status', 'mac_full.receipt.phase', 'mac_full.receipt.dependency_verified', 'mac_full.receipt.native_verified', 'linux_controls.receipt.status', 'linux_controls.receipt.phase')),
        ),
        "hash_maps": (
            ('formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.inputs', (), ()),
            ('formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'inputs', (), ()),
            ('formal/crypto/adoption/stage-receipt.json', 'sources', (), ()),
        ),
        "entry_hash_checks": (
        ),
        "inventory_checks": (
        ),
        "nonvacuity": (
            'formal/crypto/native_codec_domain.dfy',
            ('method TotalDecode', 'method Lossless'),
        ),
        "text_checks": (
        ),
    },
    'V6': {
        "control_groups": (
            ('kem-semantic-controls', 'formal/crypto/KEM-EVIDENCE.json', 'controls'),
            ('native-kem-semantic-controls', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'controls'),
            ('native-kem-bytecode-controls', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'bytecode_controls'),
        ),
        "receipt_checks": (
            ('formal/crypto/KEM-EVIDENCE.json', ('scope', 'proofs.proof-full', 'proofs.generate-java')),
            ('formal/crypto/NATIVE-KEM-EVIDENCE.json', ('scope', 'proofs.proof-native-composition', 'proofs.proof-reference-graph', 'proofs.proof-native-kernels', 'proofs.generate-java', 'native_runtime_guard.payload_scalar_boxings')),
            ('formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', ('status', 'exit', 'verified', 'platform', 'dafny_version', 'max_resource_count', 'max_obligation_seconds')),
            ('formal/crypto/adoption/stage-receipt.json', ('schema', 'status', 'entry', 'generation.status', 'runtime_sha256')),
            ('formal/crypto/adoption/ACCEPTANCE.json', ('schema', 'status', 'quic_jar_sha256', 'all_jar_sha256')),
            ('formal/crypto/adoption/final-bundle.json', ('schema', 'status', 'artifact_sha256', 'canonical_crypto_classes_matched')),
            ('formal/crypto/delivery.json', ('schema', 'runtime.coordinate', 'runtime.sha256', 'dafny.version_string', 'dafny.solver_version_string', 'native_evidence.replay_inventory.assertions', 'native_evidence.replay_inventory.rounds', 'native_evidence.replay_inventory.malformed', 'native_evidence.replay_inventory.selections', 'native_evidence.replay_inventory.destroyed', 'native_evidence.command_exits.dafny-version', 'native_evidence.command_exits.solver-version', 'native_evidence.command_exits.audit', 'native_evidence.command_exits.proof-native-composition', 'native_evidence.command_exits.proof-reference-graph', 'native_evidence.command_exits.proof-native-kernels', 'native_evidence.command_exits.control-wrong-coins', 'native_evidence.command_exits.control-matrix-axis', 'native_evidence.command_exits.control-matrix-transpose', 'native_evidence.command_exits.control-reused-nonce', 'native_evidence.command_exits.control-wrong-fallback-seed', 'native_evidence.command_exits.control-constant-selection', 'native_evidence.command_exits.control-short-comparison', 'native_evidence.command_exits.control-modulus-error-kind', 'native_evidence.command_exits.control-short-sampler', 'native_evidence.command_exits.control-missing-failure-wipe', 'native_evidence.command_exits.control-missing-byte-wipe', 'native_evidence.command_exits.generate-java', 'native_evidence.command_exits.javac', 'native_evidence.command_exits.native-runtime-bytecode', 'native_evidence.command_exits.runtime-helpers-bytecode', 'native_evidence.command_exits.jdk-byte-conversions', 'native_evidence.command_exits.compile-selector-narrow-helper', 'native_evidence.command_exits.inspect-selector-narrow-helper', 'native_evidence.command_exits.compile-selector-payload-branch', 'native_evidence.command_exits.inspect-selector-payload-branch', 'native_evidence.command_exits.compile-selector-payload-boxing', 'native_evidence.command_exits.inspect-selector-payload-boxing', 'native_evidence.command_exits.java-0-version', 'native_evidence.command_exits.java-0-byte-conversions', 'native_evidence.command_exits.java-0', 'native_evidence.command_exits.java-1-version', 'native_evidence.command_exits.java-1-byte-conversions', 'native_evidence.command_exits.java-1')),
        ),
        "hash_maps": (
            ('formal/crypto/NATIVE-KEM-EVIDENCE.json', 'inputs', (), ()),
            ('formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'source_graph', (), ()),
            ('formal/crypto/adoption/stage-receipt.json', 'sources', (), ()),
        ),
        "entry_hash_checks": (
            ('formal/crypto/delivery.json', 'providers', 'source', 'sha256'),
            ('formal/crypto/delivery.json', 'facades', 'destination', 'sha256'),
        ),
        "inventory_checks": (
            {'id': 'native-production-delivery-inventory', 'root': 'quic/src/main/java', 'receipt': 'formal/crypto/adoption/stage-receipt.json', 'delivered_field': 'delivered_sources', 'managed_prefixes': ['io/github/mahmoudimus/quic/internal/verifiedcrypto/'], 'facade_manifest': 'formal/crypto/delivery.json', 'runtime_manifest': 'formal/crypto/delivery.json', 'expected_runtime_sha256': 'dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6'},
        ),
        "nonvacuity": (
            'formal/crypto/native_kem_domain.dfy',
            ('Every finite native byte input', 'no value-dependent public preconditions'),
        ),
        "text_checks": (
        ),
    },
    'V7': {
        "control_groups": (
        ),
        "receipt_checks": (
            ('formal/saw/evidence/report.json', ('runs.nonce.result',)),
        ),
        "hash_maps": (
            ('formal/packet/inputs.json', 'inputs', ('formal/packet/', 'quic/src/'), ()),
        ),
        "entry_hash_checks": (
        ),
        "inventory_checks": (
        ),
        "nonvacuity": (
        ),
        "text_checks": (
        ),
    },
    'V8': {
        "control_groups": (
        ),
        "receipt_checks": (
        ),
        "hash_maps": (
        ),
        "entry_hash_checks": (
        ),
        "inventory_checks": (
        ),
        "nonvacuity": (
        ),
        "text_checks": (
            ('docs/security-timing-audit.md', ('statistical pass/fail threshold', 'JVM timing remains unproved')),
        ),
    },
}

REQUIRED_CONTROL_INVENTORY = {
    'saw-scoped-replay': ('proof', 'wrong_modulus', 'vacuous', 'nonce'),
    'shake-semantic-controls': ('padding-suffix', 'padding-final-bit', 'padding-shared-octet', 'zero-read-phase', 'input-after-output', 'absorb-boundary', 'squeeze-boundary', 'absorb-byte-order', 'squeeze-byte-order', 'domain-rates', 'domain-states', 'domain-slices', 'domain-output-lengths', 'domain-input-lengths'),
    'codec-semantic-controls': ('compress-rounding', 'decompress-half-tie', 'encode-bit', 'decode-modulus', 'cbd-sign', 'feed-order', 'feed-reject-q', 'feed-cap', 'feed-consumption', 'full-domain'),
    'polynomial-semantic-controls': ('root', 'sign', 'index', 'product', 'wrap', 'scale'),
    'native-codec-semantic-controls': ('compress-rounding', 'decompress-half-tie', 'encode-bit', 'native-int-overflow', 'decode-modulus', 'wipe', 'cbd-sign', 'feed-order', 'feed-reject-q', 'feed-cap', 'feed-consumption', 'extract-shift', 'extract-mask', 'compress-reciprocal', 'full-domain'),
    'native-codec-bytecode-controls': ('payload-idiv', 'payload-euclidean', 'payload-metadata', 'payload-array-length', 'payload-runtime-array-length', 'payload-array-feed', 'payload-reference-array', 'payload-runtime-dimensions'),
    'native-polynomial-mac-controls': ('reduce', 'correction-shift', 'barrett-shift', 'mask', 'reciprocal', 'sign', 'index', 'inverse', 'product', 'root', 'wipe', 'positive-dividend', 'scale', 'freshness'),
    'native-polynomial-linux-controls': ('reduce', 'correction-shift', 'barrett-shift', 'mask', 'reciprocal', 'sign', 'index', 'inverse', 'product', 'root', 'wipe', 'positive-dividend', 'scale', 'freshness'),
    'kem-semantic-controls': ('wrong-coins', 'matrix-axis', 'matrix-transpose', 'reused-nonce', 'wrong-fallback-seed', 'constant-selection', 'short-comparison', 'modulus-error-kind', 'short-sampler'),
    'native-kem-semantic-controls': ('wrong-coins', 'matrix-axis', 'matrix-transpose', 'reused-nonce', 'wrong-fallback-seed', 'constant-selection', 'short-comparison', 'modulus-error-kind', 'short-sampler', 'missing-failure-wipe', 'missing-byte-wipe'),
    'native-kem-bytecode-controls': ('selector-narrow-helper', 'selector-payload-branch', 'selector-payload-boxing'),
}

REQUIRED_CONTROL_FIELDS = {
    'saw-scoped-replay': ('exit_code', 'result'),
    'shake-semantic-controls': ('errors', 'verified'),
    'codec-semantic-controls': ('errors', 'verified'),
    'polynomial-semantic-controls': ('result',),
    'native-codec-semantic-controls': ('errors', 'verified'),
    'native-codec-bytecode-controls': ('rejected',),
    'native-polynomial-mac-controls': ('result',),
    'native-polynomial-linux-controls': ('result',),
    'kem-semantic-controls': ('errors', 'verified'),
    'native-kem-semantic-controls': ('errors', 'verified'),
    'native-kem-bytecode-controls': ('rejected',),
}

# The failure-bearing field required for each named control group.  A group may
# also pin successful fields (for example the SAW positive proof), but each
# mandatory group must contain at least one genuine failure/counterexample label.
REQUIRED_CONTROL_FAILURE_FIELDS = {
    "saw-scoped-replay": "result",
    "shake-semantic-controls": "errors",
    "codec-semantic-controls": "errors",
    "polynomial-semantic-controls": "result",
    "native-codec-semantic-controls": "errors",
    "native-codec-bytecode-controls": "rejected",
    "native-polynomial-mac-controls": "result",
    "native-polynomial-linux-controls": "result",
    "kem-semantic-controls": "errors",
    "native-kem-semantic-controls": "errors",
    "native-kem-bytecode-controls": "rejected",
}

HKDF_COMPONENT_EVIDENCE = {
    'V1': (
        ('formal/dafny/PRODUCTION-EVIDENCE.json', 'component-receipt'),
        ('formal/dafny/inputs.json', 'input-manifest'),
        ('formal/dafny/hkdf/GENERATED.json', 'delivery-receipt'),
        ('formal/dafny/hkdf/Hkdf.dfy', 'spec-source'),
        ('formal/dafny/deliver_hkdf.py', 'tool-manifest'),
        ('formal/dafny/run.py', 'tool-manifest'),
        ('formal/dafny/test_run.py', 'test-source'),
        ('formal/dafny/tools.json', 'tool-manifest'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'test-source'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'test-source'),
        ('formal/reference/aws-hkdf/TARGET-RECEIPT.json', 'component-receipt'),
        ('formal/reference/aws-hkdf/CLOSURE-RECEIPT.json', 'upstream-closure-receipt'),
        ('formal/reference/aws-hkdf/EXECUTION-INPUTS.json', 'input-manifest'),
        ('formal/reference/aws-hkdf/inputs.json', 'input-manifest'),
        ('formal/reference/aws-hkdf/README.md', 'documentation'),
        ('formal/dafny/NOTICE', 'documentation'),
    ),
    'V2': (
        ('formal/dafny/PRODUCTION-EVIDENCE.json', 'component-receipt'),
        ('formal/dafny/inputs.json', 'input-manifest'),
        ('formal/dafny/hkdf/GENERATED.json', 'delivery-receipt'),
        ('formal/dafny/hkdf/Hkdf.dfy', 'spec-source'),
        ('formal/dafny/deliver_hkdf.py', 'tool-manifest'),
        ('formal/dafny/run.py', 'tool-manifest'),
        ('formal/dafny/test_run.py', 'test-source'),
        ('formal/dafny/tools.json', 'tool-manifest'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'test-source'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'test-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'generated-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'production-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'production-source'),
        ('quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java', 'production-source'),
        ('quic/src/test/java/io/github/mahmoudimus/quic/HkdfGeneratedAdoptionTest.java', 'test-source'),
        ('quic/src/test/java/io/github/mahmoudimus/quic/HkdfTest.java', 'test-source'),
        ('formal/crypto/delivery.json', 'delivery-receipt'),
    ),
}

HKDF_COMPONENT_CHECKS = {
    'V1': {
        'control_groups': (),
        'receipt_checks': (('formal/dafny/PRODUCTION-EVIDENCE.json', ('status', 'verified', 'public_domain_verified', 'controls', 'assumptions', 'dafny_version', 'tool_asset', 'translation_metadata_sha256', 'top_level_aggregator_sha256')), ('formal/dafny/hkdf/GENERATED.json', ('schema', 'verified', 'outer_module', 'output_name', 'module', 'aggregator_sha256', 'translation_metadata_sha256')), ('formal/reference/aws-hkdf/TARGET-RECEIPT.json', ('status', 'scope', 'full_dependency_graph_verified', 'manifest_sha256', 'dafny_sha256', 'tool_identity.version')), ('formal/reference/aws-hkdf/CLOSURE-RECEIPT.json', ('status', 'scope', 'full_dependency_graph_verified', 'exit_code', 'manifest_sha256', 'execution_manifest', 'dafny_sha256')), ('formal/reference/aws-hkdf/EXECUTION-INPUTS.json', ('schema', 'repository', 'commit', 'entry', 'submodules', 'dafny_version')), ('formal/reference/aws-hkdf/inputs.json', ('schema', 'commit', 'entry', 'dafny_version', 'dafny_build', 'closure_verified_minimum', 'tool_inputs'))),
        'hash_maps': (('formal/dafny/inputs.json', 'inputs', (), (), ''), ('formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs', (), (), ''), ('formal/reference/aws-hkdf/inputs.json', 'tool_inputs', (), (), '')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': ({'id': 'hkdf-generated-source-inventory', 'root': 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf', 'receipt': 'formal/dafny/hkdf/GENERATED.json', 'field': 'source'},),
        'nonvacuity': ('formal/dafny/PRODUCTION-EVIDENCE.json', ('public_domain_verified', 'proof-obligation-rejected')),
        'text_checks': (),
    },
    'V2': {
        'control_groups': (),
        'receipt_checks': (('formal/dafny/PRODUCTION-EVIDENCE.json', ('status', 'verified', 'public_domain_verified', 'production_test_note', 'not_proved', 'controls', 'assumptions', 'delivered_generated_java', 'top_level_aggregator_sha256', 'translation_metadata_sha256')), ('formal/dafny/hkdf/GENERATED.json', ('schema', 'verified', 'source', 'classes')), ('formal/crypto/delivery.json', ('existing_generated_dependencies',))),
        'hash_maps': (('formal/dafny/inputs.json', 'inputs', (), (), ''), ('formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs', (), (), ''), ('formal/crypto/delivery.json', 'existing_generated_sources', ('io/github/mahmoudimus/quic/internal/verifiedhkdf/',), (), 'quic/src/main/java'), ('formal/crypto/delivery.json', 'existing_generated_dependencies', (), (), 'quic/src/main/java')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': ({'id': 'hkdf-generated-source-inventory', 'root': 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf', 'receipt': 'formal/dafny/hkdf/GENERATED.json', 'field': 'source'},),
        'nonvacuity': ('formal/dafny/PRODUCTION-EVIDENCE.json', ('public_domain_verified', 'proof-obligation-rejected')),
        'text_checks': (('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', ('io.github.mahmoudimus.verifiedcrypto.JdkHmac', 'compute')), ('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', ('class HkdfBridge',)), ('quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', ('HkdfBridge',)), ('quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java', ('javax.crypto.Mac', 'HmacSHA256'))),
    },
}
REQUIRED_COMPONENT_EVIDENCE.update(HKDF_COMPONENT_EVIDENCE)
REQUIRED_COMPONENT_CHECKS.update(HKDF_COMPONENT_CHECKS)

REQUIRED_COMPONENT_EVIDENCE.update({
    'V0': (
        ('formal/assurance.json', 'component-receipt'),
        ('formal/lean/RecordBounds.lean', 'model-source'),
        ('formal/lean/ResourceBounds.lean', 'model-source'),
        ('formal/lean/CryptoEncoding.lean', 'model-source'),
        ('formal/tla/TrafficKeys.tla', 'model-source'),
        ('formal/tla/TrafficKeys-cap2.cfg', 'model-source'),
        ('formal/tla/TrafficKeys-unsafe-reuse.cfg', 'model-source'),
        ('formal/saw/evidence/report.json', 'bytecode-report'),
        ('formal/saw/evidence/proof.log', 'proof-log'),
        ('formal/packet/inputs.json', 'input-manifest'),
        ('formal/packet/EVIDENCE.md', 'component-receipt'),
        ('formal/primitives/inputs.json', 'input-manifest'),
        ('formal/primitives/EVIDENCE.md', 'component-receipt'),
        ('scripts/security/formal_check.py', 'tool-manifest'),
        ('scripts/security/test_crypto_obligations.py', 'test-source'),
    ),
    'V1': (
        ('formal/dafny/PRODUCTION-EVIDENCE.json', 'component-receipt'),
        ('formal/dafny/inputs.json', 'input-manifest'),
        ('formal/dafny/hkdf/GENERATED.json', 'delivery-receipt'),
        ('formal/dafny/hkdf/Hkdf.dfy', 'spec-source'),
        ('formal/dafny/deliver_hkdf.py', 'tool-manifest'),
        ('formal/dafny/run.py', 'tool-manifest'),
        ('formal/dafny/test_run.py', 'test-source'),
        ('formal/dafny/check_adapter_discipline.py', 'tool-manifest'),
        ('formal/dafny/java/dafny/BulkOnlySequence.java', 'generated-source'),
        ('formal/dafny/tools.json', 'tool-manifest'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'test-source'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'test-source'),
        ('formal/reference/aws-hkdf/TARGET-RECEIPT.json', 'component-receipt'),
        ('formal/reference/aws-hkdf/CLOSURE-RECEIPT.json', 'upstream-closure-receipt'),
        ('formal/reference/aws-hkdf/EXECUTION-INPUTS.json', 'input-manifest'),
        ('formal/reference/aws-hkdf/inputs.json', 'input-manifest'),
        ('formal/reference/aws-hkdf/README.md', 'documentation'),
        ('formal/dafny/NOTICE', 'documentation'),
    ),
    'V2': (
        ('formal/dafny/PRODUCTION-EVIDENCE.json', 'component-receipt'),
        ('formal/dafny/inputs.json', 'input-manifest'),
        ('formal/dafny/hkdf/GENERATED.json', 'delivery-receipt'),
        ('formal/dafny/hkdf/Hkdf.dfy', 'spec-source'),
        ('formal/dafny/deliver_hkdf.py', 'tool-manifest'),
        ('formal/dafny/run.py', 'tool-manifest'),
        ('formal/dafny/test_run.py', 'test-source'),
        ('formal/dafny/check_adapter_discipline.py', 'tool-manifest'),
        ('formal/dafny/java/dafny/BulkOnlySequence.java', 'generated-source'),
        ('formal/dafny/tools.json', 'tool-manifest'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'test-source'),
        ('formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'test-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'generated-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'production-source'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'production-source'),
        ('quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java', 'production-source'),
        ('quic/src/test/java/io/github/mahmoudimus/quic/HkdfGeneratedAdoptionTest.java', 'test-source'),
        ('quic/src/test/java/io/github/mahmoudimus/quic/HkdfTest.java', 'test-source'),
        ('formal/crypto/delivery.json', 'delivery-receipt'),
    ),
    'V3': (
        ('formal/saw/inputs.json', 'input-manifest'),
        ('formal/saw/evidence/report.json', 'bytecode-report'),
        ('formal/saw/evidence/proof.log', 'proof-log'),
        ('formal/saw/evidence/wrong_modulus.log', 'proof-log'),
        ('formal/saw/evidence/vacuous.log', 'proof-log'),
        ('formal/saw/evidence/nonce.log', 'proof-log'),
        ('formal/saw/README.md', 'documentation'),
        ('formal/saw/run.py', 'tool-manifest'),
        ('formal/saw/historical/README.md', 'documentation'),
        ('formal/saw/historical/quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java', 'snapshot-receipt'),
        ('formal/saw/mlkem-reduce-once.saw', 'spec-source'),
        ('formal/saw/blocked/packet-key-nonce.saw', 'spec-source'),
        ('formal/crypto/reference/MlKem768.java', 'spec-source'),
        ('formal/crypto/reference/provenance.json', 'documentation'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java', 'production-source'),
        ('formal/nonce/Nonce.dfy', 'spec-source'),
        ('formal/nonce/NonceDomain.dfy', 'spec-source'),
        ('formal/nonce/run.py', 'tool-manifest'),
        ('formal/nonce/test_run.py', 'test-source'),
        ('formal/nonce/tools.json', 'tool-manifest'),
        ('formal/nonce/inputs.json', 'input-manifest'),
        ('formal/nonce/GENERATED.json', 'generated-source'),
        ('formal/nonce/PRODUCTION-EVIDENCE.json', 'component-receipt'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce/__default.java', 'generated-source'),
        ('quic/src/test/java/io/github/mahmoudimus/quic/crypto/PacketKeyNonceTest.java', 'test-source'),
        ('formal/nonce/BundleNonceSmoke.java', 'test-source'),
        ('formal/nonce/bench/NonceBenchmark.java', 'test-source'),
        ('formal/nonce/bench_nonce.py', 'tool-manifest'),
        ('formal/nonce/java/io/github/mahmoudimus/nonce/GeneratedNonceTest.java', 'test-source'),
        ('formal/nonce/java/io/github/mahmoudimus/nonce/ReferenceNonce.java', 'test-source'),
        ('formal/dafny/toolchain.py', 'tool-manifest'),
        ('formal/dafny/tools.json', 'tool-manifest'),
        ('formal/crypto/delivery.json', 'delivery-receipt'),
        ('formal/crypto/bundle_checks.py', 'tool-manifest'),
        ('scripts/security/crypto_current_release.py', 'tool-manifest'),
    ),
})
REQUIRED_COMPONENT_CHECKS.update({
    'V0': {
        'control_groups': (('saw-scoped-replay', 'formal/saw/evidence/report.json', 'runs'),),
        'receipt_checks': (('formal/assurance.json', ('schema', 'minimum_observations.record', 'minimum_observations.nonce', 'minimum_observations.budget', 'minimum_observations.cache', 'minimum_observations.label')), ('formal/saw/evidence/report.json', ('status', 'runs.proof.result', 'runs.wrong_modulus.result', 'runs.wrong_modulus.exit_code', 'runs.vacuous.result', 'runs.nonce.result'))),
        'hash_maps': (('formal/assurance.json', 'java_sources', (), (), ''), ('formal/packet/inputs.json', 'inputs', ('formal/packet/', 'quic/src/'), (), ''), ('formal/primitives/inputs.json', 'inputs', ('formal/primitives/', 'formal/crypto/reference/'), (), '')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': (),
        'nonvacuity': ('scripts/security/test_crypto_obligations.py', ('test_v0_finite_fixture_cannot_be_relabelled_as_production_claim', 'test_dependency_cycle_fails')),
        'text_checks': (),
    },
    'V1': {
        'control_groups': (),
        'receipt_checks': (('formal/dafny/PRODUCTION-EVIDENCE.json', ('status', 'verified', 'public_domain_verified', 'controls', 'java_runs', 'adapter_discipline', 'assumptions', 'dafny_version', 'tool_asset', 'translation_metadata_sha256', 'top_level_aggregator_sha256')), ('formal/dafny/hkdf/GENERATED.json', ('schema', 'verified', 'outer_module', 'output_name', 'module', 'aggregator_sha256', 'translation_metadata_sha256')), ('formal/reference/aws-hkdf/TARGET-RECEIPT.json', ('status', 'scope', 'full_dependency_graph_verified', 'manifest_sha256', 'dafny_sha256', 'tool_identity.version')), ('formal/reference/aws-hkdf/CLOSURE-RECEIPT.json', ('status', 'scope', 'full_dependency_graph_verified', 'exit_code', 'manifest_sha256', 'execution_manifest', 'dafny_sha256')), ('formal/reference/aws-hkdf/EXECUTION-INPUTS.json', ('schema', 'repository', 'commit', 'entry', 'submodules', 'dafny_version')), ('formal/reference/aws-hkdf/inputs.json', ('schema', 'commit', 'entry', 'dafny_version', 'dafny_build', 'closure_verified_minimum', 'tool_inputs'))),
        'hash_maps': (('formal/dafny/inputs.json', 'inputs', (), (), ''), ('formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs', (), (), ''), ('formal/reference/aws-hkdf/inputs.json', 'tool_inputs', (), (), '')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': ({'id': 'hkdf-generated-source-inventory', 'root': 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf', 'receipt': 'formal/dafny/hkdf/GENERATED.json', 'field': 'source'},),
        'nonvacuity': ('formal/dafny/PRODUCTION-EVIDENCE.json', ('public_domain_verified', 'proof-obligation-rejected')),
        'text_checks': (),
    },
    'V2': {
        'control_groups': (),
        'receipt_checks': (('formal/dafny/PRODUCTION-EVIDENCE.json', ('status', 'verified', 'public_domain_verified', 'production_test_note', 'not_proved', 'controls', 'java_runs', 'adapter_discipline', 'assumptions', 'delivered_generated_java', 'top_level_aggregator_sha256', 'translation_metadata_sha256')), ('formal/dafny/hkdf/GENERATED.json', ('schema', 'verified', 'source', 'classes')), ('formal/crypto/delivery.json', ('existing_generated_dependencies',))),
        'hash_maps': (('formal/dafny/inputs.json', 'inputs', (), (), ''), ('formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs', (), (), ''), ('formal/crypto/delivery.json', 'existing_generated_sources', ('io/github/mahmoudimus/quic/internal/verifiedhkdf/',), (), 'quic/src/main/java'), ('formal/crypto/delivery.json', 'existing_generated_dependencies', (), (), 'quic/src/main/java')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': ({'id': 'hkdf-generated-source-inventory', 'root': 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf', 'receipt': 'formal/dafny/hkdf/GENERATED.json', 'field': 'source'},),
        'nonvacuity': ('formal/dafny/PRODUCTION-EVIDENCE.json', ('public_domain_verified', 'proof-obligation-rejected')),
        'text_checks': (('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', ('io.github.mahmoudimus.verifiedcrypto.JdkHmac', 'compute')), ('quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', ('class HkdfBridge',)), ('quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', ('HkdfBridge',)), ('quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java', ('javax.crypto.Mac', 'HmacSHA256'))),
    },
    'V3': {
        'control_groups': (('saw-scoped-replay', 'formal/saw/evidence/report.json', 'runs'),),
        'receipt_checks': (('formal/saw/evidence/report.json', ('status', 'runs.proof.result', 'runs.wrong_modulus.result', 'runs.vacuous.result', 'runs.nonce.result')),),
        'hash_maps': (('formal/saw/inputs.json', 'inputs', ('formal/',), (), ''), ('formal/saw/inputs.json', 'inputs', ('quic/src/',), (), 'formal/saw/historical')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': (),
        'nonvacuity': ('formal/saw/evidence/proof.log', ('a = 1', 'Proof succeeded')),
        'text_checks': (),
    },
})
REQUIRED_HASH_MAP_KEYS = {
    ('V0', 'formal/assurance.json', 'java_sources', (), ''): ('microproxy/src/main/java/org/microproxy/dns/BoundedExpiringCache.java', 'microproxy/src/main/java/org/microproxy/dns/DnssecHostResolver.java', 'microproxy/src/main/java/org/microproxy/dns/DnssecValidator.java', 'microproxy/src/test/java/org/microproxy/dns/FormalResourceModelTest.java', 'quic/src/main/java/io/github/mahmoudimus/quic/CipherSuite.java', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/tls/Tls12CipherSuite.java', 'quic/src/main/java/io/github/mahmoudimus/quic/tls/TlsClientConnection.java', 'quic/src/main/java/io/github/mahmoudimus/quic/tls/TlsRecordLayer.java', 'quic/src/test/java/io/github/mahmoudimus/quic/FormalCryptoModelTest.java', 'quic/src/test/java/io/github/mahmoudimus/quic/tls/FormalRecordModelTest.java', 'quic/src/test/java/io/github/mahmoudimus/quic/tls/TlsKeyUsageTest.java'),
    ('V0', 'formal/packet/inputs.json', 'inputs', ('formal/packet/', 'quic/src/'), ''): ('formal/packet/PacketKernel.dfy', 'formal/packet/TraceMachine.dfy', 'formal/packet/bytecode_guard.py', 'formal/packet/lowering.py', 'formal/packet/run.py', 'formal/packet/test_bytecode.py', 'formal/packet/test_io.py', 'formal/packet/test_lowering.py', 'formal/packet/test_replay.py', 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/HeaderKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verified/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/PacketNumber.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/ProtectedPacket.java', 'quic/src/test/java/io/github/mahmoudimus/quic/packet/HeaderProtectionTimingTest.java'),
    ('V0', 'formal/primitives/inputs.json', 'inputs', ('formal/primitives/', 'formal/crypto/reference/'), ''): ('formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy', 'formal/primitives/java/io/github/mahmoudimus/quic/tls/GeneratedPrimitivesTest.java', 'formal/primitives/run.py', 'formal/primitives/test_run.py'),
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs', (), ''): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V1', 'formal/dafny/inputs.json', 'inputs', (), ''): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V1', 'formal/reference/aws-hkdf/inputs.json', 'tool_inputs', (), ''): ('formal/dafny/toolchain.py', 'formal/dafny/tools.json'),
    ('V2', 'formal/crypto/delivery.json', 'existing_generated_dependencies', (), 'quic/src/main/java'): ('io/github/mahmoudimus/verifiedcrypto/JdkHmac.java',),
    ('V2', 'formal/crypto/delivery.json', 'existing_generated_sources', ('io/github/mahmoudimus/quic/internal/verifiedhkdf/',), 'quic/src/main/java'): ('io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java'),
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs', (), ''): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V2', 'formal/dafny/inputs.json', 'inputs', (), ''): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V3', 'formal/saw/inputs.json', 'inputs', ('formal/',), ''): ('formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/provenance.json'),
    ('V3', 'formal/saw/inputs.json', 'inputs', ('quic/src/',), 'formal/saw/historical'): ('quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java',),
    ('V4', 'formal/crypto/adoption/stage-receipt.json', 'sources', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy', 'formal/source/SourceTrace.dfy', 'formal/source/vocabulary/ObservationVocabulary.dfy'),
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.inputs', (), ''): ('formal/crypto/NativeField.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/native_polynomial_checks.py', 'formal/crypto/native_polynomial_domain.dfy', 'formal/crypto/native_polynomial_test.java', 'formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy', 'formal/source/SourceTrace.dfy', 'formal/source/vocabulary/ObservationVocabulary.dfy'),
    ('V5', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'inputs', (), ''): ('formal/crypto/NativeTypes.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/Codec.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/native_codec_domain.dfy', 'formal/crypto/native_sampling_domain.dfy', 'formal/crypto/native_codec_checks.py', 'formal/crypto/native_codec_test.java', 'formal/primitives/Field.dfy', 'formal/crypto/reference/provenance.json', 'formal/source/SourceTrace.dfy', 'formal/source/vocabulary/ObservationVocabulary.dfy', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/MlKem768.java'),
    ('V5', 'formal/crypto/adoption/stage-receipt.json', 'sources', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy', 'formal/source/SourceTrace.dfy', 'formal/source/vocabulary/ObservationVocabulary.dfy'),
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'inputs', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/native_kem_checks.py', 'formal/crypto/native_kem_domain.dfy', 'formal/crypto/native_kem_hash.java', 'formal/crypto/native_kem_test.java', 'formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy', 'formal/source/SourceTrace.dfy', 'formal/source/vocabulary/ObservationVocabulary.dfy'),
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'source_graph', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/native_kem_domain.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy', 'formal/source/SourceTrace.dfy', 'formal/source/vocabulary/ObservationVocabulary.dfy'),
    ('V6', 'formal/crypto/adoption/stage-receipt.json', 'sources', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy', 'formal/source/SourceTrace.dfy', 'formal/source/vocabulary/ObservationVocabulary.dfy'),
    ('V7', 'formal/packet/inputs.json', 'inputs', ('formal/packet/', 'quic/src/'), ''): ('formal/packet/PacketKernel.dfy', 'formal/packet/TraceMachine.dfy', 'formal/packet/bytecode_guard.py', 'formal/packet/lowering.py', 'formal/packet/run.py', 'formal/packet/test_bytecode.py', 'formal/packet/test_io.py', 'formal/packet/test_lowering.py', 'formal/packet/test_replay.py', 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/HeaderKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verified/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/PacketNumber.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/ProtectedPacket.java', 'quic/src/test/java/io/github/mahmoudimus/quic/packet/HeaderProtectionTimingTest.java'),
    ('V7', 'formal/timing/inputs.json', 'inputs', (), ''): ('formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'formal/timing/HkdfShape.dfy', 'formal/timing/PositiveTraceCheck.dfy', 'formal/timing/README.md', 'formal/timing/SecretTrace.dfy', 'formal/timing/bytecode_trace.py', 'formal/timing/fixtures/CategoryTwo.java', 'formal/timing/fixtures/ClassOracle.java', 'formal/timing/fixtures/ConstantTime.java', 'formal/timing/fixtures/EarlyCompare.java', 'formal/timing/fixtures/ExceptionOracle.java', 'formal/timing/fixtures/FieldAlias.java', 'formal/timing/fixtures/NewIdentity.java', 'formal/timing/fixtures/ResultArrayCall.java', 'formal/timing/fixtures/SecretAlloc.java', 'formal/timing/fixtures/SecretBranch.java', 'formal/timing/fixtures/SecretDigestBranch.java', 'formal/timing/fixtures/SecretIndex.java', 'formal/timing/fixtures/SecretLoopBound.java', 'formal/timing/fixtures/VirtualDispatch.java', 'formal/timing/policy.json', 'formal/timing/run.py', 'formal/timing/test_trace.py', 'formal/timing/test_exception_table.py', 'formal/timing/threat-model.md', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_Decoded.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidWidth.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Encapsulation.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidCiphertextLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidKeyLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidMessageLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidSeedLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_RejectionLimit.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/PublicKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/SecretKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_Decoded.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidWidth.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/Encapsulation.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/PublicKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativePolynomial/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_Full.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidBlockLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidPrefix.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_NeedMore.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/Sponge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/L.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolySpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/Residue.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_Full.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidBlockLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidPrefix.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_NeedMore.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/ReadResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/State.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InputAfterOutput.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InvalidSlice.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_Updated.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedCodec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedField/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedKeccak/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedPolynomial/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedSampling/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedShake/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/kem_hash.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/native_kem_hash.java', 'formal/timing/execution_controls.py', 'formal/timing/test_coverage.py'),
}
REQUIRED_FILE_SET_KEYS = {
    ('V1', 'hkdf-generated-source-inventory'): ('BytesResult.java', 'BytesResult_Failure.java', 'BytesResult_Success.java', 'FailureKind.java', 'FailureKind_InvalidHash.java', 'FailureKind_InvalidKey.java', 'FailureKind_InvalidLabel.java', 'FailureKind_InvalidLength.java', '__default.java'),
    ('V2', 'hkdf-generated-source-inventory'): ('BytesResult.java', 'BytesResult_Failure.java', 'BytesResult_Success.java', 'FailureKind.java', 'FailureKind_InvalidHash.java', 'FailureKind_InvalidKey.java', 'FailureKind_InvalidLabel.java', 'FailureKind_InvalidLength.java', '__default.java'),
}
REQUIRED_INVENTORY_KEYS = {
    ('V6', 'native-production-delivery-inventory'): ('io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_Decoded.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidWidth.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_ModulusError.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Encapsulation.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidCiphertextLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidKeyLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidMessageLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidSeedLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_ModulusError.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_RejectionLimit.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/PublicKey.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Failure.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Success.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/SecretKey.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_Decoded.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidWidth.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_ModulusError.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/Encapsulation.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/PublicKey.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativePolynomial/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_Full.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidBlockLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidPrefix.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_NeedMore.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/Sponge.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/L.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/PolySpec/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/Residue.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_Full.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidBlockLength.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidPrefix.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_NeedMore.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/ReadResult.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/State.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InputAfterOutput.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InvalidSlice.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_Updated.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedCodec/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedField/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedKeccak/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedPolynomial/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedSampling/__default.java', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedShake/__default.java', 'io/github/mahmoudimus/verifiedcrypto/kem_hash.java', 'io/github/mahmoudimus/verifiedcrypto/native_kem_hash.java'),
}
REQUIRED_RECEIPT_EXACT = {
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'controls'): {'counter': 'proof-obligation-rejected', 'feedback': 'proof-obligation-rejected', 'truncation': 'proof-obligation-rejected', 'prefix': 'proof-obligation-rejected', 'public-domain': 'proof-obligation-rejected', 'extra-assumption': 'audit-rejected', 'skipped-proof': 'audit-rejected', 'adapter-select-loop': 'bytecode-rejected', 'adapter-bare-cast': 'bytecode-rejected', 'adapter-dead-decoy': 'bytecode-rejected'},
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'java_runs'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)', 'tests': 'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: HmacSHA256=SunJCE, HmacSHA384=SunJCE, HmacSHA512=SunJCE', 'executable_sha256': 'd7ab2ea6a7e731a8a2cee7d722046c9f7d8c5f184cd769b9954a392592337770'}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)', 'tests': 'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: HmacSHA256=SunJCE, HmacSHA384=SunJCE, HmacSHA512=SunJCE', 'executable_sha256': 'd6b5c8ffce485baa7e9aacfd9c652e2999c89053a5070104c598731636bd2249'}],
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'assumptions'): ['VerifiedHkdf.Mac: deterministic external HMAC with fixed output length'],
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'adapter_discipline'): 'JdkHmac.bytes has a guarded toRawArray/instanceof [B/branch/checkcast/areturn shape; HkdfBridge delegates; select/Byte rejected',
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'verified'): 248,
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'public_domain_verified'): 249,
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'generated_java'): {'HkdfCrypto.java': 'c23818b14294d7a4da21e329a4fa1a67148549537aac5d07a3f9198bc71955ba', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'delivered_generated_java'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'source'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'classes'): {'io/github/mahmoudimus/quic/Hkdf.class': 'b096db75e610d1a8aec5e6f85e615557b17be6673d353e92add4611b42d65b6e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.class': '4a1d2f0aeef211e31bc8f204ea455bd0a5ee0d43a56c1ebfb5baea4d8ea847ef', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.class': '0e10e3dc75b944c5bf1b5c4986135a0c7d9b84d4bd68cec561c3e8179adfa89b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.class': '8406abdea86743df597c5ef3a5fdcd5a5bda053b3040eaa575009ee2862f0256', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.class': 'b1be80387efcd1dccd87ad586b4cc03c8c2942583947c786c95779132f725ce4', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.class': 'b6fed8819f430368ce56ef3f38bede250405feab0b0911d71fc77407aa8db48b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.class': '9f32cbaa3220d547003a5f0f8872a8842682cba11532571bb9d61a09da986446', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.class': '8e0600b18dce5a6ebaec135ae8f17e1b55bbde8b733ba06f3705ef61ebe54f2e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.class': 'f69ef50597d54f66b0cf03b253511aa737e503fd2406bd99a4d83f198deeeb14', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.class': '147e8dee1936965914cd70f74f5565cfe068bf9c955d5a18dbd29f3080433b2b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class': 'c1df4e947257748b79568313e8381d02e83db8f58c1e42342c1bbbb98f76b0d5', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.class': '08b9ffd9cdb9d350732ba66f44ed5c4374652776e78f7a4ab28adcf5df84666b'},
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'verified'): 62,
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'aggregator_sha256'): 'c23818b14294d7a4da21e329a4fa1a67148549537aac5d07a3f9198bc71955ba',
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'translation_metadata_sha256'): 'b374f6b9506da02fb5c0c579a6c588807575eac7548a296ef823bc9c89ba4052',
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'controls'): {'counter': 'proof-obligation-rejected', 'feedback': 'proof-obligation-rejected', 'truncation': 'proof-obligation-rejected', 'prefix': 'proof-obligation-rejected', 'public-domain': 'proof-obligation-rejected', 'extra-assumption': 'audit-rejected', 'skipped-proof': 'audit-rejected', 'adapter-select-loop': 'bytecode-rejected', 'adapter-bare-cast': 'bytecode-rejected', 'adapter-dead-decoy': 'bytecode-rejected'},
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'java_runs'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)', 'tests': 'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: HmacSHA256=SunJCE, HmacSHA384=SunJCE, HmacSHA512=SunJCE', 'executable_sha256': 'd7ab2ea6a7e731a8a2cee7d722046c9f7d8c5f184cd769b9954a392592337770'}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)', 'tests': 'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: HmacSHA256=SunJCE, HmacSHA384=SunJCE, HmacSHA512=SunJCE', 'executable_sha256': 'd6b5c8ffce485baa7e9aacfd9c652e2999c89053a5070104c598731636bd2249'}],
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'assumptions'): ['VerifiedHkdf.Mac: deterministic external HMAC with fixed output length'],
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'adapter_discipline'): 'JdkHmac.bytes has a guarded toRawArray/instanceof [B/branch/checkcast/areturn shape; HkdfBridge delegates; select/Byte rejected',
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'verified'): 248,
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'public_domain_verified'): 249,
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'generated_java'): {'HkdfCrypto.java': 'c23818b14294d7a4da21e329a4fa1a67148549537aac5d07a3f9198bc71955ba', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'delivered_generated_java'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'source'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'classes'): {'io/github/mahmoudimus/quic/Hkdf.class': 'b096db75e610d1a8aec5e6f85e615557b17be6673d353e92add4611b42d65b6e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.class': '4a1d2f0aeef211e31bc8f204ea455bd0a5ee0d43a56c1ebfb5baea4d8ea847ef', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.class': '0e10e3dc75b944c5bf1b5c4986135a0c7d9b84d4bd68cec561c3e8179adfa89b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.class': '8406abdea86743df597c5ef3a5fdcd5a5bda053b3040eaa575009ee2862f0256', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.class': 'b1be80387efcd1dccd87ad586b4cc03c8c2942583947c786c95779132f725ce4', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.class': 'b6fed8819f430368ce56ef3f38bede250405feab0b0911d71fc77407aa8db48b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.class': '9f32cbaa3220d547003a5f0f8872a8842682cba11532571bb9d61a09da986446', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.class': '8e0600b18dce5a6ebaec135ae8f17e1b55bbde8b733ba06f3705ef61ebe54f2e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.class': 'f69ef50597d54f66b0cf03b253511aa737e503fd2406bd99a4d83f198deeeb14', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.class': '147e8dee1936965914cd70f74f5565cfe068bf9c955d5a18dbd29f3080433b2b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class': 'c1df4e947257748b79568313e8381d02e83db8f58c1e42342c1bbbb98f76b0d5', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.class': '08b9ffd9cdb9d350732ba66f44ed5c4374652776e78f7a4ab28adcf5df84666b'},
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'verified'): 62,
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'aggregator_sha256'): 'c23818b14294d7a4da21e329a4fa1a67148549537aac5d07a3f9198bc71955ba',
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'translation_metadata_sha256'): 'b374f6b9506da02fb5c0c579a6c588807575eac7548a296ef823bc9c89ba4052',
    ('V3', 'formal/saw/evidence/report.json', 'status'): 'complete',
    ('V3', 'formal/saw/evidence/report.json', 'runs.proof.result'): 'verified',
    ('V3', 'formal/saw/evidence/report.json', 'runs.wrong_modulus.result'): 'proof_counterexample',
    ('V3', 'formal/saw/evidence/report.json', 'runs.wrong_modulus.exit_code'): 2,
    ('V3', 'formal/saw/evidence/report.json', 'runs.vacuous.result'): 'rejected_vacuous_specification',
    ('V3', 'formal/saw/evidence/report.json', 'runs.nonce.result'): 'blocked_by_array_clone_translation',
}


REQUIRED_RECEIPT_EXACT.update({
    ('V4', 'formal/crypto/SHAKE-EVIDENCE.json', 'scope'): 'SHAKE functional proof and finite generated-Java checks only',
    ('V4', 'formal/crypto/SHAKE-EVIDENCE.json', 'proofs'): {'formal/crypto/ByteLanes.dfy': {'verified': 24, 'errors': 0}, 'formal/crypto/Shake.dfy': {'verified': 115, 'errors': 0}, 'formal/crypto/SpongeSpec.dfy': {'verified': 159, 'errors': 0}, 'formal/crypto/shake_domain.dfy': {'verified': 11, 'errors': 0}, 'formal/primitives/Keccak.dfy': {'verified': 122, 'errors': 0}},
    ('V4', 'formal/crypto/SHAKE-EVIDENCE.json', 'audits'): {'formal/crypto/ByteLanes.dfy': 0, 'formal/crypto/Shake.dfy': 0, 'formal/crypto/SpongeSpec.dfy': 0, 'formal/crypto/shake_domain.dfy': 0, 'formal/primitives/Keccak.dfy': 0},
    ('V4', 'formal/crypto/SHAKE-EVIDENCE.json', 'generation'): {'verified': 42, 'errors': 0},
    ('V4', 'formal/crypto/SHAKE-EVIDENCE.json', 'vectors'): {'sha256': '6ee22c84ac0e738d6805a92692777100e1d94a7718ad30b1a03123a1d72b6cb3', 'count': 198, 'inventory': [{'rate': 136, 'input_bytes': 0, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 0, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 1, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 7, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 8, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 134, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 135, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 136, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 137, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 271, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 272, 'output_bytes': 273}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 0}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 1}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 7}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 8}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 135}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 136}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 137}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 272}, {'rate': 136, 'input_bytes': 273, 'output_bytes': 273}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 0, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 1, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 7, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 8, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 166, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 167, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 168, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 169, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 335, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 336, 'output_bytes': 337}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 0}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 1}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 7}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 8}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 167}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 168}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 169}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 336}, {'rate': 168, 'input_bytes': 337, 'output_bytes': 337}]},
    ('V4', 'formal/crypto/SHAKE-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)\n', 'tests': {'vectors': 198, 'partitions': 198, 'slices': 24, 'word_cases': 36864, 'assertions': 47663}}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)\n', 'tests': {'vectors': 198, 'partitions': 198, 'slices': 24, 'word_cases': 36864, 'assertions': 47663}}],
    ('V5', 'formal/crypto/CODEC-EVIDENCE.json', 'scope'): 'Codec and finite rejection Feed only; generated Java finite regression evidence, not universal Java refinement or production adoption.',
    ('V5', 'formal/crypto/CODEC-EVIDENCE.json', 'proofs'): {'proof-Codec': 469, 'proof-Sampling': 26, 'codec_domain': 7, 'sampling_domain': 2},
    ('V5', 'formal/crypto/CODEC-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.2" 2024-01-16 LTS\nOpenJDK Runtime Environment Temurin-21.0.2+13 (build 21.0.2+13-LTS)\nOpenJDK 64-Bit Server VM Temurin-21.0.2+13 (build 21.0.2+13-LTS, mixed mode, sharing)\n', 'tests': {'scalars': 40713, 'encodings': 7044, 'malformed': 1820, 'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 207513}}, {'version': 'openjdk version "25.0.4" 2026-07-21 LTS\nOpenJDK Runtime Environment Temurin-25.0.4+7 (build 25.0.4+7-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.4+7 (build 25.0.4+7-LTS, mixed mode, sharing)\n', 'tests': {'scalars': 40713, 'encodings': 7044, 'malformed': 1820, 'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 207513}}],
    ('V5', 'formal/crypto/POLYNOMIAL-EVIDENCE.json', 'scope'): 'Canonical polynomial operations, mathematical NTT representation, two-sided inverse and negacyclic multiplication',
    ('V5', 'formal/crypto/POLYNOMIAL-EVIDENCE.json', 'status'): 'passed',
    ('V5', 'formal/crypto/POLYNOMIAL-EVIDENCE.json', 'phase'): 'all',
    ('V5', 'formal/crypto/POLYNOMIAL-EVIDENCE.json', 'verified'): 1562,
    ('V5', 'formal/crypto/POLYNOMIAL-EVIDENCE.json', 'domain_harness'): 'Dafny program verifier finished with 1 verified, 0 errors',
    ('V5', 'formal/crypto/POLYNOMIAL-EVIDENCE.json', 'java_runs'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)', 'result': 'POLYNOMIAL_CHECKS cases=288 product_cases=32 assertions=551008', 'java_sha256': 'd7ab2ea6a7e731a8a2cee7d722046c9f7d8c5f184cd769b9954a392592337770'}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)', 'result': 'POLYNOMIAL_CHECKS cases=288 product_cases=32 assertions=551008', 'java_sha256': 'd6b5c8ffce485baa7e9aacfd9c652e2999c89053a5070104c598731636bd2249'}],
    ('V5', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'validation_kind'): 'Fresh actual proof, semantic-control, generation, compilation, bytecode and JDK21/JDK25 replay of the adopted source; the pre-Poly proof-reuse lineage is retained under historical only and is not evidence for these source hashes.',
    ('V5', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)\n', 'tests': {'scalars': 40713, 'encodings': 7044, 'malformed': 1820, 'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 334753}}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)\n', 'tests': {'scalars': 40713, 'encodings': 7044, 'malformed': 1820, 'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 334753}}],
    ('V5', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'proofs'): {'proof-NativeField': 86, 'proof-NativeCodec': 1503, 'proof-NativeSampling': 281, 'native_codec_domain': 8, 'native_sampling_domain': 4},
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'scope'): 'Full positive-domain proof/translation/runtime replay on macOS ARM64; all 14 strict negative controls on Linux amd64. The Linux replay is control-only, not another proof of the unrestricted positive graph.',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'status'): 'passed',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'unchanged_policy'): {'positive_domain': 'Every array of exactly 256 coefficients in [0,3329); input aliasing permitted', 'negative_control_count': 14, 'required_semantic_exit': 4, 'resource_timeout_crash_diagnostics': 'rejected', 'cores': 2, 'verification_time_limit_seconds': 30, 'resource_limit': 50000000, 'native_case_split': 0, 'dependency_case_split': 'unchanged default 3'},
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.status'): 'passed',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.phase'): 'all',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.dependency_verified'): 1562,
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.native_verified'): 1092,
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'linux_controls.receipt.status'): 'passed',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'linux_controls.receipt.phase'): 'controls',
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'scope'): 'full',
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'proofs'): {'proof-full': 2775, 'generate-java': 80},
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)\n', 'tests': {'assertions': 5091, 'rounds': 100, 'malformed': 30, 'selections': 3265}}, {'version': 'openjdk version "25.0.4" 2026-07-21 LTS\nOpenJDK Runtime Environment Temurin-25.0.4+7 (build 25.0.4+7-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.4+7 (build 25.0.4+7-LTS, mixed mode, sharing)\n', 'tests': {'assertions': 5091, 'rounds': 100, 'malformed': 30, 'selections': 3265}}],
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'provider_assumptions'): ['formal/crypto/JdkHash.dfy(8,4): Warning: H: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/JdkHash.dfy(11,4): Warning: G: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.'],
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'scope'): 'full',
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'proofs'): {'proof-native-composition': 2776, 'proof-reference-graph': 2695, 'proof-native-kernels': 4097, 'generate-java': 162},
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)\n', 'tests': {'assertions': 7813, 'rounds': 100, 'malformed': 30, 'selections': 3265, 'destroyed': 101}}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)\n', 'tests': {'assertions': 7813, 'rounds': 100, 'malformed': 30, 'selections': 3265, 'destroyed': 101}}],
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'provider_assumptions'): {'primitive_count': 2, 'declaration_count': 4, 'declarations': ['formal/crypto/JdkHash.dfy(8,4): Warning: H: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/JdkHash.dfy(11,4): Warning: G: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/NativeJdkHash.dfy(12,4): Warning: Hash: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/NativeJdkHash.dfy(17,4): Warning: Expand: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.']},
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'bytecode_controls'): {'selector-narrow-helper': {'rejected': 'Unreviewed or payload-sensitive runtime helper'}, 'selector-payload-branch': {'rejected': 'Selector payload branch or changed loop control'}, 'selector-payload-boxing': {'rejected': 'Payload scalar boxing: 47: invokestatic  #35                 // Method java/lang/Byte.valueOf:(B)Ljava/lang/Byte;'}},
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'native_runtime_guard.payload_scalar_boxings'): 0,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'status'): 'complete',
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'verified'): 2776,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'exit'): 0,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'platform'): 'linux/amd64',
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'dafny_version'): '4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2',
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'max_resource_count'): 10275514,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'max_obligation_seconds'): 10.1399173,
})

REQUIRED_COMPONENT_CHECKS['V7'] = dict(REQUIRED_COMPONENT_CHECKS['V7'])
REQUIRED_COMPONENT_CHECKS['V7']['text_checks'] = (('formal/packet/EVIDENCE.md', ('| macOS arm64, Homebrew21.0.12.1 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| macOS arm64, Temurin25.0.5+8 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| Linux x86-64, Temurin21.0.7+6 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', 'All33 Python gate tests passed on macOS and Linux.', 'The extracted scalar programs contain160 SSA nodes for Decode,13 for ReadPrefix')),)

# Fresh ROOT replay after the one generated-Java text pin moved to the migrated
# canonical output; the report was regenerated from the actual classes, not renewed.
REQUIRED_TRACE_REPORT_SHA256 = '07be9330dc2dc183a726f52f255c5895e3f485dab3746c304fe4fe7f367a44c5'

REQUIRED_TRACE_ROOTS = ({'class': 'io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default',
  'method': 'Select:([B[B[B[B)[B',
  'status': 'checked',
  'obligations': 84,
  'instructions': 75,
  'instructions_reachable': 75,
  'cfg_edges_checked': True},
 {'class': 'io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.__default',
  'method': 'Feed:([I[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;',
  'status': 'checked',
  'obligations': 179,
  'instructions': 167,
  'instructions_reachable': 167,
  'cfg_edges_checked': True},
 {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default',
  'method': 'Extract:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;',
  'status': 'checked',
  'obligations': 34,
  'instructions': 30,
  'instructions_reachable': 30,
  'cfg_edges_checked': True},
 {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default',
  'method': 'Expand:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;',
  'status': 'checked',
  'obligations': 111,
  'instructions': 103,
  'instructions_reachable': 103,
  'cfg_edges_checked': True},
 {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default',
  'method': 'LabelInfo:(Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;',
  'status': 'checked',
  'obligations': 169,
  'instructions': 158,
  'instructions_reachable': 158,
  'cfg_edges_checked': True},
 {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'method': 'sequence:([BLjava/lang/String;)Ldafny/DafnySequence;',
  'status': 'checked',
  'obligations': 11,
  'instructions': 5,
  'instructions_reachable': 5,
  'cfg_edges_checked': True},
 {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'method': 'labelUnits:(Ljava/lang/String;)Ldafny/DafnySequence;',
  'status': 'checked',
  'obligations': 28,
  'instructions': 23,
  'instructions_reachable': 23,
  'cfg_edges_checked': True})
REQUIRED_TRACE_ROOT_CASE_SPLIT = {'Select:([B[B[B[B)[B': True,
 'Feed:([I[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;': False,
 'Extract:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;': True,
 'Expand:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;': False,
 'LabelInfo:(Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;': False,
 'sequence:([BLjava/lang/String;)Ldafny/DafnySequence;': True,
 'labelUnits:(Ljava/lang/String;)Ldafny/DafnySequence;': True}
REQUIRED_TRACE_ASSUMED_TARGETS = ('io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Extract:(JII)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.PublicMod:(II)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Wipe:([I)V', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_Full:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidBlockLength:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidPrefix:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_NeedMore:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.IsPrefix:([I)Z', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I._typeDescriptor:()Ldafny/TypeDescriptor;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Failure:(Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Success:(Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidHash:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidKey:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLabel:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLength:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.ValidHash:(Ljava/math/BigInteger;)Z', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.compute:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Ldafny/DafnySequence;')
REQUIRED_TRACE_OPEN_TARGETS = (('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge',
  'Update:([BII)I',
  'unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge',
  'AbsorbOne:(B)V',
  'unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge',
  'XorByte:(IB)V',
  'unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge',
  'Next:()B',
  'unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge',
  'Start:()V',
  'unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default',
  'Decaps:(Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey;[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result;',
  'caller-skeleton-unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default',
  'ExpandLabel:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;',
  'unsupported-object-dispatch'),
 ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'extract:(I[B[B)[B',
  'unsupported-object-dispatch'),
 ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'expand:(I[B[BI)[B',
  'unsupported-object-dispatch'),
 ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'labelInfo:(Ljava/lang/String;[BI)[B',
  'unsupported-object-dispatch'),
 ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'failure:(Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;IZ)Ljava/lang/RuntimeException;',
  'unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'hash:(I)Ljava/math/BigInteger;',
  'unsupported'),
 ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
  'bytes:(Ldafny/DafnySequence;)[B',
  'unsupported'))
REQUIRED_TRACE_UNCHECKED = ('NativeHkdf.Expanded bytes via bridges (not all adapter paths)', 'NativeKeccak.Permute', 'NativeKeccak.PermuteScratch', 'NativeMlKem.Decaps (caller skeleton only)', 'NativeMlKem.Decrypt', 'NativeMlKem.Encaps', 'NativeMlKem.Encrypt', 'NativeMlKem.ExpandMatrix', 'NativeMlKem.Field/NTT/codec/sampling helpers', 'NativeMlKem.KeyGen', 'NativeShake.Sponge.*', 'NativeShake.Xof', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Extract:(JII)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.PublicMod:(II)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Wipe:([I)V', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_Full:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidBlockLength:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidPrefix:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_NeedMore:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.IsPrefix:([I)Z', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I._typeDescriptor:()Ldafny/TypeDescriptor;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Failure:(Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Success:(Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidHash:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidKey:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLabel:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLength:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.ValidHash:(Ljava/math/BigInteger;)Z', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.compute:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Ldafny/DafnySequence;')
REQUIRED_TRACE_FIXTURES = (('ConstantTime', 'accept', 'checked'),
 ('SecretBranch', 'reject', 'rejected'),
 ('SecretIndex', 'reject', 'rejected'),
 ('EarlyCompare', 'reject', 'rejected'),
 ('ExceptionOracle', 'reject', 'rejected'),
 ('SecretAlloc', 'reject', 'rejected'),
 ('SecretLoopBound', 'reject', 'rejected'),
 ('SecretDigestBranch', 'reject', 'rejected'),
 ('FieldAlias', 'reject', 'rejected'),
 ('VirtualDispatch', 'reject', 'rejected'),
 ('ClassOracle', 'reject', 'rejected'),
 ('NewIdentity', 'reject', 'rejected'),
 ('ResultArrayCall', 'reject', 'rejected'),
 ('CategoryTwo', 'reject', 'rejected'),
 ('CalleeOwner', 'reject', 'rejected'),
 ('CalleeDescriptor', 'reject', 'rejected'),
 ('SecretResultBranch', 'reject', 'rejected'),
 ('HeapResultLaunder', 'reject', 'rejected'),
 ('PostWipeLaunder', 'reject', 'rejected'),
 ('PrivateEuclidean', 'reject', 'rejected'),
 ('PublicEuclidean', 'accept', 'checked'),
 ('PrivateEuclideanDivision', 'reject', 'rejected'),
 ('LongSlotPrivate', 'reject', 'rejected'),
 ('LongSlotPublic', 'accept', 'checked'),
 ('LongSlotArray', 'reject', 'rejected'),
 ('HeapExternalCompare', 'reject', 'rejected'),
 ('HeapExternalPublic', 'accept', 'checked'))
REQUIRED_TRACE_MUTANTS = (('secret-guard', 'proof-obligation-rejected'), ('secret-index', 'proof-obligation-rejected'), ('early-compare-guard', 'proof-obligation-rejected'), ('public-taint-launder', 'proof-obligation-rejected'))
REQUIRED_TRACE_INPUT_KEYS = ('formal/dafny/hkdf/Hkdf.dfy',
 'formal/dafny/run.py',
 'formal/dafny/toolchain.py',
 'formal/dafny/tools.json',
 'formal/timing/ApplyProbe.dfy',
 'formal/timing/HkdfShape.dfy',
 'formal/timing/PositiveTraceCheck.dfy',
 'formal/timing/PublicProvider.dfy',
 'formal/timing/PublicProviderPublic.dfy',
 'formal/timing/README.md',
 'formal/timing/SecretTrace.dfy',
 'formal/timing/WordArithmetic.dfy',
 'formal/timing/bytecode_trace.py',
 'formal/timing/compact_certificates.py',
 'formal/timing/composition.py',
 'formal/timing/execution_controls.py',
 'formal/timing/fixtures/CalleeDescriptor.java',
 'formal/timing/fixtures/CalleeOwner.java',
 'formal/timing/fixtures/CategoryTwo.java',
 'formal/timing/fixtures/ClassOracle.java',
 'formal/timing/fixtures/ConstantTime.java',
 'formal/timing/fixtures/EarlyCompare.java',
 'formal/timing/fixtures/ExceptionOracle.java',
 'formal/timing/fixtures/ExtractShape.java',
 'formal/timing/fixtures/FieldAlias.java',
 'formal/timing/fixtures/FieldStoreProbe.java',
 'formal/timing/fixtures/HeapExternalCompare.java',
 'formal/timing/fixtures/HeapExternalPublic.java',
 'formal/timing/fixtures/HeapResultLaunder.java',
 'formal/timing/fixtures/InlineCallee.java',
 'formal/timing/fixtures/InlineCaller.java',
 'formal/timing/fixtures/LongSlotArray.java',
 'formal/timing/fixtures/LongSlotPrivate.java',
 'formal/timing/fixtures/LongSlotPublic.java',
 'formal/timing/fixtures/MergeRoleCallee.java',
 'formal/timing/fixtures/MergeRoleCaller.java',
 'formal/timing/fixtures/NewIdentity.java',
 'formal/timing/fixtures/PostWipeLaunder.java',
 'formal/timing/fixtures/PrivateEuclidean.java',
 'formal/timing/fixtures/PrivateEuclideanDivision.java',
 'formal/timing/fixtures/PublicEuclidean.java',
 'formal/timing/fixtures/RecursiveCallee.java',
 'formal/timing/fixtures/ResultArrayCall.java',
 'formal/timing/fixtures/SecretAlloc.java',
 'formal/timing/fixtures/SecretBranch.java',
 'formal/timing/fixtures/SecretDigestBranch.java',
 'formal/timing/fixtures/SecretIndex.java',
 'formal/timing/fixtures/SecretLoopBound.java',
 'formal/timing/fixtures/SecretResultBranch.java',
 'formal/timing/fixtures/VirtualDispatch.java',
 'formal/timing/keccak_traces.py',
 'formal/timing/policy.json',
 'formal/timing/run.py',
 'formal/timing/runtime_primitives.py',
 'formal/timing/test_compact_certificates.py',
 'formal/timing/test_coverage.py',
 'formal/timing/test_exception_table.py',
 'formal/timing/test_keccak_traces.py',
 'formal/timing/test_runtime_primitives.py',
 'formal/timing/test_trace.py',
 'formal/timing/threat-model.md',
 'formal/timing/trace_exec.py',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_Decoded.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidWidth.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_ModulusError.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Encapsulation.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidCiphertextLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidKeyLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidMessageLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidSeedLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_ModulusError.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_RejectionLimit.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/PublicKey.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Failure.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Success.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/SecretKey.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_Decoded.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidWidth.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_ModulusError.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/Encapsulation.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/PublicKey.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativePolynomial/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_Full.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidBlockLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidPrefix.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_NeedMore.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/Sponge.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/L.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolySpec/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/Residue.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_Full.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidBlockLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidPrefix.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_NeedMore.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/ReadResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/State.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InputAfterOutput.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InvalidSlice.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_Updated.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedCodec/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedField/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedKeccak/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedPolynomial/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedSampling/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedShake/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java',
 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/kem_hash.java',
 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/native_kem_hash.java')
REQUIRED_TRACE_CLASS_BINDING_KEYS = ('io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_Decoded.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidWidth.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_ModulusError.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Encapsulation.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidCiphertextLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidKeyLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidMessageLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidSeedLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_ModulusError.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_RejectionLimit.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/PublicKey.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Failure.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Success.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/SecretKey.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_Decoded.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidWidth.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_ModulusError.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/Encapsulation.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/PublicKey.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativePolynomial/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_Full.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidBlockLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidPrefix.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_NeedMore.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/Sponge.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/L.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/PolySpec/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/Residue.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_Full.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidBlockLength.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidPrefix.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_NeedMore.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/ReadResult.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/State.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InputAfterOutput.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InvalidSlice.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_Updated.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedCodec/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedField/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedKeccak/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedPolynomial/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedSampling/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedShake/__default.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.class', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.class', 'io/github/mahmoudimus/verifiedcrypto/kem_hash.class', 'io/github/mahmoudimus/verifiedcrypto/native_kem_hash.class')
REQUIRED_TRACE_TOOL_IDENTITY = {
    'version': '4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2',
    'binary_sha256': '9ae7c1d3dc24d82d2bd0058b3c29a1071eacfcebb5782f05d5ed53f8e41662c6',
    'solver_sha256': '5eaebf0f9dd366b7acd0f69bb390dac285c12bb684310504d17502b54917a396',
    'compiler_runtime_sha256': '2c028565d81751f5f659d962c98613b118e45bfae6a295fb140f5e07f4b82b2f',
    'archive_sha256': '3209da6998c98c10e15970b85f6aa27925682c3273cd41539348ab8f7941553e',
    'manifest_version': '4.9.1',
}
REQUIRED_TRACE_JDK_IDENTITY = {
    'java': 'd7ab2ea6a7e731a8a2cee7d722046c9f7d8c5f184cd769b9954a392592337770',
    'javac': 'ab9b94d81dd22c843ef637be9aa2121253c6d4cfe2ba0a89a7bde5c0b9567945',
    'javap': '45e7ec2c0b002e6dc716651ede247ac1f2c25d4cc8cf37ee20591ddc439162ac',
}

REQUIRED_COMPONENT_EVIDENCE.update({
    'V7': (
        ('docs/security-timing-audit.md', 'documentation'),
        ('scripts/security/assess-local-timing.sh', 'tool-manifest'),
        ('formal/packet/EVIDENCE.md', 'component-receipt'),
        ('formal/packet/inputs.json', 'input-manifest'),
        ('formal/packet/README.md', 'documentation'),
        ('formal/packet/TraceMachine.dfy', 'model-source'),
        ('formal/packet/bytecode_guard.py', 'tool-manifest'),
        ('formal/saw/evidence/report.json', 'bytecode-report'),
        ('formal/timing/README.md', 'documentation'),
        ('formal/timing/threat-model.md', 'documentation'),
        ('formal/timing/inputs.json', 'input-manifest'),
        ('formal/timing/policy.json', 'component-receipt'),
        ('formal/timing/run.py', 'tool-manifest'),
        ('formal/timing/bytecode_trace.py', 'tool-manifest'),
        ('formal/timing/composition.py', 'tool-manifest'),
        ('formal/timing/trace_exec.py', 'tool-manifest'),
        ('formal/timing/ApplyProbe.dfy', 'finite-test'),
        ('formal/timing/SecretTrace.dfy', 'model-source'),
        ('formal/timing/HkdfShape.dfy', 'model-source'),
        ('formal/timing/PositiveTraceCheck.dfy', 'finite-test'),
        ('formal/timing/test_trace.py', 'test-source'),
        ('formal/timing/test_exception_table.py', 'test-source'),
        ('formal/timing/execution_controls.py', 'tool-manifest'),
        ('formal/timing/test_coverage.py', 'test-source'),
        ('formal/timing/PRODUCTION-EVIDENCE.json', 'component-receipt'),
        ('docs/formal-security.md', 'documentation'),
        ('docs/project/2026-10-28-java-crypto-verification.md', 'documentation'),
        (POLY_SOURCE_RECEIPT, 'component-receipt'),
        (POLY_SOURCE_INPUTS, 'input-manifest'),
        ('formal/source/polynomial/replay.py', 'tool-manifest'),
        ('formal/source/polynomial/checker/PolynomialSourceCoverage.cs', 'tool-manifest'),
        ('formal/source/polynomial/checker/PolynomialSourceCoverage.csproj', 'tool-manifest'),
    ),
})
REQUIRED_COMPONENT_CHECKS.update({
    'V7': {
        'control_groups': (),
        'receipt_checks': (('formal/saw/evidence/report.json', ('runs.nonce.result',)),),
        'hash_maps': (('formal/packet/inputs.json', 'inputs', ('formal/packet/', 'quic/src/'), (), ''), ('formal/timing/inputs.json', 'inputs', (), (), ''),
                      ('formal/source/polynomial/inputs.json', 'inputs', (), (), ''),
                      (POLY_SOURCE_RECEIPT, 'inputs_before', (), (), ''),
                      (POLY_SOURCE_RECEIPT, 'inputs_after', (), (), '')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': (),
        'nonvacuity': (),
        'text_checks': (('formal/packet/EVIDENCE.md', ('| macOS arm64, Homebrew21.0.12.1 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| macOS arm64, Temurin25.0.5+8 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| Linux x86-64, Temurin21.0.7+6 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', 'All33 Python gate tests passed on macOS and Linux.', 'The extracted scalar programs contain160 SSA nodes for Decode,13 for ReadPrefix')),),
    },
})
REQUIRED_HASH_MAP_KEYS[('V7', 'formal/timing/inputs.json', 'inputs', (), '')] = REQUIRED_TRACE_INPUT_KEYS
for _poly_map in (('formal/source/polynomial/inputs.json', tuple(sorted((
        'formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy',
        'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy',
        'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy',
        'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy',
        'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy',
        'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy',
        'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/delivery.py',
        'formal/crypto/kem_hash.java', 'formal/crypto/native_kem_hash.java',
        'formal/crypto/native_polynomial_domain.dfy', 'formal/dafny/toolchain.py',
        'formal/dafny/tools.json', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy',
        'formal/source/SourceTrace.dfy', 'formal/source/polynomial/AllPolynomialTraceRoots.dfy',
        'formal/source/polynomial/FieldTraceCompatibility.dfy',
        'formal/source/polynomial/NativePolynomialTraceHarness.dfy',
        'formal/source/polynomial/README.md',
        'formal/source/polynomial/checker/PolynomialSourceCoverage.cs',
        'formal/source/polynomial/checker/PolynomialSourceCoverage.csproj',
        'formal/source/polynomial/controls/BranchObservedHarness.dfy',
        'formal/source/polynomial/controls/ByMethodControl.dfy',
        'formal/source/polynomial/controls/ControlHarnesses.dfy',
        'formal/source/polynomial/controls/FunctionBranchHarness.dfy',
        'formal/source/polynomial/controls/FunctionIndexHarness.dfy',
        'formal/source/polynomial/controls/FunctionUnmarkedHarnesses.dfy',
        'formal/source/polynomial/controls/IndexObservedHarness.dfy',
        'formal/source/polynomial/controls/LemmaOutControl.dfy',
        'formal/source/polynomial/controls/PolynomialControls.dfy',
        'formal/source/polynomial/controls/UnmarkedHarnesses.dfy',
        'formal/source/polynomial/replay.py', 'formal/source/polynomial/test_replay.py',
        'formal/source/vocabulary/ObservationVocabulary.dfy',
    )))) ,
                  (POLY_SOURCE_RECEIPT, tuple(sorted((
        'formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy',
        'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy',
        'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy',
        'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy',
        'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy',
        'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy',
        'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/delivery.py',
        'formal/crypto/kem_hash.java', 'formal/crypto/native_kem_hash.java',
        'formal/crypto/native_polynomial_domain.dfy', 'formal/dafny/toolchain.py',
        'formal/dafny/tools.json', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy',
        'formal/source/SourceTrace.dfy', 'formal/source/polynomial/AllPolynomialTraceRoots.dfy',
        'formal/source/polynomial/FieldTraceCompatibility.dfy',
        'formal/source/polynomial/NativePolynomialTraceHarness.dfy',
        'formal/source/polynomial/README.md',
        'formal/source/polynomial/checker/PolynomialSourceCoverage.cs',
        'formal/source/polynomial/checker/PolynomialSourceCoverage.csproj',
        'formal/source/polynomial/controls/BranchObservedHarness.dfy',
        'formal/source/polynomial/controls/ByMethodControl.dfy',
        'formal/source/polynomial/controls/ControlHarnesses.dfy',
        'formal/source/polynomial/controls/FunctionBranchHarness.dfy',
        'formal/source/polynomial/controls/FunctionIndexHarness.dfy',
        'formal/source/polynomial/controls/FunctionUnmarkedHarnesses.dfy',
        'formal/source/polynomial/controls/IndexObservedHarness.dfy',
        'formal/source/polynomial/controls/LemmaOutControl.dfy',
        'formal/source/polynomial/controls/PolynomialControls.dfy',
        'formal/source/polynomial/controls/UnmarkedHarnesses.dfy',
        'formal/source/polynomial/inputs.json', 'formal/source/polynomial/replay.py',
        'formal/source/polynomial/test_replay.py',
        'formal/source/vocabulary/ObservationVocabulary.dfy',
    ))))):
    for _path in (('inputs',) if _poly_map[0] == 'formal/source/polynomial/inputs.json' else ('inputs_before', 'inputs_after')):
        REQUIRED_HASH_MAP_KEYS[('V7', _poly_map[0], _path, (), '')] = _poly_map[1]


# Reviewed immutable policies for a claim that is marked supported.  These are
# deliberately explicit rather than reading the claim's own strength/dependency
# fields: a ledger edit cannot relabel a V0 finite-test fixture as a production
# SHAKE/ML-KEM implementation claim.  Claims that are not supported are allowed
# to remain in their reviewed deferred/blocked/snapshot state.
_SHAKE_MLKEM_REQUIRED_EVIDENCE = (
    REQUIRED_COMPONENT_EVIDENCE["V4"]
    + REQUIRED_COMPONENT_EVIDENCE["V5"]
    + REQUIRED_COMPONENT_EVIDENCE["V6"]
)
_HKDF_FUTURE_EVIDENCE = HKDF_COMPONENT_EVIDENCE["V1"] + HKDF_COMPONENT_EVIDENCE["V2"]
_PACKET_TRACE_EVIDENCE = (
    ("formal/packet/EVIDENCE.md", "component-receipt"),
    ("formal/packet/inputs.json", "input-manifest"),
    ("formal/packet/TraceMachine.dfy", "model-source"),
    ("formal/packet/bytecode_guard.py", "tool-manifest"),
)
_RELEASE_GATE_EVIDENCE = (
    ("scripts/security/check_crypto_obligations.py", "tool-manifest"),
    ("scripts/security/check_crypto_release.py", "tool-manifest"),
    ("scripts/security/crypto_current_release.py", "tool-manifest"),
    ("scripts/security/test_crypto_obligations.py", "test-source"),
    ("scripts/security/test_crypto_current_release.py", "test-source"),
    ("formal/obligations.md", "documentation"),
)

CLAIM_POLICIES = {
    "shake-mlkem-functional-production": {
        "obligations": ("V4", "V5", "V6"),
        "strength": "implementation",
        "production": True,
        "assumptions": frozenset({
            "dafny-toolchain", "dafny-runtime", "javac-jvm", "jdk-primitives",
            "generated-runtime-discipline", "reviewed-java-facades",
        }),
        "required_evidence": _SHAKE_MLKEM_REQUIRED_EVIDENCE,
        "required_statuses": {
            "V4": ("implementation-proof",),
            "V5": ("implementation-proof",),
            "V6": ("implementation-proof",),
        },
        "component_checks": ("V4", "V5", "V6"),
    },
    "hkdf-isolated-functional": {
        "obligations": ("V1", "V2"),
        "strength": "implementation",
        "production": False,
        "assumptions": frozenset({
            "dafny-toolchain", "dafny-runtime", "javac-jvm", "jdk-primitives",
            "reviewed-java-facades", "crypto-hardness-entropy",
        }),
        "required_evidence": _HKDF_FUTURE_EVIDENCE,
        "required_statuses": {"V1": ("partial",), "V2": ("implementation-proof",)},
        "component_checks": ("V1", "V2"),
    },
    "hkdf-production-functional": {
        "obligations": ("V1", "V2"),
        "strength": "implementation",
        "production": True,
        "assumptions": frozenset({
            "dafny-toolchain", "dafny-runtime", "javac-jvm", "jdk-primitives",
            "reviewed-java-facades",
        }),
        "required_evidence": _HKDF_FUTURE_EVIDENCE,
        "required_statuses": {"V1": ("partial",), "V2": ("implementation-proof",)},
        "component_checks": ("V1", "V2"),
    },
    "mlkem-reduceonce-historical-bytecode": {
        "obligations": ("V3",),
        "strength": "bytecode",
        "production": False,
        "assumptions": frozenset({"saw-toolchain", "javac-jvm"}),
        "required_evidence": (
            ("formal/saw/evidence/report.json", "bytecode-report"),
            ("formal/saw/evidence/proof.log", "proof-log"),
            ("formal/saw/evidence/wrong_modulus.log", "proof-log"),
            ("formal/saw/evidence/vacuous.log", "proof-log"),
            ("formal/saw/inputs.json", "input-manifest"),
        ),
        "required_statuses": {},
        "component_checks": (),
        "required_receipt_values": (
            ("formal/saw/evidence/report.json", {
                "status": "complete",
                "runs.proof.result": "verified",
                "runs.wrong_modulus.result": "proof_counterexample",
                "runs.wrong_modulus.exit_code": 2,
                "runs.vacuous.result": "rejected_vacuous_specification",
            }),
        ),
    },
    "packet-nonce-bytecode": {
        "obligations": ("V3",),
        "strength": "bytecode",
        "production": False,
        "assumptions": frozenset({"saw-toolchain", "javac-jvm"}),
        "required_evidence": (
            ("formal/saw/evidence/report.json", "bytecode-report"),
            ("formal/saw/evidence/nonce.log", "proof-log"),
            ("formal/saw/inputs.json", "input-manifest"),
            ("formal/saw/README.md", "documentation"),
        ),
        "required_statuses": {"V3": ("bytecode-proof",)},
        "component_checks": (),
        "required_receipt_values": (
            ("formal/saw/evidence/report.json", {"runs.nonce.result": "verified"}),
        ),
    },
    "saw-portable-alternate-route": {
        "obligations": ("V3",),
        "strength": "bytecode",
        "production": False,
        "assumptions": frozenset({"saw-toolchain"}),
        "required_evidence": (
            ("formal/saw/evidence/report.json", "bytecode-report"),
            ("formal/saw/evidence/nonce.log", "proof-log"),
            ("formal/saw/inputs.json", "input-manifest"),
            ("formal/saw/README.md", "documentation"),
        ),
        "required_statuses": {"V3": ("bytecode-proof",)},
        "component_checks": (),
        "required_receipt_values": (
            ("formal/saw/evidence/report.json", {"runs.nonce.result": "verified"}),
        ),
    },
    "packet-nonce-functional-production": {
        "obligations": ("V3",),
        "strength": "implementation",
        "production": True,
        "assumptions": frozenset({
            "dafny-toolchain", "dafny-runtime", "javac-jvm", "generated-runtime-discipline",
        }),
        "required_evidence": (
            ("formal/nonce/PRODUCTION-EVIDENCE.json", "component-receipt"),
            ("formal/nonce/Nonce.dfy", "spec-source"),
            ("formal/nonce/NonceDomain.dfy", "spec-source"),
            ("formal/nonce/GENERATED.json", "generated-source"),
            ("formal/nonce/inputs.json", "input-manifest"),
            ("quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce/__default.java", "generated-source"),
            ("quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java", "production-source"),
            ("quic/src/test/java/io/github/mahmoudimus/quic/crypto/PacketKeyNonceTest.java", "test-source"),
            ("formal/nonce/BundleNonceSmoke.java", "test-source"),
            ("formal/crypto/delivery.json", "delivery-receipt"),
            ("formal/saw/historical/quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java", "snapshot-receipt"),
        ),
        "required_statuses": {"V3": ("blocked",)},
        "component_checks": ("V3",),
    },
    "packet-receive-trace-scoped": {
        "obligations": ("V7",),
        "strength": "model",
        "production": False,
        "assumptions": frozenset({
            "packet-compiler-lowering", "generated-runtime-discipline", "jvm-timing-jit-cpu-gc",
        }),
        "required_evidence": _PACKET_TRACE_EVIDENCE,
        "required_statuses": {"V7": ("partial", "model-proof", "implementation-proof")},
        "component_checks": ("V7",),
    },
    "v8-nontiming-release-gate": {
        "obligations": ("V0", "V8"),
        "strength": "finite",
        "production": False,
        "assumptions": frozenset({
            "dafny-toolchain", "lean-toolchain", "tlc-finite-model", "saw-toolchain",
        }),
        "required_evidence": _RELEASE_GATE_EVIDENCE,
        "required_statuses": {
            "V0": ("finite-tests",),
            "V8": ("partial", "finite-tests"),
        },
        "component_checks": ("V0", "V8"),
    },
    "v8-timing-release-evidence": {
        "obligations": ("V8", "V7"),
        "strength": "finite",
        "production": False,
        "assumptions": frozenset({"jvm-timing-jit-cpu-gc"}),
        "required_evidence": (
            ("scripts/security/assess-local-timing.sh", "tool-manifest"),
            ("docs/security-timing-audit.md", "documentation"),
            (None, "timing-proof-receipt"),
        ),
        "required_statuses": {},
        "component_checks": ("V7",),
    },
    "current-release-jar-identity": {
        "obligations": ("V4", "V5", "V6"),
        "strength": "implementation",
        "production": True,
        "assumptions": frozenset({"dafny-runtime", "javac-jvm", "generated-runtime-discipline"}),
        "required_evidence": (
            ("formal/crypto/adoption/stage-receipt.json", "delivery-receipt"),
            ("formal/crypto/delivery.json", "delivery-receipt"),
            (None, "current-jar-receipt"),
        ),
        "required_statuses": {
            "V4": ("implementation-proof",),
            "V5": ("implementation-proof",),
            "V6": ("implementation-proof",),
        },
        "component_checks": ("V4", "V5", "V6"),
    },
    "historical-adoption-jar-identity": {
        "obligations": ("V4", "V5", "V6"),
        "strength": "implementation",
        "production": False,
        "assumptions": frozenset({"dafny-runtime", "javac-jvm"}),
        "required_evidence": (
            ("formal/crypto/adoption/ACCEPTANCE.json", "snapshot-receipt"),
            ("formal/crypto/adoption/final-bundle.json", "snapshot-receipt"),
            ("formal/crypto/adoption/stage-receipt.json", "delivery-receipt"),
        ),
        "required_statuses": {
            "V4": ("implementation-proof",),
            "V5": ("implementation-proof",),
            "V6": ("implementation-proof",),
        },
        "component_checks": ("V4", "V5", "V6"),
    },
    "independent-expert-review": {
        "obligations": ("V8",),
        "strength": "none",
        "production": False,
        "assumptions": frozenset({"crypto-hardness-entropy"}),
        "required_evidence": (
            ("docs/formal-security.md", "documentation"),
            (None, "expert-review-receipt"),
        ),
        "required_statuses": {},
        "component_checks": (),
    },
    "cryptographic-security-proof": {
        "obligations": ("V6", "V7"),
        "strength": "model",
        "production": False,
        "assumptions": frozenset({"crypto-hardness-entropy"}),
        "required_evidence": ((None, "security-reduction-receipt"),),
        "required_statuses": {},
        "component_checks": ("V6",),
    },
    "jvm-constant-time": {
        "obligations": ("V7",),
        "strength": "bytecode",
        "production": False,
        "assumptions": frozenset({"jvm-timing-jit-cpu-gc"}),
        "required_evidence": (
            ("docs/security-timing-audit.md", "documentation"),
            (None, "timing-proof-receipt"),
        ),
        "required_statuses": {"V7": ("bytecode-proof",)},
        "component_checks": ("V7",),
    },
    "whole-proxy-security": {
        "obligations": ("V8",),
        "strength": "model",
        "production": False,
        "assumptions": frozenset({"crypto-hardness-entropy", "jvm-timing-jit-cpu-gc"}),
        "required_evidence": ((None, "whole-system-proof-receipt"),),
        "required_statuses": {"V8": ("implementation-proof",)},
        "component_checks": ("V8",),
    },
    "aws-full-upstream-hkdf-replay": {
        "obligations": ("V1", "V2"),
        "strength": "model",
        "production": False,
        "assumptions": frozenset({"dafny-toolchain"}),
        "required_evidence": (
            ("formal/reference/aws-hkdf/CLOSURE-RECEIPT.json", "upstream-closure-receipt"),
            ("formal/reference/aws-hkdf/inputs.json", "input-manifest"),
            ("formal/reference/aws-hkdf/README.md", "documentation"),
        ),
        "required_statuses": {},
        "component_checks": (),
        "required_receipt_values": (
            ("formal/reference/aws-hkdf/CLOSURE-RECEIPT.json", {
                "status": "complete",
                "scope": "closure",
                "full_dependency_graph_verified": True,
            }),
        ),
    },
    "poly-source-trace-ni": {
        "obligations": ("V5", "V7"),
        "strength": "implementation",
        "production": False,
        "assumptions": frozenset({
            "dafny-toolchain", "dafny-runtime", "javac-jvm", "generated-runtime-discipline",
            "trusted-source-observation-coverage",
        }),
        "required_evidence": POLY_SOURCE_CLAIM_EVIDENCE,
        "required_statuses": {"V5": ("implementation-proof",), "V7": ("partial",)},
        "component_checks": ("V5", "V7"),
    },
    "all-v0-v8-complete": {
        "obligations": ("V0", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"),
        "strength": "none",
        "production": False,
        "assumptions": frozenset({"jvm-timing-jit-cpu-gc", "crypto-hardness-entropy"}),
        "required_evidence": (
            ("formal/obligations.md", "documentation"),
            ("scripts/security/check_crypto_release.py", "tool-manifest"),
        ),
        "required_statuses": {},
        "component_checks": ("V0", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"),
        "complete_all": True,
    },
}

# Exact claim inventory.  A removed claim fails just as a removed obligation
# does; a new claim requires a reviewed checker update.
ALLOWED_CLAIMS = {
    "shake-mlkem-functional-production",
    "hkdf-isolated-functional",
    "hkdf-production-functional",
    "mlkem-reduceonce-historical-bytecode",
    "packet-nonce-bytecode",
    "saw-portable-alternate-route",
    "packet-receive-trace-scoped",
    "v8-nontiming-release-gate",
    "v8-timing-release-evidence",
    "current-release-jar-identity",
    "historical-adoption-jar-identity",
    "independent-expert-review",
    "cryptographic-security-proof",
    "jvm-constant-time",
    "whole-proxy-security",
    "aws-full-upstream-hkdf-replay",
    "packet-nonce-functional-production",
    "poly-source-trace-ni",
    "all-v0-v8-complete",
}
# A metadata/schema recognizer cannot establish a new theorem, expert review or
# timing result.  Only these claims have a reviewed, implemented semantic evidence
# validator in this checker.  Any other claim marked supported fails closed until a
# reviewed code+tests change adds validation for that category.
SEMANTICALLY_VALIDATED_SUPPORTED_CLAIMS = {
    "shake-mlkem-functional-production",
    "hkdf-isolated-functional",
    "hkdf-production-functional",
    "packet-receive-trace-scoped",
    "v8-nontiming-release-gate",
    "packet-nonce-functional-production",
    "poly-source-trace-ni",
}
COMPLETION_REQUIRED_CLAIMS = {
    "shake-mlkem-functional-production",
    "hkdf-production-functional",
    "v8-nontiming-release-gate",
    "v8-timing-release-evidence",
    "current-release-jar-identity",
    "independent-expert-review",
    "all-v0-v8-complete",
}
HASH_RE = re.compile(r"[0-9a-f]{64}")
# HKDF same-body source traces remain a scoped V7 contribution. These facts
# are pinned in checker code as well as ledger JSON: receipt/manifest trimming
# cannot silently remove the observer, controls or its trusted AST adapter.
HKDF_SOURCE_RECEIPT = "formal/source/hkdf/SOURCE-EVIDENCE.json"
HKDF_SOURCE_EVIDENCE = (('formal/source/hkdf/README.md', 'documentation'),
 ('formal/source/hkdf/HkdfTrace.dfy', 'proof-receipt'),
 ('formal/source/hkdf/inputs.json', 'input-manifest'),
 ('formal/source/hkdf/SOURCE-EVIDENCE.json', 'component-receipt'),
 ('formal/source/hkdf/run.py', 'tool-manifest'),
 ('formal/source/hkdf/test_run.py', 'test-source'),
 ('formal/source/hkdf/declarations.txt', 'source-inventory'),
 ('formal/source/hkdf/checker/HkdfCoverage.cs', 'tool-manifest'),
 ('formal/source/hkdf/checker/HkdfCoverage.csproj', 'tool-manifest'),
 ('formal/dafny/hkdf/Hkdf.dfy', 'spec-source'))
HKDF_SOURCE_EXACT = {'status': 'complete',
 'schema': 'microproxy.hkdf-source-traces/v1',
 'positive': {'harness_included': {'errors': 0, 'verified': 259},
              'hkdf_body': {'errors': 0, 'verified': 248}},
 'audit': [{'file': 'formal/dafny/hkdf/Hkdf.dfy', 'findings': 1},
           {'file': 'formal/source/hkdf/HkdfTrace.dfy', 'findings': 0}],
 'controls': {'actual-call-trace-binding': {'classification': 'resolved-ast-coverage-rejection',
                                            'needle': 'actual trace output cannot be rebound by a '
                                                      'call'},
              'array-shadow': {'classification': 'resolved-ast-coverage-rejection',
                               'needle': "sequence read source is not the method's formal "
                                         'labelUnits'},
              'block-boundary-pending': {'classification': 'resolved-ast-coverage-rejection',
                                         'harness': {'errors': 0, 'verified': 259},
                                         'method': {'errors': 0, 'verified': 248},
                                         'needle': 'pending observations at standalone block '
                                                   'boundary'},
              'by-method-helper': {'classification': 'resolved-ast-coverage-rejection',
                                   'needle': 'unsupported by-method function'},
              'callee-order-encTrace': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'callee ghost trace append is not the first '
                                                  'trace update'},
              'callee-order-expTrace': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'callee ghost trace append is not the first '
                                                  'trace update'},
              'callee-suchthat-model-erasure': {'classification': 'resolved-ast-coverage-rejection',
                                                'harness': {'errors': 0, 'verified': 257},
                                                'java_identical': True,
                                                'java_package_files': 9,
                                                'method': {'errors': 0, 'verified': 246},
                                                'needle': 'unsupported ghost statement '
                                                          'AssignSuchThatStmt in HKDF binding '
                                                          'grammar'},
              'callee-suchthat-same-model': {'classification': 'resolved-ast-coverage-rejection',
                                             'needle': 'unsupported ghost statement '
                                                       'AssignSuchThatStmt in HKDF binding '
                                                       'grammar'},
              'expect-secret-branch': {'classification': 'resolved-ast-coverage-rejection',
                                       'needle': 'unsupported executable statement ExpectStmt'},
              'ghost-call-callee-binding': {'classification': 'resolved-ast-coverage-rejection',
                                            'needle': 'ghost call output binding is unsupported in '
                                                      'HKDF binding grammar'},
              'ghost-call-trace-binding': {'classification': 'resolved-ast-coverage-rejection',
                                           'needle': 'ghost call output binding is unsupported in '
                                                     'HKDF binding grammar'},
              'ghost-if-marker': {'classification': 'resolved-ast-coverage-rejection',
                                  'needle': 'trace assignment inside ghost control flow'},
              'included-assumption-entry-audit': {'findings': 0,
                                                  'meaning': 'audit of EntryBom.dfy does not '
                                                             'traverse the included file'},
              'included-assumption-file-audit': {'findings': 1,
                                                 'meaning': 'official parser discovered the '
                                                            'BOM/comment-inline include; per-file '
                                                            'audit caught the axiom'},
              'interposed-assignment': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'observation count'},
              'local-shadow-trace': {'classification': 'resolved-ast-coverage-rejection',
                                     'needle': 'local/shadow trace variable'},
              'loop-exit-missing': {'classification': 'resolved-ast-coverage-rejection',
                                    'needle': 'missing post-loop false-guard observation'},
              'loop-exit-wrong-index': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'EvLoopExit index does not match'},
              'loop-increment-mismatch': {'classification': 'resolved-ast-coverage-rejection',
                                          'needle': 'loop increment must be loopVar'},
              'loop-init-conditional': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'loop initializer is not an unconditional '
                                                  'same-block definition'},
              'loop-start-mismatch': {'classification': 'resolved-ast-coverage-rejection',
                                      'needle': 'does not match executable event'},
              'match-source-secret': {'classification': 'resolved-ast-coverage-rejection',
                                      'needle': "sequence read source is not the method's formal "
                                                'labelUnits'},
              'metadata-branch-erases-boolean': {'classification': 'dafny-metadata-proof-failure',
                                                 'errors': 1,
                                                 'needle': 'MetadataEvBranchBoolean',
                                                 'verified': 0},
              'metadata-branch-erases-one-id': {'classification': 'dafny-metadata-proof-failure',
                                                'errors': 1,
                                                'needle': 'MetadataEvBranchBoolean',
                                                'verified': 0},
              'metadata-call-erases-arity': {'classification': 'dafny-metadata-proof-failure',
                                             'errors': 1,
                                             'needle': 'MetadataEvCallArity',
                                             'verified': 0},
              'metadata-mac-erases-lengths': {'classification': 'dafny-metadata-proof-failure',
                                              'errors': 2,
                                              'needle': 'MetadataEvMacKeyLen',
                                              'verified': 0},
              'metadata-mac-erases-target': {'classification': 'dafny-metadata-proof-failure',
                                             'errors': 1,
                                             'needle': 'MetadataEvMacTarget',
                                             'verified': 0},
              'metadata-ops-erases-shift': {'classification': 'dafny-metadata-proof-failure',
                                            'errors': 1,
                                            'needle': 'MetadataEvOpsShift',
                                            'verified': 0},
              'metadata-read-erases-address': {'classification': 'dafny-metadata-proof-failure',
                                               'errors': 1,
                                               'needle': 'MetadataEvReadAddress',
                                               'verified': 0},
              'nested-callee-suchthat': {'classification': 'resolved-ast-coverage-rejection',
                                         'needle': 'unsupported ghost statement AssignSuchThatStmt '
                                                   'in HKDF binding grammar'},
              'observed-secret-branch-harness': {'classification': 'dafny-assertion-failure',
                                                 'errors': 3,
                                                 'named': 'assert t1 == t2',
                                                 'verified': 257},
              'observed-secret-branch-method': {'errors': 0, 'verified': 249},
              'observed-secret-index-harness': {'classification': 'dafny-assertion-failure',
                                                'errors': 3,
                                                'named': 'assert t1 == t2',
                                                'verified': 257},
              'observed-secret-index-method': {'errors': 0, 'verified': 249},
              'observed-secret-metadata-harness': {'classification': 'dafny-assertion-failure',
                                                   'errors': 3,
                                                   'named': 'assert t1 == t2',
                                                   'verified': 257},
              'observed-secret-metadata-method': {'errors': 0, 'verified': 249},
              'omitted-mac-observer': {'classification': 'resolved-ast-coverage-rejection',
                                       'needle': 'observation count'},
              'pattern-call': {'classification': 'resolved-ast-coverage-rejection',
                               'needle': 'unobserved compiled function call'},
              'print-secret-index': {'classification': 'resolved-ast-coverage-rejection',
                                     'needle': 'unsupported executable statement PrintStmt'},
              'rereview-callee-order': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'callee ghost trace append is not the first '
                                                  'trace update'},
              'rereview-callee-order-harness': {'errors': 0, 'verified': 259},
              'rereview-callee-order-method': {'errors': 0, 'verified': 248},
              'rereview-datatype-eq2': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'unsupported executable equality/order on '
                                                  'non-scalar operand type'},
              'rereview-shadow-class-compilefalse': {'classification': 'resolved-ast-coverage-rejection',
                                                     'needle': 'reserved root name outside exact '
                                                               'VerifiedHkdf._default method'},
              'rereview-shadow-marker-map': {'classification': 'resolved-ast-coverage-rejection',
                                             'needle': 'reserved marker name outside exact '
                                                       'VerifiedHkdf._default ghost declaration'},
              'rereview-target-overflow': {'classification': 'resolved-ast-coverage-rejection',
                                           'needle': 'marker integer is outside supported 32-bit '
                                                     'range'},
              'reset-empty-trace': {'classification': 'resolved-ast-coverage-rejection',
                                    'needle': 'later trace update must append to the same actual '
                                              'trace prefix'},
              'reviewer-expect-ite-guarded': {'classification': 'resolved-ast-coverage-rejection',
                                              'needle': 'unsupported executable statement '
                                                        'ExpectStmt'},
              'reviewer-golden-before': {'classification': 'resolved-ast-coverage-rejection',
                                         'needle': 'later trace update must append to the same '
                                                   'actual trace prefix'},
              'reviewer-golden-empty': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'later trace update must append to the same '
                                                  'actual trace prefix'},
              'reviewer-golden-empty-before2': {'classification': 'resolved-ast-coverage-rejection',
                                                'needle': 'later trace update must append to the '
                                                          'same actual trace prefix'},
              'reviewer-golden-overwrite': {'classification': 'resolved-ast-coverage-rejection',
                                            'needle': 'later trace update must append to the same '
                                                      'actual trace prefix'},
              'reviewer-pattern-call': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'unobserved compiled function call'},
              'reviewer-print-secret-index': {'classification': 'resolved-ast-coverage-rejection',
                                              'needle': 'unsupported executable statement '
                                                        'PrintStmt'},
              'reviewer-shadow-fake': {'classification': 'resolved-ast-coverage-rejection',
                                       'needle': 'local/shadow trace variable'},
              'reviewer-shadow-marker-call': {'classification': 'resolved-ast-coverage-rejection',
                                              'needle': 'unobserved compiled function call'},
              'seqeq-private': {'classification': 'resolved-ast-coverage-rejection',
                                'needle': 'unsupported executable sequence/collection comparison '
                                          'operator'},
              'shadow-callee': {'classification': 'resolved-ast-coverage-rejection',
                                'needle': 'unobserved compiled function call'},
              'shadow-marker-call': {'classification': 'resolved-ast-coverage-rejection',
                                     'needle': 'unobserved compiled function call'},
              'site-label-collision': {'classification': 'resolved-ast-coverage-rejection',
                                       'needle': 'duplicate site label'},
              'site-label-nonliteral': {'classification': 'resolved-ast-coverage-rejection',
                                        'needle': 'site label must be an integer literal'},
              'site-relabel-accept': {'checker': 'HKDF-SOURCE-COVERAGE OK',
                                      'classification': 'accepted-bijective-relabel',
                                      'harness': {'errors': 0, 'verified': 259},
                                      'method': {'errors': 0, 'verified': 248}},
              'stale-marker': {'classification': 'resolved-ast-coverage-rejection',
                               'needle': 'unmatched marker'},
              'statement-expression': {'classification': 'resolved-ast-coverage-rejection',
                                       'needle': 'unsupported statement expression in HKDF binding '
                                                 'grammar'},
              'synthetic-golden-trace': {'classification': 'resolved-ast-coverage-rejection',
                                         'needle': 'later trace update must append to the same '
                                                   'actual trace prefix'},
              'third-callee-dup': {'checker': {'classification': 'resolved-ast-coverage-rejection',
                                               'needle': 'duplicate callee ghost output binding'},
                                   'harness': {'errors': 0, 'verified': 260},
                                   'method': {'errors': 0, 'verified': 249}},
              'third-expdup': {'checker': {'classification': 'resolved-ast-coverage-rejection',
                                           'needle': 'duplicate callee ghost output binding'},
                               'harness': {'errors': 0, 'verified': 259},
                               'method': {'errors': 0, 'verified': 248}},
              'trace-suchthat-reset': {'classification': 'resolved-ast-coverage-rejection',
                                       'needle': 'unsupported ghost statement AssignSuchThatStmt '
                                                 'in HKDF binding grammar'},
              'unmarked-alloc': {'classification': 'resolved-ast-coverage-rejection',
                                 'needle': 'observation count'},
              'unmarked-call': {'classification': 'resolved-ast-coverage-rejection',
                                'needle': 'observation count'},
              'unmarked-secret-branch': {'classification': 'resolved-ast-coverage-rejection',
                                         'needle': 'if guard: observation count'},
              'unmarked-secret-read': {'classification': 'resolved-ast-coverage-rejection',
                                       'needle': "sequence read source is not the method's formal "
                                                 'labelUnits'}},
 'flags': ['--allow-external-contracts',
           '--verification-time-limit',
           '30',
           '--resource-limit',
           '50000000',
           '--cores',
           '2',
           '--solver-option',
           'O:smt.case_split=0'],
 'checker.positive': 'HKDF-SOURCE-COVERAGE OK',
 'checker.declarations': 66,
 'checker.source_closure': {'formal/dafny/hkdf/Hkdf.dfy': 'caea4393f1e85e77f717dbf47f635bc1851b4182b7b4f9d011eb66fddfaf3ddb',
                            'formal/source/hkdf/HkdfTrace.dfy': 'bef2d15cdc8f696b55e769777a6963fc3679affde9c1d50bedfe2368fe99f383'},
 'checker.build.assembly_sha256': '892df4bda85b2e4b5b884cdd321cb354bbbb7b1debc5c59ac28b257b4bb11a3e',
 'checker.build.sdk': '10.0.400',
 'checker.build.source_pins': {'HkdfCoverage.cs': '5dddfb8137f75509618d07265a77ecd5cf90b77751549044ad7e16237b120923',
                               'HkdfCoverage.csproj': 'a5cc8f6943c20e8476787b7b2858fa1a0c57982821e261bfb580eddfde7412a5'},
 'checker.build.directory_build_imports_disabled': True,
 'checker.assembly_sha256_after': '892df4bda85b2e4b5b884cdd321cb354bbbb7b1debc5c59ac28b257b4bb11a3e',
 'java.generated_package_files': 9,
 'java.generated_package_matches_committed_production': True,
 'java.aggregator_matches_fixture': True,
 'java.class_inventory_identical': True,
 'java.classes': 12,
 'java.abi_signatures': ['public static '
                         'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult '
                         'Extract(java.math.BigInteger, dafny.DafnySequence<? extends '
                         'java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>);',
                         'public static '
                         'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult '
                         'Expand(java.math.BigInteger, dafny.DafnySequence<? extends '
                         'java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>, '
                         'java.math.BigInteger);',
                         'public static '
                         'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult '
                         'LabelInfo(dafny.DafnySequence<? extends java.lang.Short>, '
                         'dafny.DafnySequence<? extends java.lang.Byte>, java.math.BigInteger);',
                         'public static '
                         'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult '
                         'ExpandLabel(java.math.BigInteger, dafny.DafnySequence<? extends '
                         'java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Short>, '
                         'dafny.DafnySequence<? extends java.lang.Byte>, java.math.BigInteger);'],
 'java.javac': 'javac 21.0.2',
 'metadata_targets': {'EvBranch': {'errors': 0, 'verified': 1},
                      'EvCall': {'errors': 0, 'verified': 1},
                      'EvMac': {'errors': 0, 'verified': 1},
                      'EvOps': {'errors': 0, 'verified': 1},
                      'EvRead': {'errors': 0, 'verified': 1}}}
REQUIRED_COMPONENT_EVIDENCE['V7'] += HKDF_SOURCE_EVIDENCE
REQUIRED_COMPONENT_CHECKS['V7']['receipt_checks'] += (
    (HKDF_SOURCE_RECEIPT, tuple(HKDF_SOURCE_EXACT)),
)
REQUIRED_COMPONENT_CHECKS['V7']['hash_maps'] += (
    ('formal/source/hkdf/inputs.json', 'inputs', (), (), ''),
    (HKDF_SOURCE_RECEIPT, 'inputs', (), (), ''),
    (HKDF_SOURCE_RECEIPT, 'java.hashes', (), (), 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf'),
)
for _path, _expected in HKDF_SOURCE_EXACT.items():
    REQUIRED_RECEIPT_EXACT[('V7', HKDF_SOURCE_RECEIPT, _path)] = _expected
_HKDF_SOURCE_INPUT_KEYS = ('formal/crypto/delivery.py',
 'formal/dafny/hkdf/GENERATED.json',
 'formal/dafny/hkdf/Hkdf.dfy',
 'formal/dafny/toolchain.py',
 'formal/dafny/tools.json',
 'formal/source/hkdf/HkdfTrace.dfy',
 'formal/source/hkdf/README.md',
 'formal/source/hkdf/checker/HkdfCoverage.cs',
 'formal/source/hkdf/checker/HkdfCoverage.csproj',
 'formal/source/hkdf/controls/rereview/callee-order/Hkdf.dfy',
 'formal/source/hkdf/controls/rereview/callee-order/HkdfTrace.dfy',
 'formal/source/hkdf/controls/rereview/datatype-eq2/Hkdf.dfy',
 'formal/source/hkdf/controls/rereview/shadow-class-compilefalse/Hkdf.dfy',
 'formal/source/hkdf/controls/rereview/shadow-marker-map/Hkdf.dfy',
 'formal/source/hkdf/controls/rereview/target-overflow/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/expect-ite-guarded/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/golden-before/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/golden-empty-before2/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/golden-empty/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/golden-overwrite/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/pattern-call/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/print-secret-index/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/shadow-fake/Hkdf.dfy',
 'formal/source/hkdf/controls/reviewer/shadow-marker-call/Hkdf.dfy',
 'formal/source/hkdf/controls/third/callee-dup/Hkdf.dfy',
 'formal/source/hkdf/controls/third/callee-dup/HkdfTrace.dfy',
 'formal/source/hkdf/controls/third/expdup/Hkdf.dfy',
 'formal/source/hkdf/controls/third/expdup/HkdfTrace.dfy',
 'formal/source/hkdf/declarations.txt',
 'formal/source/hkdf/fixtures/HkdfCrypto.java',
 'formal/source/hkdf/run.py',
 'formal/source/hkdf/test_run.py',
 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java',
 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java',
 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java')
for _receipt in ('formal/source/hkdf/inputs.json', HKDF_SOURCE_RECEIPT):
    REQUIRED_HASH_MAP_KEYS[('V7', _receipt, 'inputs', (), '')] = _HKDF_SOURCE_INPUT_KEYS
REQUIRED_HASH_MAP_KEYS[('V7', HKDF_SOURCE_RECEIPT, 'java.hashes', (), 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf')] = ('BytesResult.java',
 'BytesResult_Failure.java',
 'BytesResult_Success.java',
 'FailureKind.java',
 'FailureKind_InvalidHash.java',
 'FailureKind_InvalidKey.java',
 'FailureKind_InvalidLabel.java',
 'FailureKind_InvalidLength.java',
 '__default.java')
def _poly_require(condition: bool, label: str, message: str) -> None:
    if not condition:
        raise LedgerError(f"{label}: {message}")


def _poly_sha(value: Any, label: str, what: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise LedgerError(f"{label}: {what} is not a sha256")
    return value


def _poly_log_text(root: Path, index: dict[str, Any], relative: str, label: str) -> str:
    """Return the tracked bytes of a pinned producer log, bound by path+digest."""
    producer = index.get("producer_root")
    files = index.get("logs")
    if not isinstance(producer, str) or not producer:
        raise LedgerError(f"{label}: index producer_root missing")
    if not isinstance(files, dict):
        raise LedgerError(f"{label}: index logs missing")
    if relative not in files:
        raise LedgerError(f"{label}: required producer log is not indexed: {relative}")
    tracked = checked_path(root, POLY_SOURCE_TRACKED_PREFIX + relative, label)
    if digest(tracked) != files[relative]:
        raise LedgerError(f"{label}: tracked log differs from the index: {relative}")
    try:
        return tracked.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise LedgerError(f"{label}: unreadable log {relative}: {error}") from error


def _poly_diagnostics(text: str) -> tuple[tuple[int, int, str], ...]:
    """Parse the ordered (line, column, message) verifier diagnostics."""
    return tuple((int(line), int(column), message)
                 for line, column, message in re.findall(
                     r"\((\d+),(\d+)\): (?:Error|Related location): (.+)", text))


def _poly_record_log(root: Path, index: dict[str, Any], record: dict[str, Any],
                     key: str, relative: str, label: str, *, require_sha: bool = True) -> str:
    """Bind one record's absolute producer path and digest to the pinned log."""
    producer = index["producer_root"]
    expected = producer.rstrip("/") + "/" + relative
    _poly_require(record.get(key) == expected, label,
                  f"{label}: log path is not the pinned producer path {relative}")
    sha_key = key + "_sha256"
    if sha_key not in record and require_sha:
        raise LedgerError(f"{label}: {relative} record lacks its {sha_key}")
    if sha_key in record:
        _poly_sha(record.get(sha_key), label, f"{sha_key} for {relative}")
        _poly_require(record.get(sha_key) == index["logs"].get(relative), label,
                      f"{label}: log digest does not match the index for {relative}")
    return _poly_log_text(root, index, relative, label)


def _poly_summary(text: str, label: str, what: str) -> tuple[int, int, int]:
    summaries = POLY_SOURCE_LOG_SUMMARY.findall(text)
    if len(summaries) != 1:
        raise LedgerError(f"{label}: {what} must contain exactly one verifier summary")
    verified, errors, oor = summaries[0]
    return int(verified), int(errors), int(oor or 0)


def _poly_dafny_positive(text: str, verified: int, label: str, what: str,
                         *, minimum: int | None = None) -> None:
    if POLY_SOURCE_BAD_LOG.search(text):
        raise LedgerError(f"{label}: {what} contains an inconclusive diagnostic")
    if POLY_SOURCE_DIAGNOSTIC.search(text):
        raise LedgerError(f"{label}: {what} contains a verifier diagnostic")
    resolution = POLY_SOURCE_RESOLUTION.search(text)
    if resolution and int(resolution.group(1)) != 0:
        raise LedgerError(f"{label}: {what} contains resolution errors")
    got, errors, oor = _poly_summary(text, label, what)
    if errors != 0 or oor != 0:
        raise LedgerError(f"{label}: {what} is not clean (errors={errors}, oor={oor})")
    if minimum is not None:
        if got < minimum:
            raise LedgerError(f"{label}: {what} did not clear the minimum {minimum}")
    elif got != verified:
        raise LedgerError(f"{label}: {what} verified {got}, expected {verified}")


def _poly_audit_positive(text: str, findings: int, label: str, what: str) -> None:
    if POLY_SOURCE_BAD_LOG.search(text):
        raise LedgerError(f"{label}: {what} contains an inconclusive diagnostic")
    summaries = POLY_SOURCE_AUDIT_SUMMARY.findall(text)
    if len(summaries) != 1 or int(summaries[0]) != findings:
        raise LedgerError(f"{label}: {what} auditor findings do not match the record")


def _poly_checker_ok(text: str, roots: tuple[str, ...], label: str, what: str) -> None:
    if POLY_SOURCE_BAD_LOG.search(text):
        raise LedgerError(f"{label}: {what} contains an inconclusive diagnostic")
    if "Error:" in text or "resolution/type errors detected" in text:
        raise LedgerError(f"{label}: {what} contains a rejection diagnostic")
    match = POLY_SOURCE_CHECKER_OK.search(text)
    if match is None:
        raise LedgerError(f"{label}: {what} lacks the exact positive marker")
    printed = tuple(part for part in match.group(1).split(",") if part)
    if printed != tuple(roots):
        raise LedgerError(f"{label}: {what} printed roots differ from the recorded roots")


def _poly_checker_reject(text: str, needle: str, label: str, what: str) -> None:
    if POLY_SOURCE_BAD_LOG.search(text):
        raise LedgerError(f"{label}: {what} contains a tool crash/resource diagnostic")
    if "POLYNOMIAL-SOURCE-COVERAGE OK" in text:
        raise LedgerError(f"{label}: {what} is a success, not a rejection")
    if not needle or needle not in text:
        raise LedgerError(f"{label}: {what} does not contain the named rejection")
    if not POLY_SOURCE_DIAGNOSTIC.search(text):
        raise LedgerError(f"{label}: {what} has no Dafny diagnostic line")
    if not POLY_SOURCE_RESOLUTION.search(text):
        raise LedgerError(f"{label}: {what} has no resolution-error summary")


def _poly_dafny_negative(text: str, verified: int, errors: int, label: str,
                         what: str, anchor: str | None = None) -> None:
    if POLY_SOURCE_BAD_LOG.search(text):
        raise LedgerError(f"{label}: {what} is an inconclusive diagnostic, not a rejection")
    got, got_errors, oor = _poly_summary(text, label, what)
    if oor != 0 or got_errors != errors or got != verified:
        raise LedgerError(
            f"{label}: {what} summary {got}/{got_errors} does not match {verified}/{errors}")
    if "Error: " not in text:
        raise LedgerError(f"{label}: {what} has no named error diagnostic")
    if anchor and anchor not in text:
        raise LedgerError(f"{label}: {what} lacks the reviewed named anchor")


def _poly_log_index(root: Path, receipt: dict[str, Any], label: str) -> dict[str, Any]:
    index = load_json(checked_path(root, POLY_SOURCE_TRACKED_INDEX, label))
    _poly_require(index.get("schema") == "microproxy.crypto-poly-source-log-index/v1", label,
                  "tracked log index schema changed")
    report_ref = index.get("report")
    _poly_require(isinstance(report_ref, dict)
                  and report_ref.get("path") == POLY_SOURCE_TRACKED_REPORT, label,
                  "tracked report reference changed")
    tracked_report = checked_path(root, POLY_SOURCE_TRACKED_REPORT, label)
    _poly_require(report_ref.get("sha256") == digest(tracked_report), label,
                  "tracked report copy does not match the index")
    adopted = checked_path(root, POLY_SOURCE_RECEIPT, label)
    _poly_require(digest(tracked_report) == digest(adopted), label,
                  "adopted receipt is not the tracked actual producer report")
    files = index.get("logs")
    _poly_require(isinstance(files, dict) and files, label, "tracked log index has no logs")
    _poly_require(set(files) == set(POLY_SOURCE_LOG_PATHS), label,
                  "tracked log inventory changed; missing="
                  f"{sorted(set(POLY_SOURCE_LOG_PATHS) - set(files))} "
                  f"added={sorted(set(files) - set(POLY_SOURCE_LOG_PATHS))}")
    for relative, sha in files.items():
        _poly_sha(sha, label, f"tracked log sha for {relative}")
    return index


def _poly_validate_checks(root: Path, index: dict[str, Any], receipt: dict[str, Any],
                          label: str) -> int:
    """Require the exact 64-record inventory, not a 64-dict count."""
    checks = receipt.get("checks")
    _poly_require(isinstance(checks, list) and len(checks) == 64, label,
                  "reviewed check-record count changed")
    dump = json.dumps
    remaining = list(checks)
    top = (list(receipt["proofs"]) + list(receipt["audits"])
           + list(receipt["controls"]["canonical"]) + [receipt["controls"]["decoy"]]
           + list(receipt["controls"]["mutations"]) + list(receipt["controls"]["n1b"])
           + [receipt["controls"]["scope_probe"]])
    for record in top:
        wanted = dump(record, sort_keys=True)
        for position, candidate in enumerate(remaining):
            if dump(candidate, sort_keys=True) == wanted:
                remaining.pop(position)
                break
        else:
            name = (record.get("label") or record.get("file") or record.get("control")
                    or record.get("probe"))
            raise LedgerError(f"{label}: checks inventory dropped the reviewed record {name!r}")

    default_keys = {"classification", "command", "exit", "expected_pure_functions", "log",
                    "log_sha256", "root_count", "root_set_sha256", "roots", "selector", "text"}
    scope_keys = {"classification", "command", "exit", "log", "log_sha256", "root_count",
                  "root_set_sha256", "roots", "selector", "text"}
    rejection_keys = {"classification", "command", "exit", "log", "log_sha256", "needle",
                      "selector", "text"}
    negative_keys = {"classification", "command", "errors", "exit", "log", "log_sha256", "named",
                     "text", "verified"}
    green_keys = {"command", "errors", "exit", "log", "log_sha256", "text", "verified"}
    green_lemma_keys = {"command", "exit", "log", "log_sha256", "text"}
    counts = {"default": 0, "scope": 0, "rejection": 0, "negative": 0, "green": 0}
    seen_scopes: list[str] = []
    seen_rejections: list[tuple[str, str]] = []
    seen_negatives: list[tuple[Any, ...]] = []
    seen_greens: list[tuple[str, int]] = []
    checked = 0
    for item in remaining:
        if not isinstance(item, dict):
            raise LedgerError(f"{label}: malformed check record")
        keys = set(item)
        if keys == default_keys:
            counts["default"] += 1
            text = _poly_record_log(root, index, item, "log", POLY_SOURCE_DEFAULT_CHECKER_LOG,
                                    label)
            _poly_require(item.get("text") == text, label,
                          "default checker record text is not its tracked log")
            _poly_require(item.get("classification") == "resolved-ast-coverage-positive-exact",
                          label, "default checker classification changed")
            _poly_require(item.get("selector") == POLY_SOURCE_DEFAULT_SELECTOR, label,
                          "default checker selector changed")
            _poly_require(tuple(item.get("roots") or ()) == POLY_SOURCE_METHOD_ROOTS, label,
                          "default checker roots changed")
            _poly_require(item.get("root_count") == len(POLY_SOURCE_METHOD_ROOTS), label,
                          "default checker root count changed")
            _poly_require(tuple(item.get("expected_pure_functions") or ())
                          == POLY_SOURCE_PURE_FUNCTIONS, label,
                          "default checker pure-function identities changed")
            _poly_require(item.get("root_set_sha256") ==
                          hashlib.sha256("\n".join(item["roots"]).encode()).hexdigest(), label,
                          "default checker root-set digest changed")
            _poly_require(text.split("\n", 1)[0] == POLY_SOURCE_DEFAULT_FIRST_LINE, label,
                          "default checker printed roots changed")
            _poly_checker_ok(text, POLY_SOURCE_METHOD_ROOTS, label, "default checker log")
            checked += 8
            continue
        if keys == scope_keys:
            counts["scope"] += 1
            selector = dump(item.get("selector"), sort_keys=True)
            roots = tuple(item.get("roots") or ())
            matches = [entry for entry in POLY_SOURCE_POSITIVE_SCOPES if entry[0] == selector]
            _poly_require(len(matches) == 1, label, f"unexpected positive scope {selector}")
            seen_scopes.append(selector)
            _, want_roots, want_count, rel, want_first = matches[0]
            _poly_require(roots == want_roots and item.get("root_count") == want_count, label,
                          f"positive scope roots/count changed for {selector}")
            _poly_require(item.get("text", "").split("\n", 1)[0] == want_first, label,
                          f"positive scope diagnostic changed for {selector}")
            text = _poly_record_log(root, index, item, "log", rel, label)
            _poly_require(item.get("text") == text, label,
                          f"positive scope text is not its tracked log for {selector}")
            _poly_require(item.get("classification") == "resolved-ast-coverage-positive-exact",
                          label, f"positive scope classification changed for {selector}")
            _poly_require(item.get("root_set_sha256") ==
                          hashlib.sha256("\n".join(item["roots"]).encode()).hexdigest(), label,
                          f"positive scope root-set digest changed for {selector}")
            _poly_checker_ok(text, roots, label, f"positive scope log {selector}")
            checked += 7
            continue
        if keys == rejection_keys:
            counts["rejection"] += 1
            selector = dump(item.get("selector"), sort_keys=True)
            needle = item.get("needle")
            matches = [entry for entry in POLY_SOURCE_REJECTIONS
                       if entry[0] == selector and entry[1] == needle]
            _poly_require(len(matches) == 1, label,
                          f"unexpected checker rejection {selector}: {needle}")
            seen_rejections.append((selector, needle))
            _, _, rel, want_first = matches[0]
            _poly_require(item.get("text", "").split("\n", 1)[0] == want_first, label,
                          f"checker rejection diagnostic changed for {selector}")
            text = _poly_record_log(root, index, item, "log", rel, label)
            _poly_require(item.get("text") == text, label,
                          f"rejection text is not its tracked log for {selector}")
            _poly_require(item.get("classification") == "resolved-ast-coverage-rejection", label,
                          f"rejection classification changed for {selector}")
            _poly_require(item.get("exit") == 2, label, f"rejection exit changed for {selector}")
            _poly_checker_reject(text, needle, label, f"rejection log {selector}")
            checked += 6
            continue
        if keys == negative_keys:
            counts["negative"] += 1
            first = item.get("text", "").split("\n", 1)[0]
            matches = [entry for entry in POLY_SOURCE_DAFNY_NEGATIVES
                       if entry[1] == first and entry[2] == item.get("verified")]
            _poly_require(len(matches) == 1, label, f"unexpected Dafny negative {first}")
            seen_negatives.append(matches[0])
            rel, _, _, anchor = matches[0]
            _poly_require(item.get("named") == anchor, label,
                          f"Dafny negative anchor changed for {first}")
            _poly_require(item.get("classification") == "dafny-assertion-failure", label,
                          f"Dafny negative classification changed for {first}")
            _poly_require(item.get("errors") == 1, label, f"Dafny negative errors changed for {first}")
            text = _poly_record_log(root, index, item, "log", rel, label)
            _poly_require(item.get("text") == text, label,
                          f"Dafny negative text is not its tracked log for {first}")
            _poly_dafny_negative(text, item["verified"], 1, label, f"Dafny negative {first}", anchor)
            checked += 6
            continue
        if keys in (green_keys, green_lemma_keys):
            counts["green"] += 1
            producer = index["producer_root"].rstrip("/") + "/"
            path = item.get("log")
            _poly_require(isinstance(path, str) and path.startswith(producer), label,
                          "green check log is not a producer path")
            relative = path[len(producer):]
            _poly_require((relative, item.get("verified", 2)) in set(POLY_SOURCE_GREEN_CHECKS),
                          label, f"green check log is not a reviewed green log: {relative}")
            text = _poly_record_log(root, index, item, "log", relative, label)
            _poly_require(item.get("text") == text, label,
                          f"green check text is not its tracked log {relative}")
            _poly_dafny_positive(text, item.get("verified", 2), label, f"green check {relative}")
            seen_greens.append((relative, item.get("verified", 2)))
            checked += 5
            continue
        raise LedgerError(f"{label}: unexpected check record shape: {sorted(keys)}")
    _poly_require(counts["default"] == 1, label, "default checker record missing or duplicated")
    _poly_require(counts["scope"] == len(POLY_SOURCE_POSITIVE_SCOPES), label,
                  "method/function positive scope inventory changed")
    _poly_require(counts["rejection"] == len(POLY_SOURCE_REJECTIONS), label,
                  "checker rejection inventory changed")
    _poly_require(counts["negative"] == len(POLY_SOURCE_DAFNY_NEGATIVES), label,
                  "Dafny negative control inventory changed")
    _poly_require(counts["green"] == len(POLY_SOURCE_GREEN_CHECKS), label,
                  "green control inventory changed")
    _poly_require(len(seen_scopes) == len(set(seen_scopes))
                  and set(seen_scopes) == {entry[0] for entry in POLY_SOURCE_POSITIVE_SCOPES},
                  label, "positive-scope identities are duplicated or incomplete")
    _poly_require(len(seen_rejections) == len(set(seen_rejections))
                  and set(seen_rejections) ==
                  {(entry[0], entry[1]) for entry in POLY_SOURCE_REJECTIONS},
                  label, "checker-rejection identities are duplicated or incomplete")
    _poly_require(len(seen_negatives) == len(set(seen_negatives))
                  and set(seen_negatives) == set(POLY_SOURCE_DAFNY_NEGATIVES),
                  label, "Dafny-negative identities are duplicated or incomplete")
    _poly_require(len(seen_greens) == len(set(seen_greens))
                  and set(seen_greens) == set(POLY_SOURCE_GREEN_CHECKS),
                  label, "green-control identities are duplicated or incomplete")
    return checked + len(remaining)


def _poly_validate_focused_control(root: Path, index: dict[str, Any],
                                   receipt: dict[str, Any], item: dict[str, Any],
                                   label: str) -> int:
    """Bind the actual ZetasValue counterexample to a non-vacuous original.

    This checks the executed producer's scope/records/logs. It does not turn
    logs into a proof of execution or remove the verifier/producer boundary.
    """
    focus = item.get("focused")
    _poly_require(item.get("control") == POLY_SOURCE_FOCUSED_CONTROL
                  and isinstance(focus, dict)
                  and set(focus) == {"filter_symbol", "original", "mutant", "note"},
                  label, "focused control record is missing or malformed")
    _poly_require(focus["filter_symbol"] == POLY_SOURCE_FOCUSED_SYMBOL, label,
                  "focused filter symbol changed")
    view = item.get("dafny")
    _poly_require(isinstance(view, dict)
                  and set(view) == {"verified", "errors", "filter_symbol", "named",
                                   "classification", "paired_original"}, label,
                  "focused Dafny result shape changed")
    _poly_require(view["filter_symbol"] == POLY_SOURCE_FOCUSED_SYMBOL
                  and view["named"] == POLY_SOURCE_FOCUSED_ANCHOR
                  and view["classification"] == "focused-dafny-postcondition-counterexample",
                  label, "focused Dafny symbol, anchor or classification changed")
    original, mutant = focus["original"], focus["mutant"]
    keys = {"command", "exit", "log", "log_sha256", "verified", "errors"}
    _poly_require(isinstance(original, dict) and set(original) == keys
                  and isinstance(mutant, dict) and set(mutant) == keys, label,
                  "focused original/mutant record shape changed")
    _poly_require(view["paired_original"] == original, label,
                  "focused paired original copies disagree")
    _poly_require(all(type(original[k]) is int for k in ("verified", "errors", "exit"))
                  and (original["verified"], original["errors"], original["exit"]) == (1, 0, 0),
                  label, "focused original must verify one obligation without errors")
    _poly_require(all(type(mutant[k]) is int for k in ("verified", "errors", "exit"))
                  and (mutant["verified"], mutant["errors"], mutant["exit"]) == (0, 1, 4),
                  label, "focused mutant must fail the one actual postcondition")
    _poly_require(mutant == {"command": item.get("dafny_command"),
                            "exit": item.get("dafny_exit"), "log": item.get("dafny_log"),
                            "log_sha256": item.get("dafny_log_sha256"),
                            "verified": view["verified"], "errors": view["errors"]},
                  label, "focused mutant copies disagree")
    proof = next((p for p in receipt.get("proofs", [])
                  if p.get("label") == "polynomial"), {})
    command = proof.get("command")
    _poly_require(isinstance(command, list) and len(command) == 11
                  and all(isinstance(x, str) for x in command)
                  and command[1] == "verify"
                  and command[3:] == list(POLY_SOURCE_FOCUSED_POLICY), label,
                  "focused original's full positive command or policy changed")
    suffix = [*POLY_SOURCE_FOCUSED_POLICY, "--filter-symbol", POLY_SOURCE_FOCUSED_SYMBOL]
    _poly_require(original["command"] == [*command[:3], *suffix], label,
                  "focused original command does not target the actual positive source")
    mutant_command = mutant["command"]
    _poly_require(isinstance(mutant_command, list) and len(mutant_command) == 13
                  and all(isinstance(x, str) for x in mutant_command)
                  and mutant_command[:2] == command[:2]
                  and mutant_command[3:] == suffix, label,
                  "focused mutant command, filter or policy changed")
    source = Path(mutant_command[2])
    _poly_require(source.is_absolute() and ".." not in source.parts
                  and source.parts[-3:] == ("formal", "crypto", "NativePolynomial.dfy")
                  and source.parents[2].name.startswith("poly-mutation-missing-false-prefix-"),
                  label, "focused mutant command is not the actual mutation source")
    text = _poly_record_log(root, index, original, "log",
                            POLY_SOURCE_FOCUSED_ORIGINAL_LOG, label)
    _poly_dafny_positive(text, 1, label, "focused original log")
    mutant_log = POLY_SOURCE_MUTATION_LOGS[POLY_SOURCE_FOCUSED_CONTROL][1]
    text = _poly_record_log(root, index, mutant, "log", mutant_log, label)
    _poly_require(_poly_diagnostics(text) ==
                  POLY_SOURCE_MUTATION_DIAGNOSTICS[POLY_SOURCE_FOCUSED_CONTROL], label,
                  "focused mutant diagnostics changed")
    _poly_require(POLY_SOURCE_FOCUSED_ANCHOR in text, label,
                  "focused mutant log lacks the actual trace postcondition")
    _poly_dafny_negative(text, 0, 1, label, "focused mutant log",
                         POLY_SOURCE_MUTATION_DIAGNOSTICS[POLY_SOURCE_FOCUSED_CONTROL][0][2])
    return 14


def _validate_poly_source_evidence(root: Path, label: str = "V7:poly-source") -> int:
    """Semantic gate for the actual portable-package report; not a shape check.

    The report is a real run artifact, so this function re-derives every
    load-bearing property from repository bytes instead of trusting a boolean:
    before/after guards, the two input maps, exact proof/audit/control
    inventories, the 20 resolved method identities (uniqueness, not a count),
    the 19 pure functions, the repeated-root rejection guard, checker pins, the
    pre-adoption baseline and the 65/65 dual-JDK class identity.
    """
    receipt = load_json(checked_path(root, POLY_SOURCE_RECEIPT, label))
    index = _poly_log_index(root, receipt, label)
    checked = 1
    _poly_require(receipt.get("schema") == POLY_SOURCE_SCHEMA, label, "receipt schema changed")
    _poly_require(receipt.get("status") == "complete", label, "receipt is not complete")
    _poly_require(receipt.get("all_checks_ok") is True, label, "runner did not report all_checks_ok")
    _poly_require(str(receipt.get("artifact_claim", "")).startswith("none"), label,
                  "receipt must not claim a delivery artifact")
    _poly_require(receipt.get("inputs_unchanged") is True, label, "inputs_unchanged is not true")
    _poly_require(isinstance(receipt.get("root"), str) and receipt["root"], label,
                  "producer root is missing")
    checked += 5

    before = receipt.get("inputs_before")
    after = receipt.get("inputs_after")
    _poly_require(isinstance(before, dict) and isinstance(after, dict), label,
                  "inputs_before/after must be objects")
    _poly_require(before == after, label, "inputs_before and inputs_after differ")
    _poly_require(set(before) == set(POLY_SOURCE_INPUT_KEYS), label,
                  "input inventory changed; missing="
                  f"{sorted(set(POLY_SOURCE_INPUT_KEYS) - set(before))} "
                  f"added={sorted(set(before) - set(POLY_SOURCE_INPUT_KEYS))}")
    for relative in sorted(before):
        _poly_sha(before[relative], label, f"input hash for {relative}")
        if checked_path(root, relative, label).is_file():
            if digest(checked_path(root, relative, label)) != before[relative]:
                raise LedgerError(f"{label}: stale input hash for {relative}")
        else:
            raise LedgerError(f"{label}: missing input {relative}")
    checked += len(before)

    manifest = load_json(checked_path(root, POLY_SOURCE_INPUTS, label))
    _poly_require(manifest.get("schema") == POLY_SOURCE_INPUTS_SCHEMA, label,
                  "inputs.json schema changed")
    pins = manifest.get("inputs")
    _poly_require(isinstance(pins, dict) and pins, label, "inputs.json has no pin map")
    expected_pins = {name: sha for name, sha in before.items() if name != POLY_SOURCE_INPUTS}
    _poly_require(pins == expected_pins, label,
                  "inputs.json pins differ from the receipt's before/after guard")
    _poly_require(receipt.get("inputs_manifest_sha256") == before[POLY_SOURCE_INPUTS], label,
                  "inputs_manifest_sha256 does not match the pinned inputs.json")
    checked += 4

    _poly_require(receipt.get("policy") == POLY_SOURCE_POLICY, label, "proof budget policy changed")
    checked += 1

    proofs = receipt.get("proofs")
    _poly_require(isinstance(proofs, list) and len(proofs) == len(POLY_SOURCE_PROOFS), label,
                  "proof inventory changed")
    by_label = {item.get("label"): item for item in proofs if isinstance(item, dict)}
    _poly_require(len(by_label) == len(POLY_SOURCE_PROOFS), label, "duplicate proof labels")
    for proof_label, target, verified in POLY_SOURCE_PROOFS:
        item = by_label.get(proof_label)
        _poly_require(isinstance(item, dict), label, f"missing proof {proof_label}")
        _poly_require(item.get("target") == target, label, f"proof target changed: {proof_label}")
        _poly_require(item.get("verified") == verified and item.get("expected") == verified, label,
                      f"proof count changed: {proof_label}")
        _poly_require(item.get("errors") == 0 and item.get("exit") == 0, label,
                      f"proof failed: {proof_label}")
        split = 3 if proof_label == "mlkem-composition" else 0
        _poly_require(item.get("flags") == ["--verification-time-limit", "30", "--resource-limit",
                                           "50000000", "--cores", "2", "--solver-option",
                                           f"O:smt.case_split={split}"], label,
                      f"proof flags changed: {proof_label}")
        text = _poly_record_log(root, index, item, "log",
                                POLY_SOURCE_PROOF_LOGS[proof_label], label)
        _poly_dafny_positive(text, verified, label, f"proof log {proof_label}")
        checked += 7

    audits = receipt.get("audits")
    _poly_require(isinstance(audits, list) and len(audits) == len(POLY_SOURCE_AUDIT_FILES), label,
                  "audit inventory changed")
    audit_files = []
    for item in audits:
        _poly_require(isinstance(item, dict), label, "malformed audit record")
        audit_files.append(item.get("file"))
        _poly_require(item.get("findings") == 0 and item.get("expected") == 0
                      and item.get("exit") == 0 and item.get("ok") is True, label,
                      f"audit finding for {item.get('file')}")
        relative = POLY_SOURCE_AUDIT_LOGS.get(item.get("file"))
        _poly_require(relative is not None, label, f"unexpected audited file {item.get('file')}")
        text = _poly_record_log(root, index, item, "log", relative, label)
        _poly_audit_positive(text, 0, label, f"audit log {item.get('file')}")
    _poly_require(sorted(audit_files) == sorted(POLY_SOURCE_AUDIT_FILES), label,
                  "audited file set changed")
    checked += len(audits) * 7

    checker = receipt.get("checker")
    _poly_require(isinstance(checker, dict), label, "checker block missing")
    _poly_require(checker.get("source_pins") == {
        "PolynomialSourceCoverage.cs": POLY_SOURCE_CHECKER_SOURCE_PIN,
        "PolynomialSourceCoverage.csproj": POLY_SOURCE_CHECKER_PROJECT_PIN}, label,
        "checker source pins changed")
    _poly_require(checker.get("project_pin") == POLY_SOURCE_CHECKER_PROJECT_PIN, label,
                  "checker project pin changed")
    _poly_require(checker.get("sdk") == POLY_SOURCE_CHECKER_SDK, label, "checker SDK changed")
    _poly_require(checker.get("deterministic") is True and checker.get("debug_symbols") is False,
                  label, "checker build is not deterministic/debug-free")
    _poly_require(checker.get("directory_build_imports_disabled") is True, label,
                  "directory build imports are not disabled")
    commands = checker.get("command")
    _poly_require(isinstance(commands, list) and commands and commands[0] == "dotnet", label,
                  "checker build command changed")
    _poly_require("-p:ImportDirectoryBuildProps=false" in commands
                  and "-p:ImportDirectoryBuildTargets=false" in commands, label,
                  "checker build does not disable directory imports")
    _poly_require(any(str(part).startswith("-p:DafnyHome=") for part in commands), label,
                  "checker project does not take a portable DafnyHome")
    _poly_sha(checker.get("assembly_sha256"), label, "checker assembly sha")
    build_text = _poly_record_log(root, index, checker, "build_log",
                                  "checker-build/build.log", label)
    _poly_require("Build FAILED" not in build_text and "error CS" not in build_text, label,
                  "checker build log reports a failure")
    _poly_require(not POLY_SOURCE_BAD_LOG.search(build_text), label,
                  "checker build log is inconclusive")
    for relative, pin in (("formal/source/polynomial/checker/PolynomialSourceCoverage.cs",
                           POLY_SOURCE_CHECKER_SOURCE_PIN),
                          ("formal/source/polynomial/checker/PolynomialSourceCoverage.csproj",
                           POLY_SOURCE_CHECKER_PROJECT_PIN)):
        if digest(checked_path(root, relative, label)) != pin:
            raise LedgerError(f"{label}: checker file changed: {relative}")
    project_text = checked_path(
        root, "formal/source/polynomial/checker/PolynomialSourceCoverage.csproj", label).read_text(
            encoding="utf-8")
    _poly_require("ImportDirectoryBuild" not in project_text, label,
                  "checker project imports a directory build file")
    _poly_require("/Users/" not in project_text and "/opt/" not in project_text, label,
                  "checker project embeds an absolute toolchain path")
    checked += 17

    scope = receipt.get("checker_scope")
    _poly_require(isinstance(scope, dict), label, "checker_scope block missing")
    _poly_require(scope.get("identity_not_count_gate") is True, label,
                  "checker scope is a count-only gate")
    _poly_require(tuple(scope.get("default_method_roots") or ()) == POLY_SOURCE_METHOD_ROOTS, label,
                  "default resolved method roots changed")
    _poly_require(scope.get("default_method_root_count") == len(POLY_SOURCE_METHOD_ROOTS), label,
                  "default method root count changed")
    _poly_require(len(set(scope["default_method_roots"])) == len(POLY_SOURCE_METHOD_ROOTS), label,
                  "default method roots are not unique identities")
    _poly_require(tuple(scope.get("default_pure_functions") or ()) == POLY_SOURCE_PURE_FUNCTIONS,
                  label, "default pure function identities changed")
    _poly_require(scope.get("default_pure_function_count") == len(POLY_SOURCE_PURE_FUNCTIONS),
                  label, "default pure function count changed")
    _poly_require(set(scope.get("ambient_selectors_cleared") or ()) == {
        "POLY_TRACE_ROOTS", "POLY_TRACE_FUNCS"}, label, "ambient selector clearing changed")
    checked += 7

    controls = receipt.get("controls")
    _poly_require(isinstance(controls, dict), label, "controls block missing")
    canonical = controls.get("canonical")
    _poly_require(isinstance(canonical, list) and len(canonical) == 4, label,
                  "canonical control inventory changed")
    canonical_names = []
    for item in canonical:
        _poly_require(isinstance(item, dict), label, "malformed canonical control")
        canonical_names.append(item.get("control"))
        checker_view = item.get("checker") if isinstance(item.get("checker"), dict) else {}
        dafny_view = item.get("dafny") if isinstance(item.get("dafny"), dict) else {}
        _poly_require(checker_view.get("classification") == "resolved-ast-coverage-rejection"
                      and str(checker_view.get("needle") or "").strip(), label,
                      f"canonical control lacks a named checker rejection: {item.get('control')}")
        _poly_require(dafny_view.get("classification") == "dafny-proof-failure"
                      and isinstance(dafny_view.get("errors"), int) and dafny_view["errors"] > 0,
                      label, f"canonical control lacks a genuine proof failure: {item.get('control')}")
        _poly_require(item.get("ok") is True and item.get("checker_exit") == 2, label,
                      f"canonical control not rejected: {item.get('control')}")
        entry = POLY_SOURCE_CANONICAL_LOGS.get(item.get("control"))
        _poly_require(entry is not None, label, f"unexpected canonical control {item.get('control')}")
        dafny_text = _poly_record_log(root, index, item, "dafny_log", entry[1], label)
        checker_text = _poly_record_log(root, index, item, "checker_log", entry[0], label)
        _poly_require(item.get("dafny_exit") == 4 and item.get("checker_exit") == 2, label,
                      f"canonical control exits changed: {item.get('control')}")
        _poly_require(isinstance(item.get("named_bridge"), str)
                      and item["named_bridge"].strip(), label,
                      f"canonical control lacks a named bridge: {item.get('control')}")
        _poly_require(checker_view.get("needle") ==
                      POLY_SOURCE_CANONICAL_NEEDLES.get(item.get("control")), label,
                      f"canonical checker needle changed: {item.get('control')}")
        _poly_require(dafny_view.get("named") ==
                      POLY_SOURCE_CANONICAL_ANCHORS.get(item.get("control")), label,
                      f"canonical Dafny anchor changed: {item.get('control')}")
        _poly_require(_poly_diagnostics(dafny_text) ==
                      POLY_SOURCE_CANONICAL_DIAGNOSTICS.get(item.get("control")), label,
                      f"canonical Dafny diagnostics changed: {item.get('control')}")
        _poly_dafny_negative(dafny_text, dafny_view["verified"], dafny_view["errors"], label,
                             f"canonical dafny log {item.get('control')}",
                             POLY_SOURCE_CANONICAL_ANCHORS[item["control"]])
        _poly_checker_reject(checker_text, POLY_SOURCE_CANONICAL_NEEDLES[item["control"]], label,
                             f"canonical checker log {item.get('control')}")
        checked += 11
    _poly_require(tuple(canonical_names) == POLY_SOURCE_CANONICAL_CONTROLS, label,
                  "canonical control names changed")

    mutations = controls.get("mutations")
    _poly_require(isinstance(mutations, list) and len(mutations) == 16, label,
                  "mutation control inventory changed")
    mutation_names = []
    for item in mutations:
        _poly_require(isinstance(item, dict), label, "malformed mutation control")
        name = item.get("control")
        mutation_names.append(name)
        kind = POLY_SOURCE_MUTATIONS.get(name)
        _poly_require(kind is not None, label, f"unexpected mutation control: {name}")
        checker_view = item.get("checker") if isinstance(item.get("checker"), dict) else {}
        dafny_view = item.get("dafny") if isinstance(item.get("dafny"), dict) else {}
        if name == POLY_SOURCE_FOCUSED_CONTROL:
            checked += _poly_validate_focused_control(root, index, receipt, item, label)
        else:
            _poly_require("focused" not in item and "paired_original" not in dafny_view
                          and "filter_symbol" not in dafny_view, label,
                          f"unexpected focused scope on mutation {name}")
        _poly_require(str(checker_view.get("needle") or "").strip(), label,
                      f"mutation lacks a named checker rejection: {name}")
        _poly_require(item.get("ok") is True and item.get("checker_exit") == 2, label,
                      f"mutation not rejected by the checker: {name}")
        errors = dafny_view.get("errors")
        verified = dafny_view.get("verified")
        if kind == "dafny-proof-failure":
            _poly_require(isinstance(errors, int) and errors > 0, label,
                          f"reviewed proof failure no longer fails: {name}")
            _poly_require(item.get("dafny_evidence_usable") is True, label,
                          f"usable proof failure was downgraded: {name}")
        elif kind == "checker-only-rejection":
            _poly_require(errors == 0 and isinstance(verified, int) and verified > 0, label,
                          f"checker-only rejection no longer has a verifying proof: {name}")
            _poly_require(item.get("dafny_evidence_usable") is True, label,
                          f"checker-only rejection changed usability: {name}")
        else:
            _poly_require(item.get("dafny_evidence_usable") is False, label,
                          f"inconclusive mutation is usable as evidence: {name}")
            _poly_require(dafny_view.get("classification") == "observed-not-used-as-proof", label,
                          f"inconclusive mutation classification changed: {name}")
        entry = POLY_SOURCE_MUTATION_LOGS.get(name)
        _poly_require(entry is not None, label, f"unexpected mutation log for {name}")
        checker_text = _poly_record_log(root, index, item, "checker_log", entry[0], label)
        dafny_text = _poly_record_log(root, index, item, "dafny_log", entry[1], label)
        expected_dafny_exit = 0 if kind == "checker-only-rejection" else 4
        _poly_require(item.get("checker_exit") == 2
                      and item.get("dafny_exit") == expected_dafny_exit, label,
                      f"mutation exits changed: {name}")
        _poly_require(checker_view.get("needle") == POLY_SOURCE_MUTATION_NEEDLES.get(name), label,
                      f"mutation checker needle changed: {name}")
        _poly_checker_reject(checker_text, POLY_SOURCE_MUTATION_NEEDLES[name], label,
                             f"mutation checker log {name}")
        if kind == "dafny-proof-failure":
            _poly_require(_poly_diagnostics(dafny_text) ==
                          POLY_SOURCE_MUTATION_DIAGNOSTICS.get(name), label,
                          f"mutation Dafny diagnostics changed: {name}")
            diagnostics = POLY_SOURCE_MUTATION_DIAGNOSTICS[name]
            _poly_dafny_negative(dafny_text, verified, errors, label,
                                 f"mutation dafny log {name}", diagnostics[0][2])
        elif kind == "checker-only-rejection":
            _poly_dafny_positive(dafny_text, verified, label, f"mutation dafny log {name}")
        else:
            _poly_require("out of resource" in dafny_text
                          or "out of memory" in dafny_text.lower(), label,
                          f"unusable mutation log is not an inconclusive resource diagnostic: {name}")
        checked += 8
    _poly_require(tuple(sorted(mutation_names)) == tuple(sorted(POLY_SOURCE_MUTATIONS)), label,
                  "mutation inventory changed")

    decoy = controls.get("decoy")
    _poly_require(isinstance(decoy, dict), label, "decoy control missing")
    _poly_require(decoy.get("ok") is True and decoy.get("checker_exit") == 2, label,
                  "decoy instance-class control was not rejected")
    _poly_require(decoy.get("rejection") == POLY_SOURCE_DECOY_REJECTION, label,
                  "decoy rejection is not the reviewed instance-class rejection")
    decoy_text = _poly_record_log(root, index, decoy, "checker_log",
                                  POLY_SOURCE_DECOY_LOG, label)
    _poly_checker_reject(decoy_text, POLY_SOURCE_DECOY_REJECTION, label, "decoy checker log")
    checked += 6

    n1b = controls.get("n1b")
    _poly_require(isinstance(n1b, list) and len(n1b) == 2, label, "N1b control inventory changed")
    for item in n1b:
        body = item.get("body") if isinstance(item, dict) else None
        _poly_require(isinstance(body, dict) and body.get("errors") == 0
                      and isinstance(body.get("verified"), int)
                      and isinstance(body.get("minimum"), int)
                      and body["verified"] >= body["minimum"], label,
                      "N1b proof did not clear its minimum")
        entry = POLY_SOURCE_N1B_LOGS.get(item.get("control"))
        _poly_require(entry is not None, label, f"unexpected N1b control {item.get('control')}")
        _poly_require(item.get("java_files") == POLY_SOURCE_GENERATED_FILES
                      and item.get("java_identical") is True, label,
                      f"N1b generated-Java identity changed: {item.get('control')}")
        body_text = _poly_record_log(root, index, item, "body_log", entry["body"], label,
                                     require_sha=False)
        _poly_dafny_positive(body_text, body["verified"], label,
                             f"N1b body log {item.get('control')}", minimum=body["minimum"])
        harness = item.get("harness") if isinstance(item.get("harness"), dict) else {}
        harness_text = _poly_record_log(root, index, item, "harness_log", entry["harness"], label,
                                        require_sha=False)
        _poly_dafny_positive(harness_text, harness.get("verified"), label,
                             f"N1b harness log {item.get('control')}")
        checker_text = _poly_record_log(root, index, item, "checker_log", entry["checker"], label)
        checker_view = item.get("checker") if isinstance(item.get("checker"), dict) else {}
        _poly_checker_reject(checker_text, checker_view.get("needle"), label,
                             f"N1b checker log {item.get('control')}")
        _poly_record_log(root, index, item, "generate_log", entry["generate"], label,
                         require_sha=False)
        checked += 8

    probe = controls.get("scope_probe")
    _poly_require(isinstance(probe, dict), label, "repeated-root scope probe missing")
    _poly_require(probe.get("probe") == "repeated-single-root", label,
                  "repeated-root scope probe changed")
    _poly_require(probe.get("rejected") is True and probe.get("ok") is True, label,
                  "repeated-root duplicate output was not rejected")
    _poly_require(probe.get("reason") == POLY_SOURCE_PROBE_REASON, label,
                  "repeated-root rejection reason changed")
    _poly_require(probe.get("exit") == 0, label,
                  "scope probe must record the checker's successful exit to prove the guard, not exit")
    selector = [part for part in str(probe.get("selector") or "").split(",") if part]
    _poly_require(len(selector) == len(POLY_SOURCE_METHOD_ROOTS), label,
                  "scope probe did not request as many roots as the default scope")
    _poly_require(len(set(selector)) == 1, label,
                  "scope probe selector is not the repeated single-root form")
    _poly_require(tuple(probe.get("expected_roots") or ()) == POLY_SOURCE_METHOD_ROOTS, label,
                  "scope probe expected-root identities changed")
    probe_text = _poly_record_log(root, index, probe, "log", POLY_SOURCE_PROBE_LOG, label)
    _poly_require(not POLY_SOURCE_BAD_LOG.search(probe_text), label,
                  "repeated-root probe log is inconclusive")
    probe_match = POLY_SOURCE_CHECKER_OK.search(probe_text)
    _poly_require(probe_match is not None, label,
                  "repeated-root probe log lacks the checker's success line")
    printed = [part for part in probe_match.group(1).split(",") if part]
    _poly_require(printed == selector, label,
                  "repeated-root probe log does not print the repeated selector roots")
    _poly_require(len(set(printed)) == 1, label,
                  "repeated-root probe log is not the duplicate-root form")
    checked += 11

    erasure = receipt.get("erasure")
    _poly_require(isinstance(erasure, dict), label, "erasure block missing")
    _poly_require(tuple(erasure.get("changed_java") or ()) == POLY_SOURCE_ERASED_JAVA, label,
                  "ghost erasure changed a different generated Java file set")
    _poly_require(erasure.get("generated_files") == POLY_SOURCE_GENERATED_FILES, label,
                  "generated file count changed")
    _poly_require(erasure.get("explicit_runtime_sha256") == POLY_SOURCE_RUNTIME["explicit_sha256"],
                  label, "explicit runtime changed")
    _poly_require(erasure.get("toolchain_runtime_sha256") == POLY_SOURCE_RUNTIME["toolchain_sha256"],
                  label, "toolchain runtime changed")
    _poly_require("approved Maven" in str(erasure.get("runtime_artifact") or ""), label,
                  "erasure runtime is not the approved Maven artifact")
    identity = erasure.get("class_bytes_identical")
    _poly_require(isinstance(identity, dict) and set(identity) == {"21", "25"}, label,
                  "dual-JDK class identity missing")
    for major in ("21", "25"):
        view = identity[major]
        _poly_require(isinstance(view, dict) and view.get("all_class_bytes_identical") is True
                      and view.get("changed") == []
                      and view.get("base_classes") == POLY_SOURCE_CLASS_COUNT
                      and view.get("trace_classes") == POLY_SOURCE_CLASS_COUNT, label,
                      f"JDK{major} class identity is not 65/65 identical")
    homes = erasure.get("java_homes")
    _poly_require(isinstance(homes, dict) and set(homes) == {"21", "25"}
                  and all(str(value).endswith(("java", "javac")) for value in homes.values()), label,
                  "dual-JDK compiler homes changed")
    checked += 9

    baseline = receipt.get("baseline")
    _poly_require(isinstance(baseline, dict), label, "baseline block missing")
    for key in ("commit", "tree", "files", "manifest_sha256"):
        _poly_require(baseline.get(key) == POLY_SOURCE_BASELINE[key], label,
                      f"baseline {key} changed")
    _poly_require(baseline.get("git_show_verified") is True
                  and baseline.get("baseline_authenticated") is True, label,
                  "baseline is not authenticated by git show")
    _poly_require("git" in str(baseline.get("authentication") or "").lower()
                  and "git show" in str(baseline.get("source_discovery") or "").lower(), label,
                  "baseline authentication method changed")
    template_path = checked_path(root, POLY_SOURCE_BASELINE_TEMPLATE, label)
    _poly_require(digest(template_path) == POLY_SOURCE_BASELINE["manifest_sha256"], label,
                  "baseline template bytes do not match the reviewed baseline manifest digest")
    template = load_json(template_path)
    for key in ("commit", "tree"):
        _poly_require(template.get(key) == POLY_SOURCE_BASELINE[key], label,
                      f"baseline template {key} changed")
    template_files = template.get("files")
    _poly_require(isinstance(template_files, dict)
                  and len(template_files) == POLY_SOURCE_BASELINE["files"], label,
                  "baseline template file count changed")
    for relative, expected in POLY_SOURCE_BASELINE_COMPONENT_PINS.items():
        _poly_require(template_files.get(relative) == expected, label,
                      f"baseline template is not the pre-adoption tree for {relative} "
                      "(candidate-as-own-baseline is rejected)")
    _poly_require("ghost" in str(template.get("scope") or "").lower(), label,
                  "baseline template scope changed")
    for relative in (POLY_SOURCE_BASELINE_HELPER, POLY_SOURCE_BASELINE_TEST):
        if not checked_path(root, relative, label).is_file():
            raise LedgerError(f"{label}: missing baseline tooling {relative}")
    checked += 12

    closure = receipt.get("official_source_closure")
    _poly_require(isinstance(closure, dict) and set(closure) == set(POLY_SOURCE_CLOSURE_COUNTS),
                  label, "official source closure set changed")
    for name, expected in POLY_SOURCE_CLOSURE_COUNTS.items():
        files = closure[name]
        _poly_require(isinstance(files, dict) and len(files) == expected, label,
                      f"source closure count changed: {name}")
        for relative, sha in files.items():
            _poly_require(relative in before and before[relative] == sha, label,
                          f"source closure file is not a pinned input: {relative}")
        checked += 1 + len(files)

    package_scope = receipt.get("package_scope")
    _poly_require(isinstance(package_scope, dict), label, "package_scope block missing")
    for key, expected in POLY_SOURCE_PACKAGE_SCOPE.items():
        _poly_require(tuple(package_scope.get(key) or ()) == expected, label,
                      f"package scope changed: {key}")
        for relative in expected:
            _poly_require(relative in before, label, f"package file is not a pinned input: {relative}")
        checked += 1 + len(expected)
    _poly_require(package_scope.get("top_level_fixture_readme_pinned") is False
                  and package_scope.get("top_level_port_manifest_pinned") is False, label,
                  "package pins prototype scaffold metadata")
    checked += 2

    runtime = receipt.get("runtime")
    _poly_require(isinstance(runtime, dict), label, "runtime block missing")
    _poly_require(runtime.get("explicit_sha256") == POLY_SOURCE_RUNTIME["explicit_sha256"]
                  and runtime.get("toolchain_sha256") == POLY_SOURCE_RUNTIME["toolchain_sha256"],
                  label, "runtime hashes changed")
    _poly_require("approved Maven" in str(runtime.get("approved_artifact") or ""), label,
                  "runtime is not the approved Maven artifact")
    _poly_require(str(runtime.get("path") or "").endswith("DafnyRuntime-4.9.1.jar"), label,
                  "runtime path is not the pinned Maven jar")
    checked += 5

    tool = receipt.get("tool")
    _poly_require(isinstance(tool, dict), label, "tool block missing")
    for key, expected in POLY_SOURCE_TOOL.items():
        _poly_require(tool.get(key) == expected, label, f"tool {key} changed")
    _poly_require(tool.get("explicit_runtime_sha256") == POLY_SOURCE_RUNTIME["explicit_sha256"]
                  and tool.get("toolchain_runtime_sha256") == POLY_SOURCE_RUNTIME["toolchain_sha256"],
                  label, "tool runtime hashes changed")
    _poly_require(str(tool.get("tools_manifest") or "").endswith("formal/dafny/tools.json"), label,
                  "tool manifest path changed")
    checked += len(POLY_SOURCE_TOOL) + 3

    boundaries = receipt.get("trust_boundaries")
    _poly_require(isinstance(boundaries, list)
                  and tuple(boundaries) == POLY_SOURCE_TRUST_BOUNDARIES, label,
                  "trust boundary list changed")
    checked += len(boundaries)

    checked += _poly_validate_checks(root, index, receipt, label)

    baseline_manifest = index.get("baseline")
    _poly_require(isinstance(baseline_manifest, dict), label,
                  "tracked baseline manifest reference missing")
    _poly_require(baseline_manifest.get("manifest_sha256") == POLY_SOURCE_BASELINE["manifest_sha256"],
                  label, "tracked baseline manifest sha changed")
    component = baseline_manifest.get("components")
    _poly_require(isinstance(component, dict), label, "tracked baseline lacks component pins")
    for relative, sha in POLY_SOURCE_BASELINE_COMPONENT_PINS.items():
        if component.get(relative) != sha:
            raise LedgerError(
                f"{label}: baseline is not the pre-adoption tree for {relative} "
                "(candidate-as-own-baseline is rejected)")
    checked += 6
    return checked


def _validate_poly_source_claim(root: Path, claim: dict[str, Any], label: str) -> int:
    """A supported poly claim must cite every reviewed input and pass the gate."""
    missing = [path for path, _kind in POLY_SOURCE_CLAIM_EVIDENCE if path not in claim["evidence"]]
    if missing:
        raise LedgerError(f"{label}: poly source claim does not cite {missing[0]}")
    return _validate_poly_source_evidence(root, label)


BAD_CONTROL_RE = re.compile(
    r"\b(timeout|timed out|out of resource|resource limit|resource exhaustion|"
    r"crash|crashed|killed|signal|segfault|parser error|parse error|"
    r"solver error|inconclusive)\b",
    re.IGNORECASE,
)


class LedgerError(RuntimeError):
    """A fail-closed ledger or evidence validation failure."""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except LedgerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LedgerError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LedgerError(f"expected a JSON object in {path}")
    return value


def _clean_relative(value: Any, label: str) -> PurePosixPath:
    if type(value) is not str or not value:
        raise LedgerError(f"{label}: path must be a nonempty relative string")
    if "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise LedgerError(f"{label}: path must be POSIX relative: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise LedgerError(f"{label}: path is not normalized/relative: {value!r}")
    return path


def checked_path(root: Path, value: Any, label: str, *, allow_dir: bool = False) -> Path:
    relative = _clean_relative(value, label)
    root = root.resolve()
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            if current.is_symlink():
                raise LedgerError(f"{label}: symlink path component rejected: {value!r}")
        except OSError as exc:
            raise LedgerError(f"{label}: cannot inspect {value!r}: {exc}") from exc
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise LedgerError(f"{label}: missing evidence path {value!r}: {exc}") from exc
    if not resolved.is_relative_to(root):
        raise LedgerError(f"{label}: path escapes repository: {value!r}")
    if allow_dir:
        if not resolved.is_dir():
            raise LedgerError(f"{label}: not a directory: {value!r}")
    elif not resolved.is_file():
        raise LedgerError(f"{label}: not a regular file: {value!r}")
    return resolved


def checked_hash(value: Any, label: str) -> str:
    if type(value) is not str or not HASH_RE.fullmatch(value) or value == "0" * 64:
        raise LedgerError(f"{label}: expected a pinned nonzero lowercase SHA-256")
    return value


def dot_get(value: Any, path: str, label: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise LedgerError(f"{label}: missing field {path!r}")
        current = current[part]
    return current


def _flatten_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{k}: {_flatten_text(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " ".join(_flatten_text(v) for v in value)
    return str(value)


def reject_inconclusive_control(value: Any, label: str) -> None:
    text = _flatten_text(value)
    match = BAD_CONTROL_RE.search(text)
    if match:
        raise LedgerError(f"{label}: timeout/resource/crash/parser text cannot be a control: {match.group(0)!r}")
    if isinstance(value, dict):
        for field in ("exit", "exit_code"):
            if field in value:
                code = value[field]
                if type(code) is not int:
                    raise LedgerError(f"{label}: non-integer {field}")
                if code < 0 or code in {124, 137, 143}:
                    raise LedgerError(f"{label}: interrupted/resource exit {code} is inconclusive")


def _evidence_index(obligation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for ref in obligation.get("evidence", []):
        result[ref["path"]] = ref
    return result


def _validate_hash_map(root: Path, receipt: dict[str, Any], check: dict[str, Any], label: str) -> int:
    mapping = dot_get(receipt, check["path"], label)
    if not isinstance(mapping, dict) or not mapping:
        raise LedgerError(f"{label}: hash map must be a nonempty object")
    include = check.get("include_prefixes")
    if include is not None and (not isinstance(include, list) or not include):
        raise LedgerError(f"{label}: include_prefixes must be a nonempty list when present")
    exclude = check.get("exclude_paths", [])
    if not isinstance(exclude, list) or any(type(value) is not str or not value for value in exclude):
        raise LedgerError(f"{label}: exclude_paths must be a string list")
    path_prefix = check.get("path_prefix", "")
    if type(path_prefix) is not str:
        raise LedgerError(f"{label}: path_prefix must be a string")
    if path_prefix:
        _clean_relative(path_prefix, f"{label}:path_prefix")
    count = 0
    for relative, expected in mapping.items():
        if relative in exclude:
            continue
        if include is not None and not any(relative.startswith(prefix) for prefix in include):
            continue
        actual_relative = str(PurePosixPath(path_prefix) / relative) if path_prefix else relative
        path = checked_path(root, actual_relative, label)
        checked_hash(expected, f"{label}:{relative}")
        if digest(path) != expected:
            raise LedgerError(f"{label}: stale source/evidence hash for {relative}")
        count += 1
    if count == 0:
        raise LedgerError(f"{label}: no hash entries were checked")
    return count


def _validate_control_group(root: Path, receipt_path: str, receipt: dict[str, Any],
                            group: dict[str, Any], label: str) -> int:
    controls_path = group.get("controls_path", "controls")
    controls = dot_get(receipt, controls_path, label)
    if not isinstance(controls, dict):
        raise LedgerError(f"{label}: controls must be an object")
    expected = group.get("expected")
    if not isinstance(expected, dict) or not expected:
        raise LedgerError(f"{label}: expected controls must be a nonempty object")
    actual_names = set(controls)
    expected_names = set(expected)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise LedgerError(f"{label}: control inventory changed; missing={missing} unexpected={extra}")
    if not group.get("allow_extra", False) and actual_names != expected_names:
        raise LedgerError(f"{label}: extra controls are not allowed")
    semantic_failure = False
    for name, expected_fields in expected.items():
        control = controls[name]
        if not isinstance(control, dict):
            raise LedgerError(f"{label}:{name}: control must be an object")
        reject_inconclusive_control(control, f"{label}:{name}")
        if not isinstance(expected_fields, dict) or not expected_fields:
            raise LedgerError(f"{label}:{name}: expected fields must be a nonempty object")
        for field, wanted in expected_fields.items():
            found = dot_get(control, field, f"{label}:{name}")
            if isinstance(wanted, str) and wanted == "*":
                if found is None or found == "":
                    raise LedgerError(f"{label}:{name}: field {field} must not be empty")
            elif found != wanted:
                raise LedgerError(
                    f"{label}:{name}: {field} changed (expected {wanted!r}, found {found!r})")
        if ("errors" in control and type(control["errors"]) is int and control["errors"] > 0) or any(
                token in _flatten_text(control).lower()
                for token in ("counterexample", "proof failure", "rejected", "violated")):
            semantic_failure = True
    if group.get("require_semantic_failure", True) and not semantic_failure:
        raise LedgerError(f"{label}: controls only show success labels, not a demonstrated failure")
    return len(expected)


def _validate_inventory(root: Path, check: dict[str, Any], label: str) -> int:
    receipt_path = check["receipt"]
    receipt = load_json(checked_path(root, receipt_path, label))
    delivered = dot_get(receipt, check.get("delivered_field", "delivered_sources"), label)
    if not isinstance(delivered, dict) or not delivered:
        raise LedgerError(f"{label}: delivered source inventory is empty")
    target_root = checked_path(root, check["root"], label, allow_dir=True)
    checked = 0
    for relative, expected in delivered.items():
        path = checked_path(root, str(PurePosixPath(check["root"]) / relative), label)
        checked_hash(expected, f"{label}:{relative}")
        if digest(path) != expected:
            raise LedgerError(f"{label}: delivered generated source changed: {relative}")
        checked += 1
    prefixes = check.get("managed_prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        raise LedgerError(f"{label}: managed_prefixes must be a nonempty list")
    for prefix in prefixes:
        directory = checked_path(root, str(PurePosixPath(check["root"]) / prefix.rstrip("/")), label, allow_dir=True)
        actual = {
            str(path.relative_to(root / check["root"]).as_posix())
            for path in directory.rglob("*") if path.is_file()
        }
        expected = {name for name in delivered if name.startswith(prefix)}
        if actual != expected:
            raise LedgerError(
                f"{label}: generated file inventory changed under {prefix}; "
                f"missing={sorted(expected - actual)} added={sorted(actual - expected)}")
    facade_manifest = check.get("facade_manifest")
    if facade_manifest:
        manifest = load_json(checked_path(root, facade_manifest, label))
        facades = manifest.get("facades")
        if not isinstance(facades, list) or not facades:
            raise LedgerError(f"{label}: facade list is empty")
        for facade in facades:
            wanted = checked_hash(facade.get("sha256"), f"{label}:facade")
            for field in ("source", "destination"):
                path = checked_path(root, facade.get(field), f"{label}:facade:{field}")
                if digest(path) != wanted:
                    raise LedgerError(f"{label}: facade {field} changed: {facade.get(field)}")
            checked += 1
    runtime_manifest = check.get("runtime_manifest")
    if runtime_manifest:
        manifest = load_json(checked_path(root, runtime_manifest, label))
        runtime = dot_get(manifest, "runtime", label)
        wanted = checked_hash(runtime.get("sha256"), f"{label}:runtime")
        if wanted != checked_hash(check.get("expected_runtime_sha256"), f"{label}:expected-runtime"):
            raise LedgerError(f"{label}: runtime hash is not the reviewed pin")
        for field in ("coordinate", "url"):
            if not isinstance(runtime.get(field), str) or not runtime[field]:
                raise LedgerError(f"{label}: runtime {field} is not pinned")
        if "runtime_sha256" in receipt and receipt["runtime_sha256"] != wanted:
            raise LedgerError(f"{label}: stage and delivery runtime hashes disagree")
    return checked


def _validate_receipt_checks(root: Path, obligation: dict[str, Any], label: str) -> int:
    checked = 0
    for index, check in enumerate(obligation.get("receipt_checks", [])):
        item = f"{label}:receipt[{index}]"
        if not isinstance(check, dict):
            raise LedgerError(f"{item}: must be an object")
        receipt_path = check.get("receipt")
        if receipt_path not in _evidence_index(obligation):
            raise LedgerError(f"{item}: receipt is not cited as obligation evidence")
        receipt = load_json(checked_path(root, receipt_path, item))
        values = check.get("values")
        if not isinstance(values, dict) or not values:
            raise LedgerError(f"{item}: values must be a nonempty object")
        for path, expected in values.items():
            found = dot_get(receipt, path, item)
            if found != expected:
                raise LedgerError(f"{item}: {path} changed (expected {expected!r}, found {found!r})")
            checked += 1
    return checked


def _validate_hash_maps(root: Path, obligation: dict[str, Any], label: str) -> int:
    checked = 0
    for index, check in enumerate(obligation.get("hash_maps", [])):
        item = f"{label}:hash-map[{index}]"
        if not isinstance(check, dict):
            raise LedgerError(f"{item}: must be an object")
        receipt_path = check.get("receipt")
        if receipt_path not in _evidence_index(obligation):
            raise LedgerError(f"{item}: receipt is not cited as obligation evidence")
        receipt = load_json(checked_path(root, receipt_path, item))
        checked += _validate_hash_map(root, receipt, check, item)
    return checked


def _validate_entry_hashes(root: Path, obligation: dict[str, Any], label: str) -> int:
    checked = 0
    for index, check in enumerate(obligation.get("entry_hash_checks", [])):
        item = f"{label}:entry-hash[{index}]"
        receipt_path = check.get("receipt")
        if receipt_path not in _evidence_index(obligation):
            raise LedgerError(f"{item}: receipt is not cited as obligation evidence")
        receipt = load_json(checked_path(root, receipt_path, item))
        entries = dot_get(receipt, check["path"], item)
        if not isinstance(entries, list) or not entries:
            raise LedgerError(f"{item}: entry list is empty")
        for entry in entries:
            path = checked_path(root, entry.get(check.get("path_key", "source")), item)
            wanted = checked_hash(entry.get(check.get("hash_key", "sha256")), item)
            if digest(path) != wanted:
                raise LedgerError(f"{item}: changed input {entry.get(check.get('path_key', 'source'))}")
            checked += 1
    return checked


def _validate_controls(root: Path, obligation: dict[str, Any], label: str) -> int:
    checked = 0
    for index, group in enumerate(obligation.get("control_groups", [])):
        item = f"{label}:control[{index}]"
        if not isinstance(group, dict):
            raise LedgerError(f"{item}: must be an object")
        receipt_path = group.get("receipt")
        if receipt_path not in _evidence_index(obligation):
            raise LedgerError(f"{item}: receipt is not cited as obligation evidence")
        receipt = load_json(checked_path(root, receipt_path, item))
        checked += _validate_control_group(root, receipt_path, receipt, group, item)
    return checked


def _validate_text_checks(root: Path, obligation: dict[str, Any], label: str) -> int:
    checked = 0
    for index, check in enumerate(obligation.get("text_checks", [])):
        item = f"{label}:text[{index}]"
        if not isinstance(check, dict):
            raise LedgerError(f"{item}: must be an object")
        path = checked_path(root, check.get("path"), item)
        if check["path"] not in _evidence_index(obligation):
            raise LedgerError(f"{item}: text source is not cited as obligation evidence")
        text = path.read_text(encoding="utf-8", errors="strict")
        markers = check.get("markers")
        if not isinstance(markers, list) or not markers or any(type(v) is not str or not v for v in markers):
            raise LedgerError(f"{item}: markers must be a nonempty string list")
        for marker in markers:
            if marker not in text:
                raise LedgerError(f"{item}: required reviewed statement missing: {marker!r}")
            checked += 1
    return checked


def _validate_nonvacuity(root: Path, obligation: dict[str, Any], label: str) -> int:
    nonvacuity = obligation.get("nonvacuity")
    if not isinstance(nonvacuity, dict):
        raise LedgerError(f"{label}: proof obligation lacks a named nonvacuity/domain control")
    if type(nonvacuity.get("name")) is not str or not nonvacuity["name"].strip():
        raise LedgerError(f"{label}: nonvacuity control lacks a name")
    path = nonvacuity.get("path")
    if path not in _evidence_index(obligation):
        raise LedgerError(f"{label}: nonvacuity path is not cited as obligation evidence")
    text = checked_path(root, path, f"{label}:nonvacuity").read_text(encoding="utf-8", errors="strict")
    markers = nonvacuity.get("markers")
    if not isinstance(markers, list) or not markers or any(type(v) is not str or not v for v in markers):
        raise LedgerError(f"{label}: nonvacuity markers must be a nonempty string list")
    for marker in markers:
        if marker not in text:
            raise LedgerError(f"{label}: nonvacuity/domain marker missing: {marker!r}")
    return len(markers)


def _validate_assumptions(ledger: dict[str, Any]) -> set[str]:
    assumptions = ledger.get("assumptions")
    if not isinstance(assumptions, dict) or not assumptions:
        raise LedgerError("assumptions must be a nonempty object")
    names = set(assumptions)
    if names != ALLOWED_ASSUMPTIONS:
        missing = sorted(ALLOWED_ASSUMPTIONS - names)
        unknown = sorted(names - ALLOWED_ASSUMPTIONS)
        raise LedgerError(f"assumption inventory changed; missing={missing} unexpected={unknown}")
    for name, entry in assumptions.items():
        if not isinstance(entry, dict):
            raise LedgerError(f"assumption {name}: must be an object")
        if type(entry.get("statement")) is not str or not entry["statement"].strip():
            raise LedgerError(f"assumption {name}: statement is required")
        evidence = entry.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise LedgerError(f"assumption {name}: evidence paths are required")
        if len(evidence) != len(set(evidence)):
            raise LedgerError(f"assumption {name}: duplicate evidence paths")
    return names


def _validate_evidence(root: Path, obligation: dict[str, Any], label: str) -> tuple[dict[str, dict[str, Any]], int]:
    evidence = obligation.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise LedgerError(f"{label}: evidence must be a nonempty list")
    index: dict[str, dict[str, Any]] = {}
    for position, ref in enumerate(evidence):
        item = f"{label}:evidence[{position}]"
        if not isinstance(ref, dict):
            raise LedgerError(f"{item}: must be an object")
        relative = _clean_relative(ref.get("path"), item)
        if relative.as_posix() in index:
            raise LedgerError(f"{item}: duplicate evidence path {relative}")
        kind = ref.get("kind")
        if kind not in ALLOWED_EVIDENCE_KINDS:
            raise LedgerError(f"{item}: unsupported evidence kind {kind!r}")
        if type(ref.get("role")) is not str or not ref["role"].strip():
            raise LedgerError(f"{item}: role is required")
        path = checked_path(root, relative.as_posix(), item)
        wanted = checked_hash(ref.get("sha256"), item)
        if digest(path) != wanted:
            raise LedgerError(f"{item}: stale/tampered evidence hash for {relative}")
        index[relative.as_posix()] = ref
    return index, len(evidence)


def _validate_dependency_graph(obligations: dict[str, dict[str, Any]]) -> None:
    for name, obligation in obligations.items():
        deps = obligation.get("dependencies")
        if not isinstance(deps, list):
            raise LedgerError(f"{name}: dependencies must be a list")
        if len(deps) != len(set(deps)):
            raise LedgerError(f"{name}: duplicate dependency")
        for dep in deps:
            if dep not in obligations:
                raise LedgerError(f"{name}: unknown dependency {dep}")
            if dep == name:
                raise LedgerError(f"{name}: self dependency")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise LedgerError(f"dependency cycle at {node}")
        if node in visited:
            return
        visiting.add(node)
        for dep in obligations[node]["dependencies"]:
            visit(dep)
        visiting.remove(node)
        visited.add(node)

    for node in obligations:
        visit(node)
    reachable: set[str] = set()
    stack = [ROOT_OBLIGATION]
    while stack:
        node = stack.pop()
        if node in reachable:
            continue
        reachable.add(node)
        stack.extend(obligations[node]["dependencies"])
    if reachable != set(obligations):
        raise LedgerError(f"dropped root leaf; not reachable from {ROOT_OBLIGATION}: {sorted(set(obligations) - reachable)}")


def _control_failure_value(field: str, value: Any) -> bool:
    if field == "errors":
        return type(value) is int and value > 0
    if field == "rejected":
        return type(value) is str and bool(value.strip())
    if field == "result":
        if type(value) is not str:
            return False
        text = value.lower()
        return any(token in text for token in (
            "failure", "counterexample", "rejected", "blocked", "violated", "error"))
    return False


def _validate_file_set(root: Path, check: dict[str, Any], label: str) -> int:
    receipt = load_json(checked_path(root, check["receipt"], label))
    mapping = dot_get(receipt, check["field"], label)
    if not isinstance(mapping, dict) or not mapping:
        raise LedgerError(f"{label}: file-set map must be a nonempty object")
    directory = checked_path(root, check["root"], label, allow_dir=True)
    actual = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*") if path.is_file()
    }
    expected = set(mapping)
    if actual != expected:
        raise LedgerError(
            f"{label}: generated file set changed; missing={sorted(expected - actual)} "
            f"added={sorted(actual - expected)}")
    for relative, expected_hash in mapping.items():
        path = checked_path(root, str(PurePosixPath(check["root"]) / relative), label)
        checked_hash(expected_hash, f"{label}:{relative}")
        if digest(path) != expected_hash:
            raise LedgerError(f"{label}: generated file changed: {relative}")
    return len(mapping)


REQUIRED_TRACE_BOUNDARIES = {'trusted': ['Dafny/Boogie/Z3',
             'javap parser and operand mapping',
             'declared policy of public/secret parameters, fields, allocations and call results',
             'javac/JVM word-operation observer (atomic, operand-independent cost)',
             'enumerated external contracts: JDK HMAC/SHA3, DafnyRuntime, JDK BigInteger/String/boxed '
             'deterministic calls',
             'opaque owned helper/adapter contracts listed in assumed_owned_callees; these are not '
             'callee trace proofs',
             'inline expansion of exact static certified owned callees: plain parameter-role identity, '
             'register renaming, entry and return copies (shape-bound to the direct translation, '
             'mutation-tested, not a JVM-semantics theorem)',
             'execution_controls.py paired-state seeding and finite runs over the frozen trace_exec '
             'mirror: a control on the promoted roots, not a theorem (parameters are taken from the '
             'frozen extractor param_regs; only the chosen finite pair per program is exercised)',
             'keccak_traces.py exact-target composition, public-provider oracle mapping and finite OracleView controls; runtime_primitives.py loaded-source binding and named private-count controls; these trusted bridges are not JVM refinement or physical timing proofs'],
 'execution_controls': {'machine_mirror': 'trace_exec.py: bounded interpreter of the frozen SecretTrace '
                                          'Apply/DoStep/Exec semantics used only for witness execution '
                                          'and copy-operand controls',
                        'mirror_cross_check': 'compiled ApplyProbe.dfy table compared row-by-row with '
                                              'trace_exec.apply; a mismatch fails the replay',
                        'witness_execution': 'a witness is reported as validated-finite-execution only '
                                             'when both runs reach a terminal instruction; otherwise '
                                             'the emitted lemma is hypothesis-only and no completed run '
                                             'is claimed',
                        'truncation': 'a fuel-truncated prefix is never recorded as a completed '
                                      'execution',
                        'scope': 'model-level operand/execution control; not a JVM value-refinement or '
                                 'timing theorem'},
 'composition_not_a_closure': 'The five original caller certificates keep their 19 opaque owned '
                              'contracts (unchanged by this replay). The composed Feed certificate is a '
                              'separate artifact that discharges only NativeCodec.Extract, PublicMod '
                              'and Wipe by inlining their certified bodies. In addition, this replay '
                              'checks two adapter-helper roots (HkdfBridge.sequence, '
                              'HkdfBridge.labelUnits) and nine NativeField owned-callee roots (seven '
                              'private-arithmetic bodies with Q/ReduceOnce/Reduce inlined, plus the Q '
                              'and MaxReduce public leaves) as separate certificates; those check new '
                              'bodies only and do NOT discharge any contract of the five original '
                              'callers. Two of the previously fifteen open roots are now checked, so '
                              'thirteen open roots remain listed in open_roots, and every unchecked '
                              'aggregate label (31, including "NativeMlKem.Field/NTT/codec/sampling '
                              'helpers") remains explicit.',
 'promoted_kind': 'finite paired-state / bounded-length execution controls',
 'promoted_note': 'finite model-execution controls on the exact promoted program text; not JVM value '
                  'refinement and no claim that every operand affects the result. A required '
                  'private-flow control must be `ok`; a structural `not-applicable` is accepted only '
                  'for genuinely public-only targets.'}


def _validate_trace_boundaries(report: dict[str, Any], label: str) -> int:
    # Trust/scope disclosures are part of the reviewed claim, not optional prose.
    promoted = report.get("promoted_controls")
    actual = {
        "trusted": report.get("trusted"),
        "execution_controls": report.get("execution_controls"),
        "composition_not_a_closure": report.get("composition_not_a_closure"),
        "promoted_kind": promoted.get("kind") if isinstance(promoted, dict) else None,
        "promoted_note": promoted.get("note") if isinstance(promoted, dict) else None,
    }
    if actual != REQUIRED_TRACE_BOUNDARIES:
        raise LedgerError(f"{label}: trace trust/scope boundary text changed")
    return len(actual)


TRACE_FIELD_PROFILE = {
    # obligations, expanded/direct instructions, parameter count, return register,
    # audited shift calls, inlined sites. These are reviewed snapshot identities.
    "ReduceOnce:(I)I": (29, 23, 19, 1, 22, 1, 2),
    "Reduce:(I)I": (53, 45, 19, 1, 25, 2, 4),
    "Add:(II)I": (37, 31, 7, 2, 10, 1, 3),
    "Sub:(II)I": (43, 35, 9, 2, 12, 1, 4),
    "Mul:(II)I": (61, 53, 7, 2, 10, 2, 5),
    "MulSub:(III)I": (67, 59, 11, 3, 16, 2, 6),
    "AddMul:(IIII)I": (63, 55, 9, 4, 14, 2, 5),
    "Q:()I": (7, 2, 2, 0, None, 0, 0),
    "MaxReduce:()I": (7, 2, 2, 0, None, 0, 0),
}
TRACE_CONTROL_INVARIANTS = {
    "public_registers_equal", "non_parameter_private_start_at_zero",
    "parameter_values_differ_across_runs", "parameter_values_distinct_within_run",
    "role_lengths_equal", "non_parameter_role_contents_equal",
    "parameter_secret_role_contents_differ", "differences_are_inputs_only",
}


def _validate_trace_pair(control: Any, label: str, *, private_params: list[int],
                         private_roles: list[str], return_register: int | None,
                         instructions: int, shifts: int, live_return: bool) -> None:
    """Validate finite control facts, independently of snapshot-digest renewal.

    This checks a trusted interpreter's recorded control, not JVM semantics or a
    universal value-liveness theorem. Runtime shift admission is an audit rule.
    """
    if not isinstance(control, dict):
        raise LedgerError(f"{label}: trace private execution control missing")
    invariants = control.get("state_invariants")
    checks = control.get("checks")
    required_checks = {
        "state_differences_are_inputs_only", "both_terminal_stop", "trace_equal",
        "public_registers_equal", "no_parameter_only_liveness", "audit_clean",
        "shift_counts_public", "no_owned_calls_remaining",
    }
    if live_return:
        required_checks |= {"non_parameter_private_flow", "return_value_differs"}
    rule = control.get("shift_count_rule")
    shift_calls = rule.get("shift_calls") if isinstance(rule, dict) else None
    if (control.get("kind") != "paired-state-execution-control"
            or control.get("status") != "ok"
            or control.get("seeds") != {"S": [11, 3], "T": [13, 5]}
            or control.get("require_liveness") is not live_return
            or control.get("parameter_registers") != private_params
            or control.get("private_scalar_parameters") != private_params
            or control.get("secret_parameter_roles") != private_roles
            or control.get("return_register") != return_register
            or control.get("audit_failures") != []
            or control.get("owned_call_targets") != []
            or not isinstance(invariants, dict) or set(invariants) != TRACE_CONTROL_INVARIANTS
            or any(value is not True for value in invariants.values())
            or not isinstance(checks, dict) or set(checks) != required_checks
            or any(value is not True for value in checks.values())
            or control.get("terminal") != {"s": "stop", "t": "stop"}
            or control.get("steps") != {"s": instructions, "t": instructions}
            or control.get("fuel") != max(32, instructions + 8)
            or control.get("trace_equal") is not True
            or control.get("public_registers_equal") is not True
            or control.get("parameter_only_liveness") is not False
            or not isinstance(rule, dict) or rule.get("all_counts_public") is not True
            or not isinstance(shift_calls, list) or len(shift_calls) != shifts
            or any(not isinstance(call, dict) or call.get("count_taint") != "pub"
                   or call.get("word_taint") != "sec" for call in shift_calls)):
        raise LedgerError(f"{label}: trace private execution control changed")
    events = control.get("events")
    if (not isinstance(events, dict) or not isinstance(events.get("s"), list)
            or events.get("s") != events.get("t")
            or any(not isinstance(event, list) or not event or type(event[0]) is not str
                   for event in events["s"])):
        raise LedgerError(f"{label}: trace paired observation tapes differ")
    differing = control.get("differing_registers")
    non_parameter = control.get("non_parameter_differing")
    if (not isinstance(differing, list)
            or any(type(reg) is not int or reg < 0 for reg in differing)
            or differing != sorted(set(differing))
            or non_parameter != [reg for reg in differing if reg not in private_params]
            or set(differing) & set(control.get("public_registers") or [])):
        raise LedgerError(f"{label}: trace private execution register projection changed")
    if live_return:
        if (not non_parameter or return_register not in non_parameter
                or control.get("return_differs") is not True
                or any(event[0] == "guard" for event in events["s"])):
            raise LedgerError(f"{label}: trace private return liveness changed")
    elif (private_roles and (differing != [] or non_parameter != []
                            or control.get("return_differs") is not False)):
        raise LedgerError(f"{label}: sequence control must not claim modeled copy/return liveness")


def _validate_trace_public_pair(control: Any, label: str) -> None:
    if (not isinstance(control, dict)
            or control.get("kind") != "paired-state-execution-control"
            or control.get("status") != "not-applicable: no private parameters or private parameter roles"
            or control.get("require_liveness") is not False
            or control.get("parameter_registers") != []
            or control.get("private_scalar_parameters") != []
            or control.get("secret_parameter_roles") != []
            or control.get("audit_failures") != []
            or control.get("owned_call_targets") != []
            or control.get("shift_count_rule") != {"shift_calls": [], "all_counts_public": True}
            or not isinstance(control.get("state_invariants"), dict)
            or set(control["state_invariants"]) != TRACE_CONTROL_INVARIANTS
            or any(value is not True for value in control.get("state_invariants", {}).values())):
        raise LedgerError(f"{label}: trace public-only control changed")


def _validate_trace_promoted_controls(report: dict[str, Any], label: str) -> int:
    """Bind duplicated control summaries to the exact checked helper records."""
    roots = report.get("roots", [])
    by_method = {item.get("method"): item for item in roots if isinstance(item, dict)}
    sequence = by_method.get("sequence:([BLjava/lang/String;)Ldafny/DafnySequence;", {})
    units = by_method.get("labelUnits:(Ljava/lang/String;)Ldafny/DafnySequence;", {})
    owner = "io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge"
    if any(item.get("class") != owner or item.get("role") != "adapter-helper-root"
           for item in (sequence, units)):
        raise LedgerError(f"{label}: trace adapter-helper identity changed")
    if (sequence.get("certificate") != "HkdfBridge_sequence.dfy"
            or units.get("certificate") != "HkdfBridge_labelUnits.dfy"
            or sequence.get("execution_control_required") is not True
            or units.get("execution_control_required") is not False):
        raise LedgerError(f"{label}: trace adapter-helper certificate identity changed")
    if sequence.get("witness") != "validated-finite-execution":
        raise LedgerError(f"{label}: trace sequence private-input witness missing")
    _validate_trace_pair(sequence.get("execution_control"), label + ":sequence",
                         private_params=[], private_roles=[owner.replace(".", "/") + ".sequence#p0"],
                         return_register=4, instructions=5, shifts=0, live_return=False)
    unit_control = units.get("execution_control")
    if not isinstance(unit_control, dict) or set(unit_control) != {"paired", "lengths"}:
        raise LedgerError(f"{label}: trace public-label control missing")
    _validate_trace_public_pair(unit_control["paired"], label + ":labelUnits")
    lengths = unit_control["lengths"]
    if (units.get("witness") != "public-only" or not isinstance(lengths, dict)
            or lengths.get("kind") != "length-execution-control" or lengths.get("status") != "ok"
            or lengths.get("lengths") != [0, 1, 3, 5] or lengths.get("seed_register") != 1
            or not isinstance(lengths.get("runs"), list) or len(lengths["runs"]) != 4):
        raise LedgerError(f"{label}: trace public-label length cohorts changed")
    for size, run in zip((0, 1, 3, 5), lengths["runs"]):
        if (not isinstance(run, dict) or run.get("length") != size or run.get("status") != "ok"
                or run.get("terminal") != "stop" or run.get("stores") != size
                or run.get("guards") != size + 1 or run.get("allocs") != [size, size]
                or run.get("alloc_sizes_match") is not True or run.get("store_count_matches") is not True):
            raise LedgerError(f"{label}: trace public-label executed length control changed")
    expected = {Path(item["certificate"]).stem: item for item in (sequence, units)}
    field_owner = "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default"
    for item in report.get("callee_roots", []):
        if item.get("class") == field_owner:
            expected[Path(item["certificate"]).stem] = item
    promoted = report.get("promoted_controls")
    rows = promoted.get("records") if isinstance(promoted, dict) else None
    if (not isinstance(promoted, dict) or promoted.get("status") != "ok"
            or not isinstance(rows, list) or len(rows) != 11 or len(expected) != 11
            or any(not isinstance(row, dict) for row in rows)
            or {row.get("certificate") for row in rows} != set(expected)):
        raise LedgerError(f"{label}: trace promoted control inventory changed")
    for row in rows:
        item = expected[row["certificate"]]
        if (row.get("role") != item["role"]
                or row.get("require_applicable") is not item.get("execution_control_required")
                or row.get("control") != item.get("execution_control")):
            raise LedgerError(f"{label}: trace promoted control is not bound to its checked body")
    return len(rows)


def _validate_trace_field_callees(callees: list, label: str) -> int:
    owner = "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeField.__default"
    prefix = owner.replace(".", "/") + "."
    targets = {prefix + method: item for item in callees
               if (method := item.get("method")) in TRACE_FIELD_PROFILE}
    if len(targets) != 9:
        raise LedgerError(f"{label}: trace field-helper inventory changed")
    shift_target = "dafny/Helpers.bv64ShiftRight:(JB)J"
    for method, (obligations, instructions, direct, arity, ret, shifts, inline_count) in TRACE_FIELD_PROFILE.items():
        item = targets[prefix + method]
        params = list(range(1, arity + 1))
        contract = item.get("contract")
        limits = item.get("solver_limits")
        if (item.get("class") != owner or item.get("status") != "checked"
                or item.get("certificate") != "Callee_" + method.split(":")[0] + ".dfy"
                or item.get("role") != "owned-callee" or item.get("obligations") != obligations
                or item.get("instructions") != instructions or item.get("instructions_reachable") != instructions
                or item.get("direct_instructions") != direct or item.get("roles") != {}
                or item.get("parameter_registers") != params
                or item.get("execution_control_required") is not bool(arity)
                or item.get("source_sha256") != "5f88cf2708b5a2ec50583e101ac65b41f84b3c69f5177d8ffe7429009db7b645"
                or item.get("source_rebuild_sha256") != {
                    "class_sha256": "2660117043da0db8c5f0ef9dd532d16e790aebc79121edb4e906671c442a64e2",
                    "source_rebuild_sha256": "2660117043da0db8c5f0ef9dd532d16e790aebc79121edb4e906671c442a64e2"}
                or item.get("cfg_edges_checked") != ("component-cfgs-and-splice-reachability" if arity else True)
                or item.get("composition_trusted") is not bool(arity)
                or not isinstance(item.get("inlined"), list) or len(item["inlined"]) != inline_count
                or set(item.get("call_targets", {})) != ({shift_target} if arity else set())
                or not isinstance(contract, dict) or contract.get("params") != ["sec"] * arity
                or contract.get("result") != ("args" if arity else "pub") or contract.get("heap") != "none"
                or not isinstance(limits, dict) or limits.get("time") != 30 or limits.get("resources") != 50000000
                or limits.get("solver_options") != ["O:smt.case_split=0"]):
            raise LedgerError(f"{label}: trace field-helper identity/contract changed: {method}")
        mutants = item.get("mutants")
        expected_mutants = {"public-result-from-secret-arg"} if arity else set()
        if (not isinstance(mutants, dict) or set(mutants) != expected_mutants
                or any(not isinstance(value, dict) or value.get("status") != "proof-obligation-rejected"
                       or value.get("diagnostic") != "Error: possible violation of postcondition"
                       for value in mutants.values())):
            raise LedgerError(f"{label}: trace field-helper proof-mutant result changed: {method}")
        control = item.get("execution_control")
        if (not isinstance(control, dict)
                or control.get("requirement") != ("private-paired" if arity else "public-leaf")):
            raise LedgerError(f"{label}: trace field execution requirement changed: {method}")
        if arity:
            _validate_trace_pair(control, label + ":" + method, private_params=params,
                                 private_roles=[], return_register=ret, instructions=instructions,
                                 shifts=shifts, live_return=True)
            witness = item.get("witness_execution")
            witness_contract = item.get("witness_contract")
            if (item.get("witness") != "validated-finite-execution"
                    or not isinstance(witness, dict) or witness.get("terminal") != "stop"
                    or witness.get("public_registers_agree") is not True
                    or not isinstance(witness_contract, dict)
                    or witness_contract.get("parameter_registers") != params
                    or witness_contract.get("liveness") != "non-parameter-secret-live"
                    or not witness_contract.get("non_parameter_differing")
                    or witness_contract.get("differing_registers") != witness.get("differing_registers")):
                raise LedgerError(f"{label}: trace field-helper witness control changed: {method}")
        else:
            _validate_trace_public_pair(control, label + ":" + method)
            if (item.get("witness") != "public-only"
                    or item.get("witness_contract") != {"parameter_registers": [], "status": "not-required"}):
                raise LedgerError(f"{label}: trace field public-leaf witness changed")
    return 7  # Seven genuine proof-obligation mutants, separate from finite controls.


def _validate_trace_composition(report: dict[str, Any], label: str) -> int:
    """Require executed model controls and the reviewed, narrowly scoped roots.

    These are finite model-execution controls, not JVM value-refinement proofs.
    Keep the requirements independent of a future snapshot-digest renewal.
    """
    if report.get("apply_probe") != {
            "rows": 138, "status": "mirror-equals-compiled-model"}:
        raise LedgerError(f"{label}: trace Apply execution probe changed")
    expected = {
        "Extract:(JII)I": (97, 87, "validated-finite-execution", ["sec", "pub", "pub"],
                           {"public-result-from-secret-arg"}),
        "Pow2:(I)I": (57, 62, "public-only", ["pub"], {"secret-branch-cond"}),
        "PublicMod:(II)I": (7, 2, "public-only", ["pub", "pub"], {"secret-runtime-arg"}),
        "Wipe:([I)V": (25, 19, "validated-finite-execution", ["array_sec"],
                        {"secret-store-index", "secret-branch-cond"}),
    }
    callees = report.get("callee_roots")
    if (not isinstance(callees, list) or len(callees) != len(expected) + len(TRACE_FIELD_PROFILE)
            or any(not isinstance(item, dict) for item in callees)
            or {item.get("method") for item in callees} != set(expected) | set(TRACE_FIELD_PROFILE)):
        raise LedgerError(f"{label}: trace owned-callee inventory changed")
    by_method = {item["method"]: item for item in callees}
    mutant_count = 0
    for method, (obligations, instructions, witness, params, mutant_names) in expected.items():
        item = by_method[method]
        contract = item.get("contract")
        expected_cfg = ("component-cfgs-and-splice-reachability"
                        if method == "Extract:(JII)I" else True)
        if (item.get("class") != "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeCodec.__default"
                or item.get("status") != "checked" or item.get("role") != "owned-callee"
                or item.get("obligations") != obligations
                or item.get("instructions") != instructions
                or item.get("instructions_reachable") != instructions
                or item.get("cfg_edges_checked") != expected_cfg
                or item.get("witness") != witness
                or not isinstance(contract, dict) or contract.get("params") != params):
            raise LedgerError(f"{label}: trace owned-callee identity/contract changed: {method}")
        mutants = item.get("mutants")
        if (not isinstance(mutants, dict) or set(mutants) != mutant_names
                or any(not isinstance(value, dict)
                       or value.get("status") != "proof-obligation-rejected"
                       or value.get("diagnostic") != "Error: possible violation of postcondition"
                       for value in mutants.values())):
            raise LedgerError(f"{label}: trace callee mutant inventory/results changed: {method}")
        mutant_count += len(mutants)
    mutant_count += _validate_trace_field_callees(callees, label)
    wipe = by_method["Wipe:([I)V"].get("witness_execution")
    if (not isinstance(wipe, dict) or wipe.get("terminal") != "stop"
            or wipe.get("steps") != 51 or wipe.get("fuel") != 64
            or wipe.get("counts", {}).get("store") != 4
            or len(wipe.get("store_events", [])) != 4
            or wipe.get("store_roles") != [0, 0, 0, 0]
            or wipe.get("role_store_counts") != [4]
            or wipe.get("zeroed_roles") != [0]
            or wipe.get("final_heap") != [[0, 0, 0, 0]]
            or wipe.get("public_registers_agree") is not True):
        raise LedgerError(f"{label}: trace Wipe execution control changed")
    extract = by_method["Extract:(JII)I"].get("witness_execution")
    if (not isinstance(extract, dict) or extract.get("terminal") != "stop"
            or extract.get("steps") != 18 or extract.get("fuel") != 95
            or extract.get("differing_registers") != [1, 7]
            or extract.get("public_registers_agree") is not True):
        raise LedgerError(f"{label}: trace owned-callee Extract execution control changed")
    expected_contracts = {
        "Extract:(JII)I": {
            "parameter_registers": [1, 2, 3], "differing_registers": [1, 7],
            "non_parameter_differing": [7], "liveness": "non-parameter-secret-live"},
        "Pow2:(I)I": {"parameter_registers": [1], "status": "not-required"},
        "PublicMod:(II)I": {"parameter_registers": [1, 2], "status": "not-required"},
        "Wipe:([I)V": {
            "parameter_registers": [1], "differing_registers": [],
            "non_parameter_differing": [], "cleared_parameter_roles": [
                "io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Wipe#p0"]},
    }
    for method, expected_contract in expected_contracts.items():
        item = by_method[method]
        if (item.get("witness_contract") != expected_contract
                or item.get("parameter_registers") != expected_contract["parameter_registers"]):
            raise LedgerError(f"{label}: trace owned-callee witness contract changed: {method}")
    composed = report.get("composed_roots")
    if (not isinstance(composed, list) or len(composed) != 1
            or not isinstance(composed[0], dict)
            or composed[0].get("class") != "io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.__default"
            or composed[0].get("method") != "Feed:([I[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;"
            or composed[0].get("status") != "checked"
            or composed[0].get("role") != "composed-caller"
            or composed[0].get("cfg_edges_checked") != "component-cfgs-and-splice-reachability"
            or composed[0].get("obligations") != 393
            or composed[0].get("instructions") != 369
            or composed[0].get("instructions_reachable") != 369):
        raise LedgerError(f"{label}: trace owned-callee composed Feed changed")
    compositions = report.get("composition")
    if not isinstance(compositions, list) or len(compositions) != 1 or not isinstance(compositions[0], dict):
        raise LedgerError(f"{label}: trace owned-callee composition inventory changed")
    composition = compositions[0]
    prefix = "io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default."
    discharged = {prefix + method for method in ("Extract:(JII)I", "PublicMod:(II)I", "Wipe:([I)V")}
    before = set(composition.get("feed_original_assumed", []))
    after = set(composition.get("feed_composed_assumed", []))
    if (composition.get("status") != "checked-inline-expansion"
            or set(composition.get("discharged", [])) != discharged
            or set(composition.get("supporting", [])) != {prefix + "Pow2:(I)I"}
            or set(composition.get("removed_from_feed", [])) != discharged
            or composition.get("added_to_feed") != []
            or len(before) != 10 or len(after) != 7 or after != before - discharged
            or set(composition.get("caller_union_assumed", [])) != set(REQUIRED_TRACE_ASSUMED_TARGETS)
            or set(composition.get("composed_replacement_union_assumed", []))
               != set(REQUIRED_TRACE_ASSUMED_TARGETS) - discharged
            or report.get("callee_root_assumptions") != []):
        raise LedgerError(f"{label}: trace owned-callee composition assumptions changed")
    return len(callees) + len(composed) + mutant_count + 1


KECCAK_TRACE_PROFILES = {
    # method, instructions, registers, inlines, proof obligations, extracted IR
    "Rotate": ("Rotate:(JI)J", 32, 26, 2, 48, "238c1cdaa65ea61c522c0fee37a1aa3a1230ece138383d2cfa90ff365172ae29"),
    "Theta": ("Theta:([J[J)V", 130, 105, 3, 163, "bfa31f34099f3ea9a2bc62b4de8c4ffc47f98297711a848b673460f137e91344"),
    "RhoPi": ("RhoPi:([J[J[I[I)V", 59, 49, 3, 80, "420adca78a95150f1aa21bbcd463831346f2717660df3e6225d73d21e91c2343"),
    "Iota": ("Iota:([JJ)V", 12, 17, 1, 29, "2e5a5528671e04f568995671207d7f776d0439d311ff9535281fb028ceeddc40"),
    "Chi": ("Chi:([J[J)V", 46, 43, 0, 67, "538777dfe2dcc887e0759369ebc1f24c8a33acb39dad0c432917b1c9de2186e0"),
    "Round": ("Round:([J[J[J[I[IJ)V", 249, 229, 11, 294, "682d35c9340cea295ba5530aba0884d3a443e37ae00ee258ab5c412ccb48c68a"),
    "PermuteScratch": ("PermuteScratch:([J[J[J[I[I)V", 407, 322, 13, 472, "80d2f3c34076b5d81077424829cf92515b9c51c4426721d8e88a74f514fd4492"),
}
KECCAK_PUBLIC_TARGETS = {
    "java/lang/Integer.signum:(I)I", "dafny/Helpers.toInt:(I)I",
    "dafny/Helpers.toInt:(Ljava/math/BigInteger;)I",
    "dafny/DafnyEuclidean.EuclideanDivision:(II)I",
    "dafny/DafnyEuclidean.EuclideanModulus:(II)I",
}
KECCAK_BUDGET = ["--verification-time-limit", "30", "--resource-limit", "50000000",
                 "--solver-option", "O:smt.case_split=0"]
KECCAK_CLASS = "io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.class"
KECCAK_SOURCE = "quic/src/main/java/" + KECCAK_CLASS.removesuffix(".class") + ".java"
KECCAK_CLASS_SHA = "5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91"
KECCAK_SOURCE_SHA = "539f3cee594139794fde8be11853f8a09470177d42a23f5f422433ae57e3b75e"
KECCAK_HELPERS_SHA = "4e5ec798394565756a1bc8438eb1638c2ad79eca264ae105ac576f537451e76c"
KECCAK_RUNTIME_SHA = "dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6"


# Reviewed identities from actual pinned-class extraction, not from the incoming report.
# Renew only after reviewing a fresh replay against the class/source pins above.
KECCAK_BODY_IDENTITIES = {'dafny/Helpers.bv64ShiftLeft:(JB)J': {'callee_bytecode_sha256': 'a0f29776357892ec7662f459010bc464eca9c8a454c247f193720f4b0cc0645e',
                                       'callee_class_sha256': '4e5ec798394565756a1bc8438eb1638c2ad79eca264ae105ac576f537451e76c'},
 'dafny/Helpers.bv64ShiftRight:(JB)J': {'callee_bytecode_sha256': '7c986febe3a32e7ff194a0aa2c6e9febceb4bc28def87fd9947aa99cb34edd87',
                                        'callee_class_sha256': '4e5ec798394565756a1bc8438eb1638c2ad79eca264ae105ac576f537451e76c'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J': {'callee_bytecode_sha256': 'dfc1b784d46860ef6f936af6efad52f440ca5f6df819964fecbb06b1104dd5cd',
                                                                                            'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.SetLane:([JIJ)V': {'callee_bytecode_sha256': '44a97981191d08bcc78f8707b4e57fb34164384a507c1319abb726f5c2e258c2',
                                                                                               'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta:([J[J)V': {'callee_bytecode_sha256': 'ce1e0ed05688c564f43ab640d8176b79d78409bfde969faa57776a8b99b45537',
                                                                                             'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi:([J[J[I[I)V': {'callee_bytecode_sha256': '01c102c322b9a9f08f455cb681186f3e5e16cf02b2f55cac9ed8f91801581edc',
                                                                                                 'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi:([J[J)V': {'callee_bytecode_sha256': '7972ed1e1cac6b1635d8149bd37d217f5a2d4498269461ed84134edb860cd79f',
                                                                                           'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Iota:([JJ)V': {'callee_bytecode_sha256': '9c86602d998a4d0f6d49a61c09c9902e15d5f85f68074ea8df2006fe609b8ac2',
                                                                                           'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Constant:(I)J': {'callee_bytecode_sha256': '7609bf50df8c623498d2754fd10504efcd9e4e9b1c970f9d93b29a2c4fa49bd1',
                                                                                             'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'},
 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round:([J[J[J[I[IJ)V': {'callee_bytecode_sha256': '080a2d34eebade1ac705d7dd9327239d3f3ac6bb373a7cc1d3931e3af3747a0a',
                                                                                                    'callee_class_sha256': '5b4f35f3595ff8f3f5600c235e3c8fc3e2cb32c942afba291df1dcf57ec34b91'}}
KECCAK_ROOT_IDENTITIES = {'Rotate': {'call_targets': {'java/lang/Integer.signum:(I)I': 1},
            'remaining_calls': {'java/lang/Integer.signum:(I)I': 1},
            'direct': {'instructions': 12,
                       'registers': 12,
                       'call_targets': {'java/lang/Integer.signum:(I)I': 1,
                                        'dafny/Helpers.bv64ShiftLeft:(JB)J': 2,
                                        'dafny/Helpers.bv64ShiftRight:(JB)J': 3},
                       'roles': {},
                       'audit_failures': []},
            'param_regs': [1, 2],
            'roles': {},
            'inlined': ['dafny/Helpers.bv64ShiftLeft:(JB)J', 'dafny/Helpers.bv64ShiftRight:(JB)J'],
            'control': {'steps': {'s': 4, 't': 4},
                        'fuel': 40,
                        'initial_state_sha256': {'s': '4ab3719c4921cb610e29e424ca909f7cb04c09f054eca4ef19cd30a5295c58d7',
                                                 't': '2c3ff8ea6da50c988a69ae70c64ae67dfa0ab2f3120ee1825166b2343a88a79e'},
                        'final_state_sha256': {'s': '2af769ef080ab98097fcfc857714a3e7270405031686f74f722f68b48b804038',
                                               't': '9edea86ed977f374dde4e9053f9fd6372466c4f8752bfd8af62b78ca02d75b8a'}}},
 'Theta': {'call_targets': {'dafny/Helpers.toInt:(I)I': 1,
                            'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 2,
                            'java/lang/Integer.signum:(I)I': 4},
           'remaining_calls': {'dafny/Helpers.toInt:(I)I': 2,
                               'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 2,
                               'java/lang/Integer.signum:(I)I': 1},
           'direct': {'instructions': 95,
                      'registers': 79,
                      'call_targets': {'dafny/Helpers.toInt:(I)I': 1,
                                       'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 2,
                                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J': 3},
                      'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta#p0': 'sec',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta#p1': 'sec'},
                      'audit_failures': []},
           'param_regs': [1, 2],
           'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta#p0': 'sec',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta#p1': 'sec'},
           'inlined': ['io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J',
                       'dafny/Helpers.bv64ShiftLeft:(JB)J',
                       'dafny/Helpers.bv64ShiftRight:(JB)J'],
           'control': {'steps': {'s': 763, 't': 763},
                       'fuel': 1104,
                       'initial_state_sha256': {'s': 'b66f066372dbf0dc0394978369bef5393e68f4a9025c525fe78f57c31d603ea1',
                                                't': '65a12c6588b0f28128edaa801b8af6f7be7d0916df94d0a006f0a80404a6f3c2'},
                       'final_state_sha256': {'s': '0eca3b9a00749e4b6e4d2346822eba12fefbf70f5d1d02f42109642f8e5d3354',
                                              't': '8d3d346069162f7bb37930522f5f833264b281993a4e76066332dc9aac43d5ca'}}},
 'RhoPi': {'call_targets': {'dafny/Helpers.toInt:(I)I': 1, 'java/lang/Integer.signum:(I)I': 3},
           'remaining_calls': {'dafny/Helpers.toInt:(I)I': 1, 'java/lang/Integer.signum:(I)I': 1},
           'direct': {'instructions': 24,
                      'registers': 23,
                      'call_targets': {'dafny/Helpers.toInt:(I)I': 1,
                                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J': 2},
                      'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p0': 'sec',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p1': 'sec',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p2': 'pub',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p3': 'pub'},
                      'audit_failures': []},
           'param_regs': [1, 2, 3, 4],
           'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p0': 'sec',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p1': 'sec',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p2': 'pub',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi#p3': 'pub'},
           'inlined': ['io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J',
                       'dafny/Helpers.bv64ShiftLeft:(JB)J',
                       'dafny/Helpers.bv64ShiftRight:(JB)J'],
           'control': {'steps': {'s': 557, 't': 557},
                       'fuel': 1072,
                       'initial_state_sha256': {'s': '3a332e9958b53b9677728c763555675499fd148ae661c30f60031ede5e9c1143',
                                                't': '1d5cb576da6b20b9a8c27349a27917e4a7b9a5c658106dc84f9b48a8a4fc58c2'},
                       'final_state_sha256': {'s': 'a324e0d0bab03acdc8a97e82da42fdf66e81ea87a125bf03c8336e7629de89b3',
                                              't': 'f93b8d14fea604c105ee8907f296acf13a291eec6b2a9f3829dd53c855996ca8'}}},
 'Iota': {'call_targets': {'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': 1, 'dafny/Helpers.toInt:(I)I': 3},
          'remaining_calls': {'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': 1,
                              'dafny/Helpers.toInt:(I)I': 1},
          'direct': {'instructions': 8,
                     'registers': 12,
                     'call_targets': {'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': 1,
                                      'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.SetLane:([JIJ)V': 2},
                     'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Iota#p0': 'sec'},
                     'audit_failures': []},
          'param_regs': [1, 2],
          'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Iota#p0': 'sec'},
          'inlined': ['io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.SetLane:([JIJ)V'],
          'control': {'steps': {'s': 12, 't': 12},
                      'fuel': 32,
                      'initial_state_sha256': {'s': '703a85238c83759a1880d13d58a9371399b0741e7eeb8b1bdda99875f6b1ab00',
                                               't': '5c1cd685167bb974d6a1bb66de87b46d0996acbf837cd02e3bc98663cabbda57'},
                      'final_state_sha256': {'s': 'bf463629f75d722fe730b8981c1223397b79c952c71e81cf7725fad1b9feb991',
                                             't': 'c672347580c898434860e92f84a0fd2063bb2efcec437097ef43ebe233cf75c2'}}},
 'Chi': {'call_targets': {'dafny/DafnyEuclidean.EuclideanDivision:(II)I': 1,
                          'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 2,
                          'dafny/Helpers.toInt:(I)I': 3},
         'remaining_calls': {'dafny/DafnyEuclidean.EuclideanDivision:(II)I': 1,
                             'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 3,
                             'dafny/Helpers.toInt:(I)I': 1},
         'direct': {'instructions': 46,
                    'registers': 43,
                    'call_targets': {'dafny/DafnyEuclidean.EuclideanDivision:(II)I': 1,
                                     'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 2,
                                     'dafny/Helpers.toInt:(I)I': 3},
                    'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi#p0': 'sec',
                              'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi#p1': 'sec'},
                    'audit_failures': []},
         'param_regs': [1, 2],
         'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi#p0': 'sec',
                   'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi#p1': 'sec'},
         'inlined': [],
         'control': {'steps': {'s': 912, 't': 912},
                     'fuel': 1728,
                     'initial_state_sha256': {'s': '87afffa340ddbada049572242460a43fb08b657a2b46541a24f2aff3dd427a16',
                                              't': '8ae9f91aa19625d0ac0fda165c7bd641139ebd64c3470c81f2b08b9841131a19'},
                     'final_state_sha256': {'s': '038cad4a1e679854eacc54b8cd50c2beedf8a38873cefca803419d7c4af28f39',
                                            't': '36a0c9e4d2347d101342a2d93e07355876d3408c1c1c9cf1dd01f003c567246f'}}},
 'Round': {'call_targets': {'dafny/Helpers.toInt:(I)I': 5,
                            'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 6,
                            'java/lang/Integer.signum:(I)I': 8,
                            'dafny/DafnyEuclidean.EuclideanDivision:(II)I': 11,
                            'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': 12},
           'remaining_calls': {'dafny/Helpers.toInt:(I)I': 5,
                               'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 5,
                               'java/lang/Integer.signum:(I)I': 2,
                               'dafny/DafnyEuclidean.EuclideanDivision:(II)I': 1,
                               'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': 1},
           'direct': {'instructions': 5,
                      'registers': 15,
                      'call_targets': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta:([J[J)V': 1,
                                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi:([J[J[I[I)V': 2,
                                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi:([J[J)V': 3,
                                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Iota:([JJ)V': 4},
                      'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p0': 'sec',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p1': 'sec',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p2': 'sec',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p3': 'pub',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p4': 'pub'},
                      'audit_failures': []},
           'param_regs': [1, 2, 3, 4, 5, 6],
           'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p0': 'sec',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p1': 'sec',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p2': 'sec',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p3': 'pub',
                     'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round#p4': 'pub'},
           'inlined': ['io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta:([J[J)V',
                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J',
                       'dafny/Helpers.bv64ShiftLeft:(JB)J',
                       'dafny/Helpers.bv64ShiftRight:(JB)J',
                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi:([J[J[I[I)V',
                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J',
                       'dafny/Helpers.bv64ShiftLeft:(JB)J',
                       'dafny/Helpers.bv64ShiftRight:(JB)J',
                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi:([J[J)V',
                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Iota:([JJ)V',
                       'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.SetLane:([JIJ)V'],
           'control': {'steps': {'s': 2246, 't': 2246},
                       'fuel': 4112,
                       'initial_state_sha256': {'s': '33da8e96ad4a0707035401090207a09b5e0cc0d146c4dbaa6db568e5f12ae0cf',
                                                't': 'd72da3d9272a27bb54be7cd9cfdfe9fdb1ee3ba425c0cbe36cbde5c2cf301177'},
                       'final_state_sha256': {'s': '807fc158e12f6c2aca552915f4dcfd4dd6c0b933981f5f7904fd148fc45690e3',
                                              't': '1eacc1b2652ff6dea623a5010e695c2561a4b0437305f67f8b25bef4e55a9da9'}}},
 'PermuteScratch': {'call_targets': {'java/lang/Integer.signum:(I)I': 3,
                                     'dafny/Helpers.toInt:(I)I': 8,
                                     'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 9,
                                     'dafny/DafnyEuclidean.EuclideanDivision:(II)I': 13,
                                     'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': 14},
                    'remaining_calls': {'java/lang/Integer.signum:(I)I': 3,
                                        'dafny/Helpers.toInt:(I)I': 5,
                                        'dafny/DafnyEuclidean.EuclideanModulus:(II)I': 5,
                                        'dafny/DafnyEuclidean.EuclideanDivision:(II)I': 1,
                                        'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I': 1},
                    'direct': {'instructions': 17,
                               'registers': 21,
                               'call_targets': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Constant:(I)J': 1,
                                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round:([J[J[J[I[IJ)V': 2},
                               'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p0': 'sec',
                                         'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p1': 'sec',
                                         'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p2': 'sec',
                                         'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p3': 'pub',
                                         'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p4': 'pub'},
                               'audit_failures': []},
                    'param_regs': [1, 2, 3, 4, 5],
                    'roles': {'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p0': 'sec',
                              'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p1': 'sec',
                              'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p2': 'sec',
                              'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p3': 'pub',
                              'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p4': 'pub'},
                    'inlined': ['io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Constant:(I)J',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Round:([J[J[J[I[IJ)V',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Theta:([J[J)V',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J',
                                'dafny/Helpers.bv64ShiftLeft:(JB)J',
                                'dafny/Helpers.bv64ShiftRight:(JB)J',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.RhoPi:([J[J[I[I)V',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Rotate:(JI)J',
                                'dafny/Helpers.bv64ShiftLeft:(JB)J',
                                'dafny/Helpers.bv64ShiftRight:(JB)J',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Chi:([J[J)V',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.Iota:([JJ)V',
                                'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.SetLane:([JIJ)V'],
                    'control': {'steps': {'s': 54340, 't': 54340},
                                'fuel': 106240,
                                'initial_state_sha256': {'s': 'f6ec888c7851a924f764ef318dab477af45dfea743102bddf2b6b8468e01c846',
                                                         't': '940b9eb1296774c685dd8d8f7cdc42bde7083f400a8eaced841f49c986d50ea3'},
                                'final_state_sha256': {'s': 'cfafdc267251fd7364a764d446590706296f0908805c1e4830c34dffc7a766f3',
                                                       't': '6efd606b4ab545fcd49b6a779aa064fc2be5891636f7277cb1b553c8e670cbad'}}}}


# Hashes below were checked against the preserved replay files before acceptance.
KECCAK_MODEL_ARTIFACTS = {'PublicProvider': {'source_sha256': '0b974605e8c43276b422f973c3271996cc45fe33aae579e0641cd16fcef8c94b',
                    'log_sha256': 'a1abf91819beff25935d30304cae9adc6e4fe0bbe4468ba36ae5576a5ecac8a0'},
 'PublicProviderPublic': {'source_sha256': '8381910e6692e0b2f7b151c2de11d81f573f4f51181c3ec50bbc612ca4203b94',
                          'log_sha256': '3f70ba253123bed848ea5673ef78da6828f7f543eff36fc835390796c904a726'},
 'WordArithmetic': {'source_sha256': '76fb11977c40495cb530b673bab49c8722a925f24e9ade12bac325526281ce4a',
                    'log_sha256': '77a8844ef1f1bca3553a87f7c7991a556402b4e8df81beea956eda4a294217b9'}}
KECCAK_PROOF_ARTIFACTS = {'Rotate': {'source_sha256': 'eef997dc7cb976f2fa62ac87de3f316c1a73aba4da35a1d0ff03c9aedab15950',
            'log_sha256': 'ceb555bd2c219d803843ffa7a9d05df4e0088ecb328d43dfd119639a4e48781c',
            'oracle_sha256': '0a07658fcbf4c453134a830066ae61d591ca734adafb94cd5bec4b097033562e'},
 'Theta': {'source_sha256': 'c50c846fa00f4e64d174c82bff7333561ff079d39735d78a85919608cf309f19',
           'log_sha256': '6c46b70d5da52196aeff921183529d91d9e20ef050f623476a8f6142fb1e7d23',
           'oracle_sha256': '0c090b9bb08e5d70fc0a7dd5173e3cff5034648b68acf97c354151c0597073ac'},
 'RhoPi': {'source_sha256': 'bb77b4f8d0abb1fc1a733da4bc25dcb3c5c1829db8b9d9050a24ae39ae9c9422',
           'log_sha256': '8a627c10412758918e8163071fa096df30bdc46c786cffa53fffda9ffe3f08f8',
           'oracle_sha256': '19e792d293aeb73295df86e0b956e435f862c1a3165e5c745b8f8baf13182780'},
 'Iota': {'source_sha256': 'b36004f2d7c1439afc5f14f62fd993a6ca87f5dae306f6657dc0e14be9f6be21',
          'log_sha256': '25f8d5a40d8f39ccacf0bca88abd969f0364d7fced2cf1efbeb48f9ac190c6c2',
          'oracle_sha256': 'e3b50f9f5f67c6f90a069c86d3e5fd783749f411b8f39b83d1cfc889e2f343f5'},
 'Chi': {'source_sha256': '6a08088a64c8b48ef7ed38c9fc8654bd11959f2019e1f1390e4ab0a04e2bb807',
         'log_sha256': '3772eb42a41cd32b59b3a418580302f4c962af9af75bcb4bc0178469263e4388',
         'oracle_sha256': 'ac223683bcbdbe1c47524da543bf0d33bd6c246e0130b6ecefdb262cf71de17f'},
 'Round': {'source_sha256': 'acc5005e76490bedca2b197f085a9a2a9ea244396813b9194a065adea1201f69',
           'log_sha256': 'ec9d2793da03e07b435131e9d9709f3b567b27d4518aa275b41311f929429960',
           'oracle_sha256': '9e63157ef6922aaba41fc6ec0c7c4f44114b9cfe1c123ae5ae7a58db48ddacd7'},
 'PermuteScratch': {'source_sha256': '0b5fba293e975849002321c9195c1e4f4165c7e5582ef55a35b9531de359c16b',
                    'log_sha256': 'be5c46f34dfdad01a2d5d2e76ccf552ff2e59db0a93ef45a58a5c9f3e9f5c3b9',
                    'oracle_sha256': '05f24c6cee1734399a5672a29ddb53f64d885626c83e5985a3d089b38897aa2d'}}
KECCAK_AUXILIARY_IDENTITIES = {'Rotate': 'c976146b84b7ec025d24082a42d9a62e6c92e6d1026cdfbcbda0e98d843fe65f',
 'Theta': '9ba7d0d04f189cf65b956739566848d3c3ee153b3a46e42c18ee43ace784d16e',
 'RhoPi': 'c520dfd51918a74eaa9679f2ce507b50a529d437b0acda73ec29e7407caee7d2',
 'Iota': '400f8ade5feb1104a7a63dcce3f42cf46126388f425de1644e3805d9e0ea7442',
 'Chi': '184bb16b77dce925d5d6d968ada1f2803f2eabac17d9a746acd2ccc1b5ef3051',
 'Round': '4fd807a2cab08c969a3472c1e5bd9b52b77955ee8f351124bf06e7c26c333b81',
 'PermuteScratch': 'db42052c2916ecd8ed279b7b22c50801ec930f25afc556b5876ca3fc870392ba'}
KECCAK_COMPONENT_IDENTITIES = {'overlay': 'fdf47c5f53e92046dae2b0bdb28ce636c8f0152fc2229260489bac1bb75f5602',
 'actual_tables': '5eff4b5add19676b45ef1bdaf89c82d16fbb538af9accadbd6d05774c0f44ee5',
 'binding_controls': '9eed7c0225af69042779625f8484b1758300927fa0e5653308516ffeb142748a',
 'oracle_kats': '98226aad7a4d544b4eedbcbe111f8474c097486ad766e9900df2c075d5cc0a2e'}


def _validate_trace_keccak(report: dict[str, Any], label: str) -> int:
    """Check the supplemental claim even if the accepted snapshot is renewed.

    This is a trusted receipt gate, not a replay or a proof of its Python code.
    Caller assumptions/open roots stay under the original independent gates.
    """
    def require(ok: bool, reason: str) -> None:
        if not ok:
            raise LedgerError(f"{label}: Keccak {reason}")

    def obj(value: Any, reason: str) -> dict:
        require(isinstance(value, dict), reason)
        return value

    def sha(value: Any) -> bool:
        return (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                and value != "0" * 64)

    component = obj(report.get("keccak_traces"), "component missing")
    require(component.get("schema") == 1 and component.get("status") == "verified", "component incomplete")
    def record_hash(value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    roots = obj(component.get("roots"), "root inventory missing")
    require(set(roots) == set(KECCAK_TRACE_PROFILES), "root inventory changed")
    require(component.get("scope") == {
        "roots": [p[0] for p in KECCAK_TRACE_PROFILES.values()],
        "excluded": ["Permute:([J)V (array-return NewOffsets/NewSources unsupported)"],
        "not_claimed": ["Sponge ownership/NI", "13-root closure", "JVM value/timing",
                        "physical erasure", "external expert review"],
    }, "scope boundaries changed")
    require(component.get("limits") == {
        "budget": KECCAK_BUDGET, "no_resource_bump": True,
        "proof_timeout_seconds": 300, "step_cap": 1048576,
    }, "solver budget changed")
    shifts = ["dafny/Helpers.bv64ShiftLeft:(JB)J", "dafny/Helpers.bv64ShiftRight:(JB)J"]
    require(component.get("admission") == {"actual": shifts, "declared": shifts, "expected": shifts},
            "runtime admission changed")
    classification = obj(report.get("runtime_classification"), "runtime admission missing")
    require(classification.get("shift_count_public") == shifts
            and classification.get("public_heap_exceptions") == [], "runtime admission scope changed")
    runtime_policy = obj(classification.get("pinned_runtime"), "runtime policy missing")
    require(runtime_policy.get("jar_sha256") == KECCAK_RUNTIME_SHA
            and runtime_policy.get("helpers_entry_sha256") == KECCAK_HELPERS_SHA,
            "runtime class pin changed")

    binding = obj(component.get("binding"), "binding missing")
    before = obj(binding.get("before"), "binding before missing")
    require(binding.get("after") == before, "binding changed after execution")
    native = obj(binding.get("native"), "native class binding missing")
    require(native.get("class_sha256") == KECCAK_CLASS_SHA
            and native.get("source_sha256") == KECCAK_SOURCE_SHA, "native class/source binding changed")
    classes = obj(report.get("class_binding"), "class bindings missing")
    require(obj(classes.get(KECCAK_CLASS), "native class missing").get("class_sha256") == KECCAK_CLASS_SHA,
            "native class differs from the rebuilt class set")
    inputs = obj(report.get("inputs"), "input binding missing")
    require(inputs.get(KECCAK_SOURCE) == KECCAK_SOURCE_SHA, "native source pin changed")
    native_source = native.get("source")
    require(isinstance(native_source, str) and native_source.endswith("/" + KECCAK_SOURCE),
            "native source origin changed")
    origin = native_source[:-len(KECCAK_SOURCE)]
    modules = obj(before.get("modules"), "module binding missing")
    expected_modules = {name: "formal/timing/" + name + ".py" for name in (
        "bytecode_trace", "composition", "trace_exec", "runtime_primitives",
        "compact_certificates", "keccak_traces")}
    require(set(modules) == set(expected_modules), "module inventory changed")
    for name, pin in expected_modules.items():
        entry = obj(modules.get(name), "module record missing")
        require(entry.get("pin_key") == pin and entry.get("path") == origin + pin
                and sha(inputs.get(pin)) and entry.get("sha256") == inputs[pin]
                and entry.get("expected_sha256") == inputs[pin], "loaded module differs from pinned source")
    files = obj(before.get("files"), "file binding missing")
    by_pin = {entry.get("pin_key"): entry for entry in files.values() if isinstance(entry, dict)}
    expected_files = {KECCAK_SOURCE, "formal/timing/policy.json", "formal/timing/SecretTrace.dfy",
                      "formal/timing/PublicProvider.dfy", "formal/timing/PublicProviderPublic.dfy",
                      "formal/timing/WordArithmetic.dfy"}
    require(set(by_pin) == expected_files, "model/file binding inventory changed")
    for pin, entry in by_pin.items():
        require(entry.get("path") == origin + pin and sha(inputs.get(pin))
                and entry.get("actual_sha256") == inputs[pin]
                and entry.get("expected_sha256") == inputs[pin], "model/file binding changed")
    artifacts = obj(binding.get("artifacts"), "tool binding missing")
    for name, pin in (("dafny", "binary_sha256"), ("solver", "solver_sha256")):
        require(obj(artifacts.get(name), "tool binding missing").get("sha256")
                == REQUIRED_TRACE_TOOL_IDENTITY[pin], "tool identity changed")
        tool_key = "binary" if name == "dafny" else "solver"
        require(artifacts[name].get("path") == report.get("tools", {}).get(tool_key),
                "tool origin differs from top-level binding")

    def proof(value: Any, count: int | None, name: str, *, negative: bool = False) -> dict:
        p = obj(value, name + " proof missing")
        expected = ("proof_failed", 4) if negative else ("verified", 0)
        require(p.get("status") == expected[0] and type(p.get("returncode")) is int
                and p["returncode"] == expected[1] and p.get("summary_count") == 1
                and p.get("bad_run") is False and p.get("bad_match") is None,
                name + " proof status changed")
        require(type(p.get("verified")) is int and p["verified"] > 0
                and (count is None or p["verified"] == count)
                and type(p.get("errors")) is int
                and (p["errors"] > 0 if negative else p["errors"] == 0), name + " proof count changed")
        cmd = p.get("command")
        require(isinstance(cmd, list) and len(cmd) == 11 and isinstance(cmd[2], str)
                and cmd[2].endswith(".dfy"), name + " proof command changed")
        require(cmd == [artifacts["dafny"]["path"], "verify", cmd[2], "--solver-path",
                        artifacts["solver"]["path"], *KECCAK_BUDGET], name + " solver budget/command changed")
        require(sha(p.get("log_sha256")), name + " proof log binding missing")
        if negative:
            require(p.get("obligation") == "Error: possible violation of postcondition",
                    name + " negative obligation changed")
        return p

    models = obj(component.get("model_proofs"), "model inventory missing")
    require(set(models) == {"PublicProvider", "PublicProviderPublic", "WordArithmetic"}, "model inventory changed")
    for name, count in (("PublicProvider", 16), ("PublicProviderPublic", 9), ("WordArithmetic", 56)):
        p = proof(models[name], count, name)
        require(p.get("source_sha256") == inputs.get("formal/timing/" + name + ".dfy"),
                name + " model source pin changed")
        require(p["command"][2] == origin + "formal/timing/" + name + ".dfy", name + " model origin changed")
        require(all(p.get(key) == value for key, value in KECCAK_MODEL_ARTIFACTS[name].items()),
                name + " proof artifact identity changed")
    for name, (method, instructions, registers, inlines, count, ir) in KECCAK_TRACE_PROFILES.items():
        row = obj(roots[name], name + " root missing")
        require((row.get("source_method"), row.get("instructions"), row.get("registers"),
                 row.get("inlined_count"), row.get("ir_sha256"))
                == (method, instructions, registers, inlines, ir), name + " root/IR identity changed")
        require(row.get("audit_failures") == [] and isinstance(row.get("inlined"), list)
                and len(row["inlined"]) == inlines, name + " inline/audit evidence changed")
        identity = KECCAK_ROOT_IDENTITIES[name]
        require([entry.get("target") for entry in row["inlined"]] == identity["inlined"],
                name + " inline target inventory changed")
        require(row.get("direct") == identity["direct"]
                and row.get("param_regs") == identity["param_regs"]
                and row.get("roles") == identity["roles"], name + " direct extraction metadata changed")
        targets = obj(row.get("call_targets"), name + " provider targets missing")
        remaining = obj(row.get("remaining_calls"), name + " provider calls missing")
        require(targets == identity["call_targets"] and remaining == identity["remaining_calls"]
                and set(targets) == set(remaining) and set(targets).issubset(KECCAK_PUBLIC_TARGETS)
                and all(type(v) is int and v > 0 for v in targets.values())
                and all(type(v) is int and v > 0 for v in remaining.values())
                and len(set(targets.values())) == len(targets), name + " provider target set changed")
        contract = obj(row.get("public_contract"), name + " public-call contract missing")
        require(contract == {
            "known_public_ids": sorted(targets.values()), "known_public_targets": sorted(targets),
            "known_public_arity": {str(ident): 2 if target.startswith("dafny/DafnyEuclidean.") else 1
                                   for target, ident in targets.items()},
            "unknown_oracle_case": "FallbackOracle (total, defined 0; proved unreachable by CallsOnly/arity)",
            "public_only_postcondition": "PublicOnly(P(), KNOWN_PUBLIC_ARITY)",
            "every_call_target_known_lemma": "EveryCallTargetKnown",
            "every_call_arity_matches_lemma": "EveryCallArityMatches",
            "default_oracle_matches_lemma": "DefaultOracleMatches",
            "every_call_target_known_verified": True,
        }, name + " public-call contract changed")
        p = proof(row.get("proof"), count, name)
        certificate = obj(row.get("certificate"), name + " certificate binding missing")
        require(sha(p.get("source_sha256"))
                and p["source_sha256"] == certificate.get("certificate_sha256")
                and sha(certificate.get("oracle_sha256")), name + " certificate binding changed")
        require(p["command"][2] == certificate.get("certificate")
                and Path(p["command"][2]).name == name + "Provider.dfy", name + " proved certificate changed")
        expected_artifacts = KECCAK_PROOF_ARTIFACTS[name]
        require(p.get("source_sha256") == expected_artifacts["source_sha256"]
                and p.get("log_sha256") == expected_artifacts["log_sha256"]
                and certificate.get("oracle_sha256") == expected_artifacts["oracle_sha256"],
                name + " proof artifact identity changed")
        require(isinstance(certificate.get("oracle"), str)
                and Path(certificate["oracle"]).name == "Oracle_" + name + ".dfy"
                and Path(certificate["oracle"]).parent == Path(p["command"][2]).parent.parent / "oracles"
                and certificate.get("oracle_module") == "Oracle_" + name
                and certificate.get("oracle_function") == "PublicOracle", name + " oracle origin changed")
        require(all(certificate.get(key) == value for key, value in contract.items()
                    if key != "every_call_target_known_verified"), name + " certificate public contract changed")
        ctl = obj(row.get("control"), name + " execution control missing")
        require(all(ctl.get(key) == value for key, value in identity["control"].items()),
                name + " execution profile changed")
        checks = obj(ctl.get("checks"), name + " execution checks missing")
        require(ctl.get("status") == "ok" and ctl.get("terminal") == {"s": "stop", "t": "stop"}
                and ctl.get("fault_events") == {"s": [], "t": []}
                and ctl.get("trace_equal") is True and ctl.get("public_registers_equal") is True
                and ctl.get("public_heap_equal") is True
                and checks.get("public_heap_equal") is True and all(v is True for v in checks.values()),
                name + " execution control incomplete or false")
        events = obj(ctl.get("events_sha256"), name + " execution trace hash missing")
        require(sha(events.get("s")) and events.get("s") == events.get("t"), name + " execution traces differ")
        if name != "Rotate":
            require(checks.get("private_heap_output_live") is True and ctl.get("heap_output_differs"),
                    name + " execution private output not live")
    final = roots["PermuteScratch"]["control"]
    require(final.get("rounds_executed") == 24 and final["checks"].get("24_rounds_executed") is True,
            "round execution incomplete")
    expected_shapes = {f"io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.PermuteScratch#p{i}": [n, n]
                       for i, n in enumerate((25, 25, 5, 25, 25))}
    require(final.get("heap_shape") == expected_shapes, "honest heap shape changed")
    require(final["checks"].get("both_private_input_roles_vary") is True
            and final["checks"].get("both_private_outputs_live") is True
            and final["checks"].get("to_int_big_integer_only_zero_argument") is True,
            "execution private-input/public-provider controls changed")
    require(final.get("event_counts") == {side: {
        "alloc": 0, "call": 5352, "fault": 0, "guard": 3095, "len": 0,
        "load": 5064, "raise": 0, "store": 1944} for side in ("s", "t")}, "round event counts changed")
    runtime = obj(component.get("runtime_replay"), "runtime replay missing")
    require(runtime.get("status") == "verified" and runtime.get("jar_sha256") == KECCAK_RUNTIME_SHA
            and runtime.get("helpers_entry_sha256") == KECCAK_HELPERS_SHA
            and runtime.get("proofs") == {side: {"with_witness": 12, "without_witness": 11}
                                         for side in ("left", "right")}
            and runtime.get("java_adapter") == {"status": "finite-java-equals-model", "comparisons": 56, "inputs": 28},
            "runtime proof/artifact replay changed")
    helper_pin = obj(component.get("helper_entry_pin"), "runtime class pin check missing")
    require(helper_pin == {
        "declared_helpers_entry_sha256": KECCAK_HELPERS_SHA,
        "actual_helpers_entry_sha256": KECCAK_HELPERS_SHA,
        "declared_jar_sha256": KECCAK_RUNTIME_SHA, "actual_jar_sha256": KECCAK_RUNTIME_SHA,
        "matches": True,
    }, "runtime class pin check changed")
    after_bodies = obj(component.get("inlined_body_binding_after"), "callee body binding missing")
    bodies = {}
    native_owner = KECCAK_CLASS.removesuffix(".class")
    for name, row in roots.items():
        for entry in row["inlined"]:
            body = obj(entry.get("callee_body"), name + " callee body missing")
            owner = body.get("owner")
            require(owner in (native_owner, "dafny/Helpers")
                    and body.get("static") is True and body.get("exception_table") is False
                    and body.get("handlers") == [] and isinstance(body.get("bytecode"), list)
                    and body["bytecode"], name + " callee body scope changed")
            target = f"{owner}.{body.get('name')}:{body.get('descriptor')}"
            body_hash = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            class_hash = KECCAK_HELPERS_SHA if owner == "dafny/Helpers" else KECCAK_CLASS_SHA
            require(entry.get("target") == target and entry.get("callee_bytecode_sha256") == body_hash
                    and entry.get("callee_class_sha256") == class_hash
                    and KECCAK_BODY_IDENTITIES.get(target) == {
                        "callee_bytecode_sha256": body_hash, "callee_class_sha256": class_hash}
                    and entry.get("callee_shape_sha256_is_body_identity") is False,
                    name + " callee body identity changed")
            value = {"callee_bytecode_sha256": body_hash, "callee_class_sha256": class_hash}
            require(target not in bodies or bodies[target] == value, name + " callee body inconsistent")
            bodies[target] = value
        require(record_hash({"inlined": row["inlined"], "events_sha256": row["control"]["events_sha256"]})
                == KECCAK_AUXILIARY_IDENTITIES[name], name + " auxiliary identity changed")
    require(after_bodies == bodies, "callee body binding changed after replay")
    private = obj(component.get("private_count"), "private-count anchor inventory missing")
    require(set(private) == {"left", "right"}, "private-count anchor inventory changed")
    for side in ("left", "right"):
        p = proof(private[side].get("proof"), 9, "private-count " + side, negative=True)
        anchor = obj(p.get("anchor"), "private-count anchor missing")
        require(p.get("errors") == 2 and private[side].get("obligation_named") is True
                and p.get("anchor_status") == "proof_failed_named_chunk0_branch_postcondition"
                and anchor.get("certificate_statement") == "ensures InstrOK(p, p.chunks[0][j])"
                and anchor.get("model_statement") == "cond < p.registers && RegTaint(p, cond) == Pub &&"
                and anchor.get("certificate_line") == 25 and anchor.get("model_line") == 227,
                "private-count anchor changed")
        error = "Error: possible violation of postcondition of forall statement"
        related = "Related location: this proposition could not be proved"
        diagnostics = anchor.get("diagnostics")
        require(anchor.get("error_message") == error and anchor.get("related_message") == related
                and anchor.get("obligation") == "Chunk0.InstrOK universal postcondition on secret branch taint"
                and isinstance(diagnostics, list) and len(diagnostics) == 2
                and diagnostics[0] == {
                    "path": anchor.get("certificate"), "line": 25, "col": 14,
                    "message": error, "related": [{"path": "formal/timing/SecretTrace.dfy",
                        "line": 227, "col": 28, "message": related}]}
                and diagnostics[1] == {
                    "path": anchor.get("certificate"), "line": 61, "col": 12,
                    "message": "Error: function precondition could not be proved", "related": [
                        {"path": "formal/timing/SecretTrace.dfy", "line": 352, "col": 13, "message": related},
                        {"path": "formal/timing/SecretTrace.dfy", "line": 266, "col": 5, "message": related}]},
                "private-count anchor diagnostics changed")
    structural = obj(component.get("mutants"), "structural mutant inventory missing")
    require(set(structural) == {"branch", "index"}, "structural mutant inventory changed")
    for name, line in (("branch", 227), ("index", 224)):
        p = proof(structural[name].get("proof"), None, name + " mutant", negative=True)
        lines = p.get("error_lines")
        require(isinstance(lines, list) and p.get("contains_structure_error") is True
                and any(f"SecretTrace.dfy({line}," in str(s) for s in lines),
                name + " mutant obligation anchor changed")
    public = obj(component.get("public_call_mutants"), "public-call mutant inventory missing")
    require(set(public) == {"private_argument", "unknown_target", "private_heap_argument", "wrong_arity"},
            "public-call mutant inventory changed")
    for name, line in (("private_argument", 28), ("unknown_target", 26),
                       ("private_heap_argument", 27), ("wrong_arity", 29)):
        row = obj(public[name], name + " mutant missing")
        p = proof(row.get("proof"), None, name + " mutant", negative=True)
        lines = p.get("error_lines")
        require(p.get("contains_structure_error") is False and isinstance(lines, list)
                and any(f"PublicProviderPublic.dfy({line}," in str(s) for s in lines),
                name + " public-call mutant anchor changed")
        # These fields describe the diagnostic, not a separate positive
        # Structure theorem. Require consistency with the derived proof facts.
        require(row.get("derived_from_proof") is True
                and row.get("proof_status") == p["status"]
                and row.get("contains_structure_error") == p["contains_structure_error"]
                and row.get("structure_valid") == (not p["contains_structure_error"])
                and row.get("public_only_false") == (p["status"] == "proof_failed"),
                name + " public-call mutant derived metadata changed")
    kat = obj(component.get("oracle_kats"), "oracle control missing")
    require(kat.get("status") == "compiled-dafny-equals-python-kat" and kat.get("cases") == 243
            and sha(kat.get("source_sha256")) and sha(kat.get("log_sha256")), "compiled oracle comparison missing")
    controls = obj(component.get("noncompletion_controls"), "noncompletion controls missing")
    require(set(controls) == {"fuel", "out_of_bounds", "equal_inputs"}
            and all(isinstance(c, dict) and c.get("accepted_as_complete") is False for c in controls.values())
            and controls["fuel"].get("terminal") == "fuel"
            and controls["out_of_bounds"].get("terminal") == "fault"
            and controls["equal_inputs"].get("status") == "FAILED", "noncompletion control promoted or missing")
    for name, expected_hash in KECCAK_COMPONENT_IDENTITIES.items():
        require(record_hash(component.get(name)) == expected_hash, name + " component identity changed")
    return 7 + 3 + 2 + 3 + 6


def _validate_trace_report(root: Path, label: str) -> int:
    report_path = "formal/timing/PRODUCTION-EVIDENCE.json"
    report_file = checked_path(root, report_path, label)
    if digest(report_file) != REQUIRED_TRACE_REPORT_SHA256:
        raise LedgerError(f"{label}: trace report does not match reviewed snapshot")
    report = load_json(report_file)
    expected_scalars = {
        "status": "complete",
        "scope": "Extracted actual-bytecode certificates under the SecretTrace observer",
        "jvm_timing": "deferred; no JVM/JIT/CPU/provider timing claim",
        "model_obligations": 57,
        "hkdf_shape_obligations": 17,
        "positive_control": "executed",
    }
    for field, expected in expected_scalars.items():
        if report.get(field) != expected:
            raise LedgerError(f"{label}: trace report {field} changed")
    roots = report.get("roots")
    if not isinstance(roots, list):
        raise LedgerError(f"{label}: trace roots missing")
    actual_roots = tuple(
        {key: item.get(key) for key in ("class", "method", "status", "obligations",
                                        "instructions", "instructions_reachable", "cfg_edges_checked")}
        for item in roots
    )
    if actual_roots != REQUIRED_TRACE_ROOTS:
        raise LedgerError(f"{label}: checked trace root identity/counts/reachability changed")
    for item in roots:
        method = item["method"]
        if method not in REQUIRED_TRACE_ROOT_CASE_SPLIT:
            raise LedgerError(f"{label}: unexpected trace root {method}")
        expected_override = REQUIRED_TRACE_ROOT_CASE_SPLIT[method]
        actual_override = "O:smt.case_split=0" in item.get("verify_command", [])
        if actual_override != expected_override:
            raise LedgerError(f"{label}: solver override claim changed for {method}")
    fixtures = report.get("fixtures")
    if not isinstance(fixtures, dict) or tuple(
            (name, value.get("expect"), value.get("status")) for name, value in fixtures.items()
    ) != REQUIRED_TRACE_FIXTURES:
        raise LedgerError(f"{label}: trace fixture inventory/results changed")
    mutants = report.get("certificate_mutants")
    if not isinstance(mutants, dict) or tuple(
            (name, value.get("status")) for name, value in mutants.items()
    ) != REQUIRED_TRACE_MUTANTS:
        raise LedgerError(f"{label}: trace certificate mutant inventory changed")
    composition_checks = (_validate_trace_composition(report, label)
                          + _validate_trace_promoted_controls(report, label)
                          + _validate_trace_boundaries(report, label)
                          + _validate_trace_keccak(report, label))
    assumed = {
        item.get("target") for item in report.get("assumed_owned_callees", [])
        if isinstance(item, dict)
    }
    open_targets = {
        (item.get("class"), item.get("method"), item.get("status"))
        for item in report.get("open_roots", []) if isinstance(item, dict)
    }
    unchecked = set(report.get("unchecked_owned_callees", []))
    if assumed != set(REQUIRED_TRACE_ASSUMED_TARGETS):
        raise LedgerError(f"{label}: assumed owned callee set changed")
    if open_targets != set(REQUIRED_TRACE_OPEN_TARGETS):
        raise LedgerError(f"{label}: open owned root/status set changed")
    if unchecked != set(REQUIRED_TRACE_UNCHECKED):
        raise LedgerError(f"{label}: unchecked owned callee inventory changed")
    if not assumed.issubset(unchecked):
        raise LedgerError(f"{label}: assumed owned callee missing from unchecked inventory")
    manifest = load_json(checked_path(root, "formal/timing/inputs.json", label)).get("inputs")
    inputs = report.get("inputs")
    if not isinstance(inputs, dict) or not isinstance(manifest, dict):
        raise LedgerError(f"{label}: trace input inventory missing")
    if tuple(sorted(inputs)) != REQUIRED_TRACE_INPUT_KEYS or inputs != manifest:
        raise LedgerError(f"{label}: trace report inputs differ from the pinned manifest")
    if report["keccak_traces"]["binding"]["before"]["inputs"].get("sha256") != digest(
            checked_path(root, "formal/timing/inputs.json", label)):
        raise LedgerError(f"{label}: Keccak input-manifest binding changed")
    bindings = report.get("class_binding")
    if not isinstance(bindings, dict) or tuple(sorted(bindings)) != REQUIRED_TRACE_CLASS_BINDING_KEYS:
        raise LedgerError(f"{label}: crypto class binding inventory changed")
    tools = report.get("tools")
    if not isinstance(tools, dict):
        raise LedgerError(f"{label}: trace tool identity missing")
    for field, expected in REQUIRED_TRACE_TOOL_IDENTITY.items():
        if tools.get(field) != expected:
            raise LedgerError(f"{label}: trace tool {field} changed")
    jdk = report.get("jdk_identity")
    if not isinstance(jdk, dict):
        raise LedgerError(f"{label}: JDK identity missing")
    for name, expected in REQUIRED_TRACE_JDK_IDENTITY.items():
        if not isinstance(jdk.get(name), dict) or jdk[name].get("sha256") != expected:
            raise LedgerError(f"{label}: JDK {name} identity changed")
    if report.get("runtime_sha256") != "dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6":
        raise LedgerError(f"{label}: trace runtime pin changed")
    return (
        len(actual_roots) + len(fixtures) + len(mutants) + len(assumed)
        + len(open_targets) + len(unchecked) + len(inputs) + len(bindings) + len(tools)
        + composition_checks
    )


def _validate_required_component(root: Path, obligation: dict[str, Any], label: str) -> int:
    """Require the reviewed evidence and subchecks for a supported component.

    This is intentionally independent of whether the ledger happens to retain an
    optional section: deleting a control group, receipt check, hash map, inventory
    check, nonvacuity block or required evidence entry is a hard failure.
    """
    oid = obligation["id"]
    evidence = _evidence_index(obligation)
    if oid == "V7" and "trusted-source-observation-coverage" not in obligation.get("assumptions", []):
        raise LedgerError(f"{label}: required HKDF source-coverage trust assumption removed")
    checked = 0
    for relative, kind in REQUIRED_COMPONENT_EVIDENCE[oid]:
        item = f"{label}:required-evidence"
        if relative not in evidence:
            raise LedgerError(f"{item}: missing required evidence {relative}")
        if evidence[relative]["kind"] != kind:
            raise LedgerError(
                f"{item}: {relative} must be kind {kind!r}, found {evidence[relative]['kind']!r}")
        checked += 1
    checks = REQUIRED_COMPONENT_CHECKS[oid]
    groups = {group.get("id"): group for group in obligation.get("control_groups", [])
              if isinstance(group, dict)}
    for group_id, receipt_path, controls_path in checks["control_groups"]:
        item = f"{label}:required-control:{group_id}"
        group = groups.get(group_id)
        if group is None:
            raise LedgerError(f"{item}: required control group removed")
        if group.get("receipt") != receipt_path or group.get("controls_path") != controls_path:
            raise LedgerError(f"{item}: receipt/controls path rebound")
        expected = group.get("expected")
        if not isinstance(expected, dict) or set(expected) != set(REQUIRED_CONTROL_INVENTORY[group_id]):
            raise LedgerError(f"{item}: named control inventory changed")
        failure_field = REQUIRED_CONTROL_FAILURE_FIELDS[group_id]
        failure_fields = []
        for name, fields in expected.items():
            if not isinstance(fields, dict) or failure_field not in fields:
                raise LedgerError(f"{item}:{name}: missing required failure field {failure_field}")
            failure_fields.append(fields[failure_field])
        if failure_field == "errors":
            if not all(_control_failure_value(failure_field, value) for value in failure_fields):
                raise LedgerError(f"{item}: every control must pin a nonzero error count")
        elif not any(_control_failure_value(failure_field, value) for value in failure_fields):
            raise LedgerError(f"{item}: group was downgraded to success labels only")
        checked += len(expected)
    for receipt_path, required_paths in checks["receipt_checks"]:
        item = f"{label}:required-receipt:{receipt_path}"
        candidates = [entry for entry in obligation.get("receipt_checks", [])
                      if entry.get("receipt") == receipt_path]
        if not candidates:
            raise LedgerError(f"{item}: required receipt check removed")
        if not any(set(required_paths).issubset(set(entry.get("values", {}))) for entry in candidates):
            raise LedgerError(f"{item}: required receipt fields removed")
        checked += len(required_paths)
    for signature in checks["hash_maps"]:
        receipt_path, map_path, includes, excludes = signature[:4]
        path_prefix = signature[4] if len(signature) > 4 else ""
        item = f"{label}:required-hash-map:{map_path}"
        found = False
        for entry in obligation.get("hash_maps", []):
            if entry.get("receipt") != receipt_path or entry.get("path") != map_path:
                continue
            if tuple(entry.get("include_prefixes") or ()) != includes:
                continue
            if tuple(entry.get("exclude_paths") or ()) != excludes:
                continue
            if (entry.get("path_prefix") or "") != path_prefix:
                continue
            found = True
            break
        if not found:
            raise LedgerError(f"{item}: required pinned source/tool map removed or filters loosened")
        receipt = load_json(checked_path(root, receipt_path, item))
        mapping = dot_get(receipt, map_path, item)
        if not isinstance(mapping, dict) or not mapping:
            raise LedgerError(f"{item}: pinned map is empty")
        actual_keys = {
            key for key in mapping
            if key not in excludes and (not includes or any(key.startswith(prefix) for prefix in includes))
        }
        expected_keys = REQUIRED_HASH_MAP_KEYS.get(
            (oid, receipt_path, map_path, tuple(includes), path_prefix))
        if expected_keys is None:
            raise LedgerError(f"{item}: checker has no reviewed key inventory for this map")
        if actual_keys != set(expected_keys):
            raise LedgerError(
                f"{item}: pinned map key inventory changed; missing={sorted(set(expected_keys)-actual_keys)} "
                f"added={sorted(actual_keys-set(expected_keys))}")
        checked += len(expected_keys)
    for receipt_path, entry_path, path_key, hash_key in checks["entry_hash_checks"]:
        item = f"{label}:required-entry-hash:{entry_path}"
        if not any(entry.get("receipt") == receipt_path
                   and entry.get("path") == entry_path
                   and entry.get("path_key", "source") == path_key
                   and entry.get("hash_key", "sha256") == hash_key
                   for entry in obligation.get("entry_hash_checks", [])):
            raise LedgerError(f"{item}: required provider/facade hash inventory removed")
        checked += 1
    for required in checks.get("file_set_checks", ()):
        item = f"{label}:required-file-set:{required.get('id')}"
        found = False
        for entry in obligation.get("file_set_checks", []):
            if all(entry.get(key) == value for key, value in required.items()):
                found = True
                break
        if not found:
            raise LedgerError(f"{item}: generated file-set inventory removed or narrowed")
        if oid in {"V1", "V2"}:
            receipt = load_json(checked_path(root, required["receipt"], item))
            mapping = dot_get(receipt, required["field"], item)
            expected_keys = REQUIRED_FILE_SET_KEYS.get((oid, required.get("id")))
            if expected_keys is None or set(mapping) != set(expected_keys):
                raise LedgerError(f"{item}: generated file inventory no longer matches the reviewed set")
            directory = checked_path(root, required["root"], item, allow_dir=True)
            actual = {
                path.relative_to(directory).as_posix()
                for path in directory.rglob("*") if path.is_file()
            }
            if actual != set(expected_keys):
                raise LedgerError(f"{item}: actual generated file set changed")
        checked += 1
    for required in checks["inventory_checks"]:
        item = f"{label}:required-inventory:{required.get('id')}"
        found = False
        for entry in obligation.get("inventory_checks", []):
            if all(entry.get(key) == value for key, value in required.items()):
                found = True
                break
        if not found:
            raise LedgerError(f"{item}: generated-file inventory removed or narrowed")
        receipt = load_json(checked_path(root, required["receipt"], item))
        delivered = dot_get(receipt, required.get("delivered_field", "delivered_sources"), item)
        expected_keys = REQUIRED_INVENTORY_KEYS.get((oid, required.get("id")))
        if expected_keys is None or set(delivered) != set(expected_keys):
            raise LedgerError(f"{item}: delivered generated inventory no longer matches the reviewed set")
        checked += len(expected_keys)
    required_nonvacuity = checks["nonvacuity"]
    if required_nonvacuity:
        item = f"{label}:required-nonvacuity"
        nonvacuity = obligation.get("nonvacuity")
        if not isinstance(nonvacuity, dict):
            raise LedgerError(f"{item}: named nonvacuity/domain control removed")
        if (nonvacuity.get("path"), tuple(nonvacuity.get("markers") or ())) != tuple(required_nonvacuity):
            raise LedgerError(f"{item}: nonvacuity path/markers changed")
        checked += 1
    for path, markers in checks["text_checks"]:
        item = f"{label}:required-text:{path}"
        if not any(entry.get("path") == path
                   and tuple(entry.get("markers") or ()) == markers
                   for entry in obligation.get("text_checks", [])):
            raise LedgerError(f"{item}: required reviewed text checks removed")
        checked += len(markers)
    cached_receipts: dict[str, dict[str, Any]] = {}
    for (exact_oid, receipt_path, value_path), expected in REQUIRED_RECEIPT_EXACT.items():
        if exact_oid != oid:
            continue
        if receipt_path not in cached_receipts:
            cached_receipts[receipt_path] = load_json(checked_path(root, receipt_path, f"{label}:exact"))
        found = dot_get(cached_receipts[receipt_path], value_path, f"{label}:exact")
        if found != expected:
            raise LedgerError(f"{label}: required receipt value changed: {receipt_path}:{value_path}")
        checked += 1
    return checked


PACKET_NONCE_EVIDENCE = "formal/nonce/PRODUCTION-EVIDENCE.json"
PACKET_NONCE_KERNEL = "formal/nonce/Nonce.dfy"
PACKET_NONCE_DOMAIN = "formal/nonce/NonceDomain.dfy"
PACKET_NONCE_GENERATED = (
    "quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/"
    "VerifiedNonce/__default.java")
PACKET_NONCE_GENERATED_KEY = (
    "io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce/__default.java")
PACKET_NONCE_BRIDGE = "quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java"
PACKET_NONCE_TEST = "quic/src/test/java/io/github/mahmoudimus/quic/crypto/PacketKeyNonceTest.java"
PACKET_NONCE_SMOKE = "formal/nonce/BundleNonceSmoke.java"
PACKET_NONCE_SMOKE_SUITES = ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                              "TLS_CHACHA20_POLY1305_SHA256")
PACKET_NONCE_HISTORICAL = (
    "formal/saw/historical/quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java")
PACKET_NONCE_HISTORICAL_SHA256 = "501999d8871707497f9f1c6a4765524384551bb3383484045a7ca2aabe40130d"
PACKET_NONCE_BRIDGE_SHA256 = "120f456959c3bdd2edd5916d8e9a76e9ed63dbb0ca84f886f31e8ea0814e2c2e"
PACKET_NONCE_GENERATED_SHA256 = "aabace51edf58e4aefd398717b674ccbf8c138517f95fbb843139c8aea61cc06"
PACKET_NONCE_TEST_SHA256 = "c2f1b845b679bc86d1025d6c6b45d3f5ccbda80fe1c1e0382391ec280393fe57"
PACKET_NONCE_CONTROL_NAMES = (
    "wrong-endian", "counter-truncation", "alias-freshness", "input-preservation",
    "counter-truncation-injectivity")
PACKET_NONCE_JAVA_RUNS = (
    (21, "d7ab2ea6a7e731a8a2cee7d722046c9f7d8c5f184cd769b9954a392592337770",
     "ab9b94d81dd22c843ef637be9aa2121253c6d4cfe2ba0a89a7bde5c0b9567945"),
    (25, "d6b5c8ffce485baa7e9aacfd9c652e2999c89053a5070104c598731636bd2249",
     "6a9d1ef0aa490929d80e6d864fea9a4ada17303dd5a6fad6376e037aee2fcd68"),
)
PACKET_NONCE_JAVA_TESTS = "NONCE-TEST-OK cases=10 assertions=162774"
PACKET_NONCE_CORE_PINS = {
    "formal/nonce/Nonce.dfy":
        "e83c9a7a448a4b7d982f7c54822f9af53cffe4d3808870ed04ddac0bd89f5c28",
    "formal/nonce/NonceDomain.dfy":
        "9f0ed7272e430fccd3deb984814f0ce51691dac59e6c91b7fc7958d5fe9292e7",
    "formal/nonce/run.py":
        "c32876cc54f8f71982558c8fffe5f8959d5507806d009df09ed2040aceddc663",
    "formal/nonce/test_run.py":
        "f20c9a303274737166f5eed6d6047facf493621786e56697e769e69d1d1c6db1",
    "formal/nonce/tools.json":
        "96af825819ad09cd2f40d296422ada913ee56f2e3fed24570d8d3ac5fc0cd54a",
    "formal/nonce/inputs.json":
        "cd6ae07833951fcde99ed7697215a799baf222c24c5c9fc303a21ed709f79dc8",
    "formal/nonce/GENERATED.json":
        "d5f9952e1cef30f12653b2705a080d280fbb2cbc68df212f631385c9b73e7783",
}
PACKET_NONCE_CORE_RECEIPT_ROLES = {
    "formal/nonce/Nonce.dfy": "kernel_source",
    "formal/nonce/NonceDomain.dfy": "domain_source",
    "formal/nonce/run.py": "runner",
    "formal/nonce/test_run.py": "test_runner",
    "formal/nonce/tools.json": "tools",
    "formal/nonce/inputs.json": "input_manifest",
    "formal/nonce/GENERATED.json": "generated_receipt",
}
PACKET_NONCE_INPUT_PINS = {
    "formal/dafny/toolchain.py":
        "4ff94e948692ed9d358d06c58add5362c084880124d058d906d4d381cf15b5a8",
    "formal/dafny/tools.json":
        "d0400f892192bd2e603651aa36c9fed32394b5d0600955d4854c852df729f1c6",
    "formal/nonce/GENERATED.json":
        "d5f9952e1cef30f12653b2705a080d280fbb2cbc68df212f631385c9b73e7783",
    "formal/nonce/Nonce.dfy":
        "e83c9a7a448a4b7d982f7c54822f9af53cffe4d3808870ed04ddac0bd89f5c28",
    "formal/nonce/NonceDomain.dfy":
        "9f0ed7272e430fccd3deb984814f0ce51691dac59e6c91b7fc7958d5fe9292e7",
    "formal/nonce/bench/NonceBenchmark.java":
        "29b10d806fdb846d458a3a10e6d8606f968bf7f74761ecc9b3001c342f5e89cf",
    "formal/nonce/bench_nonce.py":
        "7b951a32584bdab60a2f9f11a4c427abbb29d74e85dc2c15059f172b30b83967",
    "formal/nonce/java/io/github/mahmoudimus/nonce/GeneratedNonceTest.java":
        "4434e8f11076e61dc941ff6c8ff3868eafa15a912795bbacfc9b74bc0acec070",
    "formal/nonce/java/io/github/mahmoudimus/nonce/ReferenceNonce.java":
        "03532fa616870ced3ede2b89f3194403c0480546bf1b4dac33d49feb378970a9",
    "formal/nonce/run.py":
        "c32876cc54f8f71982558c8fffe5f8959d5507806d009df09ed2040aceddc663",
    "formal/nonce/test_run.py":
        "f20c9a303274737166f5eed6d6047facf493621786e56697e769e69d1d1c6db1",
    "formal/nonce/tools.json":
        "96af825819ad09cd2f40d296422ada913ee56f2e3fed24570d8d3ac5fc0cd54a",
    "quic/src/main/java/io/github/mahmoudimus/quic/crypto/internal/verifiednonce/"
    "VerifiedNonce/__default.java":
        "aabace51edf58e4aefd398717b674ccbf8c138517f95fbb843139c8aea61cc06",
}
# Fresh actual component replay produced by the ROOT nonce run after the
# delivery-manifest renewal; the field is provenance-only and the typed checks
# below recompute every repository hash.  Producer path (absolute, not tracked):
# P/a-poly-delivery-v1/nonce/report.json
PACKET_NONCE_ACCEPTED_REPORT_SHA256 = (
    "130d82c0c3960447557ff255dae13739e322ca54bf8169370f685c9641d2f148")
PACKET_NONCE_GENERATED_CLASS_KEY = (
    "io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce/__default.class")
PACKET_NONCE_GENERATED_CLASS_SHA256 = (
    "64ba6bbcccba2bc0f519b60ba090e11cf164544e98e24e73cd4699f9481c7069")
PACKET_NONCE_TRANSLATION_METADATA_SHA256 = (
    "e65cce5ab0364a300dcebbb537648f87b9b02a13efe8c321fb731d2c341604e4")
PACKET_NONCE_LIBRARY_CLASS_COUNT = 468
PACKET_NONCE_CRYPTO_CLASS_COUNT = 84
PACKET_NONCE_RETAINED_CLASS_COUNT = 468


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> None:
    if not isinstance(value, dict):
        raise LedgerError(f"{label}: expected an object")
    wanted, found = set(expected), set(value)
    if found != wanted:
        raise LedgerError(
            f"{label}: immutable key inventory changed; missing={sorted(wanted - found)} "
            f"added={sorted(found - wanted)}")


def _nonce_receipt_ref(root: Path, value: Any, label: str, expected_path: str) -> str:
    _exact_keys(value, ("path", "sha256"), label)
    if value["path"] != expected_path:
        raise LedgerError(f"{label}: path must be {expected_path!r}, found {value['path']!r}")
    pinned = checked_hash(value["sha256"], label)
    if digest(checked_path(root, expected_path, label)) != pinned:
        raise LedgerError(f"{label}: stale hash for {expected_path}")
    return pinned


def _python_assignments(path: Path, names: Iterable[str], label: str) -> dict[str, Any]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        raise LedgerError(f"{label}: cannot parse pinned tool: {exc}") from exc
    wanted = set(names)
    found: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in wanted:
                if target.id in found:
                    raise LedgerError(f"{label}: duplicate assignment {target.id}")
                try:
                    found[target.id] = ast.literal_eval(node.value)
                except ValueError as exc:
                    raise LedgerError(f"{label}: non-literal {target.id}") from exc
    missing = wanted - set(found)
    if missing:
        raise LedgerError(f"{label}: missing tool constants {sorted(missing)}")
    return found


def _validate_packet_nonce_functional(root: Path) -> int:
    """Typed validation of the generated-nonce functional production claim.

    This reads the actual repository sources, the central delivery manifest and
    the pinned gate code. It never treats the receipt checksum, the external
    replay report checksum or a self-declared status as evidence by itself.
    """
    receipt_path = checked_path(root, PACKET_NONCE_EVIDENCE, "nonce:receipt")
    receipt = load_json(receipt_path)
    _exact_keys(receipt, (
        "schema", "status", "scope", "component", "proof", "controls", "generation",
        "bridge", "delivery", "java_runs", "junit", "bundle_smoke", "non_claims",
        "limitations"),
        "nonce:receipt")
    if receipt["schema"] != "microproxy.packet-nonce-production-evidence/v1":
        raise LedgerError("nonce:receipt: unexpected schema")
    if receipt["status"] != "complete":
        raise LedgerError("nonce:receipt: status is not complete")
    if not isinstance(receipt["scope"], str) or "Generated VerifiedNonce" not in receipt["scope"]:
        raise LedgerError("nonce:receipt: scope label changed")
    if "SAW" not in receipt["scope"] or "blocked" not in receipt["scope"]:
        raise LedgerError("nonce:receipt: scope must keep the blocked SAW boundary")
    checked = 0

    component = receipt["component"]
    _exact_keys(component, (
        "kernel_source", "domain_source", "generated_receipt", "input_manifest",
        "tools", "runner", "test_runner"), "nonce:component")
    for key, relative in (
        ("kernel_source", PACKET_NONCE_KERNEL),
        ("domain_source", PACKET_NONCE_DOMAIN),
        ("generated_receipt", "formal/nonce/GENERATED.json"),
        ("input_manifest", "formal/nonce/inputs.json"),
        ("tools", "formal/nonce/tools.json"),
        ("runner", "formal/nonce/run.py"),
        ("test_runner", "formal/nonce/test_run.py"),
    ):
        _nonce_receipt_ref(root, component[key], f"nonce:component:{key}", relative)
        checked += 1
    kernel_sha = component["kernel_source"]["sha256"]
    kernel_text = checked_path(root, PACKET_NONCE_KERNEL, "nonce:kernel").read_text(encoding="utf-8")

    # The accepted functional baseline is immutable in this trusted checker.
    # Renewing the kernel/domain/runner/tools/inputs/generated receipt requires
    # an explicit checker review, not a JSON/hash renewal alone. The accepted
    # external report hash is provenance only; it is not a theorem by checksum.
    for core_path, pinned in PACKET_NONCE_CORE_PINS.items():
        actual = digest(checked_path(root, core_path, "nonce:core-pin"))
        if actual != pinned:
            raise LedgerError(f"nonce:core-pin:{core_path}: reviewed core source changed")
        role = PACKET_NONCE_CORE_RECEIPT_ROLES[core_path]
        if component[role]["sha256"] != pinned:
            raise LedgerError(f"nonce:core-pin:{core_path}: receipt role {role} was renewed")
        checked += 1
    input_manifest = load_json(checked_path(root, "formal/nonce/inputs.json", "nonce:input-manifest"))
    if input_manifest.get("inputs") != PACKET_NONCE_INPUT_PINS:
        raise LedgerError("nonce:core-pin: exact 13-file core input map changed")
    for input_path, pinned in PACKET_NONCE_INPUT_PINS.items():
        if digest(checked_path(root, input_path, "nonce:input-pin")) != pinned:
            raise LedgerError(f"nonce:core-pin:{input_path}: reviewed input changed")
        checked += 1

    proof = receipt["proof"]
    _exact_keys(proof, ("kernel", "domain", "audits", "forbidden_source_constructs",
                        "source_sha256"), "nonce:proof")
    for name, expected in (("kernel", 337), ("domain", 343)):
        _exact_keys(proof[name], ("verified", "errors"), f"nonce:proof:{name}")
        if proof[name] != {"verified": expected, "errors": 0}:
            raise LedgerError(f"nonce:proof:{name}: proof counts changed")
        checked += 1
    _exact_keys(proof["audits"], ("kernel", "domain"), "nonce:proof:audits")
    for name in ("kernel", "domain"):
        if proof["audits"][name] != "Dafny auditor completed with 0 findings":
            raise LedgerError(f"nonce:proof:audits:{name}: trusted declaration reached the audit")
        checked += 1
    if proof["forbidden_source_constructs"] != "none found in code (comments stripped)":
        raise LedgerError("nonce:proof: forbidden source constructs changed")
    _exact_keys(proof["source_sha256"], ("before", "after"), "nonce:proof:source")
    if proof["source_sha256"] != {"before": kernel_sha, "after": kernel_sha}:
        raise LedgerError("nonce:proof: frozen source hash is not the kernel pin before and after")
    checked += 2

    controls = receipt["controls"]
    _exact_keys(controls, PACKET_NONCE_CONTROL_NAMES, "nonce:controls")
    for name in PACKET_NONCE_CONTROL_NAMES:
        control = controls[name]
        _exact_keys(control, ("status", "anchor", "summary"), f"nonce:control:{name}")
        if control["status"] != "proof-obligation-rejected":
            raise LedgerError(f"nonce:control:{name}: not a semantic proof rejection")
        if not isinstance(control["anchor"], str) or control["anchor"] not in kernel_text:
            raise LedgerError(f"nonce:control:{name}: anchor is not in the frozen kernel")
        match = re.fullmatch(r"(\d+) verified, (\d+) errors", str(control["summary"]))
        if match is None or int(match[2]) < 1 or int(match[1]) < 1:
            raise LedgerError(f"nonce:control:{name}: controls must show real proof errors")
        reject_inconclusive_control(control, f"nonce:control:{name}")
        checked += 1

    generation = receipt["generation"]
    _exact_keys(generation, (
        "dafny_version", "generator_command", "aggregator_sha256",
        "translation_metadata_sha256", "generated_java_key", "generated_java_sha256",
        "generated_class_key", "generated_class_sha256", "external_replay_report_sha256",
        "external_replay_report_role"), "nonce:generation")
    generated_receipt = load_json(checked_path(root, "formal/nonce/GENERATED.json", "nonce:generated"))
    if (generation["dafny_version"] != generated_receipt.get("dafny_version")
            or generation["generator_command"] != generated_receipt.get("generator_command")):
        raise LedgerError("nonce:generation: compiler identity differs from GENERATED.json")
    if generation["aggregator_sha256"] != generated_receipt.get("aggregator_sha256"):
        raise LedgerError("nonce:generation: aggregator differs from GENERATED.json")
    for name in ("aggregator_sha256", "translation_metadata_sha256", "generated_class_sha256",
                 "external_replay_report_sha256"):
        checked_hash(generation[name], f"nonce:generation:{name}")
    if generation["external_replay_report_sha256"] != PACKET_NONCE_ACCEPTED_REPORT_SHA256:
        raise LedgerError("nonce:generation: external report is not the accepted component replay")
    if generation["translation_metadata_sha256"] != PACKET_NONCE_TRANSLATION_METADATA_SHA256:
        raise LedgerError("nonce:generation: translation metadata is not the accepted output")
    if generation["generated_class_key"] != PACKET_NONCE_GENERATED_CLASS_KEY:
        raise LedgerError("nonce:generation: generated class key changed")
    if generation["generated_class_sha256"] != PACKET_NONCE_GENERATED_CLASS_SHA256:
        raise LedgerError("nonce:generation: generated class hash is not the reviewed output")
    if generation["generated_java_key"] != PACKET_NONCE_GENERATED_KEY:
        raise LedgerError("nonce:generation: generated source key changed")
    if generation["generated_java_sha256"] != PACKET_NONCE_GENERATED_SHA256:
        raise LedgerError("nonce:generation: generated source hash is not the reviewed output")
    actual_generated = digest(checked_path(root, PACKET_NONCE_GENERATED, "nonce:generated"))
    if actual_generated != generation["generated_java_sha256"]:
        raise LedgerError("nonce:generation: checked-in generated Java changed")
    if generated_receipt.get("generated_java", {}).get("__default.java") != actual_generated:
        raise LedgerError("nonce:generation: GENERATED.json does not bind the checked-in source")
    if generated_receipt.get("source", {}).get("sha256") != kernel_sha:
        raise LedgerError("nonce:generation: GENERATED.json does not bind the frozen kernel")
    if "provenance only" not in str(generation["external_replay_report_role"]):
        raise LedgerError("nonce:generation: external report must be labelled provenance only")
    generated_text = checked_path(root, PACKET_NONCE_GENERATED, "nonce:generated").read_text(encoding="utf-8")
    if "public static byte[] Nonce(byte[] iv, long pn)" not in generated_text:
        raise LedgerError("nonce:generation: generated signature changed")
    checked += 6

    bridge = receipt["bridge"]
    _exact_keys(bridge, ("source", "sha256", "symbol", "signature", "delegation",
                         "class_key"), "nonce:bridge")
    if bridge["source"] != PACKET_NONCE_BRIDGE or bridge["sha256"] != PACKET_NONCE_BRIDGE_SHA256:
        raise LedgerError("nonce:bridge: PacketKey source identity changed")
    if digest(checked_path(root, PACKET_NONCE_BRIDGE, "nonce:bridge")) != bridge["sha256"]:
        raise LedgerError("nonce:bridge: current PacketKey source differs from its pin")
    if bridge["delegation"] != "return Nonce(iv, packetNumber);":
        raise LedgerError("nonce:bridge: delegation statement changed")
    bridge_text = checked_path(root, PACKET_NONCE_BRIDGE, "nonce:bridge").read_text(encoding="utf-8")
    if bridge["delegation"] not in bridge_text:
        raise LedgerError("nonce:bridge: PacketKey does not delegate to the generated nonce")
    if "packetNumber >>>" in bridge_text:
        raise LedgerError("nonce:bridge: inline nonce loop is still present")
    if ("io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default.Nonce"
            not in bridge_text):
        raise LedgerError("nonce:bridge: static import of the generated symbol is missing")
    historical = checked_path(root, PACKET_NONCE_HISTORICAL, "nonce:historical")
    if digest(historical) != PACKET_NONCE_HISTORICAL_SHA256:
        raise LedgerError("nonce:historical: frozen pre-adoption source changed")
    if digest(historical) == digest(checked_path(root, PACKET_NONCE_BRIDGE, "nonce:bridge")):
        raise LedgerError("nonce:historical: live bridge silently rebound to the frozen source")
    checked += 4

    delivery = receipt["delivery"]
    _exact_keys(delivery, (
        "manifest", "manifest_sha256", "existing_generated_sources_key",
        "existing_generated_sources_sha256", "crypto_scope_prefixes",
        "expected_library_class_count", "expected_crypto_class_count",
        "expected_retained_library_class_count"), "nonce:delivery")
    if delivery["manifest"] != "formal/crypto/delivery.json":
        raise LedgerError("nonce:delivery: manifest path changed")
    manifest = load_json(checked_path(root, delivery["manifest"], "nonce:delivery"))
    if digest(checked_path(root, delivery["manifest"], "nonce:delivery")) != delivery["manifest_sha256"]:
        raise LedgerError("nonce:delivery: manifest hash is stale")
    key = delivery["existing_generated_sources_key"]
    if key != PACKET_NONCE_GENERATED_KEY:
        raise LedgerError("nonce:delivery: generated inventory key changed")
    inventory = manifest.get("existing_generated_sources", {})
    if inventory.get(key) != delivery["existing_generated_sources_sha256"]:
        raise LedgerError("nonce:delivery: delivery manifest lacks the generated nonce pin")
    if delivery["existing_generated_sources_sha256"] != PACKET_NONCE_GENERATED_SHA256:
        raise LedgerError("nonce:delivery: delivery pin is not the reviewed generated output")
    if digest(checked_path(root, "quic/src/main/java/" + key, "nonce:delivery")) != inventory[key]:
        raise LedgerError("nonce:delivery: generated nonce source differs from the delivery pin")
    if delivery["crypto_scope_prefixes"] != [
            "io/github/mahmoudimus/quic/crypto/PacketKey",
            "io/github/mahmoudimus/quic/crypto/internal/verifiednonce/"]:
        raise LedgerError("nonce:delivery: scoped crypto prefixes changed")
    counts = (delivery["expected_library_class_count"], delivery["expected_crypto_class_count"],
              delivery["expected_retained_library_class_count"])
    if counts != (PACKET_NONCE_LIBRARY_CLASS_COUNT, PACKET_NONCE_CRYPTO_CLASS_COUNT,
                  PACKET_NONCE_RETAINED_CLASS_COUNT):
        raise LedgerError("nonce:delivery: reviewed class counts changed")
    release_tool = checked_path(root, "scripts/security/crypto_current_release.py", "nonce:delivery")
    release_constants = _python_assignments(release_tool, (
        "EXPECTED_LIBRARY_CLASS_COUNT", "EXPECTED_CRYPTO_CLASS_COUNT",
        "EXPECTED_RETAINED_LIBRARY_CLASS_COUNT", "NONCE_SMOKE_SOURCE",
        "EXPECTED_NONCE_SMOKE_CASES"), "nonce:release-tool")
    if (release_constants["EXPECTED_LIBRARY_CLASS_COUNT"],
            release_constants["EXPECTED_CRYPTO_CLASS_COUNT"],
            release_constants["EXPECTED_RETAINED_LIBRARY_CLASS_COUNT"]) != counts:
        raise LedgerError("nonce:delivery: receipt counts differ from the release validator")
    if (release_constants["NONCE_SMOKE_SOURCE"] != PACKET_NONCE_SMOKE
            or release_constants["EXPECTED_NONCE_SMOKE_CASES"] != 9):
        raise LedgerError("nonce:delivery: release validator nonce smoke binding changed")
    bundle_tool = checked_path(root, "formal/crypto/bundle_checks.py", "nonce:delivery")
    bundle_constants = _python_assignments(
        bundle_tool, ("CRYPTO_PREFIXES", "REQUIRED_ROOTS"), "nonce:bundle-tool")
    for prefix in delivery["crypto_scope_prefixes"]:
        if prefix not in bundle_constants["CRYPTO_PREFIXES"]:
            raise LedgerError(f"nonce:bundle-tool: missing scoped crypto prefix {prefix}")
    for required in ("io/github/mahmoudimus/quic/crypto/PacketKey.class",
                     "io/github/mahmoudimus/quic/crypto/internal/verifiednonce/VerifiedNonce/__default.class"):
        if required not in bundle_constants["REQUIRED_ROOTS"]:
            raise LedgerError(f"nonce:bundle-tool: missing required bundle root {required}")
    checked += 8

    runs = receipt["java_runs"]
    if not isinstance(runs, list) or len(runs) != len(PACKET_NONCE_JAVA_RUNS):
        raise LedgerError("nonce:java: expected exactly JDK 21 and 25 records")
    for run, (major, java_sha, javac_sha) in zip(runs, PACKET_NONCE_JAVA_RUNS):
        _exact_keys(run, ("major", "java_sha256", "javac_sha256", "tests"), "nonce:java")
        if (run["major"], run["java_sha256"], run["javac_sha256"], run["tests"]) != (
                major, java_sha, javac_sha, PACKET_NONCE_JAVA_TESTS):
            raise LedgerError(f"nonce:java: JDK {major} identity or test result changed")
        checked += 1

    junit = receipt["junit"]
    _exact_keys(junit, ("source", "sha256", "tests", "jdk_majors", "result", "scope"),
                "nonce:junit")
    if junit["source"] != PACKET_NONCE_TEST or junit["sha256"] != PACKET_NONCE_TEST_SHA256:
        raise LedgerError("nonce:junit: test source identity changed")
    junit_text = checked_path(root, PACKET_NONCE_TEST, "nonce:junit").read_text(encoding="utf-8")
    if digest(checked_path(root, PACKET_NONCE_TEST, "nonce:junit")) != junit["sha256"]:
        raise LedgerError("nonce:junit: test source differs from its pin")
    if junit["tests"] != 8 or junit_text.count("@Test") != 8:
        raise LedgerError("nonce:junit: reviewed test count changed")
    if junit["jdk_majors"] != [21, 25]:
        raise LedgerError("nonce:junit: both JDK replays are required")
    if "8 tests successful" not in str(junit["result"]):
        raise LedgerError("nonce:junit: missing reviewed result")
    for marker in ("seal(", "open("):
        if marker not in junit_text:
            raise LedgerError(f"nonce:junit: test source lacks {marker!r}")
        checked += 1
    checked += 2

    smoke = receipt["bundle_smoke"]
    _exact_keys(smoke, ("schema", "source", "sha256", "cases", "suites",
                        "packet_numbers", "executes", "origins",
                        "not_bound_to_core_inputs", "note"), "nonce:bundle-smoke")
    if smoke["schema"] != "microproxy.nonce-bundle-smoke/v1":
        raise LedgerError("nonce:bundle-smoke: schema changed")
    if smoke["source"] != PACKET_NONCE_SMOKE:
        raise LedgerError("nonce:bundle-smoke: source path changed")
    if smoke["sha256"] != digest(checked_path(root, PACKET_NONCE_SMOKE, "nonce:bundle-smoke")):
        raise LedgerError("nonce:bundle-smoke: harness source differs from its pin")
    if smoke["cases"] != 9 or tuple(smoke["suites"]) != PACKET_NONCE_SMOKE_SUITES \
            or smoke["packet_numbers"] != [0, 1, -1]:
        raise LedgerError("nonce:bundle-smoke: case matrix changed")
    if smoke["executes"] != ["PacketKey.nonce", "PacketKey.seal", "PacketKey.open"]:
        raise LedgerError("nonce:bundle-smoke: executed production calls changed")
    _exact_keys(smoke["origins"], ("PacketKey", "VerifiedNonce", "DafnyRuntime", "harness"),
                "nonce:bundle-smoke:origins")
    if any(not isinstance(value, str) or not value for value in smoke["origins"].values()):
        raise LedgerError("nonce:bundle-smoke: origin descriptions are malformed")
    if smoke["origins"]["DafnyRuntime"] != smoke["origins"]["PacketKey"]:
        raise LedgerError("nonce:bundle-smoke: Dafny runtime must execute from the actual bundle")
    if smoke["not_bound_to_core_inputs"] is not True:
        raise LedgerError("nonce:bundle-smoke: harness must stay outside the core proof closure")
    core_inputs = load_json(checked_path(root, "formal/nonce/inputs.json", "nonce:core-inputs"))
    if PACKET_NONCE_SMOKE in core_inputs.get("inputs", {}):
        raise LedgerError("nonce:bundle-smoke: smoke harness leaked into the core input closure")
    smoke_text = checked_path(root, PACKET_NONCE_SMOKE, "nonce:bundle-smoke").read_text(encoding="utf-8")
    for marker in ("packetKey.nonce(", "packetKey.seal(", "packetKey.open(",
                   "Class.forName("):
        if marker not in smoke_text:
            raise LedgerError(f"nonce:bundle-smoke: harness lacks {marker!r}")
        checked += 1
    if smoke_text.index("origin(Class.forName(") < smoke_text.index("packetKey.open("):
        raise LedgerError("nonce:bundle-smoke: origin Class.forName precedes production execution")
    checked += 3

    non_claims = receipt["non_claims"]
    if not isinstance(non_claims, list) or not non_claims or any(
            not isinstance(item, str) or not item for item in non_claims):
        raise LedgerError("nonce:receipt: non_claims must be a nonempty string list")
    text = " ".join(non_claims).lower()
    for phrase in ("saw", "cryptographic hardness", "timing", "full-jar"):
        if phrase not in text:
            raise LedgerError(f"nonce:receipt: explicit non-claim {phrase!r} is missing")
    limitations = receipt["limitations"]
    if not isinstance(limitations, list) or not limitations or any(
            not isinstance(item, str) or not item for item in limitations):
        raise LedgerError("nonce:receipt: limitations must be a nonempty string list")
    checked += len(non_claims) + len(limitations)
    return checked


def _validate_supported_claim(root: Path, claim: dict[str, Any], policy: dict[str, Any],
                              obligations: dict[str, dict[str, Any]],
                              evidence_by_obligation: dict[str, dict[str, dict[str, Any]]],
                              claim_statuses: dict[str, str]) -> int:
    claim_id = claim["id"]
    if tuple(claim["obligations"]) != policy["obligations"]:
        raise LedgerError(
            f"{claim_id}: supported claim dependency set is not the reviewed policy "
            f"{list(policy['obligations'])}")
    if claim.get("strength") != policy["strength"]:
        raise LedgerError(f"{claim_id}: supported claim strength must be {policy['strength']!r}")
    if claim.get("production") is not policy["production"]:
        raise LedgerError(f"{claim_id}: supported claim production marker must be {policy['production']!r}")
    if frozenset(claim["assumptions"]) != policy["assumptions"]:
        raise LedgerError(f"{claim_id}: supported claim assumptions differ from the reviewed policy")
    for oid, allowed in policy.get("required_statuses", {}).items():
        if obligations[oid]["status"] not in allowed:
            raise LedgerError(
                f"{claim_id}: obligation {oid} status {obligations[oid]['status']} "
                f"cannot support this claim")
    claim_evidence = {
        ref["path"]: ref for oid in claim["obligations"]
        for ref in obligations[oid]["evidence"] if ref["path"] in claim["evidence"]
    }
    checked = 0
    for required_path, required_kind in policy["required_evidence"]:
        if required_path is None:
            if not any(ref["kind"] == required_kind for ref in claim_evidence.values()):
                raise LedgerError(
                    f"{claim_id}: missing required evidence kind {required_kind!r} in the claim")
        else:
            ref = claim_evidence.get(required_path)
            if ref is None:
                raise LedgerError(f"{claim_id}: required evidence is not cited by the claim: {required_path}")
            if ref["kind"] != required_kind:
                raise LedgerError(
                    f"{claim_id}: required evidence {required_path} must be kind {required_kind!r}")
        checked += 1
    for receipt_path, values in policy.get("required_receipt_values", ()):
        if receipt_path not in claim_evidence:
            raise LedgerError(f"{claim_id}: claim does not cite required receipt {receipt_path}")
        receipt = load_json(checked_path(root, receipt_path, f"{claim_id}:policy-receipt"))
        for path, expected in values.items():
            found = dot_get(receipt, path, f"{claim_id}:policy-receipt")
            if found != expected:
                raise LedgerError(
                    f"{claim_id}: required receipt value {path} is {found!r}, expected {expected!r}")
            checked += 1
    for kind, values in policy.get("required_kind_receipt_values", ()):
        candidates = [ref["path"] for ref in claim_evidence.values() if ref["kind"] == kind]
        if not candidates:
            raise LedgerError(f"{claim_id}: missing required receipt kind {kind!r}")
        matched = False
        for receipt_path in candidates:
            receipt = load_json(checked_path(root, receipt_path, f"{claim_id}:kind-receipt"))
            if all(dot_get(receipt, path, f"{claim_id}:kind-receipt") == expected
                   for path, expected in values.items()):
                matched = True
                break
        if not matched:
            raise LedgerError(f"{claim_id}: no {kind!r} receipt satisfies the reviewed metadata")
        checked += 1
    for oid in policy.get("component_checks", ()):
        checked += _validate_required_component(root, obligations[oid], f"{claim_id}:{oid}")
    if policy.get("complete_all"):
        completion_statuses = {
            "V0": {"finite-tests"},
            "V1": {"implementation-proof", "model-proof", "bytecode-proof"},
            "V2": {"implementation-proof", "model-proof", "bytecode-proof"},
            "V3": {"implementation-proof", "model-proof", "bytecode-proof"},
            "V4": {"implementation-proof", "model-proof", "bytecode-proof"},
            "V5": {"implementation-proof", "model-proof", "bytecode-proof"},
            "V6": {"implementation-proof", "model-proof", "bytecode-proof"},
            "V7": {"implementation-proof", "model-proof", "bytecode-proof"},
            "V8": {"finite-tests", "implementation-proof"},
        }
        incomplete = [oid for oid in REQUIRED_OBLIGATIONS
                      if obligations[oid]["status"] not in completion_statuses[oid]]
        if incomplete:
            raise LedgerError(f"{claim_id}: obligations are not complete: {incomplete}")
        missing = [other for other in sorted(COMPLETION_REQUIRED_CLAIMS)
                   if other != claim_id and claim_statuses.get(other) != "supported"]
        if missing:
            raise LedgerError(f"{claim_id}: required claims are not supported: {missing}")
    if claim_id == "packet-nonce-functional-production":
        checked += _validate_packet_nonce_functional(root)
    if claim_id == POLY_SOURCE_CLAIM:
        checked += _validate_poly_source_claim(root, claim, f"{claim_id}:poly-source")
    return checked


def _validate_claims(ledger: dict[str, Any], obligations: dict[str, dict[str, Any]],
                     evidence_by_obligation: dict[str, dict[str, dict[str, Any]]],
                     root: Path | None = None) -> tuple[dict[str, dict[str, Any]], int]:
    claims = ledger.get("claims")
    if not isinstance(claims, list) or not claims:
        raise LedgerError("claims must be a nonempty list")
    statuses: dict[str, str] = {}
    for position, claim in enumerate(claims):
        if not isinstance(claim, dict):
            raise LedgerError(f"claim[{position}]: must be an object")
        claim_id = claim.get("id")
        if type(claim_id) is str and claim_id in ALLOWED_CLAIMS:
            if claim_id in statuses:
                raise LedgerError(f"claim[{position}]: duplicate claim id {claim_id}")
            statuses[claim_id] = claim.get("status")
    result: dict[str, dict[str, Any]] = {}
    for position, claim in enumerate(claims):
        label = f"claim[{position}]"
        if not isinstance(claim, dict):
            raise LedgerError(f"{label}: must be an object")
        claim_id = claim.get("id")
        if type(claim_id) is not str or not claim_id:
            raise LedgerError(f"{label}: id is required")
        if claim_id in result:
            raise LedgerError(f"{label}: duplicate claim id {claim_id}")
        if claim_id not in ALLOWED_CLAIMS:
            raise LedgerError(f"{label}: unexpected claim id {claim_id}")
        status = claim.get("status")
        if status not in CLAIM_STATUSES:
            raise LedgerError(f"{claim_id}: unsupported claim status {status!r}")
        if status == "supported" and claim_id not in SEMANTICALLY_VALIDATED_SUPPORTED_CLAIMS:
            raise LedgerError(
                f"{claim_id}: no reviewed semantic evidence validator; supported is fail-closed")
        strength = claim.get("strength")
        if strength not in CLAIM_STRENGTHS:
            raise LedgerError(f"{claim_id}: unsupported claim strength {strength!r}")
        if type(claim.get("statement")) is not str or not claim["statement"].strip():
            raise LedgerError(f"{claim_id}: statement is required")
        refs = claim.get("obligations")
        if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)):
            raise LedgerError(f"{claim_id}: obligations must be a nonempty unique list")
        for ref in refs:
            if ref not in obligations:
                raise LedgerError(f"{claim_id}: unknown obligation reference {ref}")
        claim_assumptions = claim.get("assumptions")
        if not isinstance(claim_assumptions, list) or len(claim_assumptions) != len(set(claim_assumptions)):
            raise LedgerError(f"{claim_id}: assumptions must be a unique list")
        for assumption in claim_assumptions:
            if assumption not in ALLOWED_ASSUMPTIONS:
                raise LedgerError(f"{claim_id}: unknown assumption {assumption}")
        evidence = claim.get("evidence")
        if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)):
            raise LedgerError(f"{claim_id}: evidence must be a nonempty unique path list")
        allowed_paths = set().union(*(set(evidence_by_obligation[ref]) for ref in refs))
        for path in evidence:
            _clean_relative(path, f"{claim_id}:evidence")
            if path not in allowed_paths:
                raise LedgerError(f"{claim_id}: evidence {path} is not declared by its obligations")
        limitations = claim.get("limitations")
        if not isinstance(limitations, list) or not limitations:
            raise LedgerError(f"{claim_id}: limitations must be a nonempty list")
        policy = CLAIM_POLICIES.get(claim_id)
        if policy is None:
            raise LedgerError(f"{claim_id}: no reviewed supported-claim policy")
        if status == "supported":
            if root is None:
                raise LedgerError(f"{claim_id}: internal policy validation requires a repository root")
            _validate_supported_claim(root, claim, policy, obligations,
                                      evidence_by_obligation, statuses)
        result[claim_id] = claim
    if set(result) != ALLOWED_CLAIMS:
        missing = sorted(ALLOWED_CLAIMS - set(result))
        raise LedgerError(f"claim inventory incomplete: {missing}")
    return result, len(result)


def validate_ledger(root: Path, ledger_path: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    ledger_path = (ledger_path or root / "formal/crypto-obligations.json").resolve()
    if ledger_path.is_relative_to(root):
        ledger = load_json(checked_path(root, ledger_path.relative_to(root).as_posix(), "ledger"))
    else:
        if not ledger_path.is_file():
            raise LedgerError(f"ledger: not a regular file: {ledger_path}")
        ledger = load_json(ledger_path)
    if ledger.get("schema") != LEDGER_SCHEMA:
        raise LedgerError(f"ledger schema must be {LEDGER_SCHEMA}")
    if type(ledger.get("scope")) is not str or not ledger["scope"].strip():
        raise LedgerError("ledger scope is required")
    assumption_names = _validate_assumptions(ledger)
    obligation_list = ledger.get("obligations")
    if not isinstance(obligation_list, list):
        raise LedgerError("obligations must be a list")
    obligations: dict[str, dict[str, Any]] = {}
    for position, obligation in enumerate(obligation_list):
        if not isinstance(obligation, dict):
            raise LedgerError(f"obligation[{position}]: must be an object")
        name = obligation.get("id")
        if name not in REQUIRED_OBLIGATIONS:
            raise LedgerError(f"obligation[{position}]: unknown obligation id {name!r}")
        if name in obligations:
            raise LedgerError(f"duplicate obligation id {name}")
        obligations[name] = obligation
    if set(obligations) != set(REQUIRED_OBLIGATIONS):
        raise LedgerError(f"pinned V0-V8 inventory incomplete: missing={sorted(set(REQUIRED_OBLIGATIONS) - set(obligations))}")
    if [item.get("id") for item in obligation_list] != list(REQUIRED_OBLIGATIONS):
        raise LedgerError("obligations must be ordered V0 through V8")
    _validate_dependency_graph(obligations)

    evidence_by_obligation: dict[str, dict[str, dict[str, Any]]] = {}
    used_assumptions: set[str] = set()
    evidence_count = 0
    control_count = 0
    for name in REQUIRED_OBLIGATIONS:
        obligation = obligations[name]
        if obligation.get("status") not in ALLOWED_STATUSES:
            raise LedgerError(f"{name}: unsupported status {obligation.get('status')!r}")
        if name == "V7" and obligation.get("status") in PROOF_STATUSES:
            raise LedgerError(
                "V7 cannot be promoted while 15 open owned roots and 19 assumed owned helper "
                "trace contracts remain open")
        if type(obligation.get("title")) is not str or not obligation["title"].strip():
            raise LedgerError(f"{name}: title is required")
        if type(obligation.get("statement")) is not str or not obligation["statement"].strip():
            raise LedgerError(f"{name}: statement is required")
        refs = obligation.get("assumptions")
        if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)):
            raise LedgerError(f"{name}: assumptions must be a nonempty unique list")
        for assumption in refs:
            if assumption not in assumption_names:
                raise LedgerError(f"{name}: unknown/unlisted assumption {assumption}")
            used_assumptions.add(assumption)
        limitations = obligation.get("limitations")
        if not isinstance(limitations, list) or not limitations or any(
                type(value) is not str or not value.strip() for value in limitations):
            raise LedgerError(f"{name}: limitations must be a nonempty list of statements")
        evidence, count = _validate_evidence(root, obligation, name)
        evidence_by_obligation[name] = evidence
        evidence_count += count
        if name == "V7":
            evidence_count += _validate_trace_report(root, f"{name}:trace-report")
        if obligation["status"] in PROOF_STATUSES and not any(
                ref["kind"] in PROOF_EVIDENCE_KINDS for ref in evidence.values()):
            raise LedgerError(f"{name}: proof status lacks proof/implementation evidence")
        if obligation["status"] in PROOF_STATUSES:
            _validate_nonvacuity(root, obligation, name)
            if name in REQUIRED_COMPONENT_CHECKS:
                evidence_count += _validate_required_component(root, obligation, f"{name}:proof-contract")
        control_count += _validate_controls(root, obligation, name)
        evidence_count += _validate_receipt_checks(root, obligation, name)
        evidence_count += _validate_hash_maps(root, obligation, name)
        evidence_count += _validate_entry_hashes(root, obligation, name)
        evidence_count += _validate_text_checks(root, obligation, name)
        for index, inventory in enumerate(obligation.get("inventory_checks", [])):
            if not isinstance(inventory, dict):
                raise LedgerError(f"{name}:inventory[{index}]: must be an object")
            evidence_count += _validate_inventory(root, inventory, f"{name}:inventory[{index}]")
        for index, file_set in enumerate(obligation.get("file_set_checks", [])):
            if not isinstance(file_set, dict):
                raise LedgerError(f"{name}:file-set[{index}]: must be an object")
            evidence_count += _validate_file_set(root, file_set, f"{name}:file-set[{index}]")
    unused = sorted(assumption_names - used_assumptions)
    if unused:
        raise LedgerError(f"unlisted/unused assumptions: {unused}")
    claims, claim_count = _validate_claims(ledger, obligations, evidence_by_obligation, root)

    return {
        "schema": STATUS_SCHEMA,
        "ok": True,
        "ledger_schema": LEDGER_SCHEMA,
        "obligations": {name: obligations[name]["status"] for name in REQUIRED_OBLIGATIONS},
        "claims": {name: claims[name]["status"] for name in sorted(claims)},
        "assumptions": sorted(assumption_names),
        "completion_required_claims": sorted(COMPLETION_REQUIRED_CLAIMS),
        "residual_claims": sorted(name for name, claim in claims.items()
                                  if claim["status"] != "supported"),
        "evidence_checked": evidence_count,
        "controls_checked": control_count,
        "claims_checked": claim_count,
        "failures": [],
    }


def _failure(message: str) -> dict[str, Any]:
    return {"schema": STATUS_SCHEMA, "ok": False, "failures": [{"claim": None, "reason": message}]}


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        status = validate_ledger(args.root, args.ledger)
        code = 0
    except LedgerError as exc:
        status = _failure(str(exc))
        code = 1
    except Exception as exc:  # fail closed without hiding unexpected validator failure as success
        status = _failure(f"internal validator failure: {type(exc).__name__}: {exc}")
        code = 2
    text = json.dumps(status, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".part")
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(args.output)
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
