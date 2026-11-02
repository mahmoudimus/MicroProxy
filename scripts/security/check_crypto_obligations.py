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
            ('native-codec-semantic-controls', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'reused_evidence.semantic_controls'),
            ('native-codec-bytecode-controls', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'bytecode_controls'),
            ('native-polynomial-mac-controls', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.controls'),
            ('native-polynomial-linux-controls', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'linux_controls.receipt.controls'),
        ),
        "receipt_checks": (
            ('formal/crypto/CODEC-EVIDENCE.json', ('proofs.proof-Codec', 'proofs.proof-Sampling', 'proofs.codec_domain', 'proofs.sampling_domain')),
            ('formal/crypto/POLYNOMIAL-EVIDENCE.json', ('status', 'phase', 'verified', 'dafny_version', 'solver_version')),
            ('formal/crypto/NATIVE-CODEC-EVIDENCE.json', ('reused_evidence.proofs.proof-NativeField', 'reused_evidence.proofs.proof-NativeCodec', 'reused_evidence.proofs.proof-NativeSampling', 'reused_evidence.proofs.native_codec_domain', 'reused_evidence.proofs.native_sampling_domain')),
            ('formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', ('status', 'unchanged_policy.negative_control_count', 'unchanged_policy.required_semantic_exit', 'mac_full.receipt.status', 'mac_full.receipt.dependency_verified', 'mac_full.receipt.native_verified', 'linux_controls.receipt.status')),
        ),
        "hash_maps": (
            ('formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.inputs', (), ()),
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
            ('formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', ('exit', 'verified', 'platform', 'dafny_version')),
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
    ('V4', 'formal/crypto/adoption/stage-receipt.json', 'sources', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.inputs', (), ''): ('formal/crypto/NativeField.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/native_polynomial_checks.py', 'formal/crypto/native_polynomial_domain.dfy', 'formal/crypto/native_polynomial_test.java', 'formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy'),
    ('V5', 'formal/crypto/adoption/stage-receipt.json', 'sources', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'inputs', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/native_kem_checks.py', 'formal/crypto/native_kem_domain.dfy', 'formal/crypto/native_kem_hash.java', 'formal/crypto/native_kem_test.java', 'formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'source_graph', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/native_kem_domain.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V6', 'formal/crypto/adoption/stage-receipt.json', 'sources', (), ''): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
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
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'verified'): 21,
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'public_domain_verified'): 22,
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'generated_java'): {'HkdfCrypto.java': 'c23818b14294d7a4da21e329a4fa1a67148549537aac5d07a3f9198bc71955ba', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'delivered_generated_java'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'source'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'classes'): {'io/github/mahmoudimus/quic/Hkdf.class': 'b096db75e610d1a8aec5e6f85e615557b17be6673d353e92add4611b42d65b6e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.class': '4a1d2f0aeef211e31bc8f204ea455bd0a5ee0d43a56c1ebfb5baea4d8ea847ef', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.class': '0e10e3dc75b944c5bf1b5c4986135a0c7d9b84d4bd68cec561c3e8179adfa89b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.class': '8406abdea86743df597c5ef3a5fdcd5a5bda053b3040eaa575009ee2862f0256', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.class': 'b1be80387efcd1dccd87ad586b4cc03c8c2942583947c786c95779132f725ce4', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.class': 'b6fed8819f430368ce56ef3f38bede250405feab0b0911d71fc77407aa8db48b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.class': '9f32cbaa3220d547003a5f0f8872a8842682cba11532571bb9d61a09da986446', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.class': '8e0600b18dce5a6ebaec135ae8f17e1b55bbde8b733ba06f3705ef61ebe54f2e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.class': 'f69ef50597d54f66b0cf03b253511aa737e503fd2406bd99a4d83f198deeeb14', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.class': '147e8dee1936965914cd70f74f5565cfe068bf9c955d5a18dbd29f3080433b2b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class': 'c1df4e947257748b79568313e8381d02e83db8f58c1e42342c1bbbb98f76b0d5', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.class': '08b9ffd9cdb9d350732ba66f44ed5c4374652776e78f7a4ab28adcf5df84666b'},
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'verified'): 21,
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'aggregator_sha256'): 'c23818b14294d7a4da21e329a4fa1a67148549537aac5d07a3f9198bc71955ba',
    ('V1', 'formal/dafny/hkdf/GENERATED.json', 'translation_metadata_sha256'): 'b374f6b9506da02fb5c0c579a6c588807575eac7548a296ef823bc9c89ba4052',
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'controls'): {'counter': 'proof-obligation-rejected', 'feedback': 'proof-obligation-rejected', 'truncation': 'proof-obligation-rejected', 'prefix': 'proof-obligation-rejected', 'public-domain': 'proof-obligation-rejected', 'extra-assumption': 'audit-rejected', 'skipped-proof': 'audit-rejected', 'adapter-select-loop': 'bytecode-rejected', 'adapter-bare-cast': 'bytecode-rejected', 'adapter-dead-decoy': 'bytecode-rejected'},
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'java_runs'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)', 'tests': 'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: HmacSHA256=SunJCE, HmacSHA384=SunJCE, HmacSHA512=SunJCE', 'executable_sha256': 'd7ab2ea6a7e731a8a2cee7d722046c9f7d8c5f184cd769b9954a392592337770'}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)', 'tests': 'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: HmacSHA256=SunJCE, HmacSHA384=SunJCE, HmacSHA512=SunJCE', 'executable_sha256': 'd6b5c8ffce485baa7e9aacfd9c652e2999c89053a5070104c598731636bd2249'}],
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'assumptions'): ['VerifiedHkdf.Mac: deterministic external HMAC with fixed output length'],
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'adapter_discipline'): 'JdkHmac.bytes has a guarded toRawArray/instanceof [B/branch/checkcast/areturn shape; HkdfBridge delegates; select/Byte rejected',
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'verified'): 21,
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'public_domain_verified'): 22,
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'generated_java'): {'HkdfCrypto.java': 'c23818b14294d7a4da21e329a4fa1a67148549537aac5d07a3f9198bc71955ba', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'delivered_generated_java'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'source'): {'BytesResult.java': 'b170d437a4dfd2efbf5f18ed61c7a9097e7c370fc419c16be2bbc5376bd5e1c6', 'BytesResult_Failure.java': '17306de8b1d637f4b4dffef779a60fffb8784a575f753e05dd8be2ceb207a46f', 'BytesResult_Success.java': '52b31fc22b8ff74be795aefe9105025c7d580adb869b8e8750496a4e47321d45', 'FailureKind.java': '6e653532074d933ae42d76eef1ab1511de31ef82bfe298421c16794e6c4a2280', 'FailureKind_InvalidHash.java': 'f87dc02237947a2f0932941bdccc003a08abfb5a85b267b7423c92ee14c779b6', 'FailureKind_InvalidKey.java': 'b2f2f1ab069343ca8a5f282bf60389ef0787d3fa13d423df9e4c847a0d6c2194', 'FailureKind_InvalidLabel.java': '81db1c35cf12d398c447151c7f479941ae2047c987a377b9849bd82702f1e760', 'FailureKind_InvalidLength.java': 'f982da36e5fdc03e5053d5225ea6e3e8d8069aa2950761844dc0d79676de216b', '__default.java': 'e03016973f0e0700a760a780cbeb55a255a4dbac93ac6c847b14a1ad5032864a'},
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'classes'): {'io/github/mahmoudimus/quic/Hkdf.class': 'b096db75e610d1a8aec5e6f85e615557b17be6673d353e92add4611b42d65b6e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.class': '4a1d2f0aeef211e31bc8f204ea455bd0a5ee0d43a56c1ebfb5baea4d8ea847ef', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.class': '0e10e3dc75b944c5bf1b5c4986135a0c7d9b84d4bd68cec561c3e8179adfa89b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.class': '8406abdea86743df597c5ef3a5fdcd5a5bda053b3040eaa575009ee2862f0256', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.class': 'b1be80387efcd1dccd87ad586b4cc03c8c2942583947c786c95779132f725ce4', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.class': 'b6fed8819f430368ce56ef3f38bede250405feab0b0911d71fc77407aa8db48b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.class': '9f32cbaa3220d547003a5f0f8872a8842682cba11532571bb9d61a09da986446', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.class': '8e0600b18dce5a6ebaec135ae8f17e1b55bbde8b733ba06f3705ef61ebe54f2e', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.class': 'f69ef50597d54f66b0cf03b253511aa737e503fd2406bd99a4d83f198deeeb14', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.class': '147e8dee1936965914cd70f74f5565cfe068bf9c955d5a18dbd29f3080433b2b', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class': 'c1df4e947257748b79568313e8381d02e83db8f58c1e42342c1bbbb98f76b0d5', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.class': '08b9ffd9cdb9d350732ba66f44ed5c4374652776e78f7a4ab28adcf5df84666b'},
    ('V2', 'formal/dafny/hkdf/GENERATED.json', 'verified'): 21,
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
    ('V5', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'validation_kind'): 'Fresh Java compilation, bytecode checker and JDK replay; unchanged SMT proofs and generation reused by exact identity; later ghost-only EncodeTen proof split and strict normal-exit gate are separately recorded below',
    ('V5', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)\n', 'tests': {'scalars': 40713, 'encodings': 7044, 'malformed': 1820, 'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 334753}}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)\n', 'tests': {'scalars': 40713, 'encodings': 7044, 'malformed': 1820, 'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 334753}}],
    ('V5', 'formal/crypto/NATIVE-CODEC-EVIDENCE.json', 'reused_evidence.proofs'): {'proof-NativeField': 84, 'proof-NativeCodec': 1493, 'proof-NativeSampling': 281, 'native_codec_domain': 8, 'native_sampling_domain': 4},
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'scope'): 'Full positive-domain proof/translation/runtime replay on macOS ARM64; all 14 strict negative controls on Linux amd64. The Linux replay is control-only, not another proof of the unrestricted positive graph.',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'status'): 'passed',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'unchanged_policy'): {'positive_domain': 'Every array of exactly 256 coefficients in [0,3329); input aliasing permitted', 'negative_control_count': 14, 'required_semantic_exit': 4, 'resource_timeout_crash_diagnostics': 'rejected', 'cores': 2, 'verification_time_limit_seconds': 30, 'resource_limit': 50000000, 'native_case_split': 0, 'dependency_case_split': 'unchanged default 3'},
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.status'): 'passed',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.phase'): 'all',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.dependency_verified'): 1562,
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.native_verified'): 482,
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'linux_controls.receipt.status'): 'passed',
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'linux_controls.receipt.phase'): 'controls',
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'scope'): 'full',
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'proofs'): {'proof-full': 2775, 'generate-java': 80},
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)\n', 'tests': {'assertions': 5091, 'rounds': 100, 'malformed': 30, 'selections': 3265}}, {'version': 'openjdk version "25.0.4" 2026-07-21 LTS\nOpenJDK Runtime Environment Temurin-25.0.4+7 (build 25.0.4+7-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.4+7 (build 25.0.4+7-LTS, mixed mode, sharing)\n', 'tests': {'assertions': 5091, 'rounds': 100, 'malformed': 30, 'selections': 3265}}],
    ('V6', 'formal/crypto/KEM-EVIDENCE.json', 'provider_assumptions'): ['formal/crypto/JdkHash.dfy(8,4): Warning: H: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/JdkHash.dfy(11,4): Warning: G: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.'],
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'scope'): 'full',
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'proofs'): {'proof-native-composition': 2776, 'proof-reference-graph': 2649, 'proof-native-kernels': 3487, 'generate-java': 162},
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'java'): [{'version': 'openjdk version "21.0.12.1" 2026-08-18\nOpenJDK Runtime Environment Homebrew (build 21.0.12.1)\nOpenJDK 64-Bit Server VM Homebrew (build 21.0.12.1, mixed mode, sharing)\n', 'tests': {'assertions': 7813, 'rounds': 100, 'malformed': 30, 'selections': 3265, 'destroyed': 101}}, {'version': 'openjdk version "25.0.5" 2026-10-20 LTS\nOpenJDK Runtime Environment Temurin-25.0.5+8 (build 25.0.5+8-LTS)\nOpenJDK 64-Bit Server VM Temurin-25.0.5+8 (build 25.0.5+8-LTS, mixed mode, sharing)\n', 'tests': {'assertions': 7813, 'rounds': 100, 'malformed': 30, 'selections': 3265, 'destroyed': 101}}],
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'provider_assumptions'): {'primitive_count': 2, 'declaration_count': 4, 'declarations': ['formal/crypto/JdkHash.dfy(8,4): Warning: H: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/JdkHash.dfy(11,4): Warning: G: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/NativeJdkHash.dfy(12,4): Warning: Hash: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.', 'formal/crypto/NativeJdkHash.dfy(17,4): Warning: Expand: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.']},
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'bytecode_controls'): {'selector-narrow-helper': {'rejected': 'Unreviewed or payload-sensitive runtime helper'}, 'selector-payload-branch': {'rejected': 'Selector payload branch or changed loop control'}, 'selector-payload-boxing': {'rejected': 'Payload scalar boxing: 47: invokestatic  #35                 // Method java/lang/Byte.valueOf:(B)Ljava/lang/Byte;'}},
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'native_runtime_guard.payload_scalar_boxings'): 0,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'verified'): 2776,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'exit'): 0,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'platform'): 'linux/amd64',
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'dafny_version'): '4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2',
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'max_resource_count'): 10275514,
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'max_obligation_seconds'): 18.6739675,
})

REQUIRED_COMPONENT_CHECKS['V7'] = dict(REQUIRED_COMPONENT_CHECKS['V7'])
REQUIRED_COMPONENT_CHECKS['V7']['text_checks'] = (('formal/packet/EVIDENCE.md', ('| macOS arm64, Homebrew21.0.12.1 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| macOS arm64, Temurin25.0.5+8 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| Linux x86-64, Temurin21.0.7+6 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', 'All33 Python gate tests passed on macOS and Linux.', 'The extracted scalar programs contain160 SSA nodes for Decode,13 for ReadPrefix')),)

REQUIRED_TRACE_REPORT_SHA256 = '968e7e34d6df15045f7f87b1ef2f274590caadc4c566bdf3c6848e5eaa88ea35'

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
    ),
})
REQUIRED_COMPONENT_CHECKS.update({
    'V7': {
        'control_groups': (),
        'receipt_checks': (('formal/saw/evidence/report.json', ('runs.nonce.result',)),),
        'hash_maps': (('formal/packet/inputs.json', 'inputs', ('formal/packet/', 'quic/src/'), (), ''), ('formal/timing/inputs.json', 'inputs', (), (), '')),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': (),
        'nonvacuity': (),
        'text_checks': (('formal/packet/EVIDENCE.md', ('| macOS arm64, Homebrew21.0.12.1 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| macOS arm64, Temurin25.0.5+8 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', '| Linux x86-64, Temurin21.0.7+6 | 46 verified,0 errors | 10 verified,0 errors | 19 verified,0 errors | All7 rejected as intended |', 'All33 Python gate tests passed on macOS and Linux.', 'The extracted scalar programs contain160 SSA nodes for Decode,13 for ReadPrefix')),),
    },
})
REQUIRED_HASH_MAP_KEYS[('V7', 'formal/timing/inputs.json', 'inputs', (), '')] = REQUIRED_TRACE_INPUT_KEYS


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
 'WordArithmetic': {'source_sha256': '1353c60c5b29e02521764a5f9b6b6a209d8742f5515dd1b027d9693a5499a7be',
                    'log_sha256': '77a8844ef1f1bca3553a87f7c7991a556402b4e8df81beea956eda4a294217b9'}}
KECCAK_PROOF_ARTIFACTS = {'Rotate': {'source_sha256': 'f7500cf03a92c5cbab2ac4d1324480722cb4604571de89e82e322ac6b820cde5',
            'log_sha256': 'ceb555bd2c219d803843ffa7a9d05df4e0088ecb328d43dfd119639a4e48781c',
            'oracle_sha256': '0a07658fcbf4c453134a830066ae61d591ca734adafb94cd5bec4b097033562e'},
 'Theta': {'source_sha256': 'c8da47191378f617f3890b232be04960c1c8d8ceb13412be49ee275405746aea',
           'log_sha256': '6c46b70d5da52196aeff921183529d91d9e20ef050f623476a8f6142fb1e7d23',
           'oracle_sha256': '0c090b9bb08e5d70fc0a7dd5173e3cff5034648b68acf97c354151c0597073ac'},
 'RhoPi': {'source_sha256': '1b812a101e786b17645ecdae0f801c60d5b118a488c8b9cb1e59bc9e6f6dcb3b',
           'log_sha256': '8a627c10412758918e8163071fa096df30bdc46c786cffa53fffda9ffe3f08f8',
           'oracle_sha256': '19e792d293aeb73295df86e0b956e435f862c1a3165e5c745b8f8baf13182780'},
 'Iota': {'source_sha256': '53c03b4f727405f0a35d06810fde9f255098a33650209c30480c3058c76ea556',
          'log_sha256': '25f8d5a40d8f39ccacf0bca88abd969f0364d7fced2cf1efbeb48f9ac190c6c2',
          'oracle_sha256': 'e3b50f9f5f67c6f90a069c86d3e5fd783749f411b8f39b83d1cfc889e2f343f5'},
 'Chi': {'source_sha256': '37052e76fb2a2420e56941302eb3a25577aeccecfd92c41261ff00b61447f327',
         'log_sha256': '3772eb42a41cd32b59b3a418580302f4c962af9af75bcb4bc0178469263e4388',
         'oracle_sha256': 'ac223683bcbdbe1c47524da543bf0d33bd6c246e0130b6ecefdb262cf71de17f'},
 'Round': {'source_sha256': '618aea277ef0ea11164019d09ed8aff4e6154ff0e88a9166b23172386c941dd6',
           'log_sha256': 'ec9d2793da03e07b435131e9d9709f3b567b27d4518aa275b41311f929429960',
           'oracle_sha256': '9e63157ef6922aaba41fc6ec0c7c4f44114b9cfe1c123ae5ae7a58db48ddacd7'},
 'PermuteScratch': {'source_sha256': 'fd25b6c8eee31680ca90374b4e6d7cde0ffac554d69f08d91c9626a114199789',
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
 'actual_tables': '6c15f868f6ccf30cd6df05a781374dbd3f1125d2fd64689c0f70916e62492524',
 'binding_controls': '9eed7c0225af69042779625f8484b1758300927fa0e5653308516ffeb142748a',
 'oracle_kats': '5b28081fc8c4f75f630db3c5758a9f013859e83441a34c3af70ddc8b7473762b'}


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
PACKET_NONCE_ACCEPTED_REPORT_SHA256 = (
    "4c11918847dec99181cd317cad3092f8e5df118f2ce6e07ea6863e73175c617f")
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
