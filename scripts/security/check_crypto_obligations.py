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
        ('formal/saw/mlkem-reduce-once.saw', 'spec-source'),
        ('formal/saw/blocked/packet-key-nonce.saw', 'spec-source'),
        ('formal/crypto/reference/MlKem768.java', 'spec-source'),
        ('formal/crypto/reference/provenance.json', 'documentation'),
        ('quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java', 'production-source'),
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
        'hash_maps': (('formal/saw/inputs.json', 'inputs', ('formal/', 'quic/src/'), (), ''),),
        'entry_hash_checks': (),
        'inventory_checks': (),
        'file_set_checks': (),
        'nonvacuity': ('formal/saw/evidence/proof.log', ('a = 1', 'Proof succeeded')),
        'text_checks': (),
    },
})
REQUIRED_HASH_MAP_KEYS = {
    ('V0', 'formal/assurance.json', 'java_sources'): ('microproxy/src/main/java/org/microproxy/dns/BoundedExpiringCache.java', 'microproxy/src/main/java/org/microproxy/dns/DnssecHostResolver.java', 'microproxy/src/main/java/org/microproxy/dns/DnssecValidator.java', 'microproxy/src/test/java/org/microproxy/dns/FormalResourceModelTest.java', 'quic/src/main/java/io/github/mahmoudimus/quic/CipherSuite.java', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/tls/Tls12CipherSuite.java', 'quic/src/main/java/io/github/mahmoudimus/quic/tls/TlsClientConnection.java', 'quic/src/main/java/io/github/mahmoudimus/quic/tls/TlsRecordLayer.java', 'quic/src/test/java/io/github/mahmoudimus/quic/FormalCryptoModelTest.java', 'quic/src/test/java/io/github/mahmoudimus/quic/tls/FormalRecordModelTest.java', 'quic/src/test/java/io/github/mahmoudimus/quic/tls/TlsKeyUsageTest.java'),
    ('V0', 'formal/packet/inputs.json', 'inputs'): ('formal/packet/PacketKernel.dfy', 'formal/packet/TraceMachine.dfy', 'formal/packet/bytecode_guard.py', 'formal/packet/lowering.py', 'formal/packet/run.py', 'formal/packet/test_bytecode.py', 'formal/packet/test_io.py', 'formal/packet/test_lowering.py', 'formal/packet/test_replay.py', 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/HeaderKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verified/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/PacketNumber.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/ProtectedPacket.java', 'quic/src/test/java/io/github/mahmoudimus/quic/packet/HeaderProtectionTimingTest.java'),
    ('V0', 'formal/primitives/inputs.json', 'inputs'): ('formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy', 'formal/primitives/java/io/github/mahmoudimus/quic/tls/GeneratedPrimitivesTest.java', 'formal/primitives/run.py', 'formal/primitives/test_run.py'),
    ('V1', 'formal/dafny/inputs.json', 'inputs'): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V1', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs'): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V1', 'formal/reference/aws-hkdf/inputs.json', 'tool_inputs'): ('formal/dafny/toolchain.py', 'formal/dafny/tools.json'),
    ('V2', 'formal/dafny/inputs.json', 'inputs'): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V2', 'formal/dafny/PRODUCTION-EVIDENCE.json', 'inputs'): ('formal/dafny/bench/HkdfBenchmark.java', 'formal/dafny/bench_hkdf.py', 'formal/dafny/check_adapter_discipline.py', 'formal/dafny/deliver_hkdf.py', 'formal/dafny/hkdf/GENERATED.json', 'formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/java/dafny/BulkOnlySequence.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/DafnyHkdf.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/GeneratedHkdfTest.java', 'formal/dafny/java/io/github/mahmoudimus/verifiedcrypto/ReferenceHkdf.java', 'formal/dafny/run.py', 'formal/dafny/test_run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'quic/src/main/java/io/github/mahmoudimus/quic/Hkdf.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('V2', 'formal/crypto/delivery.json', 'existing_generated_sources'): ('io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java'),
    ('V2', 'formal/crypto/delivery.json', 'existing_generated_dependencies'): ('io/github/mahmoudimus/verifiedcrypto/JdkHmac.java',),
    ('V3', 'formal/saw/inputs.json', 'inputs'): ('formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/provenance.json', 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/PacketKey.java'),
    ('V4', 'formal/crypto/adoption/stage-receipt.json', 'sources'): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V5', 'formal/crypto/NATIVE-POLYNOMIAL-EVIDENCE.json', 'mac_full.receipt.inputs'): ('formal/crypto/NativeField.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/native_polynomial_checks.py', 'formal/crypto/native_polynomial_domain.dfy', 'formal/crypto/native_polynomial_test.java', 'formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy'),
    ('V5', 'formal/crypto/adoption/stage-receipt.json', 'sources'): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V6', 'formal/crypto/NATIVE-KEM-EVIDENCE.json', 'inputs'): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/native_kem_checks.py', 'formal/crypto/native_kem_domain.dfy', 'formal/crypto/native_kem_hash.java', 'formal/crypto/native_kem_test.java', 'formal/crypto/reference/MlKem768.java', 'formal/crypto/reference/Shake.java', 'formal/crypto/reference/provenance.json', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V6', 'formal/crypto/NATIVE-KEM-LINUX-EVIDENCE.json', 'source_graph'): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/crypto/native_kem_domain.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V6', 'formal/crypto/adoption/stage-receipt.json', 'sources'): ('formal/crypto/Codec.dfy', 'formal/crypto/JdkHash.dfy', 'formal/crypto/KemSpec.dfy', 'formal/crypto/NativeCodec.dfy', 'formal/crypto/NativeField.dfy', 'formal/crypto/NativeJdkHash.dfy', 'formal/crypto/NativeKeccak.dfy', 'formal/crypto/NativeMlKem.dfy', 'formal/crypto/NativePolynomial.dfy', 'formal/crypto/NativeSampling.dfy', 'formal/crypto/NativeShake.dfy', 'formal/crypto/NativeTypes.dfy', 'formal/crypto/Polynomial.dfy', 'formal/crypto/Sampling.dfy', 'formal/crypto/Shake.dfy', 'formal/crypto/SpongeSpec.dfy', 'formal/primitives/Field.dfy', 'formal/primitives/Keccak.dfy'),
    ('V7', 'formal/packet/inputs.json', 'inputs'): ('formal/packet/PacketKernel.dfy', 'formal/packet/TraceMachine.dfy', 'formal/packet/bytecode_guard.py', 'formal/packet/lowering.py', 'formal/packet/run.py', 'formal/packet/test_bytecode.py', 'formal/packet/test_io.py', 'formal/packet/test_lowering.py', 'formal/packet/test_replay.py', 'quic/src/main/java/io/github/mahmoudimus/quic/crypto/HeaderKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verified/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/PacketNumber.java', 'quic/src/main/java/io/github/mahmoudimus/quic/packet/ProtectedPacket.java', 'quic/src/test/java/io/github/mahmoudimus/quic/packet/HeaderProtectionTimingTest.java'),
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

REQUIRED_TRACE_REPORT_SHA256 = "9782ef72d7a725d12cc1098b88f21506b802a344c6dbcb858549ef2804a2de54"

REQUIRED_TRACE_ROOTS = (
    {'class': 'io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default', 'method': 'Select:([B[B[B[B)[B', 'status': 'checked', 'obligations': 84, 'instructions': 75, 'instructions_reachable': 75, 'cfg_edges_checked': True},
    {'class': 'io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeSampling.__default', 'method': 'Feed:([I[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'status': 'checked', 'obligations': 179, 'instructions': 167, 'instructions_reachable': 167, 'cfg_edges_checked': True},
    {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default', 'method': 'Extract:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'status': 'checked', 'obligations': 34, 'instructions': 30, 'instructions_reachable': 30, 'cfg_edges_checked': True},
    {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default', 'method': 'Expand:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'status': 'checked', 'obligations': 111, 'instructions': 103, 'instructions_reachable': 103, 'cfg_edges_checked': True},
    {'class': 'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default', 'method': 'LabelInfo:(Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'status': 'checked', 'obligations': 169, 'instructions': 158, 'instructions_reachable': 158, 'cfg_edges_checked': True},
)
REQUIRED_TRACE_ROOT_CASE_SPLIT = {
    'Select:([B[B[B[B)[B': True,
    'Feed:([I[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;': False,
    'Extract:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;': True,
    'Expand:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;': False,
    'LabelInfo:(Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;': False,
}
REQUIRED_TRACE_ASSUMED_TARGETS = ('io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Extract:(JII)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.PublicMod:(II)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Wipe:([I)V', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_Full:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidBlockLength:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidPrefix:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_NeedMore:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.IsPrefix:([I)Z', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I._typeDescriptor:()Ldafny/TypeDescriptor;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Failure:(Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Success:(Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidHash:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidKey:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLabel:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLength:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.ValidHash:(Ljava/math/BigInteger;)Z', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.compute:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Ldafny/DafnySequence;')
REQUIRED_TRACE_OPEN_TARGETS = (('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge', 'Update:([BII)I', 'unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge', 'AbsorbOne:(B)V', 'unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge', 'XorByte:(IB)V', 'unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge', 'Next:()B', 'unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeShake.Sponge', 'Start:()V', 'unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default', 'Decaps:(Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey;[B)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result;', 'caller-skeleton-unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default', 'ExpandLabel:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;Ldafny/DafnySequence;Ljava/math/BigInteger;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'unsupported-object-dispatch'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'extract:(I[B[B)[B', 'unsupported-object-dispatch'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'expand:(I[B[BI)[B', 'unsupported-object-dispatch'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'labelInfo:(Ljava/lang/String;[BI)[B', 'unsupported-object-dispatch'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'failure:(Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;IZ)Ljava/lang/RuntimeException;', 'unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'hash:(I)Ljava/math/BigInteger;', 'unsupported'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'sequence:([BLjava/lang/String;)Ldafny/DafnySequence;', 'unsupported-adapter-object'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'labelUnits:(Ljava/lang/String;)Ldafny/DafnySequence;', 'unsupported-adapter-object'), ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge', 'bytes:(Ldafny/DafnySequence;)[B', 'unsupported'))
REQUIRED_TRACE_UNCHECKED = ('NativeHkdf.Expanded bytes via bridges (not all adapter paths)', 'NativeKeccak.Permute', 'NativeKeccak.PermuteScratch', 'NativeMlKem.Decaps (caller skeleton only)', 'NativeMlKem.Decrypt', 'NativeMlKem.Encaps', 'NativeMlKem.Encrypt', 'NativeMlKem.ExpandMatrix', 'NativeMlKem.Field/NTT/codec/sampling helpers', 'NativeMlKem.KeyGen', 'NativeShake.Sponge.*', 'NativeShake.Xof', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Extract:(JII)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.PublicMod:(II)I', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.Wipe:([I)V', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_Full:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidBlockLength:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_InvalidPrefix:()Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.create_NeedMore:([II)Lio/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult;', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.IsPrefix:([I)Z', 'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I._typeDescriptor:()Ldafny/TypeDescriptor;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.Default:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Failure:(Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.create_Success:(Ldafny/DafnySequence;)Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidHash:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidKey:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLabel:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.create_InvalidLength:()Lio/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind;', 'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.ValidHash:(Ljava/math/BigInteger;)Z', 'io/github/mahmoudimus/verifiedcrypto/JdkHmac.compute:(Ljava/math/BigInteger;Ldafny/DafnySequence;Ldafny/DafnySequence;)Ldafny/DafnySequence;')
REQUIRED_TRACE_FIXTURES = (('ConstantTime', 'accept', 'checked'), ('SecretBranch', 'reject', 'rejected'), ('SecretIndex', 'reject', 'rejected'), ('EarlyCompare', 'reject', 'rejected'), ('ExceptionOracle', 'reject', 'rejected'), ('SecretAlloc', 'reject', 'rejected'), ('SecretLoopBound', 'reject', 'rejected'), ('SecretDigestBranch', 'reject', 'rejected'), ('FieldAlias', 'reject', 'rejected'), ('VirtualDispatch', 'reject', 'rejected'), ('ClassOracle', 'reject', 'rejected'), ('NewIdentity', 'reject', 'rejected'), ('ResultArrayCall', 'reject', 'rejected'), ('CategoryTwo', 'reject', 'rejected'))
REQUIRED_TRACE_MUTANTS = (('secret-guard', 'proof-obligation-rejected'), ('secret-index', 'proof-obligation-rejected'), ('early-compare-guard', 'proof-obligation-rejected'), ('public-taint-launder', 'proof-obligation-rejected'))
REQUIRED_TRACE_INPUT_KEYS = ('formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'formal/timing/HkdfShape.dfy', 'formal/timing/PositiveTraceCheck.dfy', 'formal/timing/README.md', 'formal/timing/SecretTrace.dfy', 'formal/timing/bytecode_trace.py', 'formal/timing/fixtures/CategoryTwo.java', 'formal/timing/fixtures/ClassOracle.java', 'formal/timing/fixtures/ConstantTime.java', 'formal/timing/fixtures/EarlyCompare.java', 'formal/timing/fixtures/ExceptionOracle.java', 'formal/timing/fixtures/FieldAlias.java', 'formal/timing/fixtures/NewIdentity.java', 'formal/timing/fixtures/ResultArrayCall.java', 'formal/timing/fixtures/SecretAlloc.java', 'formal/timing/fixtures/SecretBranch.java', 'formal/timing/fixtures/SecretDigestBranch.java', 'formal/timing/fixtures/SecretIndex.java', 'formal/timing/fixtures/SecretLoopBound.java', 'formal/timing/fixtures/VirtualDispatch.java', 'formal/timing/policy.json', 'formal/timing/run.py', 'formal/timing/test_trace.py', 'formal/timing/threat-model.md', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_Decoded.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidWidth.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Encapsulation.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidCiphertextLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidKeyLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidMessageLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidSeedLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_RejectionLimit.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/PublicKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/SecretKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_Decoded.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidWidth.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/Encapsulation.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/PublicKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativePolynomial/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_Full.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidBlockLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidPrefix.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_NeedMore.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/Sponge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/L.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolySpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/Residue.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_Full.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidBlockLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidPrefix.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_NeedMore.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/ReadResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/State.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InputAfterOutput.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InvalidSlice.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_Updated.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedCodec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedField/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedKeccak/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedPolynomial/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedSampling/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedShake/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/kem_hash.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/native_kem_hash.java')
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
        ('formal/timing/SecretTrace.dfy', 'model-source'),
        ('formal/timing/HkdfShape.dfy', 'model-source'),
        ('formal/timing/PositiveTraceCheck.dfy', 'finite-test'),
        ('formal/timing/test_trace.py', 'test-source'),
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
REQUIRED_HASH_MAP_KEYS[('V7', 'formal/timing/inputs.json', 'inputs')] = ('formal/dafny/hkdf/Hkdf.dfy', 'formal/dafny/run.py', 'formal/dafny/toolchain.py', 'formal/dafny/tools.json', 'formal/timing/HkdfShape.dfy', 'formal/timing/PositiveTraceCheck.dfy', 'formal/timing/README.md', 'formal/timing/SecretTrace.dfy', 'formal/timing/bytecode_trace.py', 'formal/timing/fixtures/CategoryTwo.java', 'formal/timing/fixtures/ClassOracle.java', 'formal/timing/fixtures/ConstantTime.java', 'formal/timing/fixtures/EarlyCompare.java', 'formal/timing/fixtures/ExceptionOracle.java', 'formal/timing/fixtures/FieldAlias.java', 'formal/timing/fixtures/NewIdentity.java', 'formal/timing/fixtures/ResultArrayCall.java', 'formal/timing/fixtures/SecretAlloc.java', 'formal/timing/fixtures/SecretBranch.java', 'formal/timing/fixtures/SecretDigestBranch.java', 'formal/timing/fixtures/SecretIndex.java', 'formal/timing/fixtures/SecretLoopBound.java', 'formal/timing/fixtures/VirtualDispatch.java', 'formal/timing/policy.json', 'formal/timing/run.py', 'formal/timing/test_trace.py', 'formal/timing/threat-model.md', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_Decoded.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_InvalidWidth.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/DecodeResult_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/CodecSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Encapsulation.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidCiphertextLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidKeyLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidMessageLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_InvalidSeedLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/FailureKind_RejectionLimit.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/PublicKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/Result_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/KemSpec/SecretKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_Decoded.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_InvalidWidth.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/DecodeResult_ModulusError.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeCodec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeField/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeKeccak/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/Encapsulation.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/PublicKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/SecretKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativePolynomial/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_Full.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidBlockLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_InvalidPrefix.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/FeedResult_NeedMore.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeSampling/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/Sponge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeShake/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/I.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeTypes/L.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolySpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/Residue.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/PolynomialRing/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_Full.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidBlockLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_InvalidPrefix.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/FeedResult_NeedMore.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SamplingSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/ReadResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/State.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InputAfterOutput.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_InvalidSlice.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/UpdateResult_Updated.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/SpongeSpec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedCodec/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedField/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedKeccak/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedPolynomial/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedSampling/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedcrypto/VerifiedShake/__default.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Failure.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/BytesResult_Success.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidHash.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidKey.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLabel.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/FailureKind_InvalidLength.java', 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/kem_hash.java', 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/native_kem_hash.java')


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
        expected_keys = REQUIRED_HASH_MAP_KEYS.get((oid, receipt_path, map_path))
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
