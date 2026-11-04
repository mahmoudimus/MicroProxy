#!/usr/bin/env python3
"""Portable semantic gate for the *final* Select (schema 2) full evidence.

DRAFT for integration.  It validates a real producer ``package-report.json`` plus
its referenced raw logs against the *current* workspace inputs and reviewed tool
profiles; it never trusts report summaries or producer absolute paths.

Authority split (reviewed code, not report/CLI self-repin):

* package/baseline/candidate-sources/profile/replay digests, the 25 control table,
  encoder fixtures, expected counts, baseline 13 roots and diagnostic tuples are
  literals here;
* ``workspace_root`` supplies the current 85 candidate Dafny files, the strict
  Select package (309 files), the 8 reviewed used inputs and the two pure profile
  files; every byte is re-hashed;
* the tracked report + ``evidence_root`` supply logs.  Producer roots
  (``output``/``candidate_root``/``baseline_root``/tool paths) are provenance
  strings only and are never opened; no baseline tree, ``.git``, cache or tool is
  read.

What this does NOT prove: C# checker semantics, observer/compiler/runtime/provider
correctness, physical heap identity, JVM timing, cryptographic hardness or whole-KEM
NI.  Logical read/write roles are method-local ids, not physical addresses.  Only a
fresh CI replay plus the final FULL report can qualify the actual evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

# --------------------------------------------------------------------------
# Reviewed literals copied from the reviewed producer tables (phase-3 prototype).
# --------------------------------------------------------------------------

CONTROLS = {
    'coverage-private-loop-bound': ('accepted', None),
    'neg-block-wrap-alloc': ('named-checker-rejection', 'Select allocation must be a direct top-level statement of the method body'),
    'neg-conditional-alloc': ('named-checker-rejection', 'Select allocation must be a direct top-level statement of the method body'),
    'neg-loop-alloc': ('named-checker-rejection', 'Select allocation must be a direct top-level statement of the method body'),
    'neg-private-branch-after-alloc': ('named-checker-rejection', 'expected exact SourceTrace.Read'),
    'neg-private-callee': ('named-checker-rejection', 'Select allocation initializer contains an executable call'),
    'neg-private-init-read': ('named-checker-rejection', 'Select allocation initializer contains a private/unknown array read or index'),
    'neg-private-read-after-alloc': ('named-checker-rejection', 'expected exact SourceTrace.Read'),
    'neg-private-read-before-alloc': ('named-checker-rejection', 'expected exact SourceTrace.Read'),
    'neg-public-branch-after-alloc': ('named-checker-rejection', 'expected exact SourceTrace.Branch'),
    'neg-second-alloc': ('named-checker-rejection', 'Select must allocate its returned buffer exactly once'),
    'neg-secret-init-condition': ('named-checker-rejection', 'Select allocation initializer contains an unsupported condition/branch/compound expression'),
    'neg-select-calls-rotate': ('named-checker-rejection', 'unregistered executable function call NativeKeccak._default.Rotate'),
    'neg-shadow-select': ('named-checker-rejection', 'reserved Select root outside exact default declaration'),
    'neg-trace-reset-in-loop': ('named-checker-rejection', 'later trace update must append to the same trace as its immutable left prefix'),
    'neg-unmarked-alloc': ('named-checker-rejection', 'expected exact SourceTrace.Alloc'),
    'neg-unmarked-private-loop-bound': ('named-checker-rejection', 'expected exact SourceTrace.Read'),
    'neg-wrong-alloc-site': ('named-checker-rejection', 'mismatched Alloc observation'),
    'neg-wrong-alloc-size': ('named-checker-rejection', 'mismatched Alloc observation'),
    'neg-wrong-initializer': ('named-checker-rejection', 'Select allocation initializer body is not the exact literal zero'),
    'neg-wrong-result-identity': ('named-checker-rejection', 'Select allocation result must be the sole non-ghost output formal by resolved identity'),
    'neg-wrong-size': ('named-checker-rejection', 'Select allocation size must be the exact public literal 32'),
    'positive-actual': ('accepted', None),
    'positive-alpha-out': ('accepted', None),
    'positive-zero-init': ('accepted', None),
}

ENCODER_FIXTURES = {
    'address-loss': False,
    'alpha-case-formals': True,
    'boolean-flip': False,
    'branch-tag': False,
    'encoder-body-constant4': False,
    'encoder-body-empty': False,
    'encoder-body-tag4': False,
    'ops-reordered': False,
}

EXPECTED = {
    'constant_branch_mutant': (52, 2),
    'encoder_fixtures': 8,
    'full_native_mlkem': (2773, 0),
    'jdk_classes': 65,
    'observation_vocabulary': (29, 0),
    'observed_mutant_harness': (1, 1),
    'observed_mutant_method': (2883, 0),
    'private_loop_bound_full': (2772, 1),
    'retained_callbinding_cases': 22,
    'retained_root19_cases': 18,
    'select_harness': (6, 0),
    'source_trace': (17, 0),
    'source_trace_bridge': (54, 0),
}

CASE_DIAGNOSTICS = {
    'neg-block-wrap-alloc': ((277, 11, 'Select allocation must be a direct top-level statement of the method body; allocation under a loop, conditional, wrapper block or other control flow is unsupported'), (276, 26, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (276, 26, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (276, 26, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (276, 26, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (276, 26, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (276, 26, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-conditional-alloc': ((278, 11, 'Select allocation must be a direct top-level statement of the method body; allocation under a loop, conditional, wrapper block or other control flow is unsupported'), (277, 26, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (277, 26, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (277, 26, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (277, 26, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (277, 26, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (277, 26, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-loop-alloc': ((277, 11, 'Select allocation must be a direct top-level statement of the method body; allocation under a loop, conditional, wrapper block or other control flow is unsupported'), (276, 26, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (276, 26, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (276, 26, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (276, 26, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (276, 26, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (276, 26, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-private-branch-after-alloc': ((273, 41, 'expected exact SourceTrace.Read for array read expected[0], found LoopBound'), (273, 41, 'expected exact SourceTrace.Branch for branch guard expected[0] == 0, found LoopBound'), (273, 41, 'expected exact SourceTrace.Write for array write r[0], found LoopBound'), (273, 41, 'LoopBound marker is not adjacent-before its executable operation'), (273, 41, 'mismatched LoopBound observation for for end 32'), (273, 41, 'expected exact SourceTrace.Read for array read candidate[i], found LoopBound'), (273, 41, 'expected exact SourceTrace.Read for array read fallback[i], found LoopBound'), (273, 41, 'expected exact SourceTrace.Write for array write r[i], found LoopBound'), (273, 41, 'Select: stale observation LoopBound')),
    'neg-private-callee': ((278, 33, 'Select allocation initializer contains an executable call: NativeMlKem._default.PickByte'), (277, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (277, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (277, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (277, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (277, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (277, 24, 'Select: stale observation Alloc'), (253, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-private-init-read': ((274, 41, 'Select allocation initializer contains a private/unknown array read or index'), (273, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (273, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (273, 24, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-private-read-after-alloc': ((273, 41, 'expected exact SourceTrace.Read for array read expected[0], found LoopBound'), (273, 41, 'LoopBound marker is not adjacent-before its executable operation'), (273, 41, 'mismatched LoopBound observation for for end 32'), (273, 41, 'expected exact SourceTrace.Read for array read candidate[i], found LoopBound'), (273, 41, 'expected exact SourceTrace.Read for array read fallback[i], found LoopBound'), (273, 41, 'expected exact SourceTrace.Write for array write r[i], found LoopBound'), (273, 41, 'Select: stale observation LoopBound')),
    'neg-private-read-before-alloc': ((274, 24, 'expected exact SourceTrace.Read for array read expected[0], found Alloc'),),
    'neg-public-branch-after-alloc': ((273, 41, 'expected exact SourceTrace.Branch for branch guard 1 == 2, found LoopBound'), (273, 41, 'expected exact SourceTrace.Write for array write r[0], found LoopBound'), (273, 41, 'LoopBound marker is not adjacent-before its executable operation'), (273, 41, 'mismatched LoopBound observation for for end 32'), (273, 41, 'expected exact SourceTrace.Read for array read candidate[i], found LoopBound'), (273, 41, 'expected exact SourceTrace.Read for array read fallback[i], found LoopBound'), (273, 41, 'expected exact SourceTrace.Write for array write r[i], found LoopBound'), (273, 41, 'Select: stale observation LoopBound')),
    'neg-second-alloc': ((288, 9, 'Select must allocate its returned buffer exactly once'), (287, 24, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-secret-init-condition': ((274, 33, 'Select allocation initializer contains an unsupported condition/branch/compound expression ITEExpr'), (273, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (273, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (273, 24, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-select-calls-rotate': ((276, 18, 'unregistered executable function call NativeKeccak._default.Rotate'),),
    'neg-shadow-select': ((1227, 11, 'reserved Select root outside exact default declaration: NativeMlKem.ShadowSelect.Select'),),
    'neg-trace-reset-in-loop': ((283, 12, 'Select: later trace update must append to the same trace as its immutable left prefix'), (284, 24, 'missing Read observation for array read candidate[i]'), (284, 47, 'missing Read observation for array read fallback[i]'), (284, 7, 'missing Write observation for array write r[i]')),
    'neg-unmarked-alloc': ((273, 24, 'expected exact SourceTrace.Alloc for exact Select allocation Alloc(0,32), found LoopBound'), (273, 24, 'LoopBound marker is not adjacent-before its executable operation'), (273, 24, 'mismatched LoopBound observation for for end 32'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found LoopBound'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found LoopBound'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found LoopBound'), (273, 24, 'Select: stale observation LoopBound')),
    'neg-unmarked-private-loop-bound': ((258, 16, 'expected exact SourceTrace.Read for array read expected[0], found LoopBound'), (258, 36, 'mismatched LoopBound observation for for end expected[0] as T.I'), (258, 36, 'expected exact SourceTrace.Read for array read c[i], found LoopBound'), (258, 36, 'expected exact SourceTrace.Read for array read expected[i], found LoopBound'), (258, 36, 'expected exact SourceTrace.Alloc for exact Select allocation Alloc(0,32), found LoopBound'), (258, 36, 'mismatched LoopBound observation for for start 0'), (258, 36, 'mismatched LoopBound observation for for end 32'), (258, 36, 'expected exact SourceTrace.Read for array read candidate[i], found LoopBound'), (258, 36, 'expected exact SourceTrace.Read for array read fallback[i], found LoopBound'), (258, 36, 'expected exact SourceTrace.Write for array write r[i], found LoopBound'), (258, 36, 'Select: stale observation LoopBound')),
    'neg-wrong-alloc-site': ((273, 24, 'mismatched Alloc observation for exact Select allocation Alloc(0,32)'), (273, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (273, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (273, 24, 'Select: stale observation Alloc')),
    'neg-wrong-alloc-size': ((273, 24, 'mismatched Alloc observation for exact Select allocation Alloc(0,32)'), (273, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (273, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (273, 24, 'Select: stale observation Alloc')),
    'neg-wrong-initializer': ((274, 35, 'Select allocation initializer body is not the exact literal zero'), (273, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (273, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (273, 24, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-wrong-result-identity': ((274, 8, 'Select allocation result must be the sole non-ghost output formal by resolved identity'), (273, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (273, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (273, 24, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
    'neg-wrong-size': ((274, 20, 'Select allocation size must be the exact public literal 32'), (273, 24, 'expected exact SourceTrace.LoopBound for for start 0, found Alloc'), (273, 24, 'expected exact SourceTrace.LoopBound for for end 32, found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read candidate[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Read for array read fallback[i], found Alloc'), (273, 24, 'expected exact SourceTrace.Write for array write r[i], found Alloc'), (273, 24, 'Select: stale observation Alloc'), (249, 9, 'Select: expected exactly one exact returned-buffer allocation')),
}


ENCODER_PROOF_PINS = {
    "proof-observation-vocabulary": (29, 0),
    "proof-source-trace": (17, 0),
    "proof-source-trace-bridge": (54, 0),
}

F2_TREE_SHA256 = "83bf0bb21ae57d4d47b8d9d2e8a88259254ef3a9d8f68e55fc92636dcccfa2b4"
OBSERVED_TREE_SHA256 = "5d58f26031afc87d3612124a65b82bdbd4cb5063b0c8907e5ab57160b520c5c1"
F2_ANCHOR = ("261", "16", "this loop invariant could not be proved on entry")
OBSERVED_HARNESS_ANCHOR = ("13", "11", "assertion might not hold")
OBSERVED_HARNESS_TEXT = "assert t1 == t2"
POLICY_NATIVE = ("--allow-external-contracts", "--verification-time-limit", "30",
                 "--resource-limit", "50000000", "--cores", "2",
                 "--solver-option", "O:smt.case_split=0")
POLICY_COMPOSITION = ("--allow-external-contracts", "--verification-time-limit", "30",
                      "--resource-limit", "50000000", "--cores", "2",
                      "--solver-option", "O:smt.case_split=3")
POLICY_INCLUDED = ("--allow-external-contracts", "--verification-time-limit", "30",
                   "--resource-limit", "50000000", "--cores", "2",
                   "--verify-included-files", "--solver-option", "O:smt.case_split=0")
POLICY_CONSTANT_BRANCH = ("--allow-external-contracts", "--verification-time-limit", "30",
                          "--resource-limit", "50000000", "--cores", "2",
                          "--verify-included-files", "--solver-option", "O:smt.case_split=0")




# --------------------------------------------------------------------------
# Schema-2 reviewed constants (final frozen package b1ce4b85).
# --------------------------------------------------------------------------

SELECT_ROOT = "NativeMlKem.Select"
ENCODER_ROOTS = ("NativeKeccak.SetLane", "NativeKeccak.Iota", "NativeKeccak.Wipe",
                 "NativeKeccak.Chi", "NativeKeccak.Theta", "NativeKeccak.RhoPi")
ENCODER_AUDIT_FILES = ("ObservationVocabulary.dfy", "SourceTrace.dfy", "SourceTraceBridge.dfy")
CONTROL_NAMES = tuple(sorted(CONTROLS))
ACCEPTED_CONTROLS = tuple(name for name, (status, _) in CONTROLS.items() if status == "accepted")
REJECTED_CONTROLS = tuple(name for name, (status, _) in CONTROLS.items()
                          if status == "named-checker-rejection")
CANDIDATE_ALLOWED_FORMAL_DIFF = ("crypto/NativeMlKem.dfy", "crypto/native_kem_domain.dfy")
# Cases whose emitted diagnostic tuples are identical; dual raw CASE-CONTEXT identity
# (case name + fixture/current-source SHA) is what prevents cross-case log substitution.
CASE_IDENTITY_AMBIGUOUS = ("neg-block-wrap-alloc", "neg-loop-alloc")

PACKAGE_SCHEMA = "microproxy.select-package/2"
BASELINE_SCHEMA = "microproxy.select-baseline/2"
SOURCES_SCHEMA = "microproxy.select-candidate-sources/1"
INDEX_SCHEMA = "microproxy.select-profile-index/2"
PROFILE_SCHEMA = "microproxy.select-tool-profile/2"
REPORT_SCHEMA = "microproxy.select-package-report/2"

PACKAGE_PINS = {
    "package_sha256": "b1ce4b851ba79f8a2c6d1c1b0e154c59e1ad446968c3e7da0adb54714adc0c1f",
    "baseline_sha256": "fcb201051093fdc50ae66e428a9533c88f2be00a4f8cc83c5abc04a98e870563",
    "candidate_sources_sha256": "12addcc0d2327b4033b3a99ddb8de033255c65f306395eca27defdc5754f009d",
    "replay_sha256": "14bdb5e5bdc0fd354ee9d74ff4523b4c0cf16aee1abc59908ef3330c1973cdf9",
    "package_files": 309,
    "controls": 52,
    "control_identities": 25,
    "dafny_files": 85,
    "used_inputs": {
    "formal/crypto/NativeMlKem.dfy": "267ba21db3434f40c67c8540c30264af9ff7fd93ab211478618e777286c0db3a",
    "formal/crypto/native_kem_checks.py": "7c0bedc97e02abbdd1a700e58d78c38fa1a4ae63ba4ae820a07b9e0a5b3dd91a",
    "formal/crypto/native_kem_domain.dfy": "30bda846c92ab356e3b34feab0531ce6dba3d279556d41d4f5c917596c0ef53e",
    "formal/crypto/native_kem_hash.java": "5e16490e4620a17c593ee3a81358184c65c7293d309ca80d5d374210af99e4be",
    "formal/crypto/native_kem_test.java": "8134a9adf34634324b13690006ad7b9faa12ca084180bed49333822d2e36b56c",
    "formal/crypto/reference/MlKem768.java": "58ad84f5d54474f26e7d3dfad1fae1ceecb2ec5081c01ed5e3d96113c42a1478",
    "formal/crypto/reference/Shake.java": "8fbfc723edc3aecc880affb9abc78c85b410c5c0c736f19ae7ae0c7bbf568697",
    "formal/crypto/reference/provenance.json": "5ecd37f14f0390f01c21c566eb10ecf1923c84f9966a1d0e861b4c6353777b3f"
},
    "checker": {
    "dll_sha256": "2785f06aef69011784a64f7cf5cfbeded0c3722760d9ca4317778b12e932cd67",
    "policy_sha256": "27115848f259786cd928d9d477fe0b51d84c7fc21efb5f98d83f5182358c0734",
    "project_sha256": "9df595df51acb3f3cf68d739d2551e63dd611996dc4296a404ad1be81668c75b",
    "source_sha256": "1deea29195a48b519081905b3dec8db83381f939cf57d985da2de64429e8dcee"
},
    "overlay_sha256": "267ba21db3434f40c67c8540c30264af9ff7fd93ab211478618e777286c0db3a",
    "domain_patched_sha256": "30bda846c92ab356e3b34feab0531ce6dba3d279556d41d4f5c917596c0ef53e",
    "domain_base_sha256": "d18368ecd4b4042830cbe42800a0b209e0d2ce7b4356cd16885d4b2adaa33688",
    "baseline_native_mlkem_sha256": "e4b3fe88a537b011f8581c0124d7169b45e83b294277113c16b534895f69e71f",
    "git_commit": "155bbe14cb9748cf677f4eb223af3dd2331687b0",
    "git_tree": "74a3eb686d02bf4226afed08227391e742b54f12",
    "native_kem_patch_sha256": "8c0f4362caa59d1fcdebf1993808cc8506ee5e79a79d88c809a2f6e1ad02fcd6",
}

PROFILE_PINS = {
    "linux-x64": {
        "boogie": {
            "Boogie.AbstractInterpretation.dll": "fee53cc5342956c2781f0f943daf138ccc01fad1c894afc7ea7badc2cf26c4c0",
            "Boogie.BaseTypes.dll": "616ccbebac3356c355b071da726a70fddf5accae83d4ebd0bef6961857bb9fc4",
            "Boogie.CodeContractsExtender.dll": "e6af87468977d66316ed71f7f0416e2055693c8e1f2245d7d0ec074549ce64e5",
            "Boogie.Concurrency.dll": "d247773d3bea314cdc0c26dd51e38218690d5ea087998a10d5fe1208973780cf",
            "Boogie.Core.dll": "203b35b9a0d3e433fdfc7168aba127686747a255b7232e3881e8e635048edc54",
            "Boogie.ExecutionEngine.dll": "9ec402b6e3df3a0ebd2cc24137110e71a60394a3d2ab94dbfd89bb74ed2f90c7",
            "Boogie.Graph.dll": "9e1622591705ca31ee5df45b14ee755c40146ce12b68a3c334c8494220f1dd14",
            "Boogie.Houdini.dll": "53c7ce64641d708b109db719f661b019fa4544cac34d0b4d26e74aea1ba01468",
            "Boogie.Model.dll": "3dc53a8e24603277ff1b7aa4db85aabebdb833e66d52b1a05267c13de2834750",
            "Boogie.Provers.LeanAuto.dll": "f18141a2567096b3ec3e7928811d73794c8476ab5db6a2e906f7e3fc5b88f4cc",
            "Boogie.Provers.SMTLib.dll": "568d6e7d8c48126d0a16a9b4d2ace3d7c05e13a70a4a71b19494cfcec56ac229",
            "Boogie.VCExpr.dll": "9c83d81e438709ef0cdc9626f4c8b825bed47662201288f67a7ab2ba2a3b643b",
            "Boogie.VCGeneration.dll": "6e5ee7e763b98eb09406d36ef066df1f1b177f4199a11e5b312581830e536f74"
        },
        "dafny_sha256": "7f6353ce7f97016f199bff1bd04a77a220b9670a1aff3cd100e7c073baba08ea",
        "dotnet_launcher_sha256": "0a5ec28e49da2c0be91ff3fc8fff53c250c9bbd92b25d3b9bfc5721adba96a0c",
        "jdk21_tools": {
            "bin/java": "9cad3f2620d3ef2ed10b26f922af7e773d54fdaa05f615d6d6df014f3fec4155",
            "bin/javac": "2cc288a26beebc50ca7cd924847dffbfb38ef3314e105bba6d4ebce03a0bcb6b",
            "bin/javap": "b2146e8dcfe5662c04d14f3fad68756a1a597d01461ca475a2cdbeb44c84a678",
            "lib/modules": "a5fd7c311fbd96adcbd43757dbb94461e14df353b6ae9f5c029c45805a39782c",
            "release": "f83f6dcc966043c93cd498ac8e7ee7c310852074970d62c702e4ad2710002898"
        },
        "jdk21_version": "21.0.13",
        "jdk25_tools": {
            "bin/java": "1bf1aaef01e4f8d7c85d913c60fb2ee4624cbe54d4053254c59657b7ea913b25",
            "bin/javac": "269e2dff1d0b1c34e2ea0a801b5456aaf19024ed3542f947b995fc3ec36a5ca9",
            "bin/javap": "ca8946288ae35eaa6afa1f32c671ba2ac8b5df854b41933d1436575dac2446d0",
            "lib/modules": "f5463cffa81c51b3c13f57e2c23eacceab2b12e842069acf2facd5485f63bc85",
            "release": "8545053a54a73969a65db2c8157f40f89bcdcf7526ae90a7ce9b3061c01bc34a"
        },
        "name": "linux-sdk10.0.400",
        "sha256": "89c444a9e5c4d473912fd57db16e53b71d06733f1751fe648bf9995c0a4deab1",
        "platform": "linux-x64",
        "z3_sha256": "0a91d88420f7946833ca1efd51d4cf4fa658ce91aad18c02138dfd9ee703e54a"
    },
    "macos-arm64": {
        "boogie": {
            "Boogie.AbstractInterpretation.dll": "fee53cc5342956c2781f0f943daf138ccc01fad1c894afc7ea7badc2cf26c4c0",
            "Boogie.BaseTypes.dll": "616ccbebac3356c355b071da726a70fddf5accae83d4ebd0bef6961857bb9fc4",
            "Boogie.CodeContractsExtender.dll": "e6af87468977d66316ed71f7f0416e2055693c8e1f2245d7d0ec074549ce64e5",
            "Boogie.Concurrency.dll": "d247773d3bea314cdc0c26dd51e38218690d5ea087998a10d5fe1208973780cf",
            "Boogie.Core.dll": "203b35b9a0d3e433fdfc7168aba127686747a255b7232e3881e8e635048edc54",
            "Boogie.ExecutionEngine.dll": "9ec402b6e3df3a0ebd2cc24137110e71a60394a3d2ab94dbfd89bb74ed2f90c7",
            "Boogie.Graph.dll": "9e1622591705ca31ee5df45b14ee755c40146ce12b68a3c334c8494220f1dd14",
            "Boogie.Houdini.dll": "53c7ce64641d708b109db719f661b019fa4544cac34d0b4d26e74aea1ba01468",
            "Boogie.Model.dll": "3dc53a8e24603277ff1b7aa4db85aabebdb833e66d52b1a05267c13de2834750",
            "Boogie.Provers.LeanAuto.dll": "f18141a2567096b3ec3e7928811d73794c8476ab5db6a2e906f7e3fc5b88f4cc",
            "Boogie.Provers.SMTLib.dll": "568d6e7d8c48126d0a16a9b4d2ace3d7c05e13a70a4a71b19494cfcec56ac229",
            "Boogie.VCExpr.dll": "9c83d81e438709ef0cdc9626f4c8b825bed47662201288f67a7ab2ba2a3b643b",
            "Boogie.VCGeneration.dll": "6e5ee7e763b98eb09406d36ef066df1f1b177f4199a11e5b312581830e536f74"
        },
        "dafny_sha256": "9ae7c1d3dc24d82d2bd0058b3c29a1071eacfcebb5782f05d5ed53f8e41662c6",
        "dotnet_launcher_sha256": "2ff302a3c5cecc4a371fd6482d2f5547c57d93eff9fe19919ef729a54f69ce04",
        "jdk21_tools": {
            "bin/java": "d7ab2ea6a7e731a8a2cee7d722046c9f7d8c5f184cd769b9954a392592337770",
            "bin/javac": "ab9b94d81dd22c843ef637be9aa2121253c6d4cfe2ba0a89a7bde5c0b9567945",
            "bin/javap": "45e7ec2c0b002e6dc716651ede247ac1f2c25d4cc8cf37ee20591ddc439162ac",
            "lib/modules": "f1053d4959235d6f3faaa28b74812b45a7a72463ba7edf29f1c7fb1a216c74e4",
            "release": "7b6f4e84249287203d8e1857254307a6b2dc0643b1efdeef5fa2aeaf791866f0"
        },
        "jdk21_version": "21.0.12.1",
        "jdk25_tools": {
            "bin/java": "d6b5c8ffce485baa7e9aacfd9c652e2999c89053a5070104c598731636bd2249",
            "bin/javac": "6a9d1ef0aa490929d80e6d864fea9a4ada17303dd5a6fad6376e037aee2fcd68",
            "bin/javap": "f4980e015ebf7f8ca5bcf75cfefdb79edfe3213320f88772ae41577a6a824991",
            "lib/modules": "1477b551d954c33d5069906536b10a0dbac57ba38f55c0bdecac663ef3cf916a",
            "release": "154dee9c09ff29951caa56e47ce7ecf99b78bf9be2905bde552a336c7fe4820f"
        },
        "name": "macos-sdk10.0.400",
        "sha256": "9ec9f05ce8dd1083071e6fc0aecea69d9972abe7d94ca8e7be0266c032e99f84",
        "platform": "macos-arm64",
        "z3_sha256": "5eaebf0f9dd366b7acd0f69bb390dac285c12bb684310504d17502b54917a396"
    }
}

BACKENDS = ("macos-arm64", "linux-x64")

# Ordered tool identities emitted by ``verify_tools`` (32 checks).
def expected_tool_identities(profile: dict[str, Any]) -> list[tuple[str, str]]:
    out = [("dafny_sha256", profile["dafny_sha256"]),
           ("dafny_core_sha256", DAFNY_CORE_SHA256),
           ("z3_sha256", profile["z3_sha256"])]
    out += [("boogie:" + name, digest) for name, digest in sorted(profile["boogie"].items())]
    out += [("dafny_version", DAFNY_VERSION),
            ("dotnet_launcher_sha256", profile["dotnet_launcher_sha256"]),
            ("dotnet_sdk", DOTNET_SDK)]
    for major in ("21", "25"):
        out.append(("jdk%s_version" % major, profile["jdk%s_version" % major]))
        out += [("jdk%s:%s" % (major, name), digest)
                for name, digest in sorted(profile["jdk%s_tools" % major].items())]
    out.append(("runtime_sha256", RUNTIME_SHA256))
    return out

DAFNY_CORE_SHA256 = "93ae2dee38743e358c7824d8912ac59b86f4228dd1889b00b999b3f441c44088"
DAFNY_VERSION = "4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2"
DOTNET_SDK = "10.0.400"
RUNTIME_SHA256 = "dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6"
JDK25_VERSION = "25.0.5"
JDK_TOOL_FILES = ("bin/java", "bin/javac", "bin/javap", "lib/modules", "release")
EXPECTED_BASELINE13_ROOTS = (
    "NativeField.ReduceOnce", "NativeField.Reduce", "NativeField.Add",
    "NativeField.Sub", "NativeField.Mul", "NativeField.MulSub", "NativeField.AddMul",
    "NativeKeccak.SetLane", "NativeKeccak.Iota", "NativeKeccak.Theta",
    "NativeKeccak.RhoPi", "NativeKeccak.Chi", "NativeKeccak.Wipe",
)
PROFILE_IDENTITY_FIELDS = {
    "schema", "platform", "dafny_sha256", "dafny_version", "dafny_core_sha256",
    "z3_sha256", "dotnet_sdk", "jdk21_version", "jdk25_version", "runtime_sha256",
    "checker_dll_expected_sha256", "boogie", "jdk21_tools", "jdk25_tools",
    "dotnet_launcher_sha256",
}
EXPECTED_BLOCK = {key: (list(value) if isinstance(value, tuple) else value)
                  for key, value in EXPECTED.items()}
EXPECTED_BLOCK["baseline13_roots"] = len(EXPECTED_BASELINE13_ROOTS)
USED_INPUTS = PACKAGE_PINS["used_inputs"]

RESERVED_DIR_NAMES = {"bin", "obj", "work"}
BENIGN_DIRS = {"__pycache__"}
BENIGN_SUFFIXES = (".pyc", ".pyo")
DEFAULT_DLL_RELATIVE = "checker-build/bin/Debug/net6.0/SourceCoverage.dll"

_SUMMARY = re.compile(r"Dafny program verifier finished with (\d+) verified, (\d+) errors?"
                      r"(?:, (\d+) out of resource)?")
_AUDIT = re.compile(r"Dafny auditor completed with (\d+) findings")
_DIAG = re.compile(r"\((\d+),(\d+)\): (?:Error|Warning|Related location): (.+)")
_RESOLUTION = re.compile(r"^(\d+) resolution/type errors detected in ", re.M)
_CHECKER_OK = re.compile(r"^SOURCE-COVERAGE OK: exact roots \[(.*?)\]; ordered markers; "
                         r"fail-closed$", re.M)
_BAD = re.compile(r"timeout|timed out|out of resource|resource limit|resource exhaustion|"
                  r"out of memory|OutOfMemory|Unhandled exception|Stack overflow|"
                  r"parse error|Parser error|crashed|Segmentation fault", re.I)
_BAD_DIAG = re.compile(r"pars(?:e|er) errors? detected|Error: unresolved identifier|"
                       r"Error: incorrect argument type|Error: wrong number of arguments|"
                       r"Error: invalid Ident|Error: this expression has type|"
                       r"Error: (?:function|method|argument|type mismatch)|Warning:|"
                       r"timed?\s*out|out of resource|out of memory|internal error|"
                       r"unhandled exception|CLI: Error", re.I)
_SHA = re.compile(r"[0-9a-f]{64}")


class SelectGateError(RuntimeError):
    """Fail-closed Select evidence validation failure."""


def _require(condition: bool, label: str, message: str) -> None:
    if not condition:
        raise SelectGateError(f"{label}: {message}")


def _sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _no_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise SelectGateError("duplicate JSON key: " + key)
        seen[key] = value
    return seen


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"),
                           object_pairs_hook=_no_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise SelectGateError(f"{label}: unreadable JSON: {error}") from error
    _require(isinstance(value, dict), label, "expected a JSON object")
    return value


def _rel(base: Path, relative: Any, label: str) -> Path:
    _require(isinstance(relative, str) and relative and not relative.startswith("/"),
             label, f"expected a relative path, got {relative!r}")
    pure = PurePosixPath(relative)
    _require(".." not in pure.parts and "\\" not in relative, label,
             f"escaping path {relative!r}")
    base = Path(base).resolve()
    path = base / pure
    for part in pure.parts:
        base = base / part
        _require(not base.is_symlink(), label, f"path component is a symlink: {relative!r}")
    _require(path.is_file(), label, f"missing file {relative!r}")
    _require(path.resolve().is_relative_to(Path(base).anchor and Path(relative) and
                                           Path(str(path)).parents[len(pure.parts) - 1]),
             label, f"path escapes its root: {relative!r}")
    return path


def _norm_abs(value: Any, label: str) -> str:
    _require(isinstance(value, str) and value, label, "missing provenance path")
    pure = PurePosixPath(value)
    _require(pure.is_absolute() and ".." not in pure.parts and "\\" not in value,
             label, f"provenance path is not normalized: {value!r}")
    return value.rstrip("/")


def _reldir(base: Path, relative: Any, label: str) -> Path:
    _require(isinstance(relative, str) and relative and not relative.startswith("/"),
             label, f"expected a relative path, got {relative!r}")
    pure = PurePosixPath(relative)
    _require(".." not in pure.parts and "\\" not in relative, label,
             f"escaping path {relative!r}")
    base = Path(base).resolve()
    path = base / pure
    current = base
    for part in pure.parts:
        current = current / part
        _require(not current.is_symlink(), label, f"path component is a symlink: {relative!r}")
    _require(path.is_dir(), label, f"missing directory {relative!r}")
    return path


def _under(prefix: str, value: Any, label: str, suffix: str) -> str:
    _require(value == prefix.rstrip("/") + "/" + suffix, label,
             f"path is not the declared provenance path: expected "
             f"{prefix.rstrip('/') + '/' + suffix!r}")
    return value


def _exact(obj: Any, allowed: set[str], label: str) -> None:
    _require(isinstance(obj, dict) and set(obj) == allowed, label,
             f"record shape changed: missing={sorted(allowed - set(obj or {}))} "
             f"extra={sorted(set(obj or {}) - allowed)}")


def _summary(text: str, label: str, what: str) -> tuple[int, int, int]:
    matches = _SUMMARY.findall(text)
    _require(len(matches) == 1, label, f"{what} must contain exactly one verifier summary")
    verified, errors, out_of_resource = matches[0]
    return int(verified), int(errors), int(out_of_resource or 0)


def _diagnostics(text: str) -> tuple[tuple[int, int, str], ...]:
    return tuple((int(line), int(column), message)
                 for line, column, message in _DIAG.findall(text))


def _checker_roots(text: str, label: str, what: str) -> tuple[str, ...]:
    matches = _CHECKER_OK.findall(text)
    _require(len(matches) == 1, label, f"{what} must contain exactly one SOURCE-COVERAGE OK line")
    return tuple(part for part in matches[0].split(",") if part)


def _positive_dafny(text: str, expected: tuple[int, int], label: str, what: str) -> None:
    _require(not _BAD.search(text), label, f"{what} contains an inconclusive diagnostic")
    _require(not re.search(r"\(\d+,\d+\): Warning: ", text), label, f"{what} contains a warning")
    _require(not _DIAG.search(text), label, f"{what} contains a verifier diagnostic")
    resolution = _RESOLUTION.search(text)
    _require(resolution is None or int(resolution.group(1)) == 0, label,
             f"{what} contains resolution errors")
    summary = _summary(text, label, what)
    _require(summary == (expected[0], expected[1], 0), label,
             f"{what} summary {summary} != {expected}")


def _negative_dafny(text: str, expected: tuple[int, int], label: str, what: str,
                    anchor: tuple[str, str, str] | None = None) -> None:
    # A semantic negative may contain the intended ``Error:`` diagnostics only.
    # Any tool crash, timeout/resource, parser/type/resolution or warning output
    # makes the log inconclusive, even when the intended failure is also present.
    _require(not _BAD.search(text), label,
             f"{what} contains an inconclusive tool/timeout diagnostic, not a rejection")
    scrubbed = text.replace("resolution/type errors detected", "")
    _require(not _BAD_DIAG.search(scrubbed), label,
             f"{what} contains a parser/type/resolution/warning diagnostic")
    summary = _summary(text, label, what)
    _require(summary[2] == 0 and (summary[0], summary[1]) == expected, label,
             f"{what} summary {summary} != {expected}")
    _require("Error: " in text, label, f"{what} has no named error diagnostic")
    if anchor is not None:
        line, column, message = anchor
        _require(f"({line},{column}): Error: {message}" in text, label,
                 f"{what} lacks the reviewed diagnostic anchor")


def _accepted_checker(text: str, roots: tuple[str, ...], label: str, what: str) -> None:
    _require(not _BAD.search(text), label, f"{what} contains an inconclusive diagnostic")
    _require("Error:" not in text and "resolution/type errors detected" not in text, label,
             f"{what} contains a rejection diagnostic")
    printed = _checker_roots(text, label, what)
    _require(printed == roots, label, f"{what} printed roots differ from the reviewed roots")
    _require(text.count("SOURCE-COVERAGE OK") == 1, label,
             f"{what} must report the accepted root exactly once")


def _rejected_checker(text: str, needle: str, label: str, what: str) -> None:
    _require(not _BAD.search(text), label, f"{what} contains a tool crash/resource diagnostic")
    _require("SOURCE-COVERAGE OK" not in text, label, f"{what} is a success, not a rejection")
    _require(bool(needle) and needle in text, label,
             f"{what} does not contain the reviewed named rejection")
    _require(bool(_DIAG.search(text)), label, f"{what} has no Dafny diagnostic line")
    _require(bool(_RESOLUTION.search(text)), label, f"{what} has no resolution-error summary")
    _require(not _BAD_DIAG.search(text.replace("resolution/type errors detected", "")), label,
             f"{what} contains a parser/type/tool diagnostic, not a semantic rejection")


def _context_line(record: dict[str, Any]) -> str:
    parts = ["case=" + record["case"],
             "operand_sha256=" + record["operand_sha256_before"]]
    if "expected_fixture_sha256" in record:
        parts.append("expected_fixture_sha256=" + record["expected_fixture_sha256"])
    parts.append("argv=" + json.dumps(record["argv"], separators=(",", ":")))
    parts.append("cwd=" + record["cwd"])
    if "plugin_sha256" in record:
        parts.append("plugin_sha256=" + record["plugin_sha256"])
    return "CASE-CONTEXT " + " ".join(parts)


_CONTEXT_ALLOWED = {"case", "operand_sha256_before", "operand_sha256_after", "argv", "cwd",
                    "expected_fixture_sha256", "plugin_sha256"}


def _validate_context(record: Any, *, case: str, argv: list[str], cwd: str,
                      operand_sha256: str, expected_fixture: str | None,
                      plugin_sha256: str | None, log_text: str, label: str) -> None:
    """Every primary case: typed context == raw prefix, exact identity before/after."""
    _require(isinstance(record, dict), label, "case-context record missing")
    _require(set(record) <= _CONTEXT_ALLOWED, label,
             f"case-context record has unexpected keys: {sorted(set(record) - _CONTEXT_ALLOWED)}")
    _require(record.get("case") == case, label, "case-context identity is not this case")
    _require(record.get("operand_sha256_before") == operand_sha256, label,
             "case-context operand (before) is not the reviewed fixture/current source")
    _require(record.get("operand_sha256_after") == operand_sha256, label,
             "case operand changed during the call")
    _require(record.get("argv") == [str(part) for part in argv], label,
             "case-context argv differs from the recorded command")
    _require(record.get("cwd") == cwd, label, "case-context cwd differs from the recorded cwd")
    if expected_fixture is not None:
        _require(record.get("expected_fixture_sha256") == expected_fixture, label,
                 "case-context expected fixture hash changed")
    if plugin_sha256 is not None:
        _require(record.get("plugin_sha256") == plugin_sha256, label,
                 "case-context plugin is not the reviewed checker DLL")
    first = log_text.splitlines()[0] if log_text.splitlines() else ""
    _require(first == _context_line(record), label,
             "raw log CASE-CONTEXT prefix differs from the typed case context")


def _validate_closure(baseline: dict[str, Any], label: str) -> tuple[dict[str, str], dict[str, str]]:
    base = baseline.get("baseline_formal_dafny_hashes")
    cand = baseline.get("candidate_formal_dafny_hashes_excluding_select_package")
    _require(isinstance(base, dict) and len(base) == PACKAGE_PINS["dafny_files"], label,
             "baseline Dafny inventory is not the reviewed 85-file set")
    _require(isinstance(cand, dict) and set(cand) == set(base), label,
             "candidate Dafny inventory keys differ from baseline")
    for key in base:
        pure = PurePosixPath(key)
        _require(isinstance(key, str) and key and not pure.is_absolute()
                 and ".." not in pure.parts and "\\" not in key, label,
                 f"non-relative closure key: {key!r}")
        _require(isinstance(base[key], str) and _SHA.fullmatch(base[key]) is not None, label,
                 f"malformed baseline hash: {key}")
        _require(isinstance(cand[key], str) and _SHA.fullmatch(cand[key]) is not None, label,
                 f"malformed candidate hash: {key}")
    declared = baseline.get("candidate_allowed_formal_diff")
    _require(isinstance(declared, list)
             and tuple(declared) == CANDIDATE_ALLOWED_FORMAL_DIFF, label,
             "declared candidate diff is not the reviewed two-file set")
    derived = tuple(sorted(key for key in base if base[key] != cand[key]))
    _require(derived == tuple(sorted(CANDIDATE_ALLOWED_FORMAL_DIFF)), label,
             f"actual baseline->candidate diff is not the declared two files: {derived}")
    for key in base:
        if key not in CANDIDATE_ALLOWED_FORMAL_DIFF:
            _require(base[key] == cand[key], label, f"undeclared candidate change: {key}")
    _require(base["crypto/NativeMlKem.dfy"] == PACKAGE_PINS["baseline_native_mlkem_sha256"],
             label, "immutable baseline NativeMlKem pin changed")
    _require(base["crypto/native_kem_domain.dfy"] == PACKAGE_PINS["domain_base_sha256"],
             label, "immutable baseline native_kem_domain pin changed")
    _require(cand["crypto/NativeMlKem.dfy"] == PACKAGE_PINS["overlay_sha256"], label,
             "candidate overlay NativeMlKem pin changed")
    _require(cand["crypto/native_kem_domain.dfy"] == PACKAGE_PINS["domain_patched_sha256"],
             label, "candidate native_kem_domain pin changed")
    return base, cand


def _validate_profile_file(package_root: Path, platform: str) -> tuple[dict[str, Any], str, str]:
    pin = PROFILE_PINS[platform]
    path = package_root / "profiles" / (pin["name"] + ".json")
    _require(path.is_file(), "profile", f"reviewed profile file missing: {pin['name']}")
    digest = _sha(path)
    _require(digest == PROFILE_PINS[platform]["sha256"], "profile",
             "profile digest differs from the reviewed platform profile")
    profile = _load(path, "profile")
    _require(profile.get("schema") == PROFILE_SCHEMA, "profile", "unexpected profile schema")
    _require(set(profile) == PROFILE_IDENTITY_FIELDS, "profile",
             f"profile identity fields changed: {sorted(set(profile) ^ PROFILE_IDENTITY_FIELDS)}")
    _require(profile.get("platform") == platform, "profile",
             "profile platform is not the reviewed platform")
    expected = {
        "dafny_sha256": pin["dafny_sha256"],
        "dafny_core_sha256": DAFNY_CORE_SHA256,
        "z3_sha256": pin["z3_sha256"],
        "dafny_version": DAFNY_VERSION,
        "dotnet_sdk": DOTNET_SDK,
        "jdk21_version": pin["jdk21_version"],
        "jdk25_version": JDK25_VERSION,
        "runtime_sha256": RUNTIME_SHA256,
        "dotnet_launcher_sha256": pin["dotnet_launcher_sha256"],
        "checker_dll_expected_sha256": PACKAGE_PINS["checker"]["dll_sha256"],
    }
    for key, value in expected.items():
        _require(profile.get(key) == value, "profile", f"profile {key} changed")
    for nested, values in (("boogie", pin["boogie"]), ("jdk21_tools", pin["jdk21_tools"]),
                           ("jdk25_tools", pin["jdk25_tools"])):
        _require(isinstance(profile.get(nested), dict)
                 and profile[nested] == values, "profile", f"profile {nested} identities changed")
    index_path = package_root / "profiles" / "index.json"
    _require(index_path.is_file(), "profile", "profile index missing")
    index = _load(index_path, "profile")
    _require(index.get("schema") == INDEX_SCHEMA, "profile", "unexpected profile index schema")
    _require(index.get("profiles", {}).get(pin["name"]) == digest, "profile",
             "profile index does not pin this profile digest")
    return profile, digest, pin["name"]


def _walk(root: Path, label: str) -> dict[str, Path]:
    root = Path(root)
    _require(root.is_dir(), label, "root is not a directory")
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise SelectGateError(f"{label}: symlink in tree: {rel}")
        if not path.is_file():
            continue
        if rel.endswith(BENIGN_SUFFIXES) or any(part in BENIGN_DIRS for part in rel.split("/")):
            continue
        files[rel] = path
    return files


def _validate_package_tree(package_root: Path, baseline: dict[str, Any],
                           package: dict[str, Any]) -> int:
    declared = baseline.get("package_files")
    _require(isinstance(declared, dict) and len(declared) == PACKAGE_PINS["package_files"],
             "package", "strict package inventory is not 309 files")
    actual = _walk(package_root, "package")
    expected = set(declared) | {"package.json", "baseline.json"}
    _require(set(actual) == expected, "package",
             f"package file set changed: missing={sorted(expected - set(actual))} "
             f"extra={sorted(set(actual) - expected)}")
    for rel, digest in declared.items():
        _require(_sha(actual[rel]) == digest, "package", f"package file hash changed: {rel}")
    for path in package_root.rglob("*"):
        if path.is_dir() and not path.is_symlink() and path.name in RESERVED_DIR_NAMES:
            raise SelectGateError("package: unexpected build/work directory: " +
                                  path.relative_to(package_root).as_posix())
    control_names = {p.name for p in (package_root / "controls").iterdir()
                     if p.is_dir() and (p / "meta.json").is_file()}
    _require(control_names == set(CONTROL_NAMES), "package",
             "control identity inventory changed")
    for rel, digest in baseline.get("controls", {}).items():
        _require(_sha(_rel(package_root, rel, "package")) == digest, "package",
                 f"control source hash changed: {rel}")
    for name, pin in (("checker/SourceCoverage.cs", PACKAGE_PINS["checker"]["source_sha256"]),
                      ("checker/SourceCoverage.csproj", PACKAGE_PINS["checker"]["project_sha256"]),
                      ("checker/NativeCanonicalEncoderPolicy.cs",
                       PACKAGE_PINS["checker"]["policy_sha256"])):
        _require(_sha(_rel(package_root, name, "package")) == pin, "package",
                 f"checker input hash changed: {name}")
    return len(actual)


def _contained_dir(root: Path, relative: str, label: str) -> Path:
    """Resolve a workspace directory with no symlink component below the root.

    The admitted workspace root may itself be reached via a symlink; it is resolved
    once.  Every component below it must be a real directory, so a moved package or
    a ``formal/source/select`` link cannot escape the bounded source authority.
    """
    root = Path(root)
    _require(root.is_dir(), label, "workspace root is missing")
    resolved_root = root.resolve()
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        _require(not current.is_symlink(), label,
                 f"workspace component is a symlink: {relative}")
        _require(current.is_dir(), label, f"workspace component is missing: {relative}")
    _require(current.resolve().is_relative_to(resolved_root), label,
             f"workspace component escapes the admitted root: {relative}")
    return current


def _validate_current_inputs(workspace_root: Path, platform: str | None = None) -> dict[str, Any]:
    workspace_root = Path(workspace_root).resolve()
    _require(workspace_root.is_dir(), "layout", "workspace root is missing")
    _contained_dir(workspace_root, "formal", "layout")
    package_root = _contained_dir(workspace_root, "formal/source/select", "layout")
    package_sha = _sha(package_root / "package.json")
    _require(package_sha == PACKAGE_PINS["package_sha256"], "manifest",
             "workspace package.json differs from the reviewed frozen package")
    package = _load(package_root / "package.json", "manifest")
    _require(package.get("schema") == PACKAGE_SCHEMA, "manifest", "unexpected package schema")
    controls_expected = {name: {"status": status, "needle": needle}
                         for name, (status, needle) in CONTROLS.items()}
    _require(package.get("controls_expected") == controls_expected, "manifest",
             "reviewed control table changed")
    _require(package.get("encoder_expected") == ENCODER_FIXTURES, "manifest",
             "reviewed encoder table changed")
    _require(package.get("expected") == EXPECTED_BLOCK, "manifest",
             "reviewed expected summary table changed")
    _require(package.get("candidate_inputs") == USED_INPUTS, "manifest",
             "reviewed used-input set changed")
    _require(package.get("candidate_overlay_sha256") == PACKAGE_PINS["overlay_sha256"],
             "manifest", "candidate overlay pin changed")
    _require(package.get("baseline_native_mlkem_sha256") ==
             PACKAGE_PINS["baseline_native_mlkem_sha256"], "manifest",
             "baseline NativeMlKem pin changed")
    for pin_key, manifest_key in (("source_sha256", "checker_source_sha256"),
                                  ("project_sha256", "checker_project_sha256"),
                                  ("policy_sha256", "checker_policy_sha256")):
        _require(package.get(manifest_key) == PACKAGE_PINS["checker"][pin_key], "manifest",
                 f"manifest checker {pin_key} changed")
    # The checker DLL identity is a reviewed *profile* value (schema 2 keeps tool
    # hashes out of the immutable package manifest).
    _require(package.get("native_kem_patch", {}).get("domain_patched_sha256") ==
             PACKAGE_PINS["domain_patched_sha256"], "manifest", "native domain patch changed")
    _require(package.get("native_kem_patch", {}).get("domain_base_sha256") ==
             PACKAGE_PINS["domain_base_sha256"], "manifest", "native domain base changed")
    _require(package.get("native_kem_patch", {}).get("runner_patched_sha256") ==
             USED_INPUTS["formal/crypto/native_kem_checks.py"], "manifest",
             "native runner patch pin changed")
    baseline_path = package_root / "baseline.json"
    _require(_sha(baseline_path) == PACKAGE_PINS["baseline_sha256"]
             == package.get("baseline_manifest_sha256"), "manifest",
             "baseline.json differs from its reviewed digest")
    sources_path = package_root / "candidate-sources.json"
    _require(_sha(sources_path) == PACKAGE_PINS["candidate_sources_sha256"]
             == package.get("candidate_sources_sha256"), "manifest",
             "candidate-sources.json differs from its reviewed digest")
    baseline = _load(baseline_path, "baseline")
    _require(baseline.get("schema") == BASELINE_SCHEMA, "baseline",
             "unexpected baseline schema")
    _require(baseline.get("git_commit") == PACKAGE_PINS["git_commit"]
             and baseline.get("git_tree") == PACKAGE_PINS["git_tree"], "baseline",
             "baseline Git identity changed")
    _require(baseline.get("baseline_root") == "baseline-git-155b"
             and baseline.get("package_root") == "candidate/formal/source/select",
             "baseline", "baseline relative roots changed")
    base_hashes, cand_hashes = _validate_closure(baseline, "baseline")
    _require(baseline.get("baseline_to_candidate_equal_count") ==
             PACKAGE_PINS["dafny_files"] - len(CANDIDATE_ALLOWED_FORMAL_DIFF), "baseline",
             "equal-file count changed")
    sources = _load(sources_path, "sources")
    _require(sources.get("schema") == SOURCES_SCHEMA, "sources",
             "unexpected candidate-source schema")
    _require(sources.get("dafny") == {"formal/" + rel: digest
                                      for rel, digest in cand_hashes.items()}, "sources",
             "candidate-source Dafny map differs from the reviewed 85")
    _require(sources.get("used_inputs") == USED_INPUTS, "sources",
             "candidate-source used-input map differs from the reviewed 8")
    for rel, digest in sorted(cand_hashes.items()):
        _require(_sha(_rel(workspace_root / "formal", rel, "candidate")) == digest, "candidate",
                 f"current candidate Dafny hash changed: {rel}")
    # Exact current Dafny closure outside the Select package: no extra/missing/linked
    # observer/model files.  This is the reviewed Dafny-only domain, not a sweep of
    # unrelated Python/Java/C#/docs/evidence files.
    actual_dafny = set()
    for path in sorted((workspace_root / "formal").rglob("*.dfy")):
        rel = path.relative_to(workspace_root / "formal").as_posix()
        if rel.startswith("source/select/"):
            continue
        _require(not path.is_symlink() and path.is_file(), "candidate",
                 f"current candidate Dafny entry is linked/not a file: {rel}")
        actual_dafny.add(rel)
    _require(actual_dafny == set(cand_hashes), "candidate",
             f"current candidate Dafny set changed: missing="
             f"{sorted(set(cand_hashes) - actual_dafny)} "
             f"extra={sorted(actual_dafny - set(cand_hashes))}")
    for rel, digest in sorted(USED_INPUTS.items()):
        _require(_sha(_rel(workspace_root, rel, "used")) == digest, "used",
                 f"current used input hash changed: {rel}")
    files = _validate_package_tree(package_root, baseline, package)
    platforms = (platform,) if platform else BACKENDS
    profiles = {}
    for name in platforms:
        profile, digest, selector = _validate_profile_file(package_root, name)
        profiles[name] = {"profile": profile, "sha256": digest, "selector": selector}
    return {
        "workspace_root": str(workspace_root),
        "package": package,
        "baseline": baseline,
        "package_root": package_root,
        "package_sha256": package_sha,
        "replay_sha256": _sha(package_root / "replay.py"),
        "package_files": files,
        "dafny_files": len(cand_hashes),
        "controls": len(baseline["controls"]),
        "used_inputs": len(USED_INPUTS),
        "profiles": profiles,
    }


REQUIRED_FULL = frozenset({
    "schema", "mode", "qualification", "package_root", "candidate_root", "baseline_root",
    "output", "tools", "case_contexts", "invocation_argv", "status", "package_sha256",
    "profile", "inputs", "manifest", "tool_identity_before", "checker", "controls", "harness",
    "observed", "f2", "encoder", "full_native_mlkem", "retained_native", "codegen",
    "tool_identity_after", "input_signature",
})
OPTIONAL_FULL = frozenset({"native_kem_checks"})
PROOF_KEYS = frozenset({"label", "exit", "verified", "errors", "command", "cwd",
                        "case_context", "log", "log_sha256"})


def _proof(record: Any, label: str, what: str, evidence_root: Path, *,
           expected: tuple[int, int], argv: list[str], cwd: str,
           negative: bool = False, anchor: tuple[str, str, str] | None = None) -> str:
    _exact(record, PROOF_KEYS, label)
    _require(record.get("exit") == (4 if negative else 0), label, f"{what} exit changed")
    _require((record.get("verified"), record.get("errors")) == expected, label,
             f"{what} summary counts changed")
    command = record.get("command")
    _require(isinstance(command, list) and all(isinstance(part, str) for part in command)
             and command == [str(part) for part in argv], label, f"{what} argv changed")
    _require(record.get("cwd") == cwd, label, f"{what} cwd changed")
    _require(record.get("label") == label, label, f"{what} label changed")
    log = _rel(evidence_root, record.get("log"), label)
    _require(record.get("log_sha256") == _sha(log), label, f"{what} log digest changed")
    text = log.read_text(encoding="utf-8")
    if negative:
        _negative_dafny(text, expected, label, what, anchor)
    else:
        _positive_dafny(text, expected, label, what)
    return text


def _proof_argv(dafny: str, entry: str, case_split: int, extra: tuple[str, ...] = ()) -> list[str]:
    return [dafny, "verify", entry,
            "--allow-external-contracts", "--verification-time-limit", "30",
            "--resource-limit", "50000000", "--cores", "2", *extra,
            "--solver-option", "O:smt.case_split=" + str(case_split)]


def _tool_identity(report: dict[str, Any], stage: str, profile: dict[str, Any],
                   profile_sha256: str, platform: str, label: str) -> int:
    block = report.get(stage)
    _exact(block, {"stage", "profile_sha256", "platform", "checks"}, label)
    _require(block.get("stage") == stage.split("_")[-1], label, f"{stage} marker changed")
    _require(block.get("profile_sha256") == profile_sha256, label,
             f"{stage} profile digest is not the reviewed profile")
    _require(block.get("platform") == platform, label, f"{stage} platform changed")
    checks = block.get("checks")
    expected = expected_tool_identities(profile)
    _require(isinstance(checks, list) and len(checks) == len(expected), label,
             f"{stage} tool identity count changed")
    for index, (name, value) in enumerate(expected):
        item = checks[index]
        _exact(item, {"stage", "name", "expected", "actual", "ok"}, label)
        _require(item.get("name") == name and item.get("expected") == value
                 and item.get("actual") == value and item.get("ok") is True, label,
                 f"{stage} tool identity changed: {name}")
        _require(item.get("stage") == stage.split("_")[-1], label,
                 f"{stage} tool check provenance changed: {name}")
    return len(expected)


def _validate_invocation(report: dict[str, Any], facts: dict[str, Any], platform: str,
                         profile_selector: str) -> None:
    package_root = facts["package_root"]
    profile_sha = facts["profiles"][platform]["sha256"]
    tools = report.get("tools")
    argv = report.get("invocation_argv")
    _require(isinstance(argv, list) and all(isinstance(part, str) for part in argv) and argv,
             "invocation", "invocation argv missing")
    _require(argv[0].endswith("/replay.py"), "invocation",
             "invocation does not name the package replay runner")
    _require(argv[0] == str(PurePosixPath(report["package_root"]) / "replay.py"),
             "invocation", "runner path is not package_root/replay.py")
    flags: dict[str, Any] = {}
    position = 1
    while position < len(argv):
        flag = argv[position]
        _require(flag.startswith("--"), "invocation", f"unexpected positional argument {flag!r}")
        if flag == "--native-kem-checks":
            _require(flag not in flags, "invocation", "duplicate --native-kem-checks")
            flags[flag] = True
            position += 1
            continue
        _require(position + 1 < len(argv), "invocation", f"missing value for {flag}")
        _require(flag not in flags, "invocation", f"duplicate {flag}")
        flags[flag] = argv[position + 1]
        position += 2
    expected = {
        "--package-root": report["package_root"],
        "--output": report["output"],
        "--tool-profile": profile_selector,
        "--expected-package-sha256": PACKAGE_PINS["package_sha256"],
        "--expected-profile-sha256": profile_sha,
        "--dafny": tools["dafny"],
        "--dotnet": tools["dotnet"],
        "--jdk21": tools["jdk21"],
        "--jdk25": tools["jdk25"],
        "--runtime": tools["runtime"],
        "--mode": "full",
    }
    for flag, value in expected.items():
        _require(flags.get(flag) == value, "invocation", f"invocation {flag} changed")
    allowed = set(expected) | {"--baseline-root", "--native-kem-checks"}
    _require(set(flags) <= allowed, "invocation",
             f"unreviewed invocation flags: {sorted(set(flags) - allowed)}")
    if "--baseline-root" in flags:
        _require(flags["--baseline-root"] == report["baseline_root"], "invocation",
                 "invocation baseline root differs from the report")
    _require(("--native-kem-checks" in flags) == ("native_kem_checks" in report),
             "invocation", "native-kem-checks flag/report mismatch")
    _require(facts["replay_sha256"] == PACKAGE_PINS["replay_sha256"], "invocation",
             "workspace replay.py differs from the reviewed runner")


def _validate_checker(report: dict[str, Any], evidence_root: Path, output: str,
                      dll_sha256: str, dotnet: str) -> None:
    checker = report.get("checker")
    _exact(checker, {"mode", "qualification", "source_sha256", "project_sha256",
                     "policy_sha256", "dll_sha256", "dll_path", "build_log",
                     "build_log_sha256", "dotnet"}, "checker")
    _require(checker.get("mode") == "fresh-build" and checker.get("qualification") is True,
             "checker", "checker was not a fresh qualification build")
    for key, value in (("source_sha256", PACKAGE_PINS["checker"]["source_sha256"]),
                       ("project_sha256", PACKAGE_PINS["checker"]["project_sha256"]),
                       ("policy_sha256", PACKAGE_PINS["checker"]["policy_sha256"]),
                       ("dll_sha256", dll_sha256)):
        _require(checker.get(key) == value, "checker", f"checker {key} changed")
    _under(output, checker.get("dll_path"), "checker", DEFAULT_DLL_RELATIVE)
    _require(checker.get("dotnet") == dotnet, "checker", "checker dotnet invocation changed")
    log = _rel(evidence_root, checker.get("build_log"), "checker")
    _require(checker.get("build_log_sha256") == _sha(log), "checker", "checker build log changed")
    text = log.read_text(encoding="utf-8")
    _require("Build succeeded." in text and not re.search(r"error CS|Build FAILED", text),
             "checker", "checker build log does not report success")
    _require(not _BAD.search(text), "checker", "checker build log is inconclusive")


def _validate_controls(report: dict[str, Any], evidence_root: Path, baseline: dict[str, Any],
                       output: str, dafny: str, dll: str, dll_sha256: str,
                       contexts: dict[str, Any]) -> int:
    controls = report.get("controls")
    _require(isinstance(controls, dict) and set(controls) == set(CONTROL_NAMES), "controls",
             "control record inventory changed")
    for name in CONTROL_NAMES:
        record = controls[name]
        _exact(record, {"name", "status", "exit", "command", "cwd", "env", "case_context",
                        "log", "log_sha256"}, "controls")
        status, needle = CONTROLS[name]
        _require(record.get("name") == name and record.get("status") == status, "controls",
                 f"{name}: control identity/status changed")
        _require(record.get("env") == {"SOURCE_TRACE_ROOTS": SELECT_ROOT}, "controls",
                 f"{name}: ambient selector environment changed")
        tree = output + "/trees/" + name + "/formal"
        operand = tree + "/crypto/NativeMlKem.dfy"
        command = [dafny, "resolve", operand, "--allow-external-contracts", "--plugin", dll]
        _require(record.get("command") == command, "controls", f"{name}: checker argv changed")
        _require(record.get("cwd") == tree + "/crypto", "controls",
                 f"{name}: checker cwd changed")
        _require(record.get("exit") == (0 if status == "accepted" else 2), "controls",
                 f"{name}: checker exit changed")
        if name == "positive-actual":
            fixture = PACKAGE_PINS["overlay_sha256"]
        else:
            fixture = baseline["controls"].get("controls/" + name + "/NativeMlKem.dfy")
            _require(isinstance(fixture, str), "controls", f"{name}: control fixture unbound")
        log = _rel(evidence_root, record.get("log"), "controls")
        _require(record.get("log_sha256") == _sha(log), "controls", f"{name}: log changed")
        text = log.read_text(encoding="utf-8")
        _validate_context(record.get("case_context"), case=name, argv=command, cwd=tree + "/crypto",
                          operand_sha256=fixture, expected_fixture=fixture or PACKAGE_PINS["overlay_sha256"],
                          plugin_sha256=dll_sha256, log_text=text, label="controls:" + name)
        _require(contexts.get(name) == record.get("case_context"), "controls",
                 f"{name}: report case_contexts entry differs from the control record")
        if status == "accepted":
            _accepted_checker(text, (SELECT_ROOT,), "controls", name)
        else:
            _rejected_checker(text, str(needle), "controls", name)
            _require(_diagnostics(text) == CASE_DIAGNOSTICS[name], "controls",
                     f"{name}: emitted diagnostics differ from the reviewed tuple")
    return len(CONTROL_NAMES)


def _workspace_equivalent(workspace_root: Path, candidate_formal: str, package_root: str,
                          provenance: str) -> Path:
    """Map a declared provenance file path to its current-workspace byte copy."""
    prefix_ws = str(Path(workspace_root).resolve() / "formal")
    for prefix, target in ((candidate_formal + "/", prefix_ws + "/"),
                           (package_root + "/", prefix_ws + "/source/select/")):
        if provenance.startswith(prefix):
            return Path(target + provenance[len(prefix):])
    raise SelectGateError("layout: provenance path is outside the declared roots: " + provenance)


def _validate_encoder(report: dict[str, Any], evidence_root: Path, package_root: str,
                      workspace_root: Path, output: str, dafny: str, dll: str,
                      dll_sha256: str, contexts: dict[str, Any]) -> int:
    encoder = report.get("encoder")
    _exact(encoder, {"audits", "constant_branch", "fixtures", "proofs"}, "encoder")
    candidate_formal = report["candidate_root"] + "/formal"
    proofs = encoder.get("proofs")
    _require(isinstance(proofs, list) and len(proofs) == len(ENCODER_PROOF_PINS), "encoder",
             "encoder proof inventory changed")
    seen = set()
    checked = 0
    for record in proofs:
        label = record.get("label") if isinstance(record, dict) else None
        _require(label in ENCODER_PROOF_PINS and label not in seen, "encoder",
                 f"unexpected/duplicated encoder proof {label!r}")
        seen.add(label)
        expected = ENCODER_PROOF_PINS[label]
        extra = ("--verify-included-files",) if label == "proof-source-trace-bridge" else ()
        if label == "proof-observation-vocabulary":
            entry, cwd = candidate_formal + "/source/vocabulary/ObservationVocabulary.dfy", None
        elif label == "proof-source-trace":
            entry, cwd = candidate_formal + "/source/SourceTrace.dfy", None
        else:
            entry, cwd = package_root + "/bridge/SourceTraceBridge.dfy", package_root + "/bridge"
        argv = _proof_argv(dafny, entry, 0, extra)
        cwd = cwd or str(PurePosixPath(entry).parent)
        text = _proof(record, label, label, evidence_root, expected=expected,
                      argv=argv, cwd=cwd)
        operand = _workspace_equivalent(workspace_root, candidate_formal, package_root, entry)
        _validate_context(record.get("case_context"), case=label, argv=argv, cwd=cwd,
                          operand_sha256=_sha(operand), expected_fixture=None,
                          plugin_sha256=None, log_text=text, label="encoder:" + label)
        _require(contexts.get(label) == record.get("case_context"), "encoder",
                 f"{label}: report case_contexts entry differs")
        checked += 1
    mutant = encoder.get("constant_branch")
    mut_entry = output + "/constant-branch/source/SourceTraceBridge.dfy"
    mut_cwd = output + "/constant-branch/source"
    mut_argv = _proof_argv(dafny, mut_entry, 0, ("--verify-included-files",))
    mtext = _proof(mutant, "constant-branch-bridge", "constant-branch mutant", evidence_root,
                   expected=EXPECTED["constant_branch_mutant"], argv=mut_argv, cwd=mut_cwd,
                   negative=True,
                   anchor=("50", "2", "a postcondition could not be proved on this return path"))
    _require("BranchFalseNotTrue" in mtext and "SourceTrace.dfy" in mtext, "encoder",
             "constant-branch mutant did not check the actual bridge source")
    _st_hash, _bridge_hash = _mutant_hashes(workspace_root)
    _validate_context(mutant.get("case_context"), case="constant-branch-bridge", argv=mut_argv,
                      cwd=mut_cwd, operand_sha256=_bridge_hash, expected_fixture=None,
                      plugin_sha256=None, log_text=mtext, label="encoder:constant-branch")
    _require(contexts.get("constant-branch-bridge") == mutant.get("case_context"), "encoder",
             "report case_contexts constant-branch entry differs")
    fixtures = encoder.get("fixtures")
    _require(isinstance(fixtures, dict) and set(fixtures) == set(ENCODER_FIXTURES), "encoder",
             "encoder fixture inventory changed")
    for name, accept in ENCODER_FIXTURES.items():
        record = fixtures[name]
        _exact(record, {"accept", "exit", "case_context", "log", "log_sha256"}, "encoder")
        _require(record.get("accept") is accept and record.get("exit") == (0 if accept else 2),
                 "encoder", f"{name}: encoder fixture verdict changed")
        entry = package_root + "/fixtures/encoder-fixtures-v2/" + name + \
            "/formal/crypto/NativeKeccak.dfy"
        argv = [dafny, "resolve", entry, "--allow-external-contracts", "--plugin", dll]
        log = _rel(evidence_root, record.get("log"), "encoder")
        _require(record.get("log_sha256") == _sha(log), "encoder", f"{name}: log changed")
        text = log.read_text(encoding="utf-8")
        _validate_context(record.get("case_context"), case="encoder-" + name, argv=argv,
                          cwd=str(PurePosixPath(entry).parent),
                          operand_sha256=_sha(workspace_root / "formal/source/select" /
                                              "fixtures/encoder-fixtures-v2" / name /
                                              "formal/crypto/NativeKeccak.dfy"),
                          expected_fixture=_sha(workspace_root / "formal/source/select" /
                                                "fixtures/encoder-fixtures-v2" / name /
                                                "formal/crypto/NativeKeccak.dfy"),
                          plugin_sha256=dll_sha256, log_text=text, label="encoder:" + name)
        _require(contexts.get("encoder-" + name) == record.get("case_context"), "encoder",
                 f"{name}: report case_contexts entry differs")
        if accept:
            _accepted_checker(text, ENCODER_ROOTS, "encoder", name)
        else:
            _rejected_checker(text, "canonical Encode does not implement the exact typed "
                                    "wire layout", "encoder", name)
        checked += 1
    audits = encoder.get("audits")
    _require(isinstance(audits, dict) and set(audits) == set(ENCODER_AUDIT_FILES), "encoder",
             "encoder audit inventory changed")
    for name in ENCODER_AUDIT_FILES:
        record = audits[name]
        _exact(record, {"exit", "case_context", "log", "log_sha256"}, "encoder")
        _require(record.get("exit") == 0, "encoder", f"{name}: audit did not exit cleanly")
        entry = (package_root + "/bridge/" + name if name == "SourceTraceBridge.dfy" else
                 candidate_formal + ("/source/vocabulary/" + name
                                     if name == "ObservationVocabulary.dfy"
                                     else "/source/" + name))
        argv = [dafny, "audit", entry]
        log = _rel(evidence_root, record.get("log"), "encoder")
        _require(record.get("log_sha256") == _sha(log), "encoder", f"{name}: audit log changed")
        text = log.read_text(encoding="utf-8")
        findings = _AUDIT.findall(text)
        _require(len(findings) == 1 and int(findings[0]) == 0, "encoder",
                 f"{name}: audit findings changed")
        _require(not _BAD.search(text), "encoder", f"{name}: audit log inconclusive")
        _validate_context(record.get("case_context"), case="audit-" + name, argv=argv,
                          cwd=str(PurePosixPath(entry).parent),
                          operand_sha256=_sha(_workspace_equivalent(
                              workspace_root, candidate_formal, package_root, entry)),
                          expected_fixture=None, plugin_sha256=None, log_text=text,
                          label="encoder:audit-" + name)
        _require(contexts.get("audit-" + name) == record.get("case_context"), "encoder",
                 f"{name}: report case_contexts entry differs")
        checked += 1
    return checked


def _tracked_operand(workspace_root: Path, rel: str, label: str) -> str:
    return _sha(_rel(workspace_root, rel, label))


def _mutant_hashes(workspace_root: Path) -> tuple[str, str]:
    """Recompute the deterministic constant-branch mutant file hashes (no execution)."""
    st = (workspace_root / "formal/source/SourceTrace.dfy").read_text(encoding="utf-8")
    anchor = "{ O.Encode(O.Branch(site, taken)) }"
    _require(st.count(anchor) == 1, "encoder", "constant-branch mutant anchor changed")
    mutant_st = st.replace(anchor, "{ O.Encode(O.Branch(site, false)) }", 1)
    bridge = (workspace_root / "formal/source/select/bridge/SourceTraceBridge.dfy").read_text(
        encoding="utf-8")
    mutant_bridge = bridge.replace('include "../../SourceTrace.dfy"',
                                   'include "SourceTrace.dfy"', 1)
    _require(mutant_bridge != bridge, "encoder", "constant-branch include rewrite changed")
    import hashlib as _h
    return (_h.sha256(mutant_st.encode()).hexdigest(),
            _h.sha256(mutant_bridge.encode()).hexdigest())


def _validate_observed(report: dict[str, Any], evidence_root: Path, package_root: Path,
                       output: str, candidate: str, dafny: str, dll: str, dll_sha256: str,
                       baseline: dict[str, Any], contexts: dict[str, Any]) -> int:
    observed = report.get("observed")
    _exact(observed, {"checker", "harness", "method"}, "observed")
    tree = output + "/trees/observed/formal"
    checker = observed["checker"]
    _exact(checker, {"exit", "case_context", "log", "log_sha256"}, "observed")
    _require(checker.get("exit") == 0, "observed", "observed checker did not accept")
    fixture = baseline["controls"].get("controls/observed/NativeMlKem.dfy")
    _require(isinstance(fixture, str), "observed", "observed control fixture unbound")
    operand = tree + "/crypto/NativeMlKem.dfy"
    argv = [dafny, "resolve", operand, "--allow-external-contracts", "--plugin", dll]
    log = _rel(evidence_root, checker.get("log"), "observed")
    _require(checker.get("log_sha256") == _sha(log), "observed", "observed checker log changed")
    text = log.read_text(encoding="utf-8")
    _validate_context(checker.get("case_context"), case="observed", argv=argv,
                      cwd=tree + "/crypto", operand_sha256=fixture, expected_fixture=fixture,
                      plugin_sha256=dll_sha256, log_text=text, label="observed:checker")
    _require(contexts.get("observed") == checker.get("case_context"), "observed",
             "report case_contexts observed entry differs")
    _accepted_checker(text, (SELECT_ROOT,), "observed", "observed checker")
    method_argv = _proof_argv(dafny, operand, 3)
    mtext = _proof(observed["method"], "observed-mutant-method", "observed method",
                   evidence_root, expected=EXPECTED["observed_mutant_method"],
                   argv=method_argv, cwd=tree + "/crypto")
    _validate_context(observed["method"].get("case_context"), case="observed-mutant-method",
                      argv=method_argv, cwd=tree + "/crypto", operand_sha256=fixture,
                      expected_fixture=None, plugin_sha256=None, log_text=mtext,
                      label="observed:method")
    _require(contexts.get("observed-mutant-method") == observed["method"].get("case_context"),
             "observed", "report case_contexts observed-method entry differs")
    _require("Error:" not in mtext, "observed", "observed method proof contains an error")
    harness_entry = tree + "/source/select/observed/SelectObservedHarness.dfy"
    harness_fixture = _tracked_operand(workspace_root=None, rel=None, label="unused") if False else None
    harness_sha = baseline["package_files"].get("controls/observed/SelectObservedHarness.dfy")
    _require(isinstance(harness_sha, str), "observed", "observed harness fixture unbound")
    harness_argv = _proof_argv(dafny, harness_entry, 0)
    htext = _proof(observed["harness"], "observed-mutant-harness", "observed harness",
                   evidence_root, expected=EXPECTED["observed_mutant_harness"],
                   argv=harness_argv, cwd=tree + "/source/select/observed", negative=True,
                   anchor=OBSERVED_HARNESS_ANCHOR)
    _require(OBSERVED_HARNESS_TEXT in htext, "observed",
             "observed harness log lacks the actual assert anchor")
    _validate_context(observed["harness"].get("case_context"), case="observed-mutant-harness",
                      argv=harness_argv, cwd=tree + "/source/select/observed",
                      operand_sha256=harness_sha, expected_fixture=None, plugin_sha256=None,
                      log_text=htext, label="observed:harness")
    _require(contexts.get("observed-mutant-harness") == observed["harness"].get("case_context"),
             "observed", "report case_contexts observed-harness entry differs")
    return 3


def _validate_f2(report: dict[str, Any], evidence_root: Path, output: str, dafny: str,
                 dll: str, dll_sha256: str, baseline: dict[str, Any],
                 contexts: dict[str, Any]) -> int:
    f2 = report.get("f2")
    _exact(f2, {"coverage_accept", "dafny_full"}, "f2")
    accept = f2["coverage_accept"]
    _exact(accept, {"name", "status", "exit", "command", "cwd", "env", "case_context",
                    "log", "log_sha256"}, "f2")
    _require(accept.get("name") == "coverage-private-loop-bound"
             and accept.get("status") == "accepted" and accept.get("exit") == 0, "f2",
             "F2 coverage case must be the reviewed accepted control")
    _require(accept.get("env") == {"SOURCE_TRACE_ROOTS": SELECT_ROOT}, "f2",
             "F2 coverage selector environment changed")
    tree = output + "/trees/coverage-private-loop-bound/formal"
    operand = tree + "/crypto/NativeMlKem.dfy"
    argv = [dafny, "resolve", operand, "--allow-external-contracts", "--plugin", dll]
    _require(accept.get("command") == argv and accept.get("cwd") == tree + "/crypto", "f2",
             "F2 coverage argv/cwd changed")
    fixture = baseline["controls"].get("controls/coverage-private-loop-bound/NativeMlKem.dfy")
    _require(isinstance(fixture, str), "f2", "F2 coverage fixture unbound")
    log = _rel(evidence_root, accept.get("log"), "f2")
    _require(accept.get("log_sha256") == _sha(log), "f2", "F2 coverage log changed")
    text = log.read_text(encoding="utf-8")
    _validate_context(accept.get("case_context"), case="coverage-private-loop-bound",
                      argv=argv, cwd=tree + "/crypto", operand_sha256=fixture,
                      expected_fixture=fixture, plugin_sha256=dll_sha256, log_text=text,
                      label="f2:coverage")
    _require(contexts.get("coverage-private-loop-bound") == accept.get("case_context"), "f2",
             "report case_contexts F2-coverage entry differs")
    _accepted_checker(text, (SELECT_ROOT,), "f2", "F2 coverage log")
    full = f2["dafny_full"]
    f2tree = output + "/trees/f2-private-loop-bound/formal"
    f_operand = f2tree + "/crypto/NativeMlKem.dfy"
    f_argv = _proof_argv(dafny, f_operand, 3)
    ftext = _proof(full, "f2-private-loop-bound-full", "F2 full proof", evidence_root,
                   expected=EXPECTED["private_loop_bound_full"], argv=f_argv,
                   cwd=f2tree + "/crypto", negative=True, anchor=F2_ANCHOR)
    _require("loop invariant" in ftext, "f2", "F2 full proof lacks the trace-invariant failure")
    _validate_context(full.get("case_context"), case="f2-private-loop-bound-full",
                      argv=f_argv, cwd=f2tree + "/crypto", operand_sha256=fixture,
                      expected_fixture=None, plugin_sha256=None, log_text=ftext,
                      label="f2:full")
    _require(contexts.get("f2-private-loop-bound-full") == full.get("case_context"), "f2",
             "report case_contexts F2-full entry differs")
    return 2




def _validate_retained_prefix(text: str, fixture: str, dafny: str, dotnet: str) -> None:
    """Validate the retained raw prefix with the producer Python as provenance.

    The prefix records the historical producer's ``sys.executable``; it is a
    normalized absolute provenance/TCB string, never compared to the consumer's
    interpreter and never opened or executed.  Only the normalized shape and the
    exact runner/dafny/dotnet operands and cwd are checked.
    """
    line = text.splitlines()[0] if text.splitlines() else ""
    prefix = "CASE-CONTEXT case=retained-native argv="
    _require(line.startswith(prefix) and " cwd=" in line, "retained",
             "retained raw log CASE-CONTEXT prefix changed")
    body = line[len(prefix):]
    argv_text, cwd = body.rsplit(" cwd=", 1)
    try:
        argv = json.loads(argv_text)
    except json.JSONDecodeError:
        raise SelectGateError("retained: retained raw prefix argv is not JSON")
    _require(isinstance(argv, list) and len(argv) == 6
             and all(isinstance(part, str) for part in argv), "retained",
             "retained raw prefix argv shape changed")
    interpreter = PurePosixPath(argv[0])
    _require(interpreter.is_absolute() and ".." not in interpreter.parts
             and re.fullmatch(r"python3(?:\.[0-9]+)?", interpreter.name) is not None,
             "retained", "retained producer Python provenance is not normalized")
    _require(argv[1:] == ["run.py", "--dafny", dafny, "--dotnet", dotnet], "retained",
             "retained raw prefix runner/tool operands changed")
    _require(cwd == fixture, "retained", "retained raw prefix cwd changed")



_RETAINED_COVERAGE = re.compile(r"^SOURCE-COVERAGE OK: exact roots \[([^\]]*)\]", re.M)


def _retained_accept_log(text: str, label: str, what: str) -> None:
    _require(not _BAD.search(text), label, f"{what} contains an inconclusive diagnostic")
    _require("Error:" not in text, label, f"{what} contains an error diagnostic")
    matches = _RETAINED_COVERAGE.findall(text)
    _require(len(matches) == 1, label, f"{what} lacks exactly one coverage line")
    roots = tuple(part.strip() for part in matches[0].split(",") if part.strip())
    _require(roots == EXPECTED_BASELINE13_ROOTS, label,
             f"{what} resolved identities changed")


def _retained_verify_log(text: str, expected: tuple[int, int], label: str, what: str) -> None:
    _require(not _BAD.search(text), label, f"{what} contains an inconclusive diagnostic")
    _require(not re.search(r"\(\d+,\d+\): Warning: ", text), label,
             f"{what} contains a warning")
    summary = _summary(text, label, what)
    _require(summary == (expected[0], expected[1], 0), label,
             f"{what} summary {summary} != {expected}")


def _retained_case_semantics(nested: dict[str, Any], expected_exit: int, needle: str | None,
                             label: str, what: str) -> None:
    if expected_exit == 0:
        _require(nested.get("exit") == 0 and nested.get("status") == "SOURCE-COVERAGE OK",
                 label, f"{what} is not the reviewed accepted result")
    else:
        _require(nested.get("exit") == 2
                 and nested.get("classification") == "named-checker-rejection"
                 and nested.get("needle") == needle, label,
                 f"{what} is not the reviewed named rejection")


def _validate_retained_cases(workspace_root: Path, fixture_dir: Path,
                             nested: dict[str, Any], retained: dict[str, Any]) -> int:
    """Exact 18/22 matrices/verdicts/accept sets from the reviewed b1ce fixtures."""
    package = workspace_root / "formal/source/select"
    root19_meta = _load(package / "fixtures/retained-native/controls/root19.json",
                        "retained fixtures")
    callbinding_meta = _load(package / "fixtures/retained-native/controls/callbinding.json",
                             "retained fixtures")
    root19 = nested.get("root19")
    callbinding = nested.get("callbinding")
    expected_root19 = set(root19_meta) - {"baseline13"}
    _require(isinstance(root19, dict) and set(root19) == expected_root19
             and len(expected_root19) == EXPECTED["retained_root19_cases"], "retained",
             "nested root19 case matrix changed")
    _require(isinstance(callbinding, dict) and set(callbinding) == set(callbinding_meta)
             and len(callbinding_meta) == EXPECTED["retained_callbinding_cases"], "retained",
             "nested callbinding case matrix changed")
    accepted_root19 = []
    for name, meta in sorted(root19_meta.items()):
        if name == "baseline13":
            continue
        what = "root19." + name
        _retained_case_semantics(root19[name], meta["expected_exit"], meta.get("needle"),
                                 "retained", what)
        log = _rel(fixture_dir, "work/root19-" + name + ".log", "retained")
        text = log.read_text(encoding="utf-8")
        if meta["expected_exit"] == 0:
            _retained_accept_log(text, "retained", what)
            accepted_root19.append(name)
        else:
            _rejected_checker(text, str(meta["needle"]), "retained", what)
    accepted_callbinding = []
    verify_blocks = {"verify_method": "method", "verify_nativekeccak": "nativekeccak",
                     "verify_harness": "harness"}
    verify_logs = {"verify_method": "-verify.log",
                   "verify_nativekeccak": "-nativekeccak-verify.log",
                   "verify_harness": "-harness-verify.log"}
    for name, meta in sorted(callbinding_meta.items()):
        what = "callbinding." + name
        expect_exit = 0 if meta.get("expect") == "accept" else int(meta.get("exit", 2))
        _retained_case_semantics(callbinding[name], expect_exit, meta.get("needle"),
                                 "retained", what)
        text = _rel(fixture_dir, "work/callbinding-" + name + ".log",
                    "retained").read_text(encoding="utf-8")
        if expect_exit == 0:
            _retained_accept_log(text, "retained", what)
            accepted_callbinding.append(name)
        else:
            _rejected_checker(text, str(meta["needle"]), "retained", what)
        for meta_key, block_name in verify_blocks.items():
            if meta_key not in meta:
                continue
            block = callbinding[name].get(block_name)
            _require(isinstance(block, dict) and set(block) == {"exit", "verified", "errors"},
                     "retained", f"{what} {block_name} record changed")
            _require(block.get("exit") == 0 and block.get("verified") == int(meta[meta_key])
                     and block.get("errors") == 0, "retained",
                     f"{what} {block_name} counts changed")
            vtext = _rel(fixture_dir, "work/callbinding-" + name + verify_logs[meta_key],
                         "retained").read_text(encoding="utf-8")
            _retained_verify_log(vtext, (int(meta[meta_key]), 0), "retained",
                                 f"{what} {block_name}")
    _require(isinstance(retained.get("root19_accepts"), list)
             and set(retained["root19_accepts"]) == set(accepted_root19), "retained",
             "retained root19 accepted set is not the reviewed derivation")
    _require(isinstance(retained.get("callbinding_accepts"), list)
             and set(retained["callbinding_accepts"]) == set(accepted_callbinding), "retained",
             "retained callbinding accepted set is not the reviewed derivation")
    return 18 + 22

def _validate_retained(report: dict[str, Any], evidence_root: Path, output: str,
                       dll_sha256: str, dafny: str, dotnet: str, workspace_root: Path) -> int:
    retained = report.get("retained_native")
    keys = {"exit", "workspace", "report", "report_sha256", "status", "plugin_sha256",
            "checker_source_sha256", "checker_project_sha256", "canonical_policy_sha256",
            "baseline13", "root19_count", "callbinding_count", "root19_accepts",
            "callbinding_accepts", "log", "log_sha256"}
    _exact(retained, keys, "retained")
    _require(retained.get("status") == "complete" and retained.get("exit") == 0, "retained",
             "retained Native run did not complete cleanly")
    _require(retained.get("plugin_sha256") == dll_sha256, "retained",
             "retained plugin is not the reviewed DLL")
    for key, value in (("checker_source_sha256", PACKAGE_PINS["checker"]["source_sha256"]),
                       ("checker_project_sha256", PACKAGE_PINS["checker"]["project_sha256"]),
                       ("canonical_policy_sha256", PACKAGE_PINS["checker"]["policy_sha256"])):
        _require(retained.get(key) == value, "retained", f"retained {key} changed")
    _require(retained.get("root19_count") == EXPECTED["retained_root19_cases"]
             and retained.get("callbinding_count") == EXPECTED["retained_callbinding_cases"],
             "retained", "retained case counts changed")
    baseline13 = retained.get("baseline13")
    _exact(baseline13, {"exit", "status", "count", "roots", "log", "log_sha256"}, "retained")
    _require(baseline13.get("exit") == 0 and baseline13.get("status") == "SOURCE-COVERAGE OK",
             "retained", "retained baseline13 did not report the named result")
    _require(baseline13.get("count") == len(EXPECTED_BASELINE13_ROOTS)
             and tuple(baseline13.get("roots") or ()) == EXPECTED_BASELINE13_ROOTS, "retained",
             "retained baseline13 identities changed")
    fixture = output + "/retained-native/fixture"
    _require(retained.get("workspace") == "retained-native/fixture", "retained",
             "retained workspace path role changed")
    _require(retained.get("report") == "retained-native/fixture/report.json", "retained",
             "retained nested report path role changed")
    _require(retained.get("log") == "logs/retained-native/run.log", "retained",
             "retained raw log path role changed")
    _require(baseline13.get("log") == "retained-native/fixture/work/baseline13.log",
             "retained", "retained baseline13 raw log path role changed")
    nested_path = _rel(evidence_root, "retained-native/fixture/report.json", "retained")
    _require(retained.get("report_sha256") == _sha(nested_path), "retained",
             "retained nested report digest changed")
    nested = _load(nested_path, "retained")
    _require(nested.get("status") == "complete", "retained", "nested report status changed")
    _require(nested.get("plugin_sha256") == dll_sha256, "retained",
             "nested retained plugin changed")
    _require(nested.get("pins_before") == nested.get("pins_after"), "retained",
             "nested retained pins changed")
    nb13 = nested.get("baseline13")
    _require(isinstance(nb13, dict) and nb13.get("exit") == 0
             and nb13.get("status") == "SOURCE-COVERAGE OK", "retained",
             "nested baseline13 record changed")
    _require(len(nested.get("root19", {})) == EXPECTED["retained_root19_cases"]
             and len(nested.get("callbinding", {})) == EXPECTED["retained_callbinding_cases"],
             "retained", "nested retained counts changed")
    for key in ("root19_accepts", "callbinding_accepts"):
        accepted = retained.get(key)
        _require(isinstance(accepted, list)
                 and set(accepted) <= set(nested.get(key.split("_")[0], {})), "retained",
                 f"retained {key} inventory changed")
    log = _rel(evidence_root, retained.get("log"), "retained")
    _require(retained.get("log_sha256") == _sha(log), "retained", "retained log changed")
    text = log.read_text(encoding="utf-8")
    _require(not _BAD.search(text), "retained", "retained log is inconclusive")
    _validate_retained_prefix(text, fixture, dafny, dotnet)
    log13 = _rel(evidence_root, baseline13.get("log"), "retained")
    _require(baseline13.get("log_sha256") == _sha(log13), "retained",
             "retained baseline13 raw log changed")
    matches = _CHECKER_OK.findall(log13.read_text(encoding="utf-8"))
    _require(len(matches) == 1, "retained",
             "baseline13 raw log lacks exactly one named coverage line")
    roots = tuple(part.strip() for part in matches[0].split(",") if part.strip())
    _require(roots == EXPECTED_BASELINE13_ROOTS, "retained",
             "baseline13 raw log identities changed")
    _validate_retained_cases(workspace_root,
                             _reldir(evidence_root, "retained-native/fixture", "retained"),
                             nested, retained)
    return 7


def _validate_codegen(report: dict[str, Any], evidence_root: Path, output: str) -> int:
    codegen = report.get("codegen")
    _exact(codegen, {"java_algorithm_files", "java_identity", "classes", "driver_excluded",
                     "translations"}, "codegen")
    _require(codegen.get("java_algorithm_files") == EXPECTED["jdk_classes"], "codegen",
             "algorithm Java file count changed")
    _require(codegen.get("driver_excluded") is True and codegen.get("java_identity") is True,
             "codegen", "driver exclusion or Java identity changed")
    classes = codegen.get("classes")
    _require(isinstance(classes, dict) and set(classes) == {"21", "25"}, "codegen",
             "dual-JDK class inventory changed")
    for major, view in classes.items():
        _require(isinstance(view, dict) and set(view) == {"count", "identity"}
                 and view.get("count") == EXPECTED["jdk_classes"]
                 and view.get("identity") is True, "codegen",
                 f"JDK{major} class count/identity changed")
    translations = codegen.get("translations")
    _require(isinstance(translations, dict) and set(translations) == {"base", "overlay"},
             "codegen", "translation inventory changed")
    for name, record in translations.items():
        _exact(record, {"exit", "log", "log_sha256"}, "codegen")
        _require(record.get("exit") == 0, "codegen", f"{name}: translation did not exit cleanly")
        log = _rel(evidence_root, record.get("log"), "codegen")
        _require(record.get("log_sha256") == _sha(log), "codegen", f"{name}: log changed")
        text = log.read_text(encoding="utf-8")
        _require(not _BAD.search(text), "codegen", f"{name}: translation log inconclusive")
        _require("did not attempt verification" in text, "codegen",
                 f"{name}: generation stage did not use --no-verify")
        _require("Warning:" not in text and "Error:" not in text, "codegen",
                 f"{name}: generation log contains a diagnostic")
    return 6


def _validate_report(report: dict[str, Any], evidence_root: Path, facts: dict[str, Any],
                     platform: str) -> dict[str, Any]:
    package = facts["package"]
    baseline = facts["baseline"]
    profile = facts["profiles"][platform]["profile"]
    profile_sha = facts["profiles"][platform]["sha256"]
    selector = facts["profiles"][platform]["selector"]
    keys = set(report)
    _require(REQUIRED_FULL <= keys and keys - REQUIRED_FULL <= OPTIONAL_FULL, "report",
             f"report key inventory changed: missing={sorted(REQUIRED_FULL - keys)} "
             f"extra={sorted(keys - REQUIRED_FULL - OPTIONAL_FULL)}")
    _require(report.get("schema") == REPORT_SCHEMA, "report", "unexpected report schema")
    _require(report.get("mode") == "full" and report.get("qualification") is True, "report",
             "report is not a full qualification run")
    _require(report.get("status") == "complete", "report", "status is not complete")
    _require("error" not in report and "failure_kind" not in report, "report",
             "report contains a failure marker")
    for key in ("output", "baseline_root", "candidate_root", "package_root"):
        _norm_abs(report.get(key), "layout")
    output = report["output"]
    _require(report["package_root"] == report["candidate_root"] + "/formal/source/select",
             "layout", "package_root is not candidate_root/formal/source/select")
    _require(PurePosixPath(report["candidate_root"]).name == "candidate", "layout",
             "candidate_root role changed")
    _require(PurePosixPath(report["baseline_root"]).name.startswith("baseline-git-"), "layout",
             "baseline_root role changed")
    _require(report.get("package_sha256") == PACKAGE_PINS["package_sha256"], "report",
             "report package digest is not the reviewed package")
    identity = report.get("profile")
    _exact(identity, {"selector", "path", "sha256", "platform", "package_pinned",
                      "external_expected"}, "profile")
    _require(identity.get("selector") == selector and identity.get("platform") == platform,
             "profile", "report profile selector/platform changed")
    _require(identity.get("sha256") == profile_sha and identity.get("external_expected")
             == profile_sha and identity.get("package_pinned") is True, "profile",
             "report profile digest/external pin changed")
    _norm_abs(identity.get("path"), "profile")
    _require(PurePosixPath(identity["path"]).name == selector + ".json", "profile",
             "profile provenance path role changed")
    tools = report.get("tools")
    _exact(tools, {"dafny", "dotnet", "jdk21", "jdk25", "runtime"}, "tools")
    for value in tools.values():
        _norm_abs(value, "tools")
    projection = {key: package[key] for key in
                  ("schema", "scope", "ambient_selector_policy", "candidate_overlay_sha256",
                   "baseline_native_mlkem_sha256", "expected", "native_kem_patch")}
    _require(report.get("inputs") == projection, "report",
             "report inputs block is not the reviewed package projection")
    _exact(report.get("manifest"), {"git_commit", "git_tree", "baseline_formal_files",
                                    "candidate_formal_files", "declared_formal_diff",
                                    "package_files", "controls"}, "manifest")
    manifest = report["manifest"]
    _require(manifest == {
        "git_commit": PACKAGE_PINS["git_commit"], "git_tree": PACKAGE_PINS["git_tree"],
        "baseline_formal_files": PACKAGE_PINS["dafny_files"],
        "candidate_formal_files": PACKAGE_PINS["dafny_files"],
        "declared_formal_diff": list(CANDIDATE_ALLOWED_FORMAL_DIFF),
        "package_files": PACKAGE_PINS["package_files"],
        "controls": PACKAGE_PINS["controls"]}, "manifest", "manifest summary block changed")
    _validate_invocation(report, facts, platform, selector)
    checked = 1
    checked += _tool_identity(report, "tool_identity_before", profile, profile_sha, platform,
                              "tools:before")
    dll = output + "/" + DEFAULT_DLL_RELATIVE
    _validate_checker(report, evidence_root, output, PACKAGE_PINS["checker"]["dll_sha256"],
                      tools["dotnet"])
    contexts = report.get("case_contexts")
    _require(isinstance(contexts, dict), "report", "case_contexts block missing")
    expected_cases = (set(CONTROL_NAMES) | {"observed", "observed-mutant-method",
                                            "observed-mutant-harness", "f2-private-loop-bound-full",
                                            "full-native-mlkem",
                                            "constant-branch-bridge"} |
                      {"encoder-" + name for name in ENCODER_FIXTURES} |
                      set(ENCODER_PROOF_PINS) | {"audit-" + name for name in ENCODER_AUDIT_FILES})
    _require(set(contexts) == expected_cases, "report",
             f"case-context inventory changed: missing={sorted(expected_cases - set(contexts))} "
             f"extra={sorted(set(contexts) - expected_cases)}")
    checked += _validate_controls(report, evidence_root, baseline, output, tools["dafny"], dll,
                                  PACKAGE_PINS["checker"]["dll_sha256"], contexts)
    harness_entry = report["package_root"] + "/harness/SelectTraceHarness.dfy"
    harness_cwd = report["package_root"] + "/harness"
    harness_argv = _proof_argv(tools["dafny"], harness_entry, 0)
    htext = _proof(report["harness"], "select-harness", "select harness", evidence_root,
                   expected=EXPECTED["select_harness"], argv=harness_argv,
                   cwd=harness_cwd)
    _validate_context(report["harness"].get("case_context"), case="select-harness",
                      argv=harness_argv, cwd=harness_cwd,
                      operand_sha256=_sha(facts["package_root"] / "harness/SelectTraceHarness.dfy"),
                      expected_fixture=None, plugin_sha256=None, log_text=htext,
                      label="harness")
    # The producer keeps the harness context inside its proof record (proof() emits
    # the raw prefix + typed record); the top-level convenience map does not repeat it.
    _require("select-harness" not in contexts, "harness",
             "unexpected duplicate harness context in the report map")
    checked += _validate_observed(report, evidence_root, facts["package_root"], output,
                                  report["candidate_root"], tools["dafny"], dll,
                                  PACKAGE_PINS["checker"]["dll_sha256"], baseline, contexts)
    checked += _validate_f2(report, evidence_root, output, tools["dafny"], dll,
                            PACKAGE_PINS["checker"]["dll_sha256"], baseline, contexts)
    checked += _validate_encoder(report, evidence_root, report["package_root"],
                                 Path(facts["workspace_root"]), output,
                                 tools["dafny"], dll, PACKAGE_PINS["checker"]["dll_sha256"],
                                 contexts)
    full_entry = report["candidate_root"] + "/formal/crypto/NativeMlKem.dfy"
    full_argv = _proof_argv(tools["dafny"], full_entry, 3)
    ftext = _proof(report["full_native_mlkem"], "full-native-mlkem", "full NativeMlKem",
                   evidence_root, expected=EXPECTED["full_native_mlkem"], argv=full_argv,
                   cwd=report["candidate_root"] + "/formal/crypto")
    _validate_context(report["full_native_mlkem"].get("case_context"), case="full-native-mlkem",
                      argv=full_argv, cwd=report["candidate_root"] + "/formal/crypto",
                      operand_sha256=PACKAGE_PINS["overlay_sha256"], expected_fixture=None,
                      plugin_sha256=None, log_text=ftext, label="full")
    _require(contexts.get("full-native-mlkem") == report["full_native_mlkem"].get("case_context"),
             "full", "report case_contexts full entry differs")
    checked += _validate_retained(report, evidence_root, output,
                                  PACKAGE_PINS["checker"]["dll_sha256"], tools["dafny"],
                                  tools["dotnet"], Path(facts["workspace_root"]))
    checked += _validate_codegen(report, evidence_root, output)
    if "native_kem_checks" in report:
        record = report["native_kem_checks"]
        _exact(record, {"exit", "log", "log_sha256", "output"}, "native-kem")
        _require(record.get("exit") == 0, "native-kem", "native KEM replay did not exit cleanly")
        log = _rel(evidence_root, record.get("log"), "native-kem")
        _require(record.get("log_sha256") == _sha(log), "native-kem", "native KEM log changed")
        _require(not _BAD.search(log.read_text(encoding="utf-8")), "native-kem",
                 "native KEM log is inconclusive")
        checked += 1
    checked += _tool_identity(report, "tool_identity_after", profile, profile_sha, platform,
                              "tools:after")
    signature = report.get("input_signature")
    _exact(signature, {"files", "profile_sha256", "stable"}, "signature")
    _require(signature.get("stable") is True and signature.get("profile_sha256") == profile_sha,
             "signature", "input signature stability/profile changed")
    _require(signature.get("files") == {"baseline_dafny": PACKAGE_PINS["dafny_files"],
                                        "dafny": PACKAGE_PINS["dafny_files"],
                                        "package": PACKAGE_PINS["package_files"] + 2,
                                        "used_inputs": len(USED_INPUTS)}, "signature",
             "input signature domains/counts changed")
    return {"checked": checked, "platform": platform, "profile_sha256": profile_sha,
            "package_sha256": PACKAGE_PINS["package_sha256"]}




COMPANION_MAPS = ("java-base", "java-overlay", "classes-base-jdk21", "classes-base-jdk25",
                  "classes-overlay-jdk21", "classes-overlay-jdk25")
# Reviewed digests of the Root-derived codegen maps.  The generated Java and class
# bytes are deterministic across the two reviewed platforms, so both backends share
# the same reviewed map digests.  These are code authority: the collection's own
# mutable index alone cannot renew them.
COMPANION_PINS = {
    "macos-arm64": {
        "java-base": "4217b981ea4bb4800c9da16b17846a3669c47f7b104c4f8918c0f7f82b70afb9",
        "java-overlay": "4217b981ea4bb4800c9da16b17846a3669c47f7b104c4f8918c0f7f82b70afb9",
        "classes-base-jdk21": "ee894ab070a3f39e0df9e3418e463ba4e340daa3b179406746d117beff6b6263",
        "classes-base-jdk25": "ecdfcc87f61074c88002d0d3e6d1f4c5ac15dd1d91f7de98f991013875770bd5",
        "classes-overlay-jdk21": "ee894ab070a3f39e0df9e3418e463ba4e340daa3b179406746d117beff6b6263",
        "classes-overlay-jdk25": "ecdfcc87f61074c88002d0d3e6d1f4c5ac15dd1d91f7de98f991013875770bd5",
    },
    "linux-x64": {
        "java-base": "4217b981ea4bb4800c9da16b17846a3669c47f7b104c4f8918c0f7f82b70afb9",
        "java-overlay": "4217b981ea4bb4800c9da16b17846a3669c47f7b104c4f8918c0f7f82b70afb9",
        "classes-base-jdk21": "ee894ab070a3f39e0df9e3418e463ba4e340daa3b179406746d117beff6b6263",
        "classes-base-jdk25": "ecdfcc87f61074c88002d0d3e6d1f4c5ac15dd1d91f7de98f991013875770bd5",
        "classes-overlay-jdk21": "ee894ab070a3f39e0df9e3418e463ba4e340daa3b179406746d117beff6b6263",
        "classes-overlay-jdk25": "ecdfcc87f61074c88002d0d3e6d1f4c5ac15dd1d91f7de98f991013875770bd5",
    },
}


def validate_companion_maps(collection: Path, platform: str) -> dict[str, Any]:
    """Validate Root-derived codegen maps (DERIVED, not producer-recorded).

    The producer emits counts/identity and hashes in memory; these companion maps
    are curated by hashing the actual generated files.  They are accepted only via
    the collection's own reviewed file index, with 65 unique rows each, and
    base==overlay identity (the report's reviewed Java/class identity).
    """
    _require(platform in COMPANION_PINS, "companion",
             "no reviewed companion-map pins for platform " + repr(platform))
    pins = COMPANION_PINS[platform]
    collection = Path(collection).resolve()
    index_path = collection / "COLLECTION-FILES.json"
    _require(index_path.is_file(), "companion", "collection file index missing")
    index = _load(index_path, "companion")
    entries = index.get("files")
    _require(isinstance(entries, dict), "companion", "collection index shape changed")
    maps: dict[str, dict[str, str]] = {}
    for name in COMPANION_MAPS:
        rel = "derived-codegen-maps/" + name + ".sha256"
        _require(rel in entries, "companion", f"derived map missing from index: {name}")
        path = collection / rel
        _require(path.is_file(), "companion", f"derived map missing: {name}")
        digest = _sha(path)
        _require(digest == entries[rel].get("sha256"), "companion",
                 f"derived map digest changed: {name}")
        _require(digest == pins[name], "companion",
                 f"derived map digest is not the reviewed {platform} pin: {name}")
        rows: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            parts = line.split(" ")
            _require(len(parts) == 2 and parts[0] and _SHA.fullmatch(parts[1]) is not None,
                     "companion", f"malformed derived map row: {name}")
            _require(parts[0] not in rows, "companion", f"duplicate derived map path: {name}")
            rows[parts[0]] = parts[1]
        _require(len(rows) == EXPECTED["jdk_classes"], "companion",
                 f"derived map row count changed: {name}={len(rows)}")
        maps[name] = rows
    _require(maps["java-base"] == maps["java-overlay"], "companion",
             "derived Java base/overlay identity changed")
    for major in ("21", "25"):
        _require(maps["classes-base-jdk" + major] == maps["classes-overlay-jdk" + major],
                 "companion", f"derived JDK{major} class base/overlay identity changed")
    return {"maps": sorted(maps), "rows": {name: len(rows) for name, rows in maps.items()},
            "java_identity": True, "class_identity": {"21": True, "25": True},
            "label": "DERIVED by Root from actual codegen output; not producer-recorded"}


def validate_current_inputs(workspace_root: Path, platform: str | None = None) -> dict[str, Any]:
    """Validate only the current workspace inputs (no report/logs needed)."""
    if platform is not None:
        _require(platform in PROFILE_PINS, "profile", "unknown reviewed platform " + repr(platform))
    return _validate_current_inputs(Path(workspace_root), platform)


def validate_select_source(report_path: Path, *, workspace_root: Path, platform: str,
                           evidence_root: Path | None = None,
                           expected_mode: str = "full",
                           companion_collection: Path | None = None) -> dict[str, Any]:
    """Admit a *tracked* final FULL report against the current workspace.

    ``workspace_root`` supplies the current 85 candidate Dafny files, the strict
    Select package and the reviewed profile files.  ``evidence_root`` (default the
    report's directory) supplies every report-relative log and nested retained
    report.  Producer roots/tool paths are provenance strings only and are never
    opened; no baseline tree, tool, cache or ``.git`` is read.
    """
    _require(expected_mode == "full", "report", "only full qualification is supported")
    _require(platform in PROFILE_PINS, "profile", "unknown reviewed platform " + repr(platform))
    facts = _validate_current_inputs(Path(workspace_root), platform)
    report_path = Path(report_path).resolve()
    _require(report_path.is_file(), "report", "report file is missing")
    evidence_root = (Path(evidence_root) if evidence_root else report_path.parent).resolve()
    _require(evidence_root.is_dir(), "layout", "evidence root is missing")
    report = _load(report_path, "report")
    result = _validate_report(report, evidence_root, facts, platform)
    if companion_collection is not None:
        result["companion_maps"] = validate_companion_maps(Path(companion_collection), platform)
    result["report_sha256"] = _sha(report_path)
    result["input_counts"] = {"baseline_dafny": PACKAGE_PINS["dafny_files"],
                              "dafny": PACKAGE_PINS["dafny_files"],
                              "package": PACKAGE_PINS["package_files"] + 2,
                              "used_inputs": len(USED_INPUTS)}
    return result


def validate_supported_select_claim(*, macos, linux, workspace_root: Path) -> dict[str, Any]:
    """Claim wrapper: BOTH reviewed platforms and their companion collections.

    A report-only weaker result is never accepted as the supported claim: every
    backend must supply a report and a curated companion collection, and the
    reviewed profile/package/companion pins must hold for each.
    """
    results: dict[str, Any] = {}
    for platform, value in (("macos-arm64", macos), ("linux-x64", linux)):
        report, collection = value
        _require(report is not None and collection is not None, "claim",
                 f"{platform} report and companion collection are both mandatory")
        _require(Path(collection).is_dir(), "claim",
                 f"{platform} companion collection is missing: {collection}")
        results[platform] = validate_select_source(
            Path(report), workspace_root=Path(workspace_root), platform=platform,
            companion_collection=Path(collection))
    return results


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Validate a final Select FULL report.")
    parser.add_argument("--report", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--platform", required=True, choices=BACKENDS)
    parser.add_argument("--evidence-root", default=None)
    parser.add_argument("--companion-collection", default=None)
    args = parser.parse_args(argv)
    try:
        result = validate_select_source(Path(args.report), workspace_root=Path(args.workspace),
                                        platform=args.platform,
                                        evidence_root=Path(args.evidence_root)
                                        if args.evidence_root else None,
                                        companion_collection=Path(args.companion_collection)
                                        if args.companion_collection else None)
    except SelectGateError as error:
        print(json.dumps({"status": "REJECTED", "reason": str(error)}, indent=2))
        return 2
    print(json.dumps({"status": "ACCEPTED", **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
