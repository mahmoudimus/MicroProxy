#!/usr/bin/env python3
"""Replay the HKDF direct-source ghost-trace proofs, coverage gate and Java identity.

This runner is intentionally fail-closed.  It pins every source it reads, runs the
pinned Dafny 4.9.1 with the canonical 30 s / 50 M / case_split=0 budget, audits
every file in the proof closure (Dafny audit does not traverse includes), builds
and runs the trusted resolved-AST coverage checker, executes genuine negative
controls, and compares committed production Java against fresh instrumented translation
at the same source basename.

Trust boundaries are explicit: the Dafny verifier, the pinned compiler's ghost
erasure, the C# checker, javac/JVM and the JCE provider are trusted.  This is a
source-level observation result, not a JVM-timing, compiler-refinement,
cryptographic-hardness or whole-crypto-source-trace proof.
"""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
P = HERE.parents[2]
DAFNY_DIR = P / "formal/dafny"
DELIVERY = P / "formal/crypto/delivery.py"

FLAGS = [
    "--allow-external-contracts",
    "--verification-time-limit", "30",
    "--resource-limit", "50000000",
    "--cores", "2",
    "--solver-option", "O:smt.case_split=0",
]
OUTER_MODULE = "io.github.mahmoudimus.quic.internal.verifiedhkdf"
OUTPUT_NAME = "HkdfCrypto"
PACKAGE = Path(*OUTER_MODULE.split(".")) / "VerifiedHkdf"
INSTRUMENTED = P / "formal/dafny/hkdf/Hkdf.dfy"
HARNESS = P / "formal/source/hkdf/HkdfTrace.dfy"
JAVA_PRODUCTION = P / "quic/src/main/java"
FIXTURE_AGGREGATOR = P / "formal/source/hkdf/fixtures/HkdfCrypto.java"
DECLARATIONS = P / "formal/source/hkdf/declarations.txt"
CHECKER_CS = P / "formal/source/hkdf/checker/HkdfCoverage.cs"
CHECKER_CSPROJ = P / "formal/source/hkdf/checker/HkdfCoverage.csproj"
AUDIT_EXPECTED = {
    "formal/dafny/hkdf/Hkdf.dfy": 1,
    "formal/source/hkdf/HkdfTrace.dfy": 0,
}
REVIEWER_CONTROLS = {
    "golden-before": "later trace update must append to the same actual trace prefix",
    "golden-empty": "later trace update must append to the same actual trace prefix",
    "golden-overwrite": "later trace update must append to the same actual trace prefix",
    "golden-empty-before2": "later trace update must append to the same actual trace prefix",
    "shadow-fake": "local/shadow trace variable",
    "shadow-marker-call": "unobserved compiled function call",
    "pattern-call": "unobserved compiled function call",
    "expect-ite-guarded": "unsupported executable statement ExpectStmt",
    "print-secret-index": "unsupported executable statement PrintStmt",
}
REVIEWER_DIR = P / "formal/source/hkdf/controls/reviewer"
REREVIEW_CONTROLS = {
    "callee-order": "callee ghost trace append is not the first trace update",
    "shadow-class-compilefalse": "reserved root name outside exact VerifiedHkdf._default method",
    "shadow-marker-map": "reserved marker name outside exact VerifiedHkdf._default ghost declaration",
    "datatype-eq2": "unsupported executable equality/order on non-scalar operand type",
    "target-overflow": "marker integer is outside supported 32-bit range",
}
REREVIEW_DIR = P / "formal/source/hkdf/controls/rereview"
THIRD_CONTROLS = {
    "callee-dup": ("duplicate callee ghost output binding", 249, 260),
    "expdup": ("duplicate callee ghost output binding", 248, 259),
}
THIRD_DIR = P / "formal/source/hkdf/controls/third"
SUMMARY = re.compile(r"Dafny program verifier finished with (\d+) verified, (\d+) errors?")
AUDIT = re.compile(r"Dafny auditor completed with (\d+) findings")
BAD_RUN = re.compile(r"timed?\s*out|out of resource|out of memory|internal error|unhandled exception|pars(?:e|er) error|CLI: Error", re.I)


class GateError(RuntimeError):
    pass


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command, log, timeout=300, cwd=None, env=None):
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        try:
            result = subprocess.run([str(c) for c in command], cwd=cwd or P,
                                    stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=timeout, env=env)
            rc = result.returncode
        except subprocess.TimeoutExpired:
            stream.write("\nRUNNER TIMEOUT\n")
            rc = 124
    return rc, log.read_text(errors="replace")


def summary(text):
    found = SUMMARY.findall(text)
    if len(found) != 1:
        raise GateError("expected exactly one Dafny verification summary")
    return int(found[0][0]), int(found[0][1])


def require_verified(rc, text, minimum, label, exact=None):
    if BAD_RUN.search(text):
        raise GateError(label + ": tool/resource/parse failure is not a proof: " + BAD_RUN.search(text).group(0))
    verified, errors = summary(text)
    if rc != 0 or errors != 0 or verified < minimum or (exact is not None and verified != exact):
        want = f"exactly {exact}" if exact is not None else f">= {minimum}"
        raise GateError(f"{label}: expected {want} verified and 0 errors, got {verified}/{errors} rc={rc}")
    return {"verified": verified, "errors": errors}


def require_assertion_failure(rc, text, label, named="assert t1 == t2"):
    if BAD_RUN.search(text):
        raise GateError(label + ": timeout/resource/parse failure is not a genuine assertion control")
    verified, errors = summary(text)
    if rc != 4 or errors == 0 or "assertion might not hold" not in text or named not in text:
        raise GateError(label + f": expected a genuine Dafny assertion failure at {named!r}")
    return {"verified": verified, "errors": errors, "classification": "dafny-assertion-failure", "named": named}


def require_checker_rejection(rc, text, needle, label):
    if BAD_RUN.search(text):
        raise GateError(label + ": checker failure was a tool/parse failure, not a coverage rejection")
    if rc != 2 or needle not in text:
        raise GateError(f"{label}: expected checker rejection containing {needle!r}, rc={rc}")
    return {"classification": "resolved-ast-coverage-rejection", "needle": needle}


def require_named_proof_failure(rc, text, needle, label):
    if BAD_RUN.search(text):
        raise GateError(label + ": tool/resource/parse failure is not a metadata proof counterexample")
    verified, errors = summary(text)
    proof_failure = ("postcondition could not be proved" in text or "assertion might not hold" in text)
    if rc != 4 or errors == 0 or needle not in text or not proof_failure:
        raise GateError(label + f": expected a named Dafny proof failure containing {needle!r}")
    return {"classification": "dafny-metadata-proof-failure", "needle": needle,
            "verified": verified, "errors": errors}


def audit_file(dafny, path, log, expected, display=None):
    rc, text = run([dafny, "audit", path, "--allow-external-contracts"], log)
    findings = AUDIT.findall(text)
    if rc != 0 or len(findings) != 1 or int(findings[0]) != expected:
        raise GateError(f"audit {display or path.name}: expected {expected} findings, got {findings} rc={rc}")
    return {"file": display or path.name, "findings": expected}


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise GateError(f"mutation anchor changed: {label} (count={text.count(old)})")
    return text.replace(old, new, 1)


def write_mutant_harness(folder, harness_source=HARNESS):
    text = harness_source.read_text().replace('include "../../dafny/hkdf/Hkdf.dfy"', 'include "Hkdf.dfy"')
    (folder / "HkdfTrace.dfy").write_text(text)


def binding_mutants(base_text, root, harness_source=HARNESS):
    """Actual-source probes for binding syntax outside ordinary assignment.

    In particular, the first mutant used to pass both complete Dafny proofs
    and the coverage checker while dropping a real callee's observations.
    """
    anchor = "    trace := trace + encTrace;"
    assertion = "    assert encTrace == LabelInfoTrace(labelUnits, |context|, length);\n"
    erased = replace_once(base_text,
        "EvCall(5, 3, 3) + LabelInfoTrace(labelUnits, contextLen, length) +",
        "EvCall(5, 3, 3) +", "callee-suchthat-model-erasure-model")
    erased = replace_once(erased, assertion, "", "callee-suchthat-model-erasure-assert")
    erased = replace_once(erased, anchor, "    encTrace :| encTrace == [];\n" + anchor,
                          "callee-suchthat-model-erasure-binding")
    suchthat = "unsupported ghost statement AssignSuchThatStmt in HKDF binding grammar"
    ghost_call = "ghost call output binding is unsupported in HKDF binding grammar"
    lemma = ("  lemma ResetTrace() returns (t: seq<int>)\n"
             "    ensures t == []\n"
             "  { t := []; }\n")
    with_lemma = replace_once(base_text, "module VerifiedHkdf {\n",
                              "module VerifiedHkdf {\n" + lemma, "binding-lemma")
    cases = {
        "callee-suchthat-model-erasure": (suchthat, erased),
        "callee-suchthat-same-model": (suchthat, replace_once(base_text, anchor,
            "    encTrace :| encTrace == LabelInfoTrace(labelUnits, |context|, length);\n" + anchor,
            "callee-suchthat-same-model")),
        "trace-suchthat-reset": (suchthat, replace_once(base_text, anchor,
            anchor + "\n    trace :| trace == [];", "trace-suchthat-reset")),
        "nested-callee-suchthat": (suchthat, replace_once(base_text, anchor,
            "    if true { encTrace :| encTrace == []; }\n" + anchor,
            "nested-callee-suchthat")),
        "ghost-call-callee-binding": (ghost_call, replace_once(with_lemma, anchor,
            "    encTrace := ResetTrace();\n" + anchor, "ghost-call-callee-binding")),
        "ghost-call-trace-binding": (ghost_call, replace_once(with_lemma, anchor,
            anchor + "\n    trace := ResetTrace();", "ghost-call-trace-binding")),
        "actual-call-trace-binding": ("actual trace output cannot be rebound by a call",
            replace_once(base_text, anchor, anchor +
                "\n    encoded, trace := LabelInfo(labelUnits, context, length);",
                "actual-call-trace-binding")),
        "statement-expression": ("unsupported statement expression in HKDF binding grammar",
            replace_once(base_text, anchor, anchor +
                "\n    assert (LabelInfoShape(labelUnits, context, length); true);",
                "statement-expression")),
    }
    for name, (_, text) in cases.items():
        folder = root / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "Hkdf.dfy").write_text(text)
        write_mutant_harness(folder, harness_source)
    return {name: needle for name, (needle, _) in cases.items()}


def checker_mutants(base_text, root, harness_source=HARNESS):
    root.mkdir(parents=True, exist_ok=True)
    out = {}

    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var key := salt;\n    if |ikm| > 0 && ikm[0] == 0 {\n      key := key;\n    }\n    trace := trace + EvBranch(5, |key| == 0);",
        "unmarked-secret-branch")
    out["unmarked-secret-branch"] = ("if guard: observation count", text)

    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var key := salt;\n    var leaked := ikm[0];\n    trace := trace + EvBranch(5, |key| == 0);",
        "unmarked-secret-read")
    out["unmarked-secret-read"] = ("sequence read source is not the method's formal labelUnits", text)
    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var q := salt == ikm;\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "seqeq-private")
    out["seqeq-private"] = ("unsupported executable sequence/collection comparison operator", text)

    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var key := salt;\n    trace := trace + EvRead(99, 0);\n    trace := trace + EvBranch(5, |key| == 0);",
        "stale-marker")
    out["stale-marker"] = ("unmatched marker", text)

    text = replace_once(base_text,
        "module VerifiedHkdf {\n  datatype FailureKind",
        "module VerifiedHkdf {\n  module ShadowHkdf {\n    function ValidHash(hashLen: int): bool { hashLen in {32, 48, 64} }\n  }\n  datatype FailureKind",
        "shadow-callee-module")
    text = replace_once(text,
        "    if !ValidHash(hashLen) {\n      trace := trace + EvCreate(3, 20, 0) + EvCreate(4, 11, 0);\n      r := Failure(InvalidHash); return;\n    }\n    var key := salt;",
        "    if !ShadowHkdf.ValidHash(hashLen) {\n      trace := trace + EvCreate(3, 20, 0) + EvCreate(4, 11, 0);\n      r := Failure(InvalidHash); return;\n    }\n    var key := salt;",
        "shadow-callee-call")
    out["shadow-callee"] = ("unobserved compiled function call", text)

    text = replace_once(base_text,
        "    var ascii: seq<bv8> := [];\n    var i := 0;",
        "    var ascii: seq<bv8> := [];\n    var other := labelUnits;\n    var i := 0;",
        "array-shadow-local")
    text = replace_once(text,
        "      trace := trace + EvRead(14, i) + EvAlloc(15, 1) + EvConcat(16, |ascii|, |[labelUnits[i] as bv8]|);\n      ascii := ascii + [labelUnits[i] as bv8];",
        "      trace := trace + EvRead(25, i);\n      if other[i] > 127 { ascii := ascii; }\n      trace := trace + EvRead(14, i) + EvAlloc(15, 1) + EvConcat(16, |ascii|, |[labelUnits[i] as bv8]|);\n      ascii := ascii + [labelUnits[i] as bv8];",
        "array-shadow-read")
    out["array-shadow"] = ("sequence read source is not the method's formal labelUnits", text)

    text = replace_once(base_text,
        "      trace := trace + EvRead(14, i) + EvAlloc(15, 1) + EvConcat(16, |ascii|, |[labelUnits[i] as bv8]|);\n      ascii := ascii + [labelUnits[i] as bv8];",
        "      trace := trace + EvRead(14, i) + EvAlloc(15, 1) + EvConcat(16, |ascii|, |[labelUnits[i] as bv8]|);\n      var dummy := i;\n      dummy := dummy;\n      ascii := ascii + [labelUnits[i] as bv8];",
        "interposed-assignment")
    out["interposed-assignment"] = ("observation count", text)
    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    if |ikm| == 0 {\n      trace := trace + EvRead(98, 0);\n    }\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "ghost-if-marker")
    out["ghost-if-marker"] = ("trace assignment inside ghost control flow", text)
    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var badCall := ValidHash(hashLen);\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "unmarked-call")
    out["unmarked-call"] = ("observation count", text)

    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var badAlloc := [0 as bv8];\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "unmarked-alloc")
    out["unmarked-alloc"] = ("observation count", text)

    text = replace_once(base_text,
        " + EvMac(7, 1, hashLen, |key|, |ikm|, hashLen)",
        "", "omitted-mac-observer")
    out["omitted-mac-observer"] = ("observation count", text)
    text = replace_once(base_text,
        "module VerifiedHkdf {\n  datatype FailureKind",
        "module VerifiedHkdf {\n  function IdentityProbe(v: bv64): (bv64, ghost seq<int>) {\n    (v, ghost [])\n  } by method {\n    if v == 0 {\n      return (v | v, ghost []);\n    } else {\n      return (v, ghost []);\n    }\n  }\n  datatype FailureKind",
        "by-method-helper")
    out["by-method-helper"] = ("unsupported by-method function", text)

    text = replace_once(base_text,
        "    assert length <= n * hashLen;\n    var i := 0;",
        "    assert length <= n * hashLen;\n    var i := 0;\n    if length > 0 { i := 0; }",
        "loop-init-conditional")
    out["loop-init-conditional"] = ("loop initializer is not an unconditional same-block definition", text)

    text = replace_once(base_text,
        "    var encoded, {:ghost} encTrace := LabelInfo(labelUnits, context, length);\n    trace := trace + encTrace;\n    assert encTrace == LabelInfoTrace(labelUnits, |context|, length);\n    LabelInfoShape(labelUnits, context, length);\n    trace := trace + EvBranch(6, encoded.Success?);",
        "    var encoded, {:ghost} encTrace := LabelInfo(labelUnits, context, length);\n    assert encTrace == LabelInfoTrace(labelUnits, |context|, length);\n    LabelInfoShape(labelUnits, context, length);\n    trace := trace + EvBranch(6, encoded.Success?);\n    trace := trace + encTrace;",
        "callee-order-encTrace")
    out["callee-order-encTrace"] = ("callee ghost trace append is not the first trace update", text)

    text = replace_once(base_text,
        "        r, expTrace := Expand(hashLen, secret, info, length);\n        trace := trace + expTrace;",
        "        r, expTrace := Expand(hashLen, secret, info, length);\n        trace := trace + EvBranch(99, true);\n        trace := trace + expTrace;",
        "callee-order-expTrace")
    out["callee-order-expTrace"] = ("callee ghost trace append is not the first trace update", text)

    if base_text.count("EvBranch(2,") < 1:
        raise GateError("site-label-collision anchor missing")
    text = base_text.replace("EvBranch(2,", "EvBranch(5,")
    out["site-label-collision"] = ("duplicate site label", text)

    old_nonliteral = "    trace := trace + EvCall(1, 2, 1) + EvBranch(2, !ValidHash(hashLen));\n    if !ValidHash(hashLen) {\n      trace := trace + EvCreate(3, 20, 0) + EvCreate(4, 11, 0);\n      r := Failure(InvalidHash); return;\n    }\n    var key := salt;"
    new_nonliteral = "    trace := trace + EvCall(1, 2, 1) + EvBranch(1+1, !ValidHash(hashLen));\n    if !ValidHash(hashLen) {\n      trace := trace + EvCreate(3, 20, 0) + EvCreate(4, 11, 0);\n      r := Failure(InvalidHash); return;\n    }\n    var key := salt;"
    text = replace_once(base_text, old_nonliteral, new_nonliteral, "site-label-nonliteral")
    out["site-label-nonliteral"] = ("site label must be an integer literal", text)

    text = replace_once(base_text,
        "    trace := trace + EvBranch(5, |key| == 0);\n    if |key| == 0 {",
        "    trace := trace + EvBranch(5, |key| == 0);\n    { var dummy := 0; dummy := dummy; }\n    if |key| == 0 {",
        "block-boundary-pending")
    out["block-boundary-pending"] = ("pending observations at standalone block boundary", text)

    text = replace_once(base_text,
        "    trace := trace + EvMac(7, 1, hashLen, |key|, |ikm|, hashLen) + EvCreate(8, 10, |Mac(hashLen, key, ikm)|);\n    r := Success(Mac(hashLen, key, ikm));",
        "    trace := trace + EvMac(7, 1, hashLen, |key|, |ikm|, hashLen) + EvCreate(8, 10, |Mac(hashLen, key, ikm)|);\n    trace := ExtractTrace(hashLen, |salt|, |ikm|);\n    r := Success(Mac(hashLen, key, ikm));",
        "synthetic-golden-trace")
    out["synthetic-golden-trace"] = ("later trace update must append to the same actual trace prefix", text)

    text = replace_once(base_text,
        "    r := Success(Mac(hashLen, key, ikm));\n  }",
        "    r := Success(Mac(hashLen, key, ikm));\n    trace := [];\n  }",
        "reset-empty-trace")
    out["reset-empty-trace"] = ("later trace update must append to the same actual trace prefix", text)

    text = replace_once(base_text,
        "    trace := trace + EvBranch(5, |key| == 0);\n    if |key| == 0 {\n      trace := trace + EvAlloc(6, hashLen);\n      key := seq(hashLen, i => 0 as bv8);\n    }",
        "    trace := trace + EvBranch(5, |key| == 0);\n    {\n      ghost var trace: seq<int>;\n      trace := [];\n      if |key| == 0 {\n        trace := trace + EvAlloc(6, hashLen);\n        key := seq(hashLen, i => 0 as bv8);\n      }\n    }",
        "local-shadow-trace")
    out["local-shadow-trace"] = ("local/shadow trace variable", text)

    text = replace_once(base_text,
        "module VerifiedHkdf {\n  datatype FailureKind",
        "module VerifiedHkdf {\n  module ShadowEv {\n    function EvBranch(id: int, s: seq<bv8>): int {\n      if |s| > 0 && s[0] == 0 then 1 else 0\n    }\n  }\n  datatype FailureKind",
        "shadow-marker-module")
    text = replace_once(text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var q := ShadowEv.EvBranch(0, ikm);\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "shadow-marker-call")
    out["shadow-marker-call"] = ("unobserved compiled function call", text)

    text = replace_once(base_text,
        "module VerifiedHkdf {\n  datatype FailureKind",
        "module VerifiedHkdf {\n  function Split(s: seq<bv8>): (int, int) {\n    (if |s| > 0 && s[0] == 0 then 1 else 0, |s|)\n  }\n  datatype FailureKind",
        "pattern-call-function")
    text = replace_once(text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    var (a, b) := Split(ikm);\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "pattern-call")
    out["pattern-call"] = ("unobserved compiled function call", text)

    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    expect |ikm| == 0 || (if ikm[0] == 0 then true else true);\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "expect-secret-branch")
    out["expect-secret-branch"] = ("unsupported executable statement ExpectStmt", text)

    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    print (if |ikm| == 0 then 0 else ikm[(ikm[0] as int) % |ikm|]);\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "print-secret-index")
    out["print-secret-index"] = ("unsupported executable statement PrintStmt", text)

    text = replace_once(base_text,
        "    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "    match Success([ikm[0]]) {\n      case Success(b) => r := r;\n      case Failure(reason) => r := r;\n    }\n    var key := salt;\n    trace := trace + EvBranch(5, |key| == 0);",
        "match-source-secret")
    out["match-source-secret"] = ("sequence read source is not the method's formal labelUnits", text)

    text = replace_once(base_text,
        "    assert length <= n * hashLen;\n    var i := 0;",
        "    assert length <= n * hashLen;\n    var i := 1;",
        "loop-start-mismatch")
    out["loop-start-mismatch"] = ("does not match executable event", text)

    text = replace_once(base_text,
        "      previous := next;\n      i := i + 1;",
        "      previous := next;\n      i := i + 0;",
        "loop-increment-mismatch")
    out["loop-increment-mismatch"] = ("loop increment must be loopVar", text)

    text = replace_once(base_text,
        "    trace := trace + EvLoopExit(23, i, n);\n",
        "",
        "loop-exit-missing")
    out["loop-exit-missing"] = ("missing post-loop false-guard observation", text)

    text = replace_once(base_text,
        "    trace := trace + EvLoopExit(23, i, n);",
        "    trace := trace + EvLoopExit(23, 0, n);",
        "loop-exit-wrong-index")
    out["loop-exit-wrong-index"] = ("EvLoopExit index does not match", text)

    for name, (needle, text) in out.items():
        folder = root / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "Hkdf.dfy").write_text(text)
        if name == "block-boundary-pending":
            write_mutant_harness(folder, harness_source)
    return {name: needle for name, (needle, _) in out.items()}


METADATA_ENCODERS = {
    "metadata-branch-erases-boolean": "EvBranch",
    "metadata-branch-erases-one-id": "EvBranch",
    "metadata-read-erases-address": "EvRead",
    "metadata-mac-erases-target": "EvMac",
    "metadata-mac-erases-lengths": "EvMac",
    "metadata-call-erases-arity": "EvCall",
    "metadata-ops-erases-shift": "EvOps",
}


def metadata_command(dafny, source, control):
    encoder = METADATA_ENCODERS.get(control)
    if encoder is None:
        raise GateError("unknown metadata control: " + control)
    # A trailing dot is Dafny 4.9.1's exact-symbol suffix syntax. In particular,
    # EvBranchInjective and unrelated LabelScan lemmas are not selected.
    return [dafny, "verify", source, "--filter-symbol", "VerifiedHkdf." + encoder + ".",
            "--progress", "Symbol", *FLAGS]


def metadata_mutants(base_text, root):
    root.mkdir(parents=True, exist_ok=True)
    out = {}
    text = replace_once(base_text,
        "  { [10,id,if taken then 1 else 0] }",
        "  { [10,id,0] }", "metadata-branch-erases-boolean")
    out["metadata-branch-erases-boolean"] = ("MetadataEvBranchBoolean", text)

    text = replace_once(base_text,
        "  { [10,id,if taken then 1 else 0] }",
        "  { if id == 777 then [10,id,0] else [10,id,if taken then 1 else 0] }",
        "metadata-branch-erases-one-id")
    out["metadata-branch-erases-one-id"] = ("MetadataEvBranchBoolean", text)

    text = replace_once(base_text,
        "  { [12,id,addr] }",
        "  { [12,id,0] }", "metadata-read-erases-address")
    out["metadata-read-erases-address"] = ("MetadataEvReadAddress", text)

    text = replace_once(base_text,
        "  { [14,id,target,alg,keyLen,inputLen,outLen] }",
        "  { [14,id,0,alg,keyLen,inputLen,outLen] }", "metadata-mac-erases-target")
    out["metadata-mac-erases-target"] = ("MetadataEvMacTarget", text)

    text = replace_once(base_text,
        "  { [14,id,target,alg,keyLen,inputLen,outLen] }",
        "  { [14,id,target,alg,0,0,outLen] }", "metadata-mac-erases-lengths")
    out["metadata-mac-erases-lengths"] = ("MetadataEvMacKeyLen", text)

    text = replace_once(base_text,
        "  { [13,id,target,arity] }",
        "  { [13,id,target,0] }", "metadata-call-erases-arity")
    out["metadata-call-erases-arity"] = ("MetadataEvCallArity", text)

    text = replace_once(base_text,
        "  { [19,add,sub,mul,div,mod,bit,shift] }",
        "  { [19,add,sub,mul,div,mod,bit,0] }", "metadata-ops-erases-shift")
    out["metadata-ops-erases-shift"] = ("MetadataEvOpsShift", text)

    for name, (needle, text) in out.items():
        folder = root / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "Hkdf.dfy").write_text(text)
    return {name: needle for name, (needle, _) in out.items()}


def accept_mutants(base_text, root, harness_source=HARNESS):
    root.mkdir(parents=True, exist_ok=True)
    if base_text.count("EvBranch(2,") < 1:
        raise GateError("site-relabel-accept anchor missing")
    folder = root / "site-relabel-accept"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "Hkdf.dfy").write_text(base_text.replace("EvBranch(2,", "EvBranch(99,"))
    write_mutant_harness(folder, harness_source)
    return folder


def observed_mutants(base_text, root, harness_source=HARNESS):
    root.mkdir(parents=True, exist_ok=True)
    out = {}

    # Observed secret branch: the trace postcondition is extended so the real
    # method still verifies, while two different private IKM contents must make
    # the two-run trace assertion fail.
    text = replace_once(base_text,
        "  ghost function ExtractTrace(hashLen: int, saltLen: int, ikmLen: int): seq<int> {",
        "  ghost function SecretBranch(hashLen: int, salt: seq<bv8>, ikm: seq<bv8>): seq<int> {\n"
        "    if |ikm| > 0 && ikm[0] == 0 then EvBranch(100, true) else EvBranch(100, false)\n"
        "  }\n\n  ghost function ExtractTrace(hashLen: int, saltLen: int, ikmLen: int): seq<int> {",
        "observed-secret-branch-function")
    text = replace_once(text,
        "    ensures trace == ExtractTrace(hashLen, |salt|, |ikm|)\n  {",
        "    ensures trace == ExtractTrace(hashLen, |salt|, |ikm|) +\n      (if ValidHash(hashLen) then SecretBranch(hashLen, salt, ikm) else [])\n  {",
        "observed-secret-branch-post")
    text = replace_once(text,
        "    r := Success(Mac(hashLen, key, ikm));\n  }",
        "    r := Success(Mac(hashLen, key, ikm));\n"
        "    if |ikm| > 0 && ikm[0] == 0 {\n"
        "      trace := trace + EvBranch(100, true);\n"
        "    } else {\n"
        "      trace := trace + EvBranch(100, false);\n"
        "    }\n  }",
        "observed-secret-branch-body")
    out["observed-secret-branch"] = text

    # Observed secret index and metadata-dependent private allocation.
    for name, event in (
        ("observed-secret-index", "EvRead(101, (ikm[0] as int) % hashLen)"),
        ("observed-secret-metadata", "EvAlloc(102, ikm[0] as int)"),
    ):
        t = replace_once(base_text,
            "  ghost function ExtractTrace",
            "  ghost function SecretObs(hashLen: int, ikm: seq<bv8>): seq<int> {\n"
            f"    if ValidHash(hashLen) && |ikm| > 0 then {event} else []\n"
            "  }\n\n  ghost function ExtractTrace",
            name + "-function")
        t = replace_once(t,
            "    ensures trace == ExtractTrace(hashLen, |salt|, |ikm|)\n  {",
            "    ensures trace == ExtractTrace(hashLen, |salt|, |ikm|) + SecretObs(hashLen, ikm)\n  {",
            name + "-post")
        t = replace_once(t,
            "    r := Success(Mac(hashLen, key, ikm));\n  }",
            "    r := Success(Mac(hashLen, key, ikm));\n"
            "    if |ikm| > 0 {\n"
            f"      trace := trace + {event};\n"
            "    }\n  }",
            name + "-body")
        out[name] = t

    for name, text in out.items():
        folder = root / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "Hkdf.dfy").write_text(text)
        write_mutant_harness(folder, harness_source)
    return list(out)



def main(argv=None):
    """Authenticate the externally selected portable package before any import."""
    if sys.flags.optimize:
        raise GateError('Python optimization is not supported for HKDF replay')
    argv = sys.argv[1:] if argv is None else argv
    bootstrap = argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument('--manifest', type=Path, required=True)
    bootstrap.add_argument('--expected-manifest', required=True)
    args, _ = bootstrap.parse_known_args(argv)
    if not re.fullmatch('[0-9a-f]{64}', args.expected_manifest):
        raise GateError('expected manifest must be an externally selected SHA256')
    def raw(path):
        path = Path(path).absolute()
        cursor = Path(path.anchor)
        for part in path.parts[1:]:
            cursor /= part
            if cursor.is_symlink():
                raise GateError('symlink input component: ' + str(cursor))
        return path.read_bytes()
    manifest_raw = raw(args.manifest)
    if hashlib.sha256(manifest_raw).hexdigest() != args.expected_manifest:
        raise GateError('externally selected manifest hash mismatch')
    data = json.loads(manifest_raw)
    if data.get('schema') != 'microproxy.hkdf-source-traces-inputs/v2':
        raise GateError('unsupported HKDF manifest schema')
    for name, pin in data['inputs'].items():
        rel = Path(name)
        if rel.is_absolute() or '..' in rel.parts or '\\' in name:
            raise GateError('noncanonical manifest input')
        if hashlib.sha256(raw(P / rel)).hexdigest() != pin:
            raise GateError('authenticated input mismatch: ' + name)
    # Compile the exact captured source, bypassing .pyc even if a poisoned cache
    # has valid mtime/size. Restore the prior module on failed execution.
    path = HERE / 'tooling/admission.py'
    captured = raw(path)
    if hashlib.sha256(captured).hexdigest() != data['inputs']['formal/source/hkdf/tooling/admission.py']:
        raise GateError('admission helper changed')
    name = 'hkdf_portable_admission'
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(captured, str(path), 'exec'), module.__dict__)
    except BaseException:
        if previous is None: sys.modules.pop(name, None)
        else: sys.modules[name] = previous
        raise
    module.authenticate(P, args.manifest, args.expected_manifest)
    replay = module.load_module('hkdf_portable_replay', HERE / 'replay.py',
                                 data['inputs']['formal/source/hkdf/replay.py'])
    return replay.main(argv, P, data, module)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, AssertionError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
