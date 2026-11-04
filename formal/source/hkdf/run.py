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


def snapshot(root, pattern="*.java"):
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob(pattern)) if p.is_file()}


def translate(dafny, source, folder, log):
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / "Hkdf.dfy"
    target.write_text(source.read_text())
    rc, text = run([dafny, "translate", "java", "--outer-module", OUTER_MODULE,
                    "--output", OUTPUT_NAME, "--no-verify", target.name], log, cwd=folder)
    if rc != 0 or BAD_RUN.search(text):
        raise GateError("Dafny Java translation failed: " + folder.name)
    generated = folder / f"{OUTPUT_NAME}-java"
    if not generated.is_dir():
        raise GateError("missing generated Java directory")
    return generated, generated / f"{OUTPUT_NAME}.java"


def find_jdk21():
    candidates = []
    if os.environ.get("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]))
    candidates += sorted(Path.home().glob(".sdkman/candidates/java/21*"))
    candidates += sorted(Path("/Library/Java/JavaVirtualMachines").glob("*21*"))
    for home in candidates:
        javac = home / "bin/javac"
        if javac.is_file():
            try:
                out = subprocess.check_output([str(javac), "-version"], stderr=subprocess.STDOUT, text=True)
                m = re.search(r"javac (\d+)", out)
                if m and int(m.group(1)) >= 21:
                    return home
            except subprocess.SubprocessError:
                pass
    raise GateError("a JDK 21+ is required for the Java ABI/inventory check")


def compile_java(javac, runtime, sources, classes, log):
    classes.mkdir(parents=True, exist_ok=True)
    rc, text = run([javac, "--release", "21", "-g:none", "-encoding", "UTF-8",
                    "-cp", str(runtime), "-d", str(classes)] + [str(s) for s in sources], log)
    if rc != 0 or text.strip():
        raise GateError("javac failed or emitted diagnostics: " + text[-4000:])


def class_inventory(classes):
    result = {}
    for p in sorted(classes.rglob("*.class")):
        result[str(p.relative_to(classes))] = digest(p)
    return result


def build_checker(dafny, work, checker_cs=CHECKER_CS, checker_csproj=CHECKER_CSPROJ):
    folder = work / "checker-build" / "src"
    folder.mkdir(parents=True, exist_ok=False)
    copied = {}
    for source in (checker_cs, checker_csproj):
        target = folder / source.name
        expected = digest(source)
        shutil.copyfile(source, target)
        if digest(target) != expected:
            raise GateError("copied checker input changed: " + source.name)
        copied[source.name] = expected
    env = os.environ.copy()
    env["DOTNET_CLI_HOME"] = str(folder.parent / "dotnet-home")
    env["NUGET_PACKAGES"] = str(folder.parent / "nuget")
    rc, sdk = run(["dotnet", "--version"], work / "checker-sdk.log", cwd=folder, env=env)
    if rc or not re.fullmatch(r"\d+\.\d+\.\d+\s*", sdk):
        raise GateError("cannot identify checker build SDK")
    command = ["dotnet", "build", "-v:q", "HkdfCoverage.csproj",
               "-p:DafnyHome=" + str(Path(dafny).parent),
               "-p:ImportDirectoryBuildProps=false", "-p:ImportDirectoryBuildTargets=false"]
    rc, text = run(command, work / "checker-build.log", cwd=folder, env=env)
    if rc:
        raise GateError("checker build failed: " + text[-4000:])
    for name, expected in copied.items():
        if digest(folder / name) != expected:
            raise GateError("checker build changed source: " + name)
    dll = folder / "bin/Debug/net6.0/HkdfCoverage.dll"
    if not dll.is_file():
        raise GateError("checker assembly missing")
    record = {"source_pins": copied, "sdk": sdk.strip(), "command": command,
              "assembly_sha256": digest(dll), "build_root": str(folder.parent),
              "directory_build_imports_disabled": True}
    (work / "checker-build.json").write_text(json.dumps(record, indent=2) + "\n")
    return dll


def inventory():
    # Only the owned HKDF closure is pinned.  The copied A/formal tree contains
    # unrelated worker files; they are deliberately not part of this proof
    # component and are not read by this runner.
    files = [
        P / "formal/dafny/hkdf/Hkdf.dfy",
        P / "formal/dafny/hkdf/GENERATED.json",
        HARNESS,
        CHECKER_CS,
        CHECKER_CSPROJ,
        HERE / "run.py",
        HERE / "test_run.py",
        HERE / "README.md",
        FIXTURE_AGGREGATOR,
        DECLARATIONS,
        P / "formal/dafny/tools.json",
        P / "formal/dafny/toolchain.py",
        DELIVERY,
    ]
    files += sorted((JAVA_PRODUCTION / PACKAGE).glob("*.java"))
    files += [JAVA_PRODUCTION / name for name in (
        "io/github/mahmoudimus/quic/Hkdf.java",
        "io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java",
        "io/github/mahmoudimus/verifiedcrypto/JdkHmac.java",
    )]
    files += [p for p in REVIEWER_DIR.rglob("*.dfy") if p.is_file()]
    files += [p for p in REREVIEW_DIR.rglob("*.dfy") if p.is_file()]
    files += [p for p in THIRD_DIR.rglob("*.dfy") if p.is_file()]
    return sorted(str(p.relative_to(P)) for p in files)


def pipeline(args, output, evidence):
    manifest = json.loads((HERE / "inputs.json").read_text())
    pins = manifest["inputs"]
    expected = set(pins)
    actual = set(inventory())
    if expected != actual:
        raise GateError("Proof input inventory changed; review before renewing pins: "
                        f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}")
    for name, expected_hash in pins.items():
        path = P / name
        if not path.is_file() or digest(path) != expected_hash:
            raise GateError("Input changed; review before renewing pin: " + name)

    # Freeze every pinned input before importing the pinned toolchain/delivery
    # modules.  The imports below come from the frozen copy, not from a mutable
    # working tree.
    frozen = output / "frozen"
    shutil.rmtree(frozen, ignore_errors=True)
    for name, expected_hash in pins.items():
        target = frozen / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(P / name, target)
        if digest(target) != expected_hash:
            raise GateError("Frozen input changed: " + name)
    sys.path.insert(0, str(frozen / "formal/dafny"))
    sys.path.insert(0, str(frozen / "formal/crypto"))
    import toolchain
    import delivery

    frozen_hkdf = frozen / "formal/dafny/hkdf/Hkdf.dfy"
    frozen_harness = frozen / "formal/source/hkdf/HkdfTrace.dfy"
    frozen_checker_cs = frozen / "formal/source/hkdf/checker/HkdfCoverage.cs"
    frozen_checker_csproj = frozen / "formal/source/hkdf/checker/HkdfCoverage.csproj"
    frozen_declarations = frozen / "formal/source/hkdf/declarations.txt"
    frozen_fixture = frozen / "formal/source/hkdf/fixtures/HkdfCrypto.java"
    frozen_reviewer = frozen / "formal/source/hkdf/controls/reviewer"
    frozen_java = frozen / "quic/src/main/java"

    dafny, runtime, tools, asset = toolchain.install(args.cache)
    rc, text = run([dafny, "--version"], evidence / "logs/dafny-version.log")
    if rc != 0 or not text.strip().startswith(tools["version"] + "+"):
        raise GateError("unexpected Dafny version: " + text.strip())

    def closure_call(label, command):
        return run(command, evidence / f"logs/closure-{label}.log", cwd=P)

    result = {
        "schema": "microproxy.hkdf-source-traces/v1",
        "status": "complete",
        "tool": {"name": "dafny", "version": text.strip(), "asset_sha256": asset["sha256"],
                 "runtime_sha256": digest(runtime)},
        "flags": FLAGS,
        "scope": {
            "proved": [
                "direct ghost observations on the actual VerifiedHkdf.Extract/Expand/LabelInfo/ExpandLabel bodies",
                "universal two-run trace equality under equal public hash length/lengths/label units",
                "arbitrary private salt/IKM/PRK/info/context byte contents and secret HMAC results",
                "existing functional Extract/Expand/LabelInfo/ExpandLabel postconditions retained",
            ],
            "checked_not_proved": [
                "trusted resolved-AST coverage checker over Dafny's official plugin AST",
                "actual trace out formal is initialized once and append-only, with exact callee ghost composition",
                "official Dafny include parser discovers and audits the full source closure",
                "generated Java package source identity against committed production and class/ABI inventory",
            ],
            "trusted_or_open": [
                "Dafny verifier, Boogie/Z3, Dafny compiler ghost erasure, javac, DafnyRuntime, JVM/JIT/CPU/GC",
                "JDK JCE HMAC provider correctness and physical timing",
                "Java adapter refinement, whole-crypto-source traces, cryptographic hardness, expert review",
                "coverage checker is trusted C# and is not formally verified",
                "HKDF private tags 10-21 are a scoped ghost trace, not the canonical typed vocabulary decoder",
                "existing historical 13/19/31 bytecode inventories are unchanged and not promoted here",
            ],
        },
        "audit": [], "positive": {}, "checker": {}, "controls": {},
        "java": {}, "inputs": pins,
    }

    # Positive proofs.
    rc, text = run([dafny, "verify", frozen_hkdf, *FLAGS], evidence / "logs/verify-hkdf.log")
    result["positive"]["hkdf_body"] = require_verified(rc, text, 248, "VerifiedHkdf body", exact=248)
    rc, text = run([dafny, "verify", frozen_harness, "--verify-included-files", *FLAGS], evidence / "logs/verify-harness.log")
    result["positive"]["harness_included"] = require_verified(rc, text, 259, "HkdfTrace harness + included bodies", exact=259)

    # Official Dafny parser discovery: audit every actual discovered source file.
    closure = delivery.source_closure(frozen, frozen_harness, dafny, call=closure_call)
    if set(closure) != set(AUDIT_EXPECTED):
        raise GateError("Unexpected Dafny source closure: " + repr(sorted(closure)))
    result["checker"]["source_closure"] = closure
    for name, expected_findings in AUDIT_EXPECTED.items():
        result["audit"].append(audit_file(dafny, frozen / name, evidence / f"logs/audit-{Path(name).stem}.log", expected_findings, name))

    # BOM/comment-inline include control: the official parser must discover the
    # hidden include, and explicit per-file audit must report its axiom.
    inc = output / "audit-control"
    inc.mkdir(parents=True, exist_ok=True)
    (inc / "BadIncluded.dfy").write_text("lemma {:axiom} BadAssumption()\n")
    (inc / "EntryBom.dfy").write_bytes(
        b"\xef\xbb\xbf// BOM and inline comment includes must be discovered by Dafny's parser\n"
        b'include "BadIncluded.dfy" // inline comment\n'
        b"lemma UseBad() { BadAssumption(); }\n")
    inc_closure = delivery.source_closure(inc, inc / "EntryBom.dfy", dafny, call=closure_call)
    if set(inc_closure) != {"EntryBom.dfy", "BadIncluded.dfy"}:
        raise GateError("BOM/comment-inline include escaped official closure discovery: " + repr(sorted(inc_closure)))
    rc, text = run([dafny, "audit", inc / "EntryBom.dfy", "--allow-external-contracts"],
                   evidence / "logs/audit-control-entry.log")
    entry_findings = AUDIT.findall(text)
    if rc != 0 or not entry_findings or int(entry_findings[0]) != 0:
        raise GateError("included-assumption control: entry audit unexpectedly traversed the include")
    result["controls"]["included-assumption-entry-audit"] = {"findings": 0,
        "meaning": "audit of EntryBom.dfy does not traverse the included file"}
    rc, text = run([dafny, "audit", inc / "BadIncluded.dfy", "--allow-external-contracts"],
                   evidence / "logs/audit-control-included.log")
    found = AUDIT.findall(text)
    if rc != 0 or not found or int(found[0]) < 1:
        raise GateError("included-assumption control: audit of the included file did not report the axiom")
    result["controls"]["included-assumption-file-audit"] = {"findings": int(found[0]),
        "meaning": "official parser discovered the BOM/comment-inline include; per-file audit caught the axiom"}

    # Checker build and positive run.
    checker = build_checker(dafny, output, frozen_checker_cs, frozen_checker_csproj)
    checker_sha = digest(checker)
    result["checker"]["build"] = json.loads((output / "checker-build.json").read_text())
    rc, text = run([dafny, "resolve", frozen_hkdf, "--allow-external-contracts", "--plugin", checker],
                   evidence / "logs/checker-hkdf.log")
    if rc != 0 or "HKDF-SOURCE-COVERAGE OK" not in text:
        raise GateError("positive coverage checker failed")
    result["checker"]["positive"] = "HKDF-SOURCE-COVERAGE OK"
    declarations = [line for line in text.splitlines() if line.startswith("HKDF-DECL ")]
    if declarations != frozen_declarations.read_text().splitlines():
        raise GateError("reviewed declaration inventory changed")
    result["checker"]["declarations"] = len(declarations)
    rc, text = run([dafny, "resolve", frozen_harness, "--allow-external-contracts", "--plugin", checker],
                   evidence / "logs/checker-harness.log")
    if rc != 0 or "HKDF-SOURCE-COVERAGE OK" not in text:
        raise GateError("positive coverage checker on harness failed")

    # Negative coverage controls.
    base_text = frozen_hkdf.read_text()
    mutants = checker_mutants(base_text, output / "mutants", frozen_harness)
    mutants.update(binding_mutants(base_text, output / "mutants", frozen_harness))
    for name, needle in mutants.items():
        folder = output / "mutants" / name
        rc, text = run([dafny, "resolve", folder / "Hkdf.dfy", "--allow-external-contracts", "--plugin", checker],
                       evidence / f"logs/checker-{name}.log")
        result["controls"][name] = require_checker_rejection(rc, text, needle, name)

    # This exploit was previously false-green at every semantic gate. Replay
    # the complete mutated body and paired harness, and later compare its Java,
    # so the regression is tied to the coverage rejection rather than a broken
    # proof or a changed executable algorithm.
    binding_folder = output / "mutants/callee-suchthat-model-erasure"
    binding_result = result["controls"]["callee-suchthat-model-erasure"]
    for label, path, included, count in (
            ("method", binding_folder / "Hkdf.dfy", [], 246),
            ("harness", binding_folder / "HkdfTrace.dfy", ["--verify-included-files"], 257)):
        rc, text = run([dafny, "verify", path, *included, *FLAGS],
                       evidence / f"logs/verify-binding-erasure-{label}.log")
        binding_result[label] = require_verified(rc, text, count,
            "binding erasure " + label, exact=count)

    # Frozen independent-review findings: the exact real golden/empty/shadow
    # sources that the previous checker accepted must now be rejected by name.
    for name, needle in REVIEWER_CONTROLS.items():
        rc, text = run([dafny, "resolve", frozen_reviewer / name / "Hkdf.dfy",
                        "--allow-external-contracts", "--plugin", checker],
                       evidence / f"logs/checker-reviewer-{name}.log")
        result["controls"]["reviewer-" + name] = require_checker_rejection(rc, text, needle, "reviewer-" + name)

    # The reordered-callee control is a full-gate ghost-only mutation: its
    # actual body and paired harness still verify at the baseline counts, so
    # the named checker rejection is not a count/inventory drift artifact.
    order_folder = frozen / "formal/source/hkdf/controls/rereview/callee-order"
    rc, text = run([dafny, "verify", order_folder / "Hkdf.dfy", *FLAGS],
                   evidence / "logs/verify-rereview-callee-order-method.log")
    result["controls"]["rereview-callee-order-method"] = require_verified(
        rc, text, 248, "rereview callee-order method", exact=248)
    rc, text = run([dafny, "verify", order_folder / "HkdfTrace.dfy", "--verify-included-files", *FLAGS],
                   evidence / "logs/verify-rereview-callee-order-harness.log")
    result["controls"]["rereview-callee-order-harness"] = require_verified(
        rc, text, 259, "rereview callee-order harness", exact=259)

    # Frozen independent re-review findings on the current baseline: exact
    # class-root/marker/callee-order/datatype-equality/overflow regressions.
    for name, needle in REREVIEW_CONTROLS.items():
        rc, text = run([dafny, "resolve", frozen / "formal/source/hkdf/controls/rereview" / name / "Hkdf.dfy",
                        "--allow-external-contracts", "--plugin", checker],
                       evidence / f"logs/checker-rereview-{name}.log")
        result["controls"]["rereview-" + name] = require_checker_rejection(rc, text, needle, "rereview-" + name)

    # Third-review duplicate actual-call controls: the body and paired harness
    # are green at the reviewer's exact counts, but the checker rejects the
    # rebinding of one ghost local by a second actual LabelInfo/Expand call.
    for name, (needle, method_count, harness_count) in THIRD_CONTROLS.items():
        folder = frozen / "formal/source/hkdf/controls/third" / name
        rc, text = run([dafny, "verify", folder / "Hkdf.dfy", *FLAGS],
                       evidence / f"logs/verify-third-{name}-method.log")
        method_result = require_verified(rc, text, method_count, f"third {name} method", exact=method_count)
        rc, text = run([dafny, "verify", folder / "HkdfTrace.dfy", "--verify-included-files", *FLAGS],
                       evidence / f"logs/verify-third-{name}-harness.log")
        harness_result = require_verified(rc, text, harness_count, f"third {name} harness", exact=harness_count)
        rc, text = run([dafny, "resolve", folder / "Hkdf.dfy", "--allow-external-contracts", "--plugin", checker],
                       evidence / f"logs/checker-third-{name}.log")
        checker_result = require_checker_rejection(rc, text, needle, "third-" + name)
        result["controls"]["third-" + name] = {
            "method": method_result, "harness": harness_result, "checker": checker_result}

    # Consistent fresh bijective relabel: labels are opaque method-local
    # annotation IDs.  A 2->99 relabel must be accepted and keep proofs green.
    accept_folder = accept_mutants(frozen_hkdf.read_text(), output / "mutants", frozen_harness)
    rc, text = run([dafny, "verify", accept_folder / "Hkdf.dfy", *FLAGS],
                   evidence / "logs/verify-site-relabel-accept-method.log")
    accept_method = require_verified(rc, text, 248, "site-relabel-accept method", exact=248)
    rc, text = run([dafny, "verify", accept_folder / "HkdfTrace.dfy", "--verify-included-files", *FLAGS],
                   evidence / "logs/verify-site-relabel-accept-harness.log")
    accept_harness = require_verified(rc, text, 259, "site-relabel-accept harness", exact=259)
    rc, text = run([dafny, "resolve", accept_folder / "Hkdf.dfy", "--allow-external-contracts", "--plugin", checker],
                   evidence / "logs/checker-site-relabel-accept.log")
    if rc != 0 or "HKDF-SOURCE-COVERAGE OK" not in text:
        raise GateError("consistent bijective site relabel was not accepted")
    result["controls"]["site-relabel-accept"] = {
        "classification": "accepted-bijective-relabel",
        "method": accept_method, "harness": accept_harness,
        "checker": "HKDF-SOURCE-COVERAGE OK"}

    # Block-boundary control is body/harness-green; only the named pending-block
    # coverage rule rejects it.
    block_folder = output / "mutants" / "block-boundary-pending"
    rc, text = run([dafny, "verify", block_folder / "Hkdf.dfy", *FLAGS],
                   evidence / "logs/verify-block-boundary-pending-method.log")
    result["controls"]["block-boundary-pending"]["method"] = require_verified(
        rc, text, 248, "block-boundary-pending method", exact=248)
    rc, text = run([dafny, "verify", block_folder / "HkdfTrace.dfy", "--verify-included-files", *FLAGS],
                   evidence / "logs/verify-block-boundary-pending-harness.log")
    result["controls"]["block-boundary-pending"]["harness"] = require_verified(
        rc, text, 259, "block-boundary-pending harness", exact=259)

    # Observed-secret controls: method verifies, two-run harness genuinely fails.
    for name in observed_mutants(base_text, output / "mutants", frozen_harness):
        folder = output / "mutants" / name
        rc, text = run([dafny, "verify", folder / "Hkdf.dfy", *FLAGS], evidence / f"logs/verify-{name}-method.log")
        result["controls"][name + "-method"] = require_verified(rc, text, 218, name + " method")
        rc, text = run([dafny, "verify", folder / "HkdfTrace.dfy", "--verify-included-files", *FLAGS],
                       evidence / f"logs/verify-{name}-harness.log")
        result["controls"][name + "-harness"] = require_assertion_failure(rc, text, name + " harness")

    # Baseline still verifies ALL implementation/helper bodies above. First
    # check each exact metadata symbol positively, then isolate the same actual
    # declaration in its faulty control. A deliberately broken encoder can
    # otherwise exhaust resources in unrelated recursive trace lemmas.
    result["metadata_targets"] = {}
    for control, encoder in METADATA_ENCODERS.items():
        if encoder in result["metadata_targets"]:
            continue
        rc, text = run(metadata_command(dafny, frozen_hkdf, control),
                       evidence / f"logs/metadata-target-{encoder}.log")
        if "VerifiedHkdf." + encoder not in text:
            raise GateError("metadata filter did not select actual encoder " + encoder)
        result["metadata_targets"][encoder] = require_verified(
            rc, text, 1, "metadata baseline " + encoder, exact=1)

    # Faulty actual encoder contracts must fail at the named obligation, never
    # at a parser/resource error. This does not replace full baseline proofs.
    for name, needle in metadata_mutants(base_text, output / "metadata-mutants").items():
        folder = output / "metadata-mutants" / name
        rc, text = run(metadata_command(dafny, folder / "Hkdf.dfy", name),
                       evidence / f"logs/verify-{name}.log")
        if "VerifiedHkdf." + METADATA_ENCODERS[name] not in text:
            raise GateError("metadata control did not select its actual encoder: " + name)
        result["controls"][name] = require_named_proof_failure(rc, text, needle, name)

    # Java identity: ghost-instrumented source must generate the committed
    # production package byte-for-byte; the aggregator is an erasure fixture.
    traced_dir = output / "java-instrumented"
    trace_generated, trace_agg = translate(dafny, frozen_hkdf, traced_dir, evidence / "logs/translate-instrumented.log")
    trace_pkg = snapshot(trace_generated / PACKAGE)
    committed_dir = frozen_java / Path("io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf")
    committed = snapshot(committed_dir)
    committed = {Path(k).name: v for k, v in committed.items()}
    fresh = {Path(k).name: v for k, v in trace_pkg.items()}
    if committed != fresh:
        raise GateError("instrumented generated package differs from committed production generated source")
    if digest(trace_agg) != digest(frozen_fixture):
        raise GateError("generated top-level aggregator differs from the pinned erasure fixture")
    result["java"]["generated_package_files"] = len(trace_pkg)
    result["java"]["generated_package_matches_committed_production"] = True
    result["java"]["aggregator_matches_fixture"] = True
    result["java"]["hashes"] = trace_pkg

    erased_generated, erased_agg = translate(dafny, binding_folder / "Hkdf.dfy",
        output / "java-binding-erasure", evidence / "logs/translate-binding-erasure.log")
    if snapshot(erased_generated / PACKAGE) != trace_pkg or digest(erased_agg) != digest(trace_agg):
        raise GateError("ghost binding-erasure regression changed generated executable Java")
    binding_result["java_package_files"] = len(trace_pkg)
    binding_result["java_identical"] = True

    java_home = find_jdk21()
    javac = java_home / "bin/javac"
    production_sources = [
        frozen_java / "io/github/mahmoudimus/quic/Hkdf.java",
        frozen_java / "io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java",
        frozen_java / "io/github/mahmoudimus/verifiedcrypto/JdkHmac.java",
    ]
    base_classes = output / "classes-baseline"
    trace_classes = output / "classes-instrumented"
    compile_java(javac, runtime, sorted(committed_dir.glob("*.java")) + production_sources,
                 base_classes, evidence / "logs/javac-baseline.log")
    compile_java(javac, runtime, sorted((trace_generated / PACKAGE).glob("*.java")) + production_sources,
                 trace_classes, evidence / "logs/javac-instrumented.log")
    base_inv = class_inventory(base_classes)
    trace_inv = class_inventory(trace_classes)
    if base_inv != trace_inv:
        raise GateError("compiled class inventory/hashes differ between committed production and instrumented source")
    result["java"]["class_inventory_identical"] = True
    result["java"]["classes"] = len(trace_inv)
    rc, text = run([javac, "-version"], evidence / "logs/javac-version.log")
    result["java"]["javac"] = text.strip()

    # Public ABI signatures for the four generated methods: no ghost trace parameter.
    rc, text = run([java_home / "bin/javap", "-p", "-classpath", str(trace_classes),
                    "io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default"],
                   evidence / "logs/javap-__default.log")
    signatures = [line.strip() for line in text.splitlines()
                  if re.search(r"\b(Extract|Expand|LabelInfo|ExpandLabel)\(", line)]
    expected_sigs = [
        "public static io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult Extract(java.math.BigInteger, dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>);",
        "public static io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult Expand(java.math.BigInteger, dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Byte>, java.math.BigInteger);",
        "public static io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult LabelInfo(dafny.DafnySequence<? extends java.lang.Short>, dafny.DafnySequence<? extends java.lang.Byte>, java.math.BigInteger);",
        "public static io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult ExpandLabel(java.math.BigInteger, dafny.DafnySequence<? extends java.lang.Byte>, dafny.DafnySequence<? extends java.lang.Short>, dafny.DafnySequence<? extends java.lang.Byte>, java.math.BigInteger);",
    ]
    if len(signatures) != 4 or any(exp not in text.replace("\n", " ") for exp in expected_sigs):
        raise GateError("generated public HKDF ABI changed or ghost trace leaked into Java: " + repr(signatures))
    result["java"]["abi_signatures"] = signatures

    if digest(checker) != checker_sha:
        raise GateError("checker assembly changed during replay")
    result["checker"]["assembly_sha256_after"] = checker_sha

    # Re-check pins after all work.
    for name, expected_hash in pins.items():
        if digest(P / name) != expected_hash:
            raise GateError("Input changed during replay: " + name)
    return result

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=P / "work/replay")
    parser.add_argument("--cache", type=Path,
                        default=Path(os.environ.get("MICROPROXY_FORMAL_CACHE", Path.home() / ".cache/microproxy-formal")))
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    evidence = output / "evidence"
    (evidence / "logs").mkdir(parents=True, exist_ok=True)
    report = evidence / "report.json"
    report.unlink(missing_ok=True)
    report.write_text(json.dumps({"status": "incomplete"}, indent=2) + "\n")
    try:
        result = pipeline(args, output, evidence)
    except Exception as error:
        report.write_text(json.dumps({"status": "failed", "error": str(error)}, indent=2) + "\n")
        print(str(error), file=sys.stderr)
        return 1
    report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Complete:", report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
