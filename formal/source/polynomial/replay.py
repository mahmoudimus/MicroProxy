#!/usr/bin/env python3
"""Portable replay for the NativePolynomial source-observation package.

This source-assurance component consumes the
exact, pinned executable source closure in this repository, installs the
checksum-pinned Dafny 4.9.1 toolchain outside the checkout, verifies the actual
Dafny roots with the original 30 s / 50 M / 2-core policy, audits every owned
source, builds the trusted resolved-AST checker from an isolated copy, runs the
complete current control family, and compares generated Java/class bytes against
an explicit immutable baseline.

Trust boundaries are explicit: the Dafny verifier, its ghost erasure, the C#
checker, javac/JVM, the JCE/provider runtime and the operating system are trusted.
This is a source-observation result, not a compiler-refinement, JVM-timing,
whole-crypto or cryptographic-security theorem.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent.parents[2]
POLY = ROOT / "formal/source/polynomial"
CHECKER_CS = POLY / "checker/PolynomialSourceCoverage.cs"
CHECKER_CSPROJ = POLY / "checker/PolynomialSourceCoverage.csproj"
TOOLCHAIN = ROOT / "formal/dafny/toolchain.py"
TOOLS = ROOT / "formal/dafny/tools.json"
DELIVERY = ROOT / "formal/crypto/delivery.py"
BASELINE_COMMIT = "5ce660a69a1dd496dda02705bf1e2b1aa7a2be1d"
BASELINE_TREE = "df8b49bc8d181be18d78a9db7ab0233f23f7346f"
BASELINE_FILES = 20
EXPECTED_CLASSES = 65
# Reviewed immutable-main baseline manifest digest (Root's frozen 20-file
# baseline, every byte rechecked with git show).  A self-declared commit/tree
# string is not sufficient authentication.
BASELINE_MANIFEST_SHA256 = "77daf19d88d147086717d86f06cda280e9f16d0e7b2ef769472745a77f256ff0"
APPROVED_MAVEN_RUNTIME_SHA256 = "dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6"
GIT = "/usr/bin/git"

# The C# checker's reviewed default method root set, in its exact printed order.
DEFAULT_METHOD_ROOTS = [
    "NativePolynomial.NewZetas", "NativePolynomial.NewGammas", "NativePolynomial.Add",
    "NativePolynomial.Sub", "NativePolynomial.Copy", "NativePolynomial.ForwardStage",
    "NativePolynomial.InverseStage", "NativePolynomial.Scale", "NativePolynomial.Ntt",
    "NativePolynomial.InverseNtt", "NativePolynomial.BaseCase", "NativePolynomial.NttMul",
    "NativePolynomial.Wipe", "NativeField.ReduceOnce", "NativeField.Reduce",
    "NativeField.Add", "NativeField.Sub", "NativeField.Mul", "NativeField.MulSub",
    "NativeField.AddMul",
]
# Reviewed default pure-function set (19).  The canonical positive run clears
# POLY_TRACE_FUNCS, so this set cannot be reduced by an ambient selector.
DEFAULT_PURE_FUNCS = [
    "NativePolynomial.Len", "NativePolynomial.ZetasChunk0", "NativePolynomial.ZetasChunk1",
    "NativePolynomial.ZetasChunk2", "NativePolynomial.ZetasChunk3", "NativePolynomial.ZetasChunk4",
    "NativePolynomial.ZetasChunk5", "NativePolynomial.ZetasChunk6", "NativePolynomial.ZetasChunk7",
    "NativePolynomial.ZetasValue", "NativePolynomial.GammasChunk0", "NativePolynomial.GammasChunk1",
    "NativePolynomial.GammasChunk2", "NativePolynomial.GammasChunk3", "NativePolynomial.GammasChunk4",
    "NativePolynomial.GammasChunk5", "NativePolynomial.GammasChunk6", "NativePolynomial.GammasChunk7",
    "NativePolynomial.GammasValue",
]

# Exact explicit package scope.  Do not glob all of formal/crypto: the real A
# tree contains unrelated workers' files.  These are the reviewed component
# overrides, the official NativeMlKem/Polynomial dependency closure, the two
# provider helpers, and the pinned tools/delivery helpers.
COMPONENT_OVERRIDES = [
    "formal/crypto/NativeField.dfy", "formal/crypto/NativePolynomial.dfy",
    "formal/crypto/NativeSampling.dfy", "formal/crypto/NativeMlKem.dfy",
    "formal/crypto/native_polynomial_domain.dfy",
]
HELPER_DFY = [
    "formal/crypto/Codec.dfy", "formal/crypto/JdkHash.dfy", "formal/crypto/KemSpec.dfy",
    "formal/crypto/NativeCodec.dfy", "formal/crypto/NativeJdkHash.dfy",
    "formal/crypto/NativeKeccak.dfy", "formal/crypto/NativeShake.dfy",
    "formal/crypto/NativeTypes.dfy", "formal/crypto/Polynomial.dfy",
    "formal/crypto/Sampling.dfy", "formal/crypto/Shake.dfy", "formal/crypto/SpongeSpec.dfy",
]
PRIMITIVE_FILES = ["formal/primitives/Field.dfy", "formal/primitives/Keccak.dfy"]
PROVIDER_JAVA = ["formal/crypto/kem_hash.java", "formal/crypto/native_kem_hash.java"]
TOOL_FILES = ["formal/dafny/toolchain.py", "formal/dafny/tools.json", "formal/crypto/delivery.py"]
SHARED_SOURCE = [
    "formal/source/SourceTrace.dfy",
    "formal/source/vocabulary/ObservationVocabulary.dfy",
]
CHECKER_SELECTORS = ("POLY_TRACE_ROOTS", "POLY_TRACE_FUNCS")

POLICY = ["--verification-time-limit", "30", "--resource-limit", "50000000", "--cores", "2"]
CS0 = POLICY + ["--solver-option", "O:smt.case_split=0"]
CS3 = POLICY + ["--solver-option", "O:smt.case_split=3"]
OUTER_MODULE = "io.github.mahmoudimus.quic.internal.verifiedcrypto"

SUMMARY = re.compile(r"^Dafny program verifier finished with (\d+) (?:assertions )?verified, (\d+) errors?\s*$", re.M)
AUDIT = re.compile(r"Dafny auditor completed with (\d+) findings")
BAD_RUN = re.compile(r"warning:|timed?\s*out|out of resources?|resource limit|out of memory|"
                     r"parse errors?|parser errors?|resolution/type errors?|internal error|"
                     r"unhandled exception", re.I)
PROOF_FAILURE = re.compile(r"assertion might not hold|postcondition could not be proved|"
                           r"function precondition could not be proved|invariant could not be proved")

PROOFS = [
    ("formal/crypto/NativeField.dfy", CS0, 86, "field"),
    ("formal/crypto/NativePolynomial.dfy", CS0, 1001, "polynomial"),
    ("formal/source/polynomial/NativePolynomialTraceHarness.dfy", CS0, 26, "paired-harness"),
    ("formal/crypto/NativeMlKem.dfy", CS3, 2767, "mlkem-composition"),
    ("formal/source/polynomial/FieldTraceCompatibility.dfy", CS0, 14, "field-compatibility"),
    ("formal/source/SourceTrace.dfy", CS0, 17, "source-trace"),
    ("formal/source/vocabulary/ObservationVocabulary.dfy", CS0, 29, "observation-vocabulary"),
    ("formal/source/polynomial/controls/PolynomialControls.dfy", CS0, 19, "checker-controls"),
]
AUDIT_FILES = [
    "formal/source/vocabulary/ObservationVocabulary.dfy",
    "formal/source/SourceTrace.dfy",
    "formal/crypto/NativeField.dfy",
    "formal/crypto/NativePolynomial.dfy",
    "formal/crypto/NativeMlKem.dfy",
    "formal/source/polynomial/NativePolynomialTraceHarness.dfy",
    "formal/source/polynomial/FieldTraceCompatibility.dfy",
    "formal/source/polynomial/AllPolynomialTraceRoots.dfy",
]

ROOT_CONTROLS = {
    "SecretBranchObserved": (True, "Control.SecretBranchObserved"),
    "SecretIndexObserved": (True, "Control.SecretIndexObserved"),
    "SecretBranchUnmarked": (False, "Control.SecretBranchUnmarked"),
    "SecretIndexUnmarked": (False, "Control.SecretIndexUnmarked"),
    "ShadowCallee": (False, "Control.ShadowCallee"),
    "RoleShadow": (False, "Control.RoleShadow"),
    "EventReset": (False, "Control.EventReset"),
    "Interposed": (False, "Control.Interposed"),
    "Unsupported": (False, "Control.Unsupported"),
}
FUNC_CONTROLS = {
    "FunctionControl.PrivateBranchObserved": True,
    "FunctionControl.PrivateIndexObserved": True,
    "FunctionControl.PrivateBranchUnmarked": False,
    "FunctionControl.PrivateBranchReset": False,
    "FunctionControl.PrivateIndexUnmarked": False,
}
ROOT_NEEDLES = {
    "SecretBranchUnmarked": "missing Branch observation for branch guard",
    "SecretIndexUnmarked": "missing Read observation for array read",
    "ShadowCallee": "unregistered executable callee Shadow._default.Add",
    "RoleShadow": "mismatched Read observation for array read",
    "EventReset": "later trace update must append to the same trace",
    "Interposed": "expected exact SourceTrace.Branch for branch guard, found Read",
    "Unsupported": "Ops arg 0=0, source executable count=1",
}
FUNC_NEEDLES = {
    "FunctionControl.PrivateBranchUnmarked": "arm 0 is missing Branch observation",
    "FunctionControl.PrivateBranchReset": "arm 0 is missing Branch observation",
    "FunctionControl.PrivateIndexUnmarked": "arm 0 is missing exact Read for array address",
}
PAIRED_FAILURES = {
    "controls/BranchObservedHarness.dfy": ("assert t1 == t2", 4),
    "controls/IndexObservedHarness.dfy": ("assert t1 == t2", 4),
    "controls/FunctionBranchHarness.dfy": ("assert t1 == t2", 4),
    "controls/FunctionIndexHarness.dfy": ("assert t1 == t2", 4),
}
PAIRED_GREEN = {
    "controls/UnmarkedHarnesses.dfy": 3,
    "controls/FunctionUnmarkedHarnesses.dfy": 3,
}

# label: (old, new, checker needle, dafny mode, dafny named)
# mode "error" requires a genuine non-resource Dafny proof failure; "green"
# requires the functional proof to remain green; "checker-only" records a Dafny
# observation but never treats a resource/parse result as evidence.
MUTATIONS = [
    ("leaf-branch-mutation", "if i < 16 then (ZetasChunk0(i-0).0, ghost",
     "if i < 15 then (ZetasChunk0(i-0).0, ghost",
     "arm 0 guard is not exact index<literal", "checker-only", None),
    ("real-path-mutation", "if i < 16 then (ZetasChunk0(i-0).0, ghost",
     "if i < 16 then (0, ghost", "real result is not a .0 projection", "error", "Error:"),
    ("child-ghost-mutation", " + ZetasChunk0(i-0).1)", " )",
     "ghost is not exactly five ordered leaves", "error", "Error:"),
    ("caller-arg-mutation", "trace := trace + ZetasValue(i).1 + ST.Write(500,0,i as int);",
     "trace := trace + ZetasValue(i+1).1 + ST.Write(500,0,i as int);",
     "ghost projection ZetasValue is not immediately after an actual call with the same arguments",
     "error", "Error:"),
    ("chunktrace-helper-mutation",
     "  { BranchFalsePrefix(siteBase,k) + ST.Branch(siteBase+k,true) + ST.Ops(0,0,0,0,0,0,0) }",
     "  { ST.Ops(0,0,0,0,0,0,0) }", "ChunkTrace body is not three leaves", "error", "Error:"),
    ("branchfalseprefix-helper-mutation",
     "  { if k <= 0 then [] else BranchFalsePrefix(siteBase,k-1) + ST.Branch(siteBase+k-1,false) }",
     "  { if k <= 0 then [] else BranchFalsePrefix(siteBase,k-1) }",
     "BranchFalsePrefix else is not two leaves", "error", "Error:"),
    ("missing-false-prefix",
     "else if i < 64 then (ZetasChunk3(i-48).0, ghost BranchFalsePrefix(800,3) + ST.Branch(803,true)",
     "else if i < 64 then (ZetasChunk3(i-48).0, ghost ST.Branch(803,true)",
     "arm 3 ghost is not exactly five ordered leaves", "error", "Error:"),
    ("ghost-reorder", "ghost BranchFalsePrefix(800,0) + ST.Branch(800,true) + ST.Ops(0,1,0,0,0,0,0)",
     "ghost BranchFalsePrefix(800,0) + ST.Ops(0,1,0,0,0,0,0) + ST.Branch(800,true)",
     "arm 0 true event is not exact", "error", "Error:"),
    ("fake-ops", "then (ZetasChunk0(i-0).0, ghost BranchFalsePrefix(800,0) + ST.Branch(800,true) + ST.Ops(0,1,0,0,0,0,0)",
     "then (ZetasChunk0(i-0).0, ghost BranchFalsePrefix(800,0) + ST.Branch(800,true) + ST.Ops(0,0,1,0,0,0,0)",
     "Ops payload is not exact", "error", "Error:"),
    ("synthetic-callee", "trace := trace + ft + ST.Write(504,2,i as int);",
     "trace := trace + FieldAddCallee() + ST.Write(504,2,i as int);",
     "non-approved suffix expression", "green", None),
    ("drop-callee-trace", "trace := trace + GammasValue(i).1 + ST.Write(501,0,i as int);",
     "trace := trace + ST.Write(501,0,i as int);",
     "actual pure call GammasValue has 0 immediate ghost projections", "error", "Error:"),
    ("duplicate-projection", "trace := trace + ZetasValue(i).1 + ST.Write(500,0,i as int);",
     "trace := trace + ZetasValue(i).1 + ZetasValue(i).1 + ST.Write(500,0,i as int);",
     "actual pure call ZetasValue has 2 immediate ghost projections", "error", "Error:"),
    ("wrong-local",
     "trace := trace + ST.Call(409,11,0);\n    var roots, zt := NewZetas();\n    trace := trace + zt;",
     "trace := trace + ST.Call(409,11,0);\n    var roots, zt := NewZetas();\n    trace := trace + ct;",
     "callee trace local is not appended immediately after its defining call", "error", "Error:"),
    ("rebind-local", "assert ft == FieldAddCallee();", "ft := [];",
     "ghost trace local has 2 assignments; exactly one exact ghost-out call is required (rebinding)",
     "error", "Error:"),
    ("rebind-same-model", "assert ft == FieldAddCallee();", "ft := FieldAddCallee();",
     "ghost trace local has 2 assignments; exactly one exact ghost-out call is required (rebinding)",
     "green", None),
    ("rebind-suchthat", "assert ft == FieldAddCallee();", "ft :| ft == FieldAddCallee();",
     "AssignSuchThatStmt", "green", None),
]

CANONICAL_CONTROLS = [
    ("canonical-branch-flip",
     "  { O.Encode(O.Branch(site, taken)) }",
     "  { O.Encode(O.Branch(site, !taken)) }",
     "positional formal 1: SourceTrace._default.Branch",
     "Branch(site,taken) == O.Encode(O.Branch(site,taken))"),
    ("canonical-erase-address",
     "  { O.Encode(O.Read(site, role, address)) }",
     "  { O.Encode(O.Read(site, role, 0)) }",
     "positional formal 2: SourceTrace._default.Read",
     "Read(site,role,address) == O.Encode(O.Read(site,role,address))"),
    ("canonical-erase-ops",
     "  { O.Encode(O.Ops(add, sub, mul, div, mod, bit, shift)) }",
     "  { O.Encode(O.Ops(add, sub, mul, div, 0, bit, shift)) }",
     "positional formal 4: SourceTrace._default.Ops",
     "Ops(a,b,c,d,e,f,g) == O.Encode(O.Ops(a,b,c,d,e,f,g))"),
    ("canonical-dead-branch",
     "  { O.Encode(O.Branch(site, taken)) }",
     "  { if true then [] else O.Encode(O.Branch(site, taken)) }",
     "not exact canonical Encode(constructor(positional formals)): SourceTrace._default.Branch",
     "Branch(site,taken) == O.Encode(O.Branch(site,taken))"),
]


class GateError(RuntimeError):
    pass


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def approve_runtime(runtime_sha, toolchain_runtime_sha):
    if runtime_sha == toolchain_runtime_sha:
        return "checksum-pinned toolchain DafnyRuntime.jar"
    if runtime_sha == APPROVED_MAVEN_RUNTIME_SHA256:
        return "approved Maven org.dafny:DafnyRuntime:4.9.1 (dc62d345...)"
    raise GateError("runtime jar is neither the pinned toolchain runtime nor the approved "
                    "Maven DafnyRuntime 4.9.1 artifact")


def safe_relpath(name):
    """Validate a repository-relative POSIX key before any filesystem access."""
    if not isinstance(name, str) or not name or "\\" in name:
        raise GateError("unsafe repository-relative path: " + repr(name))
    if any(char in name for char in ("\r", "\n", ";")):
        raise GateError("unsafe repository-relative path: " + repr(name))
    rel = PurePosixPath(name)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts or rel.as_posix() != name:
        raise GateError("unsafe repository-relative path: " + repr(name))
    return rel


def safe_path(root, name):
    """Return an unsymlinked path contained in root, checking raw components."""
    root = Path(root)
    rel = safe_relpath(name)
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise GateError("symlinked path component: " + str(current))
    resolved = current.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise GateError("path escapes root: " + name)
    return current


def tool_env():
    env = os.environ.copy()
    for name in CHECKER_SELECTORS:
        env.pop(name, None)
    return env


def checker_env(roots=None, funcs=None):
    """Clean checker environment: only the explicitly requested selector."""
    env = tool_env()
    if roots is not None:
        env["POLY_TRACE_ROOTS"] = roots
    if funcs is not None:
        env["POLY_TRACE_FUNCS"] = funcs
    return env


def log_run(command, log, cwd, timeout=3600, env=None):
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    argv = [str(c) for c in command]
    if env is None:
        env = tool_env()
    with log.open("w") as stream:
        try:
            result = subprocess.run(argv, cwd=str(cwd), stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout, env=env)
            rc = result.returncode
        except subprocess.TimeoutExpired:
            stream.write("\nRUNNER TIMEOUT\n")
            rc = 124
    return {"command": argv, "exit": rc, "log": str(log), "log_sha256": digest(log),
            "text": log.read_text(errors="replace")}


def summary(text):
    found = SUMMARY.findall(text)
    if len(found) != 1:
        raise GateError("expected exactly one Dafny verification summary")
    return int(found[0][0]), int(found[0][1])


def require_verified(rc, text, expected, label):
    bad = BAD_RUN.search(text)
    if bad:
        raise GateError(label + ": tool/resource/parse/warning result is not a proof: " + bad.group(0))
    verified, errors = summary(text)
    if rc != 0 or errors != 0 or verified != expected:
        raise GateError(f"{label}: expected exactly {expected} verified and 0 errors, "
                        f"got {verified}/{errors} rc={rc}")
    return {"verified": verified, "errors": errors}


def require_green_min(rc, text, minimum, label):
    bad = BAD_RUN.search(text)
    if bad:
        raise GateError(label + ": tool/resource/parse/warning result is not a green proof: " + bad.group(0))
    verified, errors = summary(text)
    if rc != 0 or errors != 0 or verified < minimum:
        raise GateError(f"{label}: expected at least {minimum} verified and 0 errors, got {verified}/{errors} rc={rc}")
    return {"verified": verified, "errors": errors, "minimum": minimum}


def require_checker_ok(rc, text, expected_roots, label):
    """Require the exact reviewed root identity sequence, not just a count.

    This rejects a repeated single root, a different set of the same length, and
    any ambient-selector narrowing.  The expected list is static reviewed data,
    never learned from the observed output or an environment variable.
    """
    bad = BAD_RUN.search(text)
    if bad:
        raise GateError(label + ": checker positive run had a tool failure: " + bad.group(0))
    if rc != 0 or "POLYNOMIAL-SOURCE-COVERAGE OK" not in text:
        raise GateError(label + ": expected POLYNOMIAL-SOURCE-COVERAGE OK")
    matches = re.findall(r"exact resolved roots \[([^\]]*)\]", text)
    if len(matches) != 1:
        raise GateError(label + ": expected exactly one resolved-root inventory")
    actual = [item for item in matches[0].split(",") if item]
    expected = list(expected_roots)
    if len(expected) != len(set(expected)):
        raise GateError(label + ": expected root inventory contains duplicates")
    if len(actual) != len(set(actual)):
        raise GateError(label + ": checker reported duplicate resolved roots")
    if actual != expected:
        raise GateError(label + ": resolved roots differ from the reviewed exact set: "
                        f"expected={expected} actual={actual}")
    return {"roots": actual, "root_count": len(actual),
            "root_set_sha256": hashlib.sha256("\n".join(actual).encode()).hexdigest(),
            "classification": "resolved-ast-coverage-positive-exact"}


def checker_diagnostics(text):
    """Dafny's plugin-rejection summary is not a parser/tool failure.

    The trusted checker reports a named coverage error and Dafny then prints
    `<n> resolution/type errors detected in <file>`.  That exact summary line is
    permitted only when the caller also requires a named coverage diagnostic;
    every other warning/parse/resource diagnostic remains fatal.
    """
    return re.sub(r"^\d+ resolution/type errors detected in .*$", "", text, flags=re.M)


def require_checker_rejection(rc, text, needle, label):
    bad = BAD_RUN.search(checker_diagnostics(text))
    if bad:
        raise GateError(label + ": checker failure was a tool/parse failure, not a coverage rejection: "
                        + bad.group(0))
    if rc != 2 or needle not in text or "POLYNOMIAL-SOURCE-COVERAGE OK" in text:
        raise GateError(f"{label}: expected named checker rejection containing {needle!r}, rc={rc}")
    return {"classification": "resolved-ast-coverage-rejection", "needle": needle}


def require_dafny_error(rc, text, named, label):
    bad = BAD_RUN.search(text)
    if bad:
        raise GateError(label + ": tool/resource/parse/warning result is not a Dafny counterexample: "
                        + bad.group(0))
    verified, errors = summary(text)
    if rc != 4 or errors == 0 or named not in text or not PROOF_FAILURE.search(text):
        raise GateError(label + f": expected a genuine named Dafny proof failure containing {named!r}")
    return {"verified": verified, "errors": errors,
            "classification": "dafny-proof-failure", "named": named}


def require_dafny_green(rc, text, label, expected=None):
    result = require_verified(rc, text, expected if expected is not None else summary(text)[0], label)
    return result


def require_assertion_failure(rc, text, label, named="assert t1 == t2"):
    bad = BAD_RUN.search(text)
    if bad:
        raise GateError(label + ": tool/resource/parse/warning result is not an assertion control: "
                        + bad.group(0))
    verified, errors = summary(text)
    if rc != 4 or errors == 0 or "assertion might not hold" not in text or named not in text:
        raise GateError(label + f": expected a genuine Dafny assertion failure at {named!r}")
    return {"verified": verified, "errors": errors,
            "classification": "dafny-assertion-failure", "named": named}


def audit_file(dafny, path, log, expected, display):
    result = log_run([dafny, "audit", path, "--allow-external-contracts"], log, ROOT)
    findings = AUDIT.findall(result["text"])
    if result["exit"] != 0 or len(findings) != 1 or int(findings[0]) != expected:
        raise GateError(f"audit {display}: expected {expected} findings, got {findings} rc={result['exit']}")
    return {"file": display, "findings": expected, "command": result["command"],
            "exit": result["exit"], "log": result["log"], "log_sha256": result["log_sha256"]}


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise GateError(f"mutation anchor changed: {label} (count={text.count(old)})")
    return text.replace(old, new, 1)


def package_files():
    """Exact reviewed input scope, independent of unrelated A files.

    This deliberately does not glob all of formal/crypto and does not include
    top-level fixture README/PORT-MANIFEST scaffolding.  The package must work
    when copied into the real main layout, which contains many unrelated files.
    """
    names = []
    names += COMPONENT_OVERRIDES
    names += HELPER_DFY
    names += PRIMITIVE_FILES
    names += PROVIDER_JAVA
    names += TOOL_FILES
    names += SHARED_SOURCE
    for name in names:
        path = safe_path(ROOT, name)
        if not path.is_file():
            raise GateError("missing reviewed package input: " + name)
    package_names = []
    for path in sorted(POLY.rglob("*")):
        if path.is_symlink():
            raise GateError("symlink in package tree: " + str(path))
        if not path.is_file():
            continue
        rel = path.relative_to(POLY).as_posix()
        if rel in ("inputs.json", "SOURCE-EVIDENCE.json"):
            continue
        if rel.startswith("evidence/") or "__pycache__" in rel or "/bin/" in "/" + rel or "/obj/" in "/" + rel:
            continue
        package_names.append(path.relative_to(ROOT).as_posix())
    names += package_names
    result = sorted(set(names))
    for name in result:
        safe_relpath(name)
        safe_path(ROOT, name)
    return result


def guard_files():
    return sorted(set(package_files()) | {"formal/source/polynomial/inputs.json"})


def inventory_hashes():
    return {name: digest(safe_path(ROOT, name)) for name in guard_files()}


def check_manifest_inputs(pins):
    actual = set(package_files())
    expected = set(pins)
    if actual != expected:
        raise GateError("Proof input inventory changed; review before renewing pins: "
                        f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}")
    for name, sha in pins.items():
        safe_relpath(name)
        path = safe_path(ROOT, name)
        if not re.fullmatch(r"[0-9a-f]{64}", str(sha)) or not path.is_file():
            raise GateError("Invalid input pin: " + name)
        if digest(path) != sha:
            raise GateError("Input changed; review before renewing pin: " + name)


def freeze_tree(pins, destination):
    destination = Path(destination)
    if destination.is_symlink():
        raise GateError("frozen destination is a symlink")
    destination.mkdir(parents=True, exist_ok=False)
    for name, sha in pins.items():
        source = safe_path(ROOT, name)
        target = safe_path(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if digest(target) != sha:
            raise GateError("Frozen input changed: " + name)
    for name, sha in pins.items():
        if digest(safe_path(destination, name)) != sha:
            raise GateError("Frozen tree mismatch: " + name)


def verify_baseline(root, git_repo=None, trusted_manifest_sha256=None):
    """Authenticate the immutable baseline before using any byte.

    Accepted authentication is either an actual /usr/bin/git `show` of every
    file at the pinned 5ce660a6 commit/tree, or an externally supplied exact
    manifest digest equal to the reviewed frozen baseline digest.  A manifest's
    self-declared commit/tree strings alone are never sufficient.
    """
    raw_root = Path(root)
    if raw_root.is_symlink():
        raise GateError("Baseline root is a symlink")
    root = raw_root.resolve()
    if not root.is_dir():
        raise GateError("Baseline root missing")
    manifest_path = safe_path(root, "manifest.json")
    if not manifest_path.is_file():
        raise GateError("Baseline manifest missing")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("commit") != BASELINE_COMMIT or manifest.get("tree") != BASELINE_TREE:
        raise GateError("Baseline commit/tree pin mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict) or len(files) != BASELINE_FILES:
        raise GateError(f"Baseline manifest must contain exactly {BASELINE_FILES} completed files")
    for name, sha in files.items():
        safe_relpath(name)
        path = safe_path(root, name)
        if not path.is_file() or digest(path) != sha:
            raise GateError("Baseline file missing or changed: " + name)

    manifest_digest = digest(manifest_path)
    authentication = None
    git_verified = False
    if trusted_manifest_sha256 is not None:
        if trusted_manifest_sha256 != BASELINE_MANIFEST_SHA256:
            raise GateError("Supplied baseline manifest digest is not the reviewed frozen digest")
        if manifest_digest != BASELINE_MANIFEST_SHA256:
            raise GateError("Baseline manifest digest does not match the reviewed frozen digest")
        authentication = "trusted-manifest-sha256"

    if git_repo is not None:
        raw_repo = Path(git_repo)
        if raw_repo.is_symlink():
            raise GateError("Baseline git repository is a symlink")
        repo = raw_repo.resolve()
        for name, sha in files.items():
            rel = safe_relpath(name).as_posix()
            result = subprocess.run([GIT, "-C", str(repo), "show", BASELINE_COMMIT + ":" + rel],
                                    capture_output=True, timeout=120, env=tool_env())
            if result.returncode != 0 or hashlib.sha256(result.stdout).hexdigest() != sha:
                raise GateError("Baseline byte does not match git show: " + name)
        tree = subprocess.run([GIT, "-C", str(repo), "rev-parse", BASELINE_COMMIT + "^{tree}"],
                              capture_output=True, text=True, timeout=120, env=tool_env())
        if tree.returncode != 0 or tree.stdout.strip() != BASELINE_TREE:
            raise GateError("Baseline tree pin does not match git")
        git_verified = True
        authentication = "git-show" if authentication is None else "git-show+trusted-manifest-sha256"

    if authentication is None:
        raise GateError("Baseline authentication required: supply --git-repo or the reviewed "
                        "--baseline-manifest-sha256")
    return {"root": str(root), "manifest_sha256": manifest_digest,
            "commit": BASELINE_COMMIT, "tree": BASELINE_TREE,
            "files": len(files), "git_show_verified": git_verified,
            "baseline_authenticated": True, "authentication": authentication,
            "source_discovery": manifest.get("source_discovery")}


def build_checker(dafny, work):
    folder = work / "src"
    folder.mkdir(parents=True, exist_ok=False)
    copied = {}
    for source in (CHECKER_CS, CHECKER_CSPROJ):
        target = folder / source.name
        expected = digest(source)
        shutil.copyfile(source, target)
        if digest(target) != expected:
            raise GateError("copied checker input changed: " + source.name)
        copied[source.name] = expected
    env = tool_env()
    env["DOTNET_CLI_HOME"] = str(work / "dotnet-home")
    env["NUGET_PACKAGES"] = str(work / "nuget")
    sdk = log_run(["dotnet", "--version"], work / "sdk.log", folder, env=env)
    if sdk["exit"] != 0 or not re.fullmatch(r"\d+\.\d+\.\d+\s*", sdk["text"]):
        raise GateError("cannot identify checker build SDK")
    command = ["dotnet", "build", "-v:q", "-c", "Release", "PolynomialSourceCoverage.csproj",
               "-p:DafnyHome=" + str(Path(dafny).parent),
               "-p:ImportDirectoryBuildProps=false", "-p:ImportDirectoryBuildTargets=false"]
    build = log_run(command, work / "build.log", folder, env=env)
    if build["exit"] != 0:
        raise GateError("checker build failed: " + build["text"][-4000:])
    for name, expected in copied.items():
        if digest(folder / name) != expected:
            raise GateError("checker build changed source: " + name)
    dll = folder / "bin/Release/net6.0/PolynomialSourceCoverage.dll"
    if not dll.is_file():
        raise GateError("checker assembly missing")
    record = {"source_pins": copied, "project_pin": copied.get("PolynomialSourceCoverage.csproj"),
              "sdk": sdk["text"].strip(), "command": command,
              "assembly_sha256": digest(dll), "build_root": str(folder.parent),
              "directory_build_imports_disabled": True,
              "deterministic": True, "debug_symbols": False,
              "build_log": build["log"], "build_log_sha256": build["log_sha256"]}
    (work / "checker-build.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return dll, record


def filemap(root):
    return {str(p.relative_to(root)): digest(p) for p in sorted(Path(root).rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cache", required=True, help="toolchain cache outside the checkout")
    parser.add_argument("--baseline", required=True, help="immutable 5ce660a6 baseline directory")
    parser.add_argument("--git-repo", default=None,
                        help="read-only repo used to authenticate every baseline byte with git show")
    parser.add_argument("--baseline-manifest-sha256", default=None,
                        help="externally trusted exact frozen baseline manifest digest")
    parser.add_argument("--javac21", required=True)
    parser.add_argument("--javac25", required=True)
    parser.add_argument("--runtime", required=True, help="DafnyRuntime 4.9.1 jar")
    args = parser.parse_args()

    out = Path(args.output).resolve()
    if out.exists():
        raise SystemExit("output directory must not exist: " + str(out))
    out.mkdir(parents=True)
    logs = out / "logs"
    logs.mkdir()
    before = inventory_hashes()
    manifest = json.loads((POLY / "inputs.json").read_text())
    pins = manifest["inputs"]
    check_manifest_inputs(pins)

    baseline = verify_baseline(args.baseline, args.git_repo, args.baseline_manifest_sha256)
    frozen = out / "frozen"
    freeze_tree(pins, frozen)
    frozen_poly = frozen / "formal/source/polynomial"
    frozen_cs = frozen / "formal/source/polynomial/checker/PolynomialSourceCoverage.cs"
    frozen_csproj = frozen / "formal/source/polynomial/checker/PolynomialSourceCoverage.csproj"

    sys.path.insert(0, str(frozen / "formal/dafny"))
    sys.path.insert(0, str(frozen / "formal/crypto"))
    import toolchain
    import delivery

    dafny, runtime_from_toolchain, tools, asset = toolchain.install(Path(args.cache))
    version = log_run([dafny, "--version"], logs / "dafny-version.log", ROOT)
    if version["exit"] != 0 or not version["text"].strip().startswith(tools["version"] + "+"):
        raise GateError("unexpected Dafny version: " + version["text"].strip())
    runtime_arg = Path(args.runtime).resolve()
    if not runtime_arg.is_file():
        raise GateError("runtime jar missing")
    runtime_sha = digest(runtime_arg)
    toolchain_runtime_sha = digest(runtime_from_toolchain)
    runtime_artifact = approve_runtime(runtime_sha, toolchain_runtime_sha)

    def closure_call(label, command):
        return (lambda: None)  # replaced below

    closure_records = {}
    closure_entries = [
        ("roots", "formal/source/polynomial/AllPolynomialTraceRoots.dfy"),
        ("mlkem", "formal/crypto/NativeMlKem.dfy"),
        ("native-field", "formal/crypto/NativeField.dfy"),
        ("native-polynomial", "formal/crypto/NativePolynomial.dfy"),
        ("paired-harness", "formal/source/polynomial/NativePolynomialTraceHarness.dfy"),
        ("field-compatibility", "formal/source/polynomial/FieldTraceCompatibility.dfy"),
        ("polynomial-domain", "formal/crypto/native_polynomial_domain.dfy"),
    ]
    for label, entry in closure_entries:
        def call(round_label, command, label=label):
            result = log_run(command, logs / f"closure-{label}-{round_label}.log", frozen)
            return result["exit"], result["text"]
        closure = delivery.source_closure(frozen, frozen / entry, dafny, call=call)
        closure_records[label] = closure
        if not closure:
            raise GateError("empty official source closure: " + label)
        for name in closure:
            if name not in pins:
                raise GateError("official closure contains an unpinned file: " + name)
            closure_path = safe_path(frozen, name)
            if not closure_path.is_file():
                raise GateError("closure path missing or not a file: " + name)
    covered = set()
    for closure in closure_records.values():
        covered |= set(closure)
    production_pins = {name for name in pins
                       if name.endswith(".dfy")
                       and not name.startswith("formal/source/polynomial/controls/")}
    if covered != production_pins:
        raise GateError("official source closure omission/extra: "
                        f"missing={sorted(production_pins - covered)} extra={sorted(covered - production_pins)}")

    results = []
    proof_records = []
    for name, flags, expected, label in PROOFS:
        result = log_run([dafny, "verify", frozen / name, *flags], logs / f"verify-{label}.log", frozen)
        try:
            gate = require_verified(result["exit"], result["text"], expected, label)
        except GateError:
            raise
        proof_records.append({"target": name, "label": label, "flags": flags,
                              "expected": expected, **gate,
                              "command": result["command"], "exit": result["exit"],
                              "log": result["log"], "log_sha256": result["log_sha256"]})
        results.append(proof_records[-1])

    audit_records = []
    for name in AUDIT_FILES:
        rec = audit_file(dafny, frozen / name, logs / ("audit-" + name.replace("/", "-") + ".log"),
                         0, name)
        rec["expected"] = 0
        rec["ok"] = rec["findings"] == 0
        audit_records.append(rec)
        results.append(rec)

    checker_dll, checker_build = build_checker(dafny, out / "checker-build")
    plugin = str(checker_dll)

    def checker(entry, log, expected_roots, env=None, cwd=None):
        result = log_run([dafny, "resolve", entry, "--plugin", plugin],
                         log, cwd or frozen, env=env if env is not None else checker_env())
        gate = require_checker_ok(result["exit"], result["text"], expected_roots, str(entry))
        result.update(gate)
        return result

    positive = checker(frozen_poly / "AllPolynomialTraceRoots.dfy", logs / "checker-positive.log",
                       DEFAULT_METHOD_ROOTS, env=checker_env())
    positive["selector"] = "default (both POLY_TRACE_* cleared)"
    positive["expected_pure_functions"] = DEFAULT_PURE_FUNCS
    results.append(positive)

    # Actual scope-bypass probe: the checker itself is allowed to request a
    # subset for controls, but the canonical gate must reject a repeated single
    # root of the correct length.  This is the exact Root probe scenario.
    repeated = ",".join([DEFAULT_METHOD_ROOTS[0]] * len(DEFAULT_METHOD_ROOTS))
    probe = log_run([dafny, "resolve", frozen_poly / "AllPolynomialTraceRoots.dfy",
                     "--plugin", plugin], logs / "checker-scope-probe-repeated.log",
                    frozen, env=checker_env(roots=repeated))
    try:
        require_checker_ok(probe["exit"], probe["text"], DEFAULT_METHOD_ROOTS,
                           "checker-scope-probe-repeated")
    except GateError as error:
        probe_record = {"probe": "repeated-single-root", "selector": repeated,
                        "exit": probe["exit"], "log": probe["log"],
                        "log_sha256": probe["log_sha256"],
                        "expected_roots": DEFAULT_METHOD_ROOTS,
                        "rejected": True, "reason": str(error), "ok": True}
    else:
        raise GateError("scope probe was wrongly accepted: repeated single root")
    results.append(probe_record)

    # Existing method controls, checked against the frozen control package.
    for name, (accepted, target) in ROOT_CONTROLS.items():
        env = checker_env(roots=target)
        result = log_run([dafny, "resolve", frozen_poly / "controls/PolynomialControls.dfy",
                          "--plugin", plugin], logs / f"controls/checker-{name}.log", frozen, env=env)
        result["selector"] = {"POLY_TRACE_ROOTS": target, "POLY_TRACE_FUNCS": None}
        if accepted:
            gate = require_checker_ok(result["exit"], result["text"], [target], "method-control " + name)
            result.update(gate)
        else:
            gate = require_checker_rejection(result["exit"], result["text"], ROOT_NEEDLES[name], "method-control " + name)
            result.update(gate)
        results.append(result)

    for name, accepted in FUNC_CONTROLS.items():
        env = checker_env(funcs=name)
        result = log_run([dafny, "resolve", frozen_poly / "controls/PolynomialControls.dfy",
                          "--plugin", plugin], logs / f"controls/checker-{name.replace('.', '-')}.log",
                         frozen, env=env)
        result["selector"] = {"POLY_TRACE_ROOTS": None, "POLY_TRACE_FUNCS": name}
        if accepted:
            # The C# default root inventory remains the reviewed 20 methods;
            # the requested function subset is the explicit control selector.
            gate = require_checker_ok(result["exit"], result["text"], DEFAULT_METHOD_ROOTS,
                                      "function-control " + name)
        else:
            gate = require_checker_rejection(result["exit"], result["text"], FUNC_NEEDLES[name], "function-control " + name)
        result.update(gate)
        results.append(result)

    env = checker_env(funcs="ByMethodProbe.Identity")
    result = log_run([dafny, "resolve", frozen_poly / "controls/ByMethodControl.dfy", "--plugin", plugin],
                     logs / "controls/checker-ByMethodProbe-Identity.log", frozen, env=env)
    result["selector"] = {"POLY_TRACE_ROOTS": None, "POLY_TRACE_FUNCS": "ByMethodProbe.Identity"}
    result.update(require_checker_rejection(result["exit"], result["text"],
                                            "function-by-method is unsupported", "by-method"))
    results.append(result)

    lemma = log_run([dafny, "verify", frozen_poly / "controls/LemmaOutControl.dfy", *CS0],
                    logs / "controls/verify-LemmaOutControl.log", frozen)
    if lemma["exit"] != 0 or "2 verified, 0 errors" not in lemma["text"] or BAD_RUN.search(lemma["text"]):
        raise GateError("LemmaOutControl proof must be 2 verified, 0 errors")
    results.append(lemma)
    env = checker_env(roots="LemmaOutControl.Use")
    result = log_run([dafny, "resolve", frozen_poly / "controls/LemmaOutControl.dfy", "--plugin", plugin],
                     logs / "controls/checker-LemmaOutControl.log", frozen, env=env)
    result["selector"] = {"POLY_TRACE_ROOTS": "LemmaOutControl.Use", "POLY_TRACE_FUNCS": None}
    result.update(require_checker_rejection(result["exit"], result["text"],
                                            "ghost lemma-out binding is unsupported", "lemma-out"))
    results.append(result)

    # Paired observed failures and green unmarked harnesses.
    for rel, (named, expected_rc) in PAIRED_FAILURES.items():
        result = log_run([dafny, "verify", frozen_poly / rel, *CS0], logs / (rel.replace("/", "-") + ".log"), frozen)
        result.update(require_assertion_failure(result["exit"], result["text"], rel, named))
        results.append(result)
    for rel, expected in PAIRED_GREEN.items():
        result = log_run([dafny, "verify", frozen_poly / rel, *CS0], logs / (rel.replace("/", "-") + ".log"), frozen)
        result.update(require_verified(result["exit"], result["text"], expected, rel))
        results.append(result)

    # Canonical wrapper source proofs and checker rejections.
    canonical_records = []
    for label, old, new, want, proof in CANONICAL_CONTROLS:
        mut = Path(tempfile.mkdtemp(prefix="poly-canon-" + label + "-"))
        shutil.copytree(frozen / "formal", mut / "formal")
        st = mut / "formal/source/SourceTrace.dfy"
        st.write_text(replace_once(st.read_text(), old, new, label))
        clog = logs / f"controls/{label}-checker.log"
        cp = log_run([dafny, "resolve", mut / "formal/source/polynomial/AllPolynomialTraceRoots.dfy",
                      "--plugin", plugin], clog, frozen)
        cgate = require_checker_rejection(cp["exit"], cp["text"], want, label)
        vlog = logs / f"controls/{label}-verify.log"
        vp = log_run([dafny, "verify", st, *CS0], vlog, frozen)
        try:
            vgate = require_dafny_error(vp["exit"], vp["text"], proof, label)
        except GateError as error:
            raise GateError(f"{label}: canonical mutation must fail its actual SourceTrace bridge: {error}")
        rec = {"control": label, "checker": cgate, "checker_command": cp["command"],
               "checker_exit": cp["exit"], "checker_log": cp["log"], "checker_log_sha256": cp["log_sha256"],
               "dafny": vgate, "dafny_command": vp["command"], "dafny_exit": vp["exit"],
               "dafny_log": vp["log"], "dafny_log_sha256": vp["log_sha256"], "named_bridge": proof,
               "ok": True}
        canonical_records.append(rec)
        results.append(rec)
    (out / "canonical-controls.json").write_text(json.dumps(
        {"schema": "microproxy.native-polynomial-canonical-controls/v1", "controls": canonical_records},
        indent=2, sort_keys=True) + "\n")

    # R2 decoy instance class.
    dec = Path(tempfile.mkdtemp(prefix="poly-decoy-class-"))
    shutil.copytree(frozen / "formal", dec / "formal")
    ddfy = dec / "formal/crypto/NativePolynomial.dfy"
    dtxt = ddfy.read_text()
    marker = "  function Len(s: T.I): (T.I, ghost seq<int>)"
    cls = ("  class Decoy {\n    constructor() {}\n"
           "    function ZetasValue(i: T.I): (T.I, ghost seq<int>) "
           "{ (i, ghost ST.Ops(0,0,0,0,0,0,0)) }\n  }\n\n")
    dtxt = replace_once(dtxt, marker, cls + marker, "decoy class")
    old_loop = ("    trace := trace + ST.LoopBound(200,128);\n    ZetasUpToZero();\n"
                "    for i: T.I := 0 to 128")
    new_loop = ("    trace := trace + ST.LoopBound(200,128);\n    var d := new Decoy();\n"
                "    ZetasUpToZero();\n    for i: T.I := 0 to 128")
    dtxt = replace_once(dtxt, old_loop, new_loop, "decoy construction")
    dtxt = replace_once(dtxt, "r[i] := ZetasValue(i).0;", "r[i] := d.ZetasValue(i).0;", "decoy call")
    ddfy.write_text(dtxt)
    dlog = logs / "controls/decoy-class.log"
    dp = log_run([dafny, "resolve", dec / "formal/source/polynomial/AllPolynomialTraceRoots.dfy",
                  "--plugin", plugin], dlog, frozen)
    dgate = require_checker_rejection(dp["exit"], dp["text"],
                                      "unregistered executable callee NativePolynomial.Decoy._ctor",
                                      "decoy-class")
    decjson = {"schema": "microproxy.native-polynomial-decoy-control/v1",
               "checker_exit": dp["exit"], "checker_command": dp["command"],
               "checker_log": dp["log"], "checker_log_sha256": dp["log_sha256"],
               "rejection": dgate["needle"], "ok": True,
               "note": "R2: exact FullName default registry rejects an instance-class shadow before its function can be used."}
    (out / "decoy-class.json").write_text(json.dumps(decjson, indent=2, sort_keys=True) + "\n")
    results.append(decjson)

    # Genuine mutation controls: checker named rejection is mandatory; the
    # Dafny side is recorded but resource/parse results are never accepted.
    mutation_records = []
    for label, old, new, want, mode, named in MUTATIONS:
        mut = Path(tempfile.mkdtemp(prefix="poly-mutation-" + label + "-"))
        shutil.copytree(frozen / "formal", mut / "formal")
        npm = mut / "formal/crypto/NativePolynomial.dfy"
        npm.write_text(replace_once(npm.read_text(), old, new, label))
        mutlog = logs / f"controls/{label}.log"
        mp = log_run([dafny, "resolve", mut / "formal/source/polynomial/AllPolynomialTraceRoots.dfy",
                      "--plugin", plugin], mutlog, frozen)
        mgate = require_checker_rejection(mp["exit"], mp["text"], want, label)
        dlog = logs / f"controls/{label}-dafny.log"
        dp = log_run([dafny, "verify", npm, *CS0], dlog, frozen)
        if mode == "error":
            dgate = require_dafny_error(dp["exit"], dp["text"], named, label + "-dafny")
            usable = True
        elif mode == "green":
            dgate = require_green_min(dp["exit"], dp["text"], 900, label + "-dafny")
            usable = True
        else:
            matches = SUMMARY.findall(dp["text"])
            verified = int(matches[0][0]) if len(matches) == 1 else None
            errors = int(matches[0][1]) if len(matches) == 1 else None
            usable = bool(matches) and not bool(BAD_RUN.search(dp["text"])) and errors > 0
            dgate = {"classification": "observed-not-used-as-proof" if not usable else "dafny-failure-observed",
                     "verified": verified, "errors": errors,
                     "dafny_rc": dp["exit"],
                     "note": "checker rejection is the load-bearing control; resource/parse output is never evidence"}
        rec = {"control": label, "checker": mgate, "dafny": dgate,
               "checker_command": mp["command"], "checker_exit": mp["exit"],
               "checker_log": mp["log"], "checker_log_sha256": mp["log_sha256"],
               "dafny_command": dp["command"], "dafny_exit": dp["exit"],
               "dafny_log": dp["log"], "dafny_log_sha256": dp["log_sha256"],
               "dafny_evidence_usable": usable, "ok": True}
        mutation_records.append(rec)
        results.append(rec)

    # N1b / N1-F1: ghost rebinding plus spec-model swap.  The checker must
    # reject; the functional body/harness and generated Java remain green.
    # Java generation is needed first.
    genbase = out / "generated-baseline"
    gentrace = out / "generated-trace"
    for d in (genbase, gentrace):
        d.mkdir()
    baseline_root = Path(args.baseline).resolve()
    blog = logs / "generate-baseline.log"
    bp = log_run([dafny, "translate", "java", "formal/crypto/NativeMlKem.dfy", "--no-verify",
                  "--outer-module", OUTER_MODULE, "--output", str(genbase / "NativeCrypto")],
                 blog, baseline_root)
    if bp["exit"] != 0 or BAD_RUN.search(bp["text"]):
        raise GateError("baseline translation failed")
    tlog = logs / "generate-trace.log"
    tp = log_run([dafny, "translate", "java", "formal/crypto/NativeMlKem.dfy", "--no-verify",
                  "--outer-module", OUTER_MODULE, "--output", str(gentrace / "NativeCrypto")],
                 tlog, frozen)
    if tp["exit"] != 0 or BAD_RUN.search(tp["text"]):
        raise GateError("trace translation failed")
    fm_base = filemap(genbase)
    fm_trace = filemap(gentrace)
    changed_java = sorted(k for k in set(fm_base) | set(fm_trace) if fm_base.get(k) != fm_trace.get(k))
    (out / "generated-files.json").write_text(json.dumps(
        {"baseline": fm_base, "trace": fm_trace,
         "text_identical": fm_base == fm_trace, "changed_java": changed_java},
        indent=2, sort_keys=True) + "\n")
    diff = subprocess.run(["diff", "-ru", str(genbase / "NativeCrypto-java"),
                           str(gentrace / "NativeCrypto-java")], capture_output=True, text=True)
    (out / "java-text-diff.patch").write_text(diff.stdout)

    class_results = {}
    for jdk, javacbin in (("21", args.javac21), ("25", args.javac25)):
        jdkres = {"javac": str(javacbin), "base": {}, "trace": {}, "changed": [],
                  "all_class_bytes_identical": False}
        ok = True
        for variant in ("base", "trace"):
            src = (genbase if variant == "base" else gentrace) / "NativeCrypto-java"
            dest = out / f"classes-jdk{jdk}" / variant
            dest.mkdir(parents=True)
            argfile = logs / f"javac-{jdk}-{variant}.argfile"
            srcs = sorted(str(x) for x in src.rglob("*.java"))
            argfile.write_text("\n".join(srcs) + "\n")
            # The generated NativeMlKem source calls the handwritten, pinned
            # provider helper.  Compile the baseline/trace copy explicitly so
            # the class-byte comparison covers it without a mutable sourcepath.
            helper_root = baseline_root if variant == "base" else frozen
            helper = helper_root / "formal/crypto/native_kem_hash.java"
            if not helper.is_file():
                raise GateError("native_kem_hash.java helper missing: " + str(helper))
            cmd = [javacbin, "-cp", str(runtime_arg), "-d", str(dest), "-encoding", "UTF-8",
                   "-g:lines,vars,source", "-Xpkginfo:always", str(helper), "@" + str(argfile)]
            pr = log_run(cmd, logs / f"javac-{jdk}-{variant}.log", ROOT)
            jdkres[variant] = {"exit": pr["exit"], "log": pr["log"], "log_sha256": pr["log_sha256"]}
            ok = ok and pr["exit"] == 0
        if not ok:
            raise GateError(f"javac JDK{jdk} failed")
        b = filemap(out / f"classes-jdk{jdk}" / "base")
        t = filemap(out / f"classes-jdk{jdk}" / "trace")
        jdkres["base_classes"] = len(b)
        jdkres["trace_classes"] = len(t)
        jdkres["changed"] = sorted(k for k in set(b) | set(t) if b.get(k) != t.get(k))
        jdkres["all_class_bytes_identical"] = (not jdkres["changed"] and b == t
                                               and len(b) == EXPECTED_CLASSES)
        (out / f"classes-jdk{jdk}-base.sha256").write_text(
            "".join(f"{h}  {k}\n" for k, h in sorted(b.items())))
        (out / f"classes-jdk{jdk}-trace.sha256").write_text(
            "".join(f"{h}  {k}\n" for k, h in sorted(t.items())))
        if not jdkres["all_class_bytes_identical"]:
            raise GateError(f"JDK{jdk}: expected {EXPECTED_CLASSES}/{EXPECTED_CLASSES} identical class bytes")
        class_results[jdk] = jdkres
    (out / "compiled-erasure.json").write_text(json.dumps(
        {"runtime_sha256": runtime_sha, "jdks": class_results}, indent=2, sort_keys=True) + "\n")

    n1b_records = []
    for label, rebind, want in (
        ("rebind-and-model-swap", "ft := FieldSubCallee();",
         "ghost trace local has 2 assignments"),
        ("rebind-suchthat-model-swap", "ft :| ft == FieldSubCallee();", "AssignSuchThatStmt"),
    ):
        mut = Path(tempfile.mkdtemp(prefix="poly-" + label + "-"))
        shutil.copytree(frozen / "formal", mut / "formal")
        mdfy = mut / "formal/crypto/NativePolynomial.dfy"
        txt = mdfy.read_text()
        txt = replace_once(txt, "+ FieldAddCallee() + ST.Write(504,2,i)",
                           "+ FieldSubCallee() + ST.Write(504,2,i)", label + "-model")
        txt = replace_once(txt, "assert ft == FieldAddCallee();", rebind, label + "-rebind")
        mdfy.write_text(txt)
        clog = logs / f"controls/{label}-checker.log"
        cp = log_run([dafny, "resolve", mut / "formal/source/polynomial/AllPolynomialTraceRoots.dfy",
                      "--plugin", plugin], clog, frozen)
        cgate = require_checker_rejection(cp["exit"], cp["text"], want, label)
        blog2 = logs / f"controls/{label}-body.log"
        bp2 = log_run([dafny, "verify", mdfy, *CS0], blog2, frozen)
        bgate = require_green_min(bp2["exit"], bp2["text"], 900, label + "-body")
        hlog = logs / f"controls/{label}-harness.log"
        hp = log_run([dafny, "verify", mut / "formal/source/polynomial/NativePolynomialTraceHarness.dfy",
                      *CS0], hlog, frozen)
        hgate = require_verified(hp["exit"], hp["text"], 26, label + "-harness")
        mout = out / (label + "-java")
        mout.mkdir()
        glog = logs / f"controls/{label}-generate.log"
        gp = log_run([dafny, "translate", "java", "formal/crypto/NativeMlKem.dfy", "--no-verify",
                      "--outer-module", OUTER_MODULE, "--output", str(mout / "NativeCrypto")], glog, mut)
        jm = filemap(mout)
        identical = gp["exit"] == 0 and not BAD_RUN.search(gp["text"]) and jm == fm_trace
        (out / (label + "-java-files.json")).write_text(json.dumps(
            {"identical_to_trace": identical, "files": jm}, indent=2, sort_keys=True) + "\n")
        if not identical:
            raise GateError(label + ": generated Java is not identical to the trace baseline")
        rec = {"control": label, "checker": cgate, "body": bgate, "harness": hgate,
               "java_identical": identical, "java_files": len(jm),
               "checker_command": cp["command"], "checker_log": cp["log"],
               "checker_log_sha256": cp["log_sha256"], "body_command": bp2["command"],
               "body_log": bp2["log"], "harness_command": hp["command"],
               "harness_log": hp["log"], "generate_command": gp["command"],
               "generate_log": gp["log"], "ok": True}
        n1b_records.append(rec)
        results.append(rec)

    after = inventory_hashes()
    if before != after:
        raise GateError("source inventory changed during replay")
    for name, sha in pins.items():
        if digest(frozen / name) != sha:
            raise GateError("frozen input mutated during replay: " + name)

    evidence = {
        "schema": "microproxy.native-polynomial-central-port/v1",
        "status": "complete",
        "scope": "NativePolynomial/Field source observation prototype; 20 method roots + 19 pure helpers; "
                 "not whole issue #117, not whole-crypto, not JVM timing",
        "root": str(ROOT),
        "tool": {"name": "dafny", "version": version["text"].strip(),
                 "asset_sha256": asset["sha256"],
                 "toolchain_runtime_sha256": toolchain_runtime_sha,
                 "explicit_runtime_sha256": runtime_sha,
                 "tools_manifest": str(TOOLS), "tools_manifest_sha256": digest(TOOLS),
                 "toolchain_sha256": digest(TOOLCHAIN)},
        "policy": {"time": 30, "resource": 50000000, "cores": 2,
                   "native_case_split": 0, "composition_case_split": 3},
        "artifact_claim": "none; this is a prototype validation package, not a delivery artifact",
        "checker_scope": {
            "ambient_selectors_cleared": list(CHECKER_SELECTORS),
            "default_method_roots": DEFAULT_METHOD_ROOTS,
            "default_method_root_count": len(DEFAULT_METHOD_ROOTS),
            "default_pure_functions": DEFAULT_PURE_FUNCS,
            "default_pure_function_count": len(DEFAULT_PURE_FUNCS),
            "identity_not_count_gate": True,
        },
        "package_scope": {
            "component_overrides": COMPONENT_OVERRIDES,
            "helper_dfy": HELPER_DFY,
            "primitive_files": PRIMITIVE_FILES,
            "provider_java": PROVIDER_JAVA,
            "tool_files": TOOL_FILES,
            "shared_source": SHARED_SOURCE,
            "top_level_fixture_readme_pinned": False,
            "top_level_port_manifest_pinned": False,
        },
        "runtime": {"path": str(runtime_arg), "approved_artifact": runtime_artifact,
                    "explicit_sha256": runtime_sha,
                    "toolchain_sha256": toolchain_runtime_sha},
        "inputs_before": before,
        "inputs_after": after,
        "inputs_unchanged": before == after,
        "inputs_manifest_sha256": digest(POLY / "inputs.json"),
        "official_source_closure": closure_records,
        "baseline": baseline,
        "proofs": proof_records,
        "audits": audit_records,
        "checker": checker_build,
        "controls": {"canonical": canonical_records, "decoy": decjson,
                     "mutations": mutation_records, "n1b": n1b_records,
                     "scope_probe": probe_record},
        "erasure": {"generated_files": len(fm_trace), "changed_java": changed_java,
                    "text_identical": fm_base == fm_trace,
                    "class_bytes_identical": class_results,
                    "explicit_runtime_sha256": runtime_sha,
                    "toolchain_runtime_sha256": toolchain_runtime_sha,
                    "runtime_artifact": runtime_artifact,
                    "java_homes": {"21": str(args.javac21), "25": str(args.javac25)}},
        "checks": results,
        "all_checks_ok": True,
        "trust_boundaries": [
            "Dafny verifier and ghost erasure",
            "trusted resolved-AST C# checker",
            "javac/JVM and DafnyRuntime",
            "JCE/provider runtime",
            "read/write roles are method-local resolved identities",
        ],
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out / "SOURCE-EVIDENCE.json").write_text(json.dumps({
        "schema": "microproxy.native-polynomial-source-evidence/v1",
        "status": "complete",
        "proofs": {r["label"]: {"verified": r["verified"], "errors": r["errors"],
                                "target": r["target"]} for r in proof_records},
        "audits": {r["file"]: r["findings"] for r in audit_records},
        "checker_assembly_sha256": checker_build["assembly_sha256"],
        "checker_source_sha256": checker_build["source_pins"]["PolynomialSourceCoverage.cs"],
        "checker_project_sha256": checker_build["source_pins"]["PolynomialSourceCoverage.csproj"],
        "generated_files": len(fm_trace),
        "changed_java": changed_java,
        "classes_identical": {jdk: r["all_class_bytes_identical"] for jdk, r in class_results.items()},
        "inputs_unchanged": before == after,
        "default_method_roots": DEFAULT_METHOD_ROOTS,
        "default_pure_functions": DEFAULT_PURE_FUNCS,
        "runtime_artifact": runtime_artifact,
        "baseline_authentication": baseline["authentication"],
    }, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "complete", "proofs": len(proof_records),
                      "audits": len(audit_records), "checks": len(results),
                      "all_checks_ok": True, "output": str(out)}, indent=2))
    # The frozen input tree is retained in the evidence directory so an
    # independent reviewer can recheck every hash and the exact proof graph.


if __name__ == "__main__":
    main()
