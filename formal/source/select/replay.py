#!/usr/bin/env python3
"""Select source package replay (v2: split package manifest / reviewed tool profiles).

Package root is formal/source/select. Candidate root is two levels up. The immutable
baseline is the Git 155b archive copied beside candidate.

Configuration is split into:
  * ``package.json``            immutable source/proof manifest (expectation tables,
                                Dafny closure bindings, checker source hashes, profile
                                index hash). No machine paths, no tool hashes.
  * ``baseline.json``           strict source hash inventory (no build/output/work
                                artifacts) bound by ``package.json``.
  * ``profiles/<name>.json``    pure expected tool identities for one reviewed
                                toolchain (hashes/versions only). Bound by
                                ``profiles/index.json`` and, externally, by
                                ``--expected-profile-sha256``.

Actual tool *locations* are explicit CLI arguments (``--dafny --dotnet --jdk21
--jdk25 --runtime``); the profile only states what those tools must be. Historical
Qualification evidence is not embedded here; the caller binds
``--expected-package-sha256`` and (optionally) ``--expected-profile-sha256``.

All logs/commands are written under ``--output``. An existing output path is refused
without mutation. Retained fixtures are copied to a fresh workspace under
``--output`` so the package tree is never written to.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform as host
import re
import shutil
import subprocess
import sys
import traceback

PACKAGE_SCHEMA = "microproxy.select-package/2"
PROFILE_SCHEMA = "microproxy.select-tool-profile/2"
INDEX_SCHEMA = "microproxy.select-profile-index/2"
REPORT_SCHEMA = "microproxy.select-package-report/2"

BAD = re.compile(r"timed?\s*out|out of resource|out of memory|internal error|unhandled exception|pars(?:e|er) error|CLI: Error", re.I)
BAD_DIAG = re.compile(r"pars(?:e|er) errors? detected|Error: unresolved identifier|Error: incorrect argument type|Error: wrong number of arguments|Error: invalid Ident|Error: this expression has type|Error: (?:function|method|argument|type mismatch)|Warning:|timed?\s*out|out of resource|out of memory|internal error|unhandled exception|CLI: Error", re.I)
SUMMARY = re.compile(r"Dafny program verifier finished with (\d+) verified, (\d+) errors?")
FLAGS = ["--allow-external-contracts", "--verification-time-limit", "30",
         "--resource-limit", "50000000", "--cores", "2"]
KECCAK_ROOTS = "NativeKeccak.SetLane,NativeKeccak.Iota,NativeKeccak.Wipe,NativeKeccak.Chi,NativeKeccak.Theta,NativeKeccak.RhoPi"
TIMEOUT_MARKER = "CASE-TIMEOUT marker: command killed by runner timeout; partial output above is preserved"

# Expected tool identities only. Locations are CLI arguments, never profile fields.
PROFILE_IDENTITY_FIELDS = {
    "schema", "platform", "dafny_sha256", "dafny_version", "dafny_core_sha256",
    "z3_sha256", "dotnet_sdk", "jdk21_version", "jdk25_version", "runtime_sha256",
    "checker_dll_expected_sha256", "boogie", "jdk21_tools", "jdk25_tools",
    "dotnet_launcher_sha256",
}
PROFILE_FORBIDDEN_KEYS = {
    "dafny", "dotnet", "jdk21", "jdk25", "runtime", "runtime_maven_jar", "z3",
    "dafny_path", "dotnet_path", "jdk21_path", "jdk25_path", "runtime_path", "z3_path",
}
PROFILE_NESTED_IDENTITY = {"boogie", "jdk21_tools", "jdk25_tools"}
# Canonical reviewed platform names; the profile must match the actual host.
PROFILE_PLATFORM_MAP = {
    ("Darwin", "arm64"): "macos-arm64",
    ("Linux", "x86_64"): "linux-x64",
}
# Reviewed exact set of candidate program inputs consumed by the runner. Every
# non-Dafny entry is bound in package.json["candidate_inputs"] and re-checked
# before and after the run; the Dafny entries are also part of the 85-file closure.
USED_CANDIDATE_INPUTS = (
    "formal/crypto/NativeMlKem.dfy",
    "formal/crypto/native_kem_domain.dfy",
    "formal/crypto/native_kem_hash.java",
    "formal/crypto/native_kem_test.java",
    "formal/crypto/native_kem_checks.py",
    "formal/crypto/reference/provenance.json",
    "formal/crypto/reference/Shake.java",
    "formal/crypto/reference/MlKem768.java",
)
# Only interpreter caches are benign at replay admission. Build/output directories
# (bin/obj/work) and retained report.json are mutable artifacts and must never sit
# under the immutable package; freeze excludes them and replay rejects any present.
BENIGN_DIRS = {"__pycache__"}
BENIGN_SUFFIXES = (".pyc", ".pyo")
# Generated build/work directory names: never admissible inside the immutable package,
# even when empty (only interpreter caches are benign).
RESERVED_DIR_NAMES = {"bin", "obj", "work"}
# Reviewed resolved identity order emitted by the legacy retained baseline13 stage.
EXPECTED_BASELINE13_ROOTS = (
    "NativeField.ReduceOnce", "NativeField.Reduce", "NativeField.Add",
    "NativeField.Sub", "NativeField.Mul", "NativeField.MulSub", "NativeField.AddMul",
    "NativeKeccak.SetLane", "NativeKeccak.Iota", "NativeKeccak.Theta",
    "NativeKeccak.RhoPi", "NativeKeccak.Chi", "NativeKeccak.Wipe",
)
COVERAGE_ROOTS = re.compile(r"SOURCE-COVERAGE OK: exact roots \[([^\]]*)\]")
# Package manifests are bound by package.json/baseline.json, not the candidate inventory.
CANDIDATE_MANIFESTS = {
    "formal/source/select/package.json",
    "formal/source/select/baseline.json",
    "formal/source/select/candidate-sources.json",
}

# Trusted expectation tables live in runner code, not in mutable per-case meta.json.
# The external --expected-package-sha256 binds this runner and the package manifest;
# meta.json is only an input hash, never the authority for a named semantic outcome.
EXPECTED_CONTROLS = {
 "coverage-private-loop-bound": {"status": "accepted", "needle": None},
 "neg-block-wrap-alloc": {"status": "named-checker-rejection", "needle": "Select allocation must be a direct top-level statement of the method body"},
 "neg-conditional-alloc": {"status": "named-checker-rejection", "needle": "Select allocation must be a direct top-level statement of the method body"},
 "neg-loop-alloc": {"status": "named-checker-rejection", "needle": "Select allocation must be a direct top-level statement of the method body"},
 "neg-private-branch-after-alloc": {"status": "named-checker-rejection", "needle": "expected exact SourceTrace.Read"},
 "neg-private-callee": {"status": "named-checker-rejection", "needle": "Select allocation initializer contains an executable call"},
 "neg-private-init-read": {"status": "named-checker-rejection", "needle": "Select allocation initializer contains a private/unknown array read or index"},
 "neg-private-read-after-alloc": {"status": "named-checker-rejection", "needle": "expected exact SourceTrace.Read"},
 "neg-private-read-before-alloc": {"status": "named-checker-rejection", "needle": "expected exact SourceTrace.Read"},
 "neg-public-branch-after-alloc": {"status": "named-checker-rejection", "needle": "expected exact SourceTrace.Branch"},
 "neg-second-alloc": {"status": "named-checker-rejection", "needle": "Select must allocate its returned buffer exactly once"},
 "neg-secret-init-condition": {"status": "named-checker-rejection", "needle": "Select allocation initializer contains an unsupported condition/branch/compound expression"},
 "neg-select-calls-rotate": {"status": "named-checker-rejection", "needle": "unregistered executable function call NativeKeccak._default.Rotate"},
 "neg-shadow-select": {"status": "named-checker-rejection", "needle": "reserved Select root outside exact default declaration"},
 "neg-trace-reset-in-loop": {"status": "named-checker-rejection", "needle": "later trace update must append to the same trace as its immutable left prefix"},
 "neg-unmarked-alloc": {"status": "named-checker-rejection", "needle": "expected exact SourceTrace.Alloc"},
 "neg-unmarked-private-loop-bound": {"status": "named-checker-rejection", "needle": "expected exact SourceTrace.Read"},
 "neg-wrong-alloc-site": {"status": "named-checker-rejection", "needle": "mismatched Alloc observation"},
 "neg-wrong-alloc-size": {"status": "named-checker-rejection", "needle": "mismatched Alloc observation"},
 "neg-wrong-initializer": {"status": "named-checker-rejection", "needle": "Select allocation initializer body is not the exact literal zero"},
 "neg-wrong-result-identity": {"status": "named-checker-rejection", "needle": "Select allocation result must be the sole non-ghost output formal by resolved identity"},
 "neg-wrong-size": {"status": "named-checker-rejection", "needle": "Select allocation size must be the exact public literal 32"},
 "positive-actual": {"status": "accepted", "needle": None},
 "positive-alpha-out": {"status": "accepted", "needle": None},
 "positive-zero-init": {"status": "accepted", "needle": None},
}
EXPECTED_ENCODER = {
 "encoder-body-tag4": False, "encoder-body-constant4": False, "encoder-body-empty": False,
 "boolean-flip": False, "address-loss": False, "ops-reordered": False,
 "branch-tag": False, "alpha-case-formals": True,
}



class GateError(RuntimeError):
    pass


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def read(p):
    return Path(p).read_text(errors="replace")


def prepare_output(out):
    """Refuse any existing path (file, directory or dangling symlink) without mutation."""
    out = Path(out)
    if os.path.lexists(str(out)):
        kind = "symlink" if out.is_symlink() else ("directory" if out.is_dir() else "file")
        raise GateError(f"output path already exists ({kind}); refusing to modify it: {out}")
    if not out.parent.is_dir():
        raise GateError(f"output parent directory does not exist: {out.parent}")
    try:
        out.mkdir(parents=False)
    except OSError as e:
        raise GateError(f"cannot create fresh output directory: {out}: {e}")
    return out.resolve()


def run(cmd, log, cwd=None, env=None, timeout=1800, prefix=None):
    """Run a tool, writing an optional context prefix then the unmodified tool output.

    On timeout the captured partial output is preserved and a marker is appended; the
    log is never truncated to a single synthetic line.
    """
    log = Path(log); log.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log.open("w") as stream:
            if prefix:
                stream.write(prefix)
                stream.flush()
            p = subprocess.run([str(c) for c in cmd], cwd=cwd or Path.cwd(),
                               stdout=stream, stderr=subprocess.STDOUT,
                               env=env, timeout=timeout)
        return p.returncode, log.read_text(errors="replace"), log
    except FileNotFoundError as e:
        raise GateError("tool missing: " + str(e.filename))
    except subprocess.TimeoutExpired:
        with log.open("a") as stream:
            stream.write("\n" + TIMEOUT_MARKER + "\n")
        return 124, log.read_text(errors="replace"), log


def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOURCE_TRACE_")}
    env["SOURCE_TRACE_ROOTS"] = "NativeMlKem.Select"
    if extra:
        env.update(extra)
    return env


def scope_ok(text):
    return text.count("SOURCE-COVERAGE OK: exact roots [NativeMlKem.Select]") == 1


def case_context(case_id, operand, argv, cwd, plugin=None, expected=None):
    """Return (raw-log prefix line, typed record) emitted immediately before the call."""
    record = {"case": case_id, "operand_sha256_before": sha(operand) if Path(operand).is_file() else None,
              "argv": [str(a) for a in argv], "cwd": str(cwd)}
    fields = [f"case={case_id}", f"operand_sha256={record['operand_sha256_before']}"]
    if expected is not None:
        record["expected_fixture_sha256"] = expected
        fields.append(f"expected_fixture_sha256={expected}")
    fields.append("argv=" + json.dumps(record["argv"], separators=(",", ":")))
    fields.append(f"cwd={record['cwd']}")
    if plugin is not None:
        record["plugin_sha256"] = plugin
        fields.append(f"plugin_sha256={plugin}")
    return "CASE-CONTEXT " + " ".join(fields) + "\n", record


def finish_context(record, operand):
    record["operand_sha256_after"] = sha(operand) if Path(operand).is_file() else None
    if record["operand_sha256_after"] != record["operand_sha256_before"]:
        raise GateError("case operand changed during the call: " + record["case"])
    return record


def verify_package(pkg, expected_package_sha256):
    if not expected_package_sha256 or not re.fullmatch(r"[0-9a-f]{64}", expected_package_sha256):
        raise GateError("missing or malformed external --expected-package-sha256")
    if sha(pkg / "package.json") != expected_package_sha256:
        raise GateError("external package hash mismatch")
    package = json.loads(read(pkg / "package.json"))
    if package.get("schema") != PACKAGE_SCHEMA:
        raise GateError("unexpected package schema: " + repr(package.get("schema")))
    if package.get("controls_expected") != EXPECTED_CONTROLS:
        raise GateError("trusted control table mismatch")
    if package.get("encoder_expected") != EXPECTED_ENCODER:
        raise GateError("trusted encoder table mismatch")
    if sha(pkg / "baseline.json") != package.get("baseline_manifest_sha256"):
        raise GateError("baseline manifest hash mismatch")
    index_path = pkg / "profiles" / "index.json"
    if not index_path.is_file() or sha(index_path) != package.get("profile_index_sha256"):
        raise GateError("profile index hash mismatch")
    return package


def load_profile(pkg, selector, expected_profile_sha256, expected_platform=None):
    """Resolve a named (package-pinned) or path profile and bind its identity hash.

    A named profile is bound twice: by the package-pinned index and, when supplied, by
    the external --expected-profile-sha256. A path profile requires the external hash.
    Profiles may only carry expected identities, never tool locations.
    """
    if not selector:
        raise GateError("missing --tool-profile")
    index = json.loads(read(pkg / "profiles" / "index.json"))
    if index.get("schema") != INDEX_SCHEMA:
        raise GateError("unexpected profile index schema")
    candidate_path = Path(selector)
    if candidate_path.is_file():
        path = candidate_path
        pinned = None
        if not expected_profile_sha256:
            raise GateError("path --tool-profile requires --expected-profile-sha256")
    else:
        table = index.get("profiles", {})
        if selector not in table:
            raise GateError("unknown named tool profile: " + selector)
        pinned = table[selector]
        path = pkg / "profiles" / (selector + ".json")
        if not path.is_file():
            raise GateError("missing profile file for named profile: " + selector)
    actual = sha(path)
    if pinned is not None and actual != pinned:
        raise GateError("named profile hash does not match package-pinned index")
    if expected_profile_sha256 and actual != expected_profile_sha256:
        raise GateError("external profile hash mismatch")
    profile = json.loads(read(path))
    if profile.get("schema") != PROFILE_SCHEMA:
        raise GateError("unexpected tool profile schema")
    extra = sorted(set(profile) - PROFILE_IDENTITY_FIELDS)
    if extra:
        raise GateError("tool profile carries non-identity fields: " + repr(extra))
    forbidden = sorted(set(profile) & PROFILE_FORBIDDEN_KEYS)
    if forbidden:
        raise GateError("tool profile carries machine locations: " + repr(forbidden))
    def _identity_value(value, label):
        if isinstance(value, str):
            if value.startswith("/") or value.startswith("~") or "\\" in value:
                raise GateError("tool profile carries an absolute/machine path value: " + value)
            return
        if not isinstance(value, dict):
            raise GateError("tool profile identity is not a string or map: " + label)
        for name, digest in value.items():
            if name.startswith("/") or name.startswith("~") or "\\" in name:
                raise GateError("tool profile carries a machine path key: " + name)
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise GateError("tool profile malformed identity for " + label + "/" + name)
    for name, value in profile.items():
        _identity_value(value, name)
    missing = sorted(PROFILE_IDENTITY_FIELDS - set(profile))
    if missing:
        raise GateError("tool profile missing identity fields: " + repr(missing))
    if expected_platform is None:
        expected_platform = host_platform()
    if profile.get("platform") != expected_platform:
        raise GateError("tool profile platform does not match this host: " +
                        repr(profile.get("platform")) + " != " + repr(expected_platform))
    return profile, {"selector": selector, "path": str(path), "sha256": actual,
                     "platform": profile["platform"],
                     "package_pinned": pinned is not None,
                     "external_expected": expected_profile_sha256}


def host_platform():
    """Canonical platform name for the actual host, or a gate failure."""
    key = (host.system(), host.machine())
    if key not in PROFILE_PLATFORM_MAP:
        raise GateError("unsupported host platform: " + repr(key))
    return PROFILE_PLATFORM_MAP[key]


def sha_checked(path, label):
    """sha() with a typed GateError instead of an uncaught OSError."""
    try:
        return sha(path)
    except OSError as e:
        raise GateError("cannot read " + label + " for identity check: " + str(path) + ": " + str(e))


def jdk_version(java):
    try:
        p = subprocess.run([str(java), "-version"], text=True, capture_output=True)
    except OSError as e:
        raise GateError("cannot execute JDK for version check: " + str(java) + ": " + str(e))
    combined = (p.stdout or "") + (p.stderr or "")
    match = re.search(r'version "([^"]+)"', combined)
    if p.returncode != 0 or not match:
        raise GateError("cannot read JDK version: " + str(java))
    return match.group(1)


def verify_tools(dafny, dotnet, jdk21, jdk25, runtime, out, profile, profile_sha256, stage):
    out = Path(out)
    checks = []
    def record(name, expected, actual):
        checks.append({"stage": stage, "name": name, "expected": expected, "actual": actual,
                       "ok": expected == actual})
        if expected != actual:
            raise GateError(f"{name} identity mismatch ({stage}): {actual} != {expected}")
    record("dafny_sha256", profile["dafny_sha256"], sha_checked(dafny, "Dafny binary"))
    core = Path(dafny).resolve().parent / "DafnyCore.dll"
    if not core.is_file():
        raise GateError("DafnyCore.dll missing beside Dafny binary")
    record("dafny_core_sha256", profile["dafny_core_sha256"], sha_checked(core, "DafnyCore.dll"))
    z3 = Path(dafny).resolve().parent / "z3/bin/z3-4.12.1"
    record("z3_sha256", profile["z3_sha256"], sha_checked(z3, "z3 binary"))
    boogie_dir = Path(dafny).resolve().parent
    for name, expected in sorted(profile["boogie"].items()):
        record("boogie:" + name, expected, sha_checked(boogie_dir / name, "Boogie DLL"))
    rc, version, log = run([dafny, "--version"], out / "logs" / ("dafny-version-" + stage + ".log"))
    record("dafny_version", profile["dafny_version"], version.strip())
    record("dotnet_launcher_sha256", profile["dotnet_launcher_sha256"], sha_checked(dotnet, "dotnet launcher"))
    rc, sdk, log = run([dotnet, "--version"], out / "logs" / ("dotnet-version-" + stage + ".log"))
    record("dotnet_sdk", profile["dotnet_sdk"], sdk.strip())
    for jdk_label, home, versions, tools in (
            ("21", jdk21, "jdk21_version", "jdk21_tools"),
            ("25", jdk25, "jdk25_version", "jdk25_tools")):
        record(versions, profile[versions], jdk_version(Path(home) / "bin/java"))
        for name, expected in sorted(profile[tools].items()):
            record("jdk" + jdk_label + ":" + name, expected,
                   sha_checked(Path(home) / name, "JDK" + jdk_label + " " + name))
    record("runtime_sha256", profile["runtime_sha256"], sha_checked(runtime, "Maven runtime"))
    return {"stage": stage, "profile_sha256": profile_sha256,
            "platform": profile["platform"], "checks": checks}


def program_files(root, label, benign_dirs=BENIGN_DIRS, benign_suffixes=BENIGN_SUFFIXES):
    """Every regular file under root, rejecting symlinks; only caches are excluded.

    Returns {relative posix path: absolute Path}. Symlinks are rejected even when
    their target is inside the tree, so a link cannot substitute a file or escape.
    Build/output artifacts are not benign: they are unexpected and fail the exact
    set comparison that callers perform.
    """
    root = Path(root).resolve()
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        parts = rel.split("/")
        if path.is_symlink():
            raise GateError(label + " contains a symlink: " + rel)
        if not path.is_file():
            continue
        if rel.endswith(benign_suffixes) or any(part in benign_dirs for part in parts):
            continue
        files[rel] = path
    return files


def tree_signature(files):
    return {rel: sha_checked(path, "tree input " + rel) for rel, path in sorted(files.items())}


def input_signature(pkg, candidate, baseline, man, package, profile_identity):
    """Exact input domains: baseline 85 + candidate 85 + strict package + used inputs + profile.

    Unrelated outer evidence/docs/receipts are deliberately absent: they are outputs
    of other processes, not Select inputs, and must not invalidate this package.
    """
    return {
        "profile_sha256": sha_checked(profile_identity["path"], "tool profile"),
        "baseline_dafny": {rel: sha_checked(baseline / "formal" / rel, "baseline Dafny " + rel)
                           for rel in sorted(man["baseline_formal_dafny_hashes"])},
        "dafny": {rel: sha_checked(candidate / "formal" / rel, "Dafny " + rel)
                  for rel in sorted(man["candidate_formal_dafny_hashes_excluding_select_package"])},
        "package": tree_signature(program_files(pkg, "package tree")),
        "used_inputs": {rel: sha_checked(candidate / rel, "used input " + rel)
                        for rel in sorted(package["candidate_inputs"])},
    }


def contained_input(candidate, rel, label):
    """Resolve a declared input path under the admitted candidate root.

    Containment contract: the path is relative and inside the root, and **no path
    component below the resolved root may be a symlink**, even when its target is
    itself inside the candidate. A directory link such as
    ``formal/crypto/reference -> /elsewhere`` must not be admitted merely because
    the leaves hash-match. The root itself may be reached through a symlink; it is
    resolved once and used as the boundary.
    """
    parts = Path(rel).parts
    if not rel.startswith("formal/") or Path(rel).is_absolute() or ".." in parts:
        raise GateError(label + " escapes the candidate root: " + rel)
    candidate = Path(candidate)
    if not candidate.is_dir():
        raise GateError(label + " candidate root is not a directory")
    resolved_root = candidate.resolve()
    current = candidate
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise GateError(label + " has a symlink component below the candidate root: " + rel)
    if not current.is_file():
        raise GateError(label + " is missing or not a regular file: " + rel)
    resolved = current.resolve()
    if resolved_root not in resolved.parents:
        raise GateError(label + " resolves outside the candidate root: " + rel)
    return resolved


def verify_used_inputs(candidate, declared):
    """Check the reviewed explicit used inputs: exact set, contained, hash-bound."""
    for rel, expected in sorted(declared.items()):
        contained_input(candidate, rel, "used candidate input")
        path = Path(candidate) / rel
        if sha(path) != expected:
            raise GateError("used candidate input hash mismatch: " + rel)
    return True


def verify_no_reserved_dirs(root, label):
    """Reject unexpected bin/obj/work directories under the immutable package."""
    root = Path(root)
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue  # file-set/symlink checks report links separately
        if path.is_dir() and path.name in RESERVED_DIR_NAMES:
            raise GateError(label + " contains an unexpected build/work directory: " +
                            path.relative_to(root).as_posix())


def parse_baseline13_roots(text):
    """Parse the single named coverage line and require the exact 13-root identity."""
    matches = COVERAGE_ROOTS.findall(text)
    if len(matches) != 1:
        raise GateError("retained baseline13 raw log must contain exactly one named coverage line")
    roots = [r.strip() for r in matches[0].split(",")]
    if len(roots) != len(EXPECTED_BASELINE13_ROOTS):
        raise GateError("retained baseline13 root count changed: " + repr(len(roots)))
    if len(set(roots)) != len(roots):
        raise GateError("retained baseline13 root list has duplicate identities")
    if tuple(roots) != EXPECTED_BASELINE13_ROOTS:
        raise GateError("retained baseline13 resolved root identities changed: " + repr(roots))
    return list(roots)


def verify_control_inventory(pkg):
    names = {p.name for p in (pkg / "controls").iterdir() if p.is_dir() and (p / "meta.json").is_file()}
    if names != set(EXPECTED_CONTROLS):
        raise GateError("control identity inventory mismatch: missing=" + repr(sorted(set(EXPECTED_CONTROLS)-names)) + " extra=" + repr(sorted(names-set(EXPECTED_CONTROLS))))


def verify_manifest(pkg, candidate, baseline, package):
    man = json.loads(read(pkg / "baseline.json"))
    verify_control_inventory(pkg)
    if man.get("schema") != "microproxy.select-baseline/2":
        raise GateError("unexpected baseline schema")
    if man["git_commit"] != "155bbe14cb9748cf677f4eb223af3dd2331687b0":
        raise GateError("baseline Git commit changed")
    if man["git_tree"] != "74a3eb686d02bf4226afed08227391e742b54f12":
        raise GateError("baseline Git tree changed")
    baseline_closure = man["baseline_formal_dafny_hashes"]
    for rel, expected in baseline_closure.items():
        contained_input(baseline, "formal/" + rel, "baseline Dafny")
        p = baseline / "formal" / rel
        if sha(p) != expected:
            raise GateError("baseline Dafny closure mismatch: " + rel)
    # Exact baseline Dafny set: no extra/missing/linked files (recursive, bounded).
    actual_baseline = set()
    for path in sorted((baseline / "formal").rglob("*.dfy")):
        rel = path.relative_to(baseline / "formal").as_posix()
        contained_input(baseline, "formal/" + rel, "baseline Dafny")
        actual_baseline.add(rel)
    if actual_baseline != set(baseline_closure):
        raise GateError("baseline Dafny file inventory changed: missing=" +
                        repr(sorted(set(baseline_closure) - actual_baseline)) +
                        " extra=" + repr(sorted(actual_baseline - set(baseline_closure))))
    # Baseline NativeMlKem is the actual codegen input: explicit identity + containment.
    contained_input(baseline, "formal/crypto/NativeMlKem.dfy", "baseline NativeMlKem")
    if sha(baseline / "formal/crypto/NativeMlKem.dfy") != package["baseline_native_mlkem_sha256"]:
        raise GateError("immutable baseline NativeMlKem mismatch")
    for rel, expected in man["candidate_formal_dafny_hashes_excluding_select_package"].items():
        p = candidate / "formal" / rel
        if not p.is_file() or sha(p) != expected:
            raise GateError("candidate Dafny closure mismatch: " + rel)
    declared = man.get("candidate_allowed_formal_diff", [])
    if sorted(declared) != ["crypto/NativeMlKem.dfy", "crypto/native_kem_domain.dfy"]:
        raise GateError("declared candidate formal diff changed: " + repr(declared))
    diff = sorted(rel for rel, h in man["baseline_formal_dafny_hashes"].items()
                  if man["candidate_formal_dafny_hashes_excluding_select_package"].get(rel) != h)
    if diff != sorted(declared):
        raise GateError("actual baseline->candidate diff is not the declared two files: " + repr(diff))
    npatch = package.get("native_kem_patch", {})
    if npatch.get("domain_patched_sha256") and sha(candidate / "formal/crypto/native_kem_domain.dfy") != npatch["domain_patched_sha256"]:
        raise GateError("Root-authorized native domain patch hash mismatch")
    if npatch.get("runner_patched_sha256") and sha(candidate / "formal/crypto/native_kem_checks.py") != npatch["runner_patched_sha256"]:
        raise GateError("Root-authorized native runner patch hash mismatch")
    if sha(candidate / "formal/crypto/NativeMlKem.dfy") != package["candidate_overlay_sha256"]:
        raise GateError("candidate NativeMlKem overlay mismatch")
    for name, expected in (("checker/SourceCoverage.cs", package["checker_source_sha256"]),
                           ("checker/SourceCoverage.csproj", package["checker_project_sha256"]),
                           ("checker/NativeCanonicalEncoderPolicy.cs", package["checker_policy_sha256"])):
        if sha(pkg / name) != expected:
            raise GateError("checker input mismatch: " + name)
    for rel, expected in man.get("controls", {}).items():
        path = pkg / rel
        if not path.is_file() or sha(path) != expected:
            raise GateError("control input mismatch: " + rel)
    declared_package = man.get("package_files", {})
    for rel, expected in declared_package.items():
        path = pkg / rel
        if not path.is_file() or sha(path) != expected:
            raise GateError("package input mismatch: " + rel)
    # Complete package file set: exact, no extras/removals/symlinks.
    actual_package = program_files(pkg, "package tree")
    expected_package = set(declared_package) | {"package.json", "baseline.json"}
    if set(actual_package) != expected_package:
        raise GateError("package file set changed: missing=" +
                        repr(sorted(expected_package - set(actual_package))) +
                        " extra=" + repr(sorted(set(actual_package) - expected_package)))
    verify_no_reserved_dirs(pkg, "package tree")
    # Exact used closure (no global source-extension sweep):
    #   * the authenticated 85 Dafny files outside the Select package,
    #   * the strict package inventory (checked above),
    #   * the reviewed explicit used inputs (provider/runner/test/java refs).
    # Unrelated outer Python/Java/C#/docs/evidence/receipts are not Select inputs.
    sources_path = pkg / "candidate-sources.json"
    if sha(sources_path) != package["candidate_sources_sha256"]:
        raise GateError("candidate source inventory hash mismatch")
    sources = json.loads(read(sources_path))
    if sources.get("schema") != "microproxy.select-candidate-sources/1":
        raise GateError("unexpected candidate source inventory schema")
    declared_dafny = sources.get("dafny", {})
    declared_used = sources.get("used_inputs", {})
    declared_closure = man["candidate_formal_dafny_hashes_excluding_select_package"]
    if set(declared_dafny) != {"formal/" + rel for rel in declared_closure}:
        raise GateError("candidate Dafny inventory does not match the declared 85")
    for rel, expected in declared_dafny.items():
        path = candidate / rel
        if path.is_symlink() or not path.is_file() or sha(path) != expected:
            raise GateError("candidate Dafny source missing/linked/modified: " + rel)
    actual_dafny = set()
    for path in sorted((candidate / "formal").rglob("*.dfy")):
        rel = "formal/" + path.relative_to(candidate / "formal").as_posix()
        if rel.startswith("formal/source/select/"):
            continue
        if path.is_symlink() or not path.is_file():
            raise GateError("candidate Dafny source linked/not a file: " + rel)
        actual_dafny.add(rel)
    expected_dafny = {"formal/" + rel for rel in declared_closure}
    if actual_dafny != expected_dafny:
        raise GateError("candidate Dafny file inventory changed outside the declared 85: missing=" +
                        repr(sorted(expected_dafny - actual_dafny)) +
                        " extra=" + repr(sorted(actual_dafny - expected_dafny)))
    inputs = package.get("candidate_inputs", {})
    if sorted(inputs) != sorted(USED_CANDIDATE_INPUTS):
        raise GateError("used candidate input set changed: " + repr(sorted(inputs)))
    if declared_used != inputs:
        raise GateError("used candidate inputs are not bound in the source inventory")
    verify_used_inputs(candidate, inputs)
    return man


def build_checker(pkg, out, dotnet, dafny, profile, checker_dll=None, self_test_only=False,
                  expected_dll_sha=None):
    if checker_dll is not None:
        if not self_test_only:
            raise GateError("explicit --checker-dll is restricted to non-qualifying self-test")
        p = Path(checker_dll)
        if not p.is_file() or not expected_dll_sha or sha(p) != expected_dll_sha:
            raise GateError("explicit self-test DLL expected hash mismatch")
        return p, {"mode": "explicit-negative-self-test", "qualification": False,
                   "dll_path": str(p), "dll_sha256": sha(p)}
    build = out / "checker-build"
    build.mkdir(parents=True)
    for n in ("SourceCoverage.cs", "SourceCoverage.csproj", "NativeCanonicalEncoderPolicy.cs"):
        shutil.copy2(pkg / "checker" / n, build / n)
    before = {n: sha(build / n) for n in ("SourceCoverage.cs", "SourceCoverage.csproj", "NativeCanonicalEncoderPolicy.cs")}
    rc, text, log = run([dotnet, "build", "-v:q", "SourceCoverage.csproj",
                         "-p:DafnyHome=" + str(Path(dafny).resolve().parent),
                         "-p:ImportDirectoryBuildProps=false",
                         "-p:ImportDirectoryBuildTargets=false"],
                        out / "logs/checker-build.log", cwd=build)
    if rc != 0:
        raise GateError("checker build failed")
    after = {n: sha(build / n) for n in before}
    if before != after:
        raise GateError("checker inputs changed during build")
    dll = build / "bin/Debug/net6.0/SourceCoverage.dll"
    if not dll.is_file():
        raise GateError("fresh checker DLL missing")
    if sha(dll) != profile["checker_dll_expected_sha256"]:
        raise GateError("fresh checker DLL hash/toolchain mismatch")
    return dll, {"mode": "fresh-build", "qualification": True,
                 "source_sha256": after["SourceCoverage.cs"],
                 "project_sha256": after["SourceCoverage.csproj"],
                 "policy_sha256": after["NativeCanonicalEncoderPolicy.cs"],
                 "dll_sha256": sha(dll), "dll_path": str(dll),
                 "build_log": str(log.relative_to(out)), "build_log_sha256": sha(log),
                 "dotnet": str(dotnet)}


def prepare_tree(candidate, out, name):
    tree = out / "trees" / name / "formal"
    if tree.parent.exists():
        shutil.rmtree(tree.parent)
    shutil.copytree(candidate / "formal", tree)
    return tree


def checker_case(candidate, pkg, out, dafny, dll, name, package):
    if name not in EXPECTED_CONTROLS:
        raise GateError("unknown control identity " + name)
    cdir = pkg / "controls" / name
    if not (cdir / "meta.json").is_file():
        raise GateError("missing control meta " + name)
    expected = EXPECTED_CONTROLS[name]
    tree = prepare_tree(candidate, out, name)
    operand = tree / "crypto/NativeMlKem.dfy"
    if name != "positive-actual":
        shutil.copy2(cdir / "NativeMlKem.dfy", operand)
        expected_fixture = sha(cdir / "NativeMlKem.dfy")
    else:
        expected_fixture = package["candidate_overlay_sha256"]
    if sha(operand) != expected_fixture:
        raise GateError("case fixture operand hash mismatch: " + name)
    cmd = [dafny, "resolve", operand, "--allow-external-contracts", "--plugin", dll]
    log = out / "logs" / "controls" / (name + ".log")
    prefix, record = case_context(name, operand, cmd, tree / "crypto",
                                  plugin=sha(dll), expected=expected_fixture)
    rc, text, _ = run(cmd, log, cwd=tree / "crypto", env=clean_env(), timeout=180, prefix=prefix)
    record = finish_context(record, operand)
    if expected["status"] == "accepted":
        ok = rc == 0 and scope_ok(text) and not BAD_DIAG.search(text)
        status = "accepted" if ok else "UNEXPECTED"
    else:
        needle = expected["needle"]
        ok = rc == 2 and needle and needle in text and not BAD_DIAG.search(text)
        status = "named-checker-rejection" if ok else "UNEXPECTED"
    if not ok:
        raise GateError("control outcome regression " + name + ": " + status)
    return {"name": name, "status": status, "exit": rc,
            "command": [str(c) for c in cmd], "cwd": str(tree / "crypto"),
            "env": {"SOURCE_TRACE_ROOTS": "NativeMlKem.Select"},
            "case_context": record,
            "log": str(log.relative_to(out)), "log_sha256": sha(log)}


def proof(out, dafny, entry, case_split, expected_verified, label, allow_errors=0, expect_exit=0,
          timeout=2400, cwd=None, extra=None, case=None):
    log = out / "logs" / "dafny" / (label + ".log")
    cmd = [dafny, "verify", entry] + FLAGS + (extra or []) + ["--solver-option", "O:smt.case_split=" + str(case_split)]
    prefix, record = case_context(case or label, entry, cmd, cwd or Path(entry).parent)
    rc, text, _ = run(cmd, log, cwd=cwd or Path(entry).parent, timeout=timeout, prefix=prefix)
    record = finish_context(record, entry)
    matches = SUMMARY.findall(text)
    if BAD.search(text) or rc != expect_exit or len(matches) != 1 or int(matches[0][0]) != expected_verified or int(matches[0][1]) != allow_errors:
        raise GateError("Dafny proof regression " + label)
    return {"label": label, "exit": rc, "verified": expected_verified, "errors": allow_errors,
            "command": [str(c) for c in cmd], "cwd": str(cwd or Path(entry).parent),
            "case_context": record,
            "log": str(log.relative_to(out)), "log_sha256": sha(log)}


def observed_case(candidate, pkg, out, dafny, dll, package):
    tree = prepare_tree(candidate, out, "observed")
    operand = tree / "crypto/NativeMlKem.dfy"
    shutil.copy2(pkg / "controls/observed/NativeMlKem.dfy", operand)
    obs = tree / "source/select/observed/SelectObservedHarness.dfy"
    obs.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(pkg / "controls/observed/SelectObservedHarness.dfy", obs)
    cmd = [dafny, "resolve", operand, "--allow-external-contracts", "--plugin", dll]
    log = out / "logs" / "controls" / "observed-checker.log"
    expected_fixture = sha(pkg / "controls/observed/NativeMlKem.dfy")
    if sha(operand) != expected_fixture:
        raise GateError("observed fixture operand hash mismatch")
    prefix, record = case_context("observed", operand, cmd, tree / "crypto",
                                  plugin=sha(dll), expected=expected_fixture)
    rc, text, _ = run(cmd, log, cwd=tree / "crypto", env=clean_env(), timeout=180, prefix=prefix)
    record = finish_context(record, operand)
    if rc != 0 or not scope_ok(text) or BAD.search(text):
        raise GateError("observed mutant coverage accept failed")
    method = proof(out, dafny, operand, 3, package["expected"]["observed_mutant_method"][0],
                   "observed-mutant-method", timeout=2400)
    harness = proof(out, dafny, obs, 0, package["expected"]["observed_mutant_harness"][0],
                    "observed-mutant-harness", allow_errors=1, expect_exit=4, timeout=600,
                    case="observed-mutant-harness")
    htext = read(out / harness["log"])
    if "SelectObservedHarness.dfy(13,11): Error: assertion might not hold" not in htext or "assert t1 == t2;" not in htext:
        raise GateError("observed harness did not fail at exact assertion")
    return {"checker": {"exit": rc, "case_context": record,
                        "log": str(log.relative_to(out)), "log_sha256": sha(log)},
            "method": method, "harness": harness}


def encoder_replay(candidate, pkg, out, dafny, dll, package):
    fixtures = pkg / "fixtures/encoder-fixtures-v2"
    names = {p.name for p in fixtures.iterdir() if p.is_dir()}
    if names != set(EXPECTED_ENCODER):
        raise GateError("encoder fixture identity inventory mismatch")
    checks = {}
    env = clean_env({"SOURCE_TRACE_ROOTS": KECCAK_ROOTS})
    for folder in sorted(fixtures.iterdir()):
        if not folder.is_dir():
            continue
        entry = folder / "formal/crypto/NativeKeccak.dfy"
        log = out / "logs" / "encoder" / (folder.name + ".log")
        cmd = [dafny, "resolve", entry, "--allow-external-contracts", "--plugin", dll]
        prefix, record = case_context("encoder-" + folder.name, entry, cmd, entry.parent,
                                      plugin=sha(dll), expected=sha(entry))
        rc, text, _ = run(cmd, log, cwd=entry.parent, env=env, timeout=180, prefix=prefix)
        record = finish_context(record, entry)
        accept = EXPECTED_ENCODER[folder.name]
        if accept:
            ok = rc == 0 and "SOURCE-COVERAGE OK" in text and not BAD.search(text)
        else:
            ok = rc == 2 and "canonical Encode does not implement the exact typed wire layout" in text and not BAD.search(text)
        if not ok:
            raise GateError("encoder fixture regression " + folder.name)
        checks[folder.name] = {"exit": rc, "accept": accept, "case_context": record,
                               "log": str(log.relative_to(out)), "log_sha256": sha(log)}
    if len(checks) != package["expected"]["encoder_fixtures"]:
        raise GateError("encoder fixture count changed")
    src = candidate / "formal/source"
    ov = src / "vocabulary/ObservationVocabulary.dfy"
    p1 = proof(out, dafny, ov, 0, package["expected"]["observation_vocabulary"][0],
               "proof-observation-vocabulary", timeout=600)
    p2 = proof(out, dafny, src / "SourceTrace.dfy", 0, package["expected"]["source_trace"][0],
               "proof-source-trace", timeout=600)
    bridge = pkg / "bridge/SourceTraceBridge.dfy"
    p3 = proof(out, dafny, bridge, 0, package["expected"]["source_trace_bridge"][0],
               "proof-source-trace-bridge", timeout=900, extra=["--verify-included-files"])
    audits = {}
    for entry in (ov, src / "SourceTrace.dfy", bridge):
        log = out / "logs" / "audit" / (entry.name + ".log")
        cmd = [dafny, "audit", entry]
        prefix, record = case_context("audit-" + entry.name, entry, cmd, entry.parent)
        rc, text, _ = run(cmd, log, cwd=entry.parent, timeout=300, prefix=prefix)
        record = finish_context(record, entry)
        if rc != 0 or "Dafny auditor completed with 0 findings" not in text:
            raise GateError("audit regression " + entry.name)
        audits[entry.name] = {"exit": rc, "case_context": record,
                              "log": str(log.relative_to(out)), "log_sha256": sha(log)}
    mut = out / "constant-branch" / "source"
    shutil.copytree(src, mut)
    st = mut / "SourceTrace.dfy"
    text = read(st)
    anchor = "{ O.Encode(O.Branch(site, taken)) }"
    if text.count(anchor) != 1:
        raise GateError("constant branch mutant anchor changed")
    st.write_text(text.replace(anchor, "{ O.Encode(O.Branch(site, false)) }", 1))
    mb = mut / "SourceTraceBridge.dfy"
    mb.write_text(read(bridge).replace('include "../../SourceTrace.dfy"', 'include "SourceTrace.dfy"', 1))
    mutant = proof(out, dafny, mb, 0, package["expected"]["constant_branch_mutant"][0],
                   "constant-branch-bridge", allow_errors=2, expect_exit=4, timeout=900,
                   cwd=mut, extra=["--verify-included-files"], case="constant-branch-bridge")
    mtext = read(out / mutant["log"])
    if "BranchFalseNotTrue" not in mtext or "postcondition could not be proved" not in mtext:
        raise GateError("constant branch mutant did not fail at named bridge")
    return {"fixtures": checks, "proofs": [p1, p2, p3], "audits": audits, "constant_branch": mutant}


def retained_workspace(pkg, out):
    """Copy the retained fixture to a fresh workspace under --output (never in-tree)."""
    src = pkg / "fixtures/retained-native"
    work = Path(out) / "retained-native"
    fixture = work / "fixture"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(src, fixture, ignore=shutil.ignore_patterns("work", "__pycache__", "*.pyc"))
    return src, fixture


def verify_retained_report(rep, package, profile, baseline13_log=None):
    """The retained report must bind the reviewed profile/checker and its 13 roots."""
    if rep.get("status") != "complete":
        raise GateError("retained Native report is not complete")
    baseline13 = rep.get("baseline13")
    if not isinstance(baseline13, dict):
        raise GateError("retained Native baseline13 record missing")
    if baseline13.get("exit") != 0 or baseline13.get("status") != "SOURCE-COVERAGE OK":
        raise GateError("retained Native baseline13 did not report the named coverage result")
    if package.get("expected", {}).get("baseline13_roots") != len(EXPECTED_BASELINE13_ROOTS):
        raise GateError("package baseline13 expectation missing or changed")
    if baseline13_log is None:
        raise GateError("retained Native baseline13 raw log missing")
    roots = parse_baseline13_roots(baseline13_log)
    if len(roots) != package["expected"]["baseline13_roots"]:
        raise GateError("retained Native baseline13 root count changed")
    if len(rep.get("root19", {})) != package["expected"]["retained_root19_cases"]:
        raise GateError("retained Native root19 case count changed")
    if len(rep.get("callbinding", {})) != package["expected"]["retained_callbinding_cases"]:
        raise GateError("retained Native callbinding case count changed")
    if rep.get("pins_before") != rep.get("pins_after"):
        raise GateError("retained Native pins changed")
    if rep.get("plugin_sha256") != profile["checker_dll_expected_sha256"]:
        raise GateError("retained Native checker plugin does not match the reviewed profile")
    if rep.get("checker_source_sha256") != package["checker_source_sha256"]:
        raise GateError("retained Native checker source does not match the package pin")
    if rep.get("checker_project_sha256") != package["checker_project_sha256"]:
        raise GateError("retained Native checker project does not match the package pin")
    if rep.get("canonical_policy_sha256") != package["checker_policy_sha256"]:
        raise GateError("retained Native canonical policy does not match the package pin")
    return rep


def retained_native(pkg, out, dafny, dotnet, package, profile):
    """Run the retained fixture in a fresh copy under --output (never in the package)."""
    src, fixture = retained_workspace(pkg, out)
    log = out / "logs" / "retained-native" / "run.log"
    cmd = [sys.executable, "run.py", "--dafny", dafny, "--dotnet", dotnet]
    child_env = {k: v for k, v in os.environ.items() if not k.startswith("SOURCE_TRACE_")}
    rc, text, _ = run(cmd, log, cwd=fixture, timeout=1800, env=child_env,
                      prefix=("CASE-CONTEXT case=retained-native argv=" +
                              json.dumps([str(c) for c in cmd], separators=(",", ":")) +
                              " cwd=" + str(fixture) + "\n"))
    rep_path = fixture / "report.json"
    if rc != 0 or not rep_path.is_file():
        raise GateError("retained Native replay failed")
    baseline13_log = fixture / "work" / "baseline13.log"
    if not baseline13_log.is_file():
        raise GateError("retained Native baseline13 raw log missing")
    rep = verify_retained_report(json.loads(read(rep_path)), package, profile,
                                 read(baseline13_log))
    package_work = src / "work"
    if package_work.exists():
        raise GateError("package retained work directory appeared after replay")
    return {"exit": rc, "workspace": str(fixture.relative_to(out)),
            "report": str(rep_path.relative_to(out)), "report_sha256": sha(rep_path),
            "status": rep["status"], "plugin_sha256": rep["plugin_sha256"],
            "checker_source_sha256": rep["checker_source_sha256"],
            "checker_project_sha256": rep["checker_project_sha256"],
            "canonical_policy_sha256": rep["canonical_policy_sha256"],
            "baseline13": {"exit": 0, "status": "SOURCE-COVERAGE OK",
                           "count": len(EXPECTED_BASELINE13_ROOTS),
                           "roots": list(EXPECTED_BASELINE13_ROOTS),
                           "log": str(baseline13_log.relative_to(out)),
                           "log_sha256": sha(baseline13_log)},
            "root19_count": len(rep["root19"]), "callbinding_count": len(rep["callbinding"]),
            "root19_accepts": [k for k, v in rep["root19"].items() if v.get("exit") == 0],
            "callbinding_accepts": [k for k, v in rep["callbinding"].items() if v.get("exit") == 0],
            "log": str(log.relative_to(out)), "log_sha256": sha(log)}


def reviewed_runtime_sha(profile):
    """Return the reviewed Maven runtime identity from the tool profile.

    Tool identities live only in ``profiles/<name>.json``; the immutable package
    manifest is a source/proof contract and deliberately carries no tool hashes.
    A missing or malformed profile value is a gate failure, never a fallback.
    """
    if not isinstance(profile, dict):
        raise GateError("missing reviewed tool profile for codegen runtime identity")
    value = profile.get("runtime_sha256")
    if not value:
        raise GateError("tool profile missing runtime_sha256 for codegen")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise GateError("malformed tool profile runtime_sha256: " + repr(value))
    return value


def codegen(candidate, baseline, pkg, out, dafny, runtime, jdk21, jdk25, package, profile):
    expected_runtime = reviewed_runtime_sha(profile)
    if sha(runtime) != expected_runtime:
        raise GateError("Maven runtime hash mismatch")
    base = out / "codegen" / "base-formal"
    ov = out / "codegen" / "overlay-formal"
    for dst, native in ((base, baseline / "formal/crypto/NativeMlKem.dfy"),
                        (ov, candidate / "formal/crypto/NativeMlKem.dfy")):
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(candidate / "formal", dst)
        shutil.copy2(native, dst / "crypto/NativeMlKem.dfy")
    gen = {}
    for label, tree in (("base", base), ("overlay", ov)):
        log = out / "logs" / "codegen" / (label + "-translate.log")
        rc, text, _ = run([dafny, "translate", "java", "NativeMlKem.dfy", "--no-verify", "--allow-external-contracts",
                           "-o", out / "codegen" / ("gen-" + label),
                           "--outer-module", "io.github.mahmoudimus.quic.internal.verifiedcrypto"],
                          log, cwd=tree / "crypto", timeout=600)
        if rc != 0 or BAD.search(text):
            raise GateError("Java translation failed " + label)
        gen[label] = {"exit": rc, "log": str(log.relative_to(out)), "log_sha256": sha(log)}
    for label in ("base", "overlay"):
        root = out / "codegen" / ("gen-" + label + "-java")
        pdir = root / "io/github/mahmoudimus/verifiedcrypto"
        pdir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate / "formal/crypto/native_kem_hash.java", pdir / "native_kem_hash.java")
    def alg_hash(root):
        rows = []
        for p in sorted(Path(root).rglob("*.java")):
            if p.name in ("gen_base.java", "gen_overlay.java"):
                continue
            rows.append(str(p.relative_to(root)) + " " + sha(p))
        return hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest(), len(rows)
    ah, ac = alg_hash(out / "codegen/gen-base-java")
    oh, oc = alg_hash(out / "codegen/gen-overlay-java")
    if ah != oh or ac != oc:
        raise GateError("algorithm Java identity changed")
    classes = {}
    for label_jdk, home in (("21", jdk21), ("25", jdk25)):
        for label in ("base", "overlay"):
            tree = out / "codegen" / ("gen-" + label + "-java")
            cl = out / "codegen" / ("classes-" + label + "-jdk" + label_jdk)
            if cl.exists():
                shutil.rmtree(cl)
            cl.mkdir(parents=True)
            sources = [str(p) for p in tree.rglob("*.java")]
            log = out / "logs" / "codegen" / ("javac" + label_jdk + "-" + label + ".log")
            rc, text, _ = run([home + "/bin/javac", "-cp", runtime, "-d", cl] + sources, log, timeout=600)
            if rc != 0 or BAD.search(text):
                raise GateError("javac failed JDK" + label_jdk + " " + label)
        def class_hash(root):
            rows = [str(p.relative_to(root)) + " " + sha(p) for p in sorted(Path(root).rglob("*.class"))]
            return hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest(), len(rows)
        bh, bn = class_hash(out / ("codegen/classes-base-jdk" + label_jdk))
        oh2, on = class_hash(out / ("codegen/classes-overlay-jdk" + label_jdk))
        if bh != oh2 or bn != on:
            raise GateError("class identity changed JDK" + label_jdk)
        classes[label_jdk] = {"count": bn, "identity": True}
        if bn != package["expected"]["jdk_classes"]:
            raise GateError("JDK class count changed on JDK" + label_jdk + ": " + str(bn))
    return {"java_algorithm_files": ac, "java_identity": True, "classes": classes,
            "driver_excluded": True, "translations": gen}


def native_kem_checks(candidate, out, dafny, runtime, jdk21, jdk25):
    script = candidate / "formal/crypto/native_kem_checks.py"
    log = out / "logs" / "native-kem-checks.log"
    cmd = [sys.executable, script, "--scope", "full", "--output", out / "native-kem-current",
           "--dafny", dafny, "--runtime", runtime,
           "--java-home", jdk21, "--java-home", jdk25]
    rc, text, _ = run(cmd, log, cwd=candidate, timeout=3600)
    if rc != 0 or "PASS full native KEM replay" not in text or BAD.search(text):
        raise GateError("native_kem_checks full replay failed")
    return {"exit": rc, "log": str(log.relative_to(out)), "log_sha256": sha(log),
            "output": str((out / "native-kem-current").relative_to(out))}


def validate_cli(args):
    if args.checker_dll and not args.self_test_only:
        raise GateError("--checker-dll is only allowed with --self-test-only (never a qualification)")
    if args.self_test_only:
        if not args.checker_dll or not args.expected_checker_dll_sha256:
            raise GateError("--self-test-only requires --checker-dll and --expected-checker-dll-sha256")
        if args.mode == "full" or args.native_kem_checks:
            raise GateError("--self-test-only cannot be combined with full qualification options")
    else:
        if args.expected_checker_dll_sha256:
            raise GateError("--expected-checker-dll-sha256 is only meaningful with --self-test-only")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--package-root", default=str(Path(__file__).resolve().parent))
    ap.add_argument("--baseline-root", default=None)
    ap.add_argument("--output", required=True)
    ap.add_argument("--tool-profile", required=True,
                    help="named profile from profiles/index.json, or a path (needs --expected-profile-sha256)")
    ap.add_argument("--expected-profile-sha256", default=None)
    ap.add_argument("--expected-package-sha256", required=True)
    ap.add_argument("--dafny", required=True)
    ap.add_argument("--dotnet", required=True)
    ap.add_argument("--jdk21", required=True)
    ap.add_argument("--jdk25", required=True)
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--mode", choices=["targeted", "full"], default="targeted")
    ap.add_argument("--native-kem-checks", action="store_true")
    ap.add_argument("--checker-dll", default=None)
    ap.add_argument("--self-test-only", action="store_true")
    ap.add_argument("--expected-checker-dll-sha256", default=None)
    args = ap.parse_args(argv)
    validate_cli(args)
    pkg = Path(args.package_root).resolve()
    candidate = pkg.parents[2]
    baseline = Path(args.baseline_root).resolve() if args.baseline_root else candidate.parent / "baseline-git-155b"
    # Admit the *unresolved* output path: a dangling symlink is refused without
    # following it, so no target directory/file is ever created.
    try:
        out = prepare_output(Path(args.output))
    except GateError as e:
        print(json.dumps({"schema": REPORT_SCHEMA, "status": "rejected",
                          "failure_kind": "output-admission", "error": str(e)}, sort_keys=True),
              file=sys.stderr)
        return 2
    case_contexts = {}
    report = {"schema": REPORT_SCHEMA, "mode": "self-test" if args.self_test_only else args.mode,
              "qualification": not args.self_test_only,
              "package_root": str(pkg), "candidate_root": str(candidate),
              "baseline_root": str(baseline), "output": str(out),
              "tools": {"dafny": args.dafny, "dotnet": args.dotnet, "jdk21": args.jdk21,
                        "jdk25": args.jdk25, "runtime": args.runtime},
              "case_contexts": case_contexts, "invocation_argv": sys.argv,
              "status": "incomplete"}
    report_path = out / "package-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    try:
        package = verify_package(pkg, args.expected_package_sha256)
        profile, profile_identity = load_profile(pkg, args.tool_profile, args.expected_profile_sha256,
                                                 host_platform())
        report["package_sha256"] = sha(pkg / "package.json")
        report["profile"] = profile_identity
        report["inputs"] = {k: package[k] for k in
                            ("schema", "scope", "ambient_selector_policy", "candidate_overlay_sha256",
                             "baseline_native_mlkem_sha256", "expected", "native_kem_patch")}
        man = verify_manifest(pkg, candidate, baseline, package)
        signature_before = input_signature(pkg, candidate, baseline, man, package, profile_identity)
        report["manifest"] = {"git_commit": man["git_commit"], "git_tree": man["git_tree"],
                              "baseline_formal_files": len(man["baseline_formal_dafny_hashes"]),
                              "candidate_formal_files": len(man["candidate_formal_dafny_hashes_excluding_select_package"]),
                              "declared_formal_diff": man["candidate_allowed_formal_diff"],
                              "package_files": len(man["package_files"]),
                              "controls": len(man["controls"])}
        report["tool_identity_before"] = verify_tools(args.dafny, args.dotnet, args.jdk21,
                                                      args.jdk25, args.runtime, out, profile,
                                                      profile_identity["sha256"], "before")
        dll, build = build_checker(pkg, out, args.dotnet, args.dafny, profile,
                                   args.checker_dll, args.self_test_only,
                                   args.expected_checker_dll_sha256)
        report["checker"] = build
        if args.self_test_only:
            report["status"] = "self-test"
            report["note"] = "non-qualifying explicit-DLL self-test; no semantic stages executed"
            (out / "package-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            print("Self-test (non-qualifying):", out / "package-report.json")
            return 0
        cases = {}
        for cdir in sorted((pkg / "controls").iterdir()):
            if cdir.is_dir() and (cdir / "meta.json").is_file():
                cases[cdir.name] = checker_case(candidate, pkg, out, args.dafny, dll, cdir.name, package)
        report["controls"] = cases
        for k, v in cases.items():
            case_contexts[k] = v["case_context"]
        report["harness"] = proof(out, args.dafny, pkg / "harness/SelectTraceHarness.dfy", 0,
                                  package["expected"]["select_harness"][0], "select-harness", timeout=900)
        report["observed"] = observed_case(candidate, pkg, out, args.dafny, dll, package)
        case_contexts["observed"] = report["observed"]["checker"]["case_context"]
        case_contexts["observed-mutant-method"] = report["observed"]["method"]["case_context"]
        case_contexts["observed-mutant-harness"] = report["observed"]["harness"]["case_context"]
        report["f2"] = {"coverage_accept": cases["coverage-private-loop-bound"]}
        f2tree = prepare_tree(candidate, out, "f2-private-loop-bound")
        shutil.copy2(pkg / "controls/coverage-private-loop-bound/NativeMlKem.dfy", f2tree / "crypto/NativeMlKem.dfy")
        report["f2"]["dafny_full"] = proof(out, args.dafny, f2tree / "crypto/NativeMlKem.dfy", 3,
                                           package["expected"]["private_loop_bound_full"][0],
                                           "f2-private-loop-bound-full", allow_errors=1, expect_exit=4, timeout=1200)
        case_contexts["f2-private-loop-bound-full"] = report["f2"]["dafny_full"]["case_context"]
        if "this loop invariant could not be proved on entry" not in read(out / report["f2"]["dafny_full"]["log"]):
            raise GateError("F2 proof did not fail at named invariant")
        report["encoder"] = encoder_replay(candidate, pkg, out, args.dafny, dll, package)
        for k, v in report["encoder"]["fixtures"].items():
            case_contexts["encoder-" + k] = v["case_context"]
        for p in report["encoder"]["proofs"]:
            case_contexts[p["label"]] = p["case_context"]
        for k, v in report["encoder"]["audits"].items():
            case_contexts["audit-" + k] = v["case_context"]
        case_contexts["constant-branch-bridge"] = report["encoder"]["constant_branch"]["case_context"]
        if args.mode == "full":
            report["full_native_mlkem"] = proof(out, args.dafny, candidate / "formal/crypto/NativeMlKem.dfy", 3,
                                                package["expected"]["full_native_mlkem"][0], "full-native-mlkem", timeout=2400)
            case_contexts["full-native-mlkem"] = report["full_native_mlkem"]["case_context"]
            report["retained_native"] = retained_native(pkg, out, args.dafny, args.dotnet,
                                                        package, profile)
            report["codegen"] = codegen(candidate, baseline, pkg, out, args.dafny, args.runtime,
                                        args.jdk21, args.jdk25, package, profile)
            if args.native_kem_checks:
                report["native_kem_checks"] = native_kem_checks(candidate, out, args.dafny,
                                                                args.runtime, args.jdk21, args.jdk25)
        report["tool_identity_after"] = verify_tools(args.dafny, args.dotnet, args.jdk21,
                                                     args.jdk25, args.runtime, out, profile,
                                                     profile_identity["sha256"], "after")
        man_after = verify_manifest(pkg, candidate, baseline, package)
        signature_after = input_signature(pkg, candidate, baseline, man_after, package, profile_identity)
        if signature_after != signature_before:
            raise GateError("package/profile/used inputs changed during replay")
        report["input_signature"] = {
            "files": {"baseline_dafny": len(signature_before["baseline_dafny"]),
                      "dafny": len(signature_before["dafny"]),
                      "package": len(signature_before["package"]),
                      "used_inputs": len(signature_before["used_inputs"])},
            "profile_sha256": signature_before["profile_sha256"], "stable": True}
        if sha(pkg / "package.json") != args.expected_package_sha256:
            raise GateError("package manifest changed during replay")
        if sha(candidate / "formal/crypto/NativeMlKem.dfy") != package["candidate_overlay_sha256"]:
            raise GateError("candidate source changed during replay")
        report["status"] = "complete"
    except GateError as e:
        report["status"] = "FAILED"; report["error"] = str(e)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("FAILED: " + str(e), file=sys.stderr)
        return 2
    except Exception as e:  # unexpected runner/helper defect: fail closed, never "complete"
        report["status"] = "FAILED"
        report["failure_kind"] = "runner-exception"
        report["error_type"] = type(e).__name__
        report["error"] = str(e)
        report["traceback"] = traceback.format_exc()
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("FAILED (runner-exception: " + type(e).__name__ + "): " + str(e), file=sys.stderr)
        return 2
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Complete:", out / "package-report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
