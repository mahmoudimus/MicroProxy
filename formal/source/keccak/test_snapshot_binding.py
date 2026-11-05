#!/usr/bin/env python3
"""Focused Task 1 pure-snapshot binding gate.

This runner is deliberately non-qualifying.  It materialises the pinned Dafny
source closure from Git objects, applies the reviewed run-002 patch, builds the
new resolved-AST checker outside the Git ancestry, and runs the actual Dafny
resolver over the frozen SnapshotBindingControls fixture and typed negative
mutations.  It also preserves the historical Select checker's rejection of the
existing registered Keccak call-binding controls (not new-root admission).

Usage:
  python3 formal/source/keccak/test_snapshot_binding.py --output /abs/new/dir

The output directory must not exist.  An existing path (including a symlink or
dangling symlink) is rejected without writes.  The report is always typed and
always says qualification:false.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
import posixpath
from pathlib import Path

# ---------------------------------------------------------------------------
# Frozen identities and inputs
# ---------------------------------------------------------------------------

PINNED_COMMIT = "d8d4a778afbdd63b39c3e5e09d203c278f0d5748"
NATIVE_BASIS_SHA = "6d152fe99d6a483912e67daa6117ca9384a69c5ffa8bcbbc50f2a45dc18d8e63"
NATIVE_CANDIDATE_SHA = "98bc614b535c4f564f3806fa091574112590c2569cdd7e2ad41d7ec3c111c44c"
CANDIDATE_PATCH_SHA = "a9b05598a63b84d47f26602907c23fe4b6ce309800bd1e7831c6f14d12806044"
BINDING_SHA = "45e56752b26d541a6768d2b3f7450a4a4e20f96055a81a908cfc4510d9c0e7b7"
BRIDGE_SHA = "cb4f2d2d9ee94cee0d1354fae405aab7e0b9909bdff9888fa85c824358d99d5d"
PINNED_PATHS = (
    "formal/crypto/NativeKeccak.dfy",
    "formal/crypto/NativeTypes.dfy",
    "formal/primitives/Keccak.dfy",
    "formal/source/SourceTrace.dfy",
    "formal/source/vocabulary/ObservationVocabulary.dfy",
)
BINDING_REL = "formal/source/keccak/controls/SnapshotBindingControls.dfy"
BRIDGE_REL = "formal/source/keccak/controls/SnapshotValueBridge.dfy"
CHECKER_REL = "formal/source/keccak/checker/PureSnapshotCoverage.cs"
CHECKER_PROJ_REL = "formal/source/keccak/checker/PureSnapshotCoverage.csproj"
RUNNER_REL = "formal/source/keccak/test_snapshot_binding.py"
RUNNER_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
OLD_CHECKER_DIR = "formal/source/select/checker"
OLD_CHECKER_FILES = ("SourceCoverage.cs", "SourceCoverage.csproj", "NativeCanonicalEncoderPolicy.cs")
PROFILE_REL = "formal/source/select/profiles/macos-sdk10.0.400.json"
PROFILE_SHA = "9ec9f05ce8dd1083071e6fc0aecea69d9972abe7d94ca8e7be0266c032e99f84"
DAFNY = None
DOTNET = None
OLD_FIXTURE_REL = "formal/source/select/fixtures/retained-native"
OLD_ROOTS = ("NativeField.ReduceOnce,NativeField.Reduce,NativeField.Add,NativeField.Sub,NativeField.Mul,"
             "NativeField.MulSub,NativeField.AddMul,NativeKeccak.SetLane,NativeKeccak.Iota,"
             "NativeKeccak.Theta,NativeKeccak.RhoPi,NativeKeccak.Chi,NativeKeccak.Wipe")
SUCCESS_LINE = ("PURE-SNAPSHOT-BINDING OK: exact roots "
                "[SnapshotBindingControls.Local,SnapshotBindingControls.ArrayRead,SnapshotBindingControls.Around]")
ROOT_LINE = "PURE-SNAPSHOT-BINDING ROOT OK: "
ROOTS = ("SnapshotBindingControls.Local", "SnapshotBindingControls.ArrayRead", "SnapshotBindingControls.Around")
GENERIC_BAD = re.compile(
    r"parse[rd]? errors? detected|Error: unresolved identifier|"
    r"Error: incorrect argument type|Error: wrong number of arguments|Error: this expression has type|"
    r"timed?\s*out|out of resource|out of memory|internal error|unhandled exception|CLI: Error", re.I)

# The exact reviewed run-002 patch.  The runner applies this text itself, rather
# than depending on the author's cache or on a mutable working tree.
CANDIDATE_PATCH = """--- baseline/formal/crypto/NativeKeccak.dfy
+++ candidate/formal/crypto/NativeKeccak.dfy
@@ -1,15 +1,21 @@
 include "NativeTypes.dfy"
 include "../primitives/Keccak.dfy"
+include "../source/SourceTrace.dfy"
\x20
 // Array refinement of the FIPS202 permutation. All runtime indices are native
 // signed Java ints with their bounds verified; values are native bv64 longs.
 module NativeKeccak {
   import T = NativeTypes
   import S = KeccakSpec
-  function Rotate(v: bv64, n: T.I): bv64
+  import ST = SourceTrace
+  ghost function RotateTrace(n: T.I): seq<int>
+  { ST.Branch(30,n == 0) + (if n == 0 then [] else ST.Ops(0,1,0,0,0,1,2)) }
+  function Rotate(v: bv64, n: T.I): (bv64, ghost seq<int>)
     requires 0 <= n < 64
-    ensures Rotate(v,n) == S.Rotate(v,n as int)
-  { if n == 0 then v else (v << n) | (v >> (64-n)) }
+    ensures Rotate(v,n).0 == S.Rotate(v,n as int)
+    ensures Rotate(v,n).1 == RotateTrace(n)
+  { if n == 0 then (v, ghost ST.Branch(30,true))
+    else ((v << n) | (v >> (64-n)), ghost ST.Branch(30,false) + ST.Ops(0,1,0,0,0,1,2)) }
   function Constant(i: T.I): bv64
     requires 0 <= i < 24
     ensures Constant(i) == S.Constants()[i]
@@ -150,7 +156,8 @@
       invariant forall k: int :: 0 <= k < 25 && k%5 < x as int ==> a[k] == S.Theta(start)[k]
       invariant forall k: int :: 0 <= k < 25 && x as int <= k%5 ==> a[k] == start[k]
     {
-      var d := c[(x+4)%5] ^ Rotate(c[(x+1)%5],1);
+      ghost var rotateWitness := Rotate(c[(x+1)%5],1);
+      var d := c[(x+4)%5] ^ Rotate(c[(x+1)%5],1).0;
       for y: T.I := 0 to 5
         modifies a
         invariant forall k: int :: 0 <= k < 25 && (k%5 < x as int || (k%5 == x as int && k/5 < y as int)) ==> a[k] == S.Theta(start)[k]
@@ -184,7 +191,8 @@
       assert j as int == (((i as int)%5)+3*((i as int)/5))%5+5*((i as int)%5);
       assert 0 <= offsets[j] < 64;
       assert offsets[j] as int == S.Offsets()[j]%64;
-      b[i] := Rotate(a[j],offsets[j]);
+      ghost var rotateWitness := Rotate(a[j],offsets[j]);
+      b[i] := Rotate(a[j],offsets[j]).0;
     }
     assert b[..] == S.Pi(S.Rho(theta));
   }
"""

REPO_ROOT = Path(__file__).resolve().parents[3]

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()

def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def is_within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False

def read_text(path):
    return Path(path).read_text(encoding="utf-8")

def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def replace_exact(text, old, new, count=1):
    n = text.count(old)
    if count is not None and n != count:
        raise RuntimeError(f"mutation expected {count} occurrence(s), found {n}: {old[:80]!r}")
    if n == 0:
        raise RuntimeError(f"mutation text not found: {old[:80]!r}")
    return text.replace(old, new)

def apply_patch_to_text(text, patch):
    lines = text.splitlines(keepends=True)
    out = []
    cur = 0
    for line in patch.splitlines():
        if line.startswith("@@"):
            m = re.match(r"@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@", line)
            if not m:
                raise RuntimeError("malformed patch hunk: " + line)
            old_start = int(m.group(1))
            while cur < old_start - 1:
                out.append(lines[cur])
                cur += 1
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("+"):
            out.append(line[1:] + "\n")
        elif line.startswith("-"):
            cur += 1
        elif line.startswith(" "):
            out.append(lines[cur])
            cur += 1
        elif line.startswith("\\"):
            continue
        elif line == "":
            continue
        else:
            raise RuntimeError("unsupported patch line: " + repr(line))
    while cur < len(lines):
        out.append(lines[cur])
        cur += 1
    return "".join(out)

def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("SOURCE_TRACE_") and k not in {"DAFNY_PLUGIN", "DAFNY_PLUGINS"}}
    if extra:
        env.update(extra)
    return env

class GateError(Exception):
    pass

# ---------------------------------------------------------------------------
# Output admission and safe writing
# ---------------------------------------------------------------------------

def output_admission_error(output):
    """Return a typed explanation if output may not be used; never writes."""
    p = Path(output)
    if not p.is_absolute():
        return "output path must be absolute"
    try:
        resolved = p.resolve(strict=False)
    except OSError as exc:
        return "output path cannot be resolved: " + str(exc)
    if resolved == REPO_ROOT or is_within(resolved, REPO_ROOT):
        return "output path is inside the Git ancestry/repository"
    if any(os.path.lexists(parent / ".git") for parent in resolved.parents):
        return "output path has a Git worktree ancestor"
    if os.path.lexists(p):
        return "output path already exists (file, directory or symlink); refusing to mutate it"
    # Every existing ancestor must be a real directory, not a symlink.
    cursor = Path(p.anchor)
    for part in p.parts[1:]:
        cursor = cursor / part
        if os.path.islink(cursor):
            return "output path has a symlink ancestor: " + str(cursor)
        if not cursor.exists():
            break
        if cursor == p:
            return "output path already exists"
    parent = p.parent
    if not parent.exists():
        # create only missing real directories below a checked ancestor
        pass
    return None

def write_json(path, obj):
    write_text(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")

# ---------------------------------------------------------------------------
# Toolchain and source staging
# ---------------------------------------------------------------------------

def tool_record(path, expected=None):
    path = Path(path)
    if not path.exists():
        raise GateError("required tool is absent: " + str(path))
    resolved = path.resolve()
    if not resolved.is_file():
        raise GateError("required tool is not a file: " + str(path))
    rec = {"path": str(path), "resolved": str(resolved), "sha256": sha_file(resolved)}
    if expected is not None:
        rec["expected_sha256"] = expected
        rec["match"] = rec["sha256"] == expected
    return rec

def freeze_toolchain(out):
    profile_path = REPO_ROOT / PROFILE_REL
    if not profile_path.is_file() or sha_file(profile_path) != PROFILE_SHA:
        raise GateError("mandatory reviewed tool profile is missing or changed")
    profile_bytes = git_blob(PROFILE_REL)
    if sha_bytes(profile_bytes) != PROFILE_SHA or profile_path.read_bytes() != profile_bytes:
        raise GateError("tool profile differs from the immutable Git identity")
    profile = json.loads(profile_bytes)
    mandatory = {"schema", "platform", "dafny_version", "dotnet_sdk", "dafny_sha256",
                 "dafny_core_sha256", "dotnet_launcher_sha256", "boogie", "checker_dll_expected_sha256"}
    if not mandatory <= set(profile) or profile["schema"] != "microproxy.select-tool-profile/2":
        raise GateError("mandatory tool profile schema/keys missing")
    if profile["platform"] != "macos-arm64" or profile["dafny_version"] != "4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2" or profile["dotnet_sdk"] != "10.0.400":
        raise GateError("unsupported reviewed tool profile")
    if not isinstance(profile["boogie"], dict) or len(profile["boogie"]) != 13:
        raise GateError("mandatory reviewed Boogie inventory changed")
    expected = {"dafny": (DAFNY, profile["dafny_sha256"]),
                "dafny_core": (DAFNY.parent / "DafnyCore.dll", profile["dafny_core_sha256"]),
                "dotnet": (DOTNET, profile["dotnet_launcher_sha256"])}
    expected.update({"boogie/" + name: (DAFNY.parent / name, digest)
                     for name, digest in sorted(profile["boogie"].items())})
    records = {}
    for label, (path, digest) in expected.items():
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise GateError("missing tool hash: " + label)
        records[label] = tool_record(path, digest)
        if not records[label]["match"]:
            raise GateError("tool identity mismatch: " + label)
    versions = {}
    for label, argv, version in [("dafny", [str(DAFNY), "--version"], profile["dafny_version"]),
                                 ("dotnet", [str(DOTNET), "--version"], "10.0.400")]:
        rec = run_command(argv, out, out / "logs" / (label + "-version"), clean_env(), timeout=60)
        if rec["exit"] != 0 or rec["stdout"].strip() != version:
            raise GateError("unexpected pinned tool version: " + label)
        versions[label] = rec
    return {"profile_path": str(profile_path), "profile_sha256": PROFILE_SHA,
            "profile_commit": PINNED_COMMIT, "files_before": records, "versions": versions,
            "old_checker_expected_sha256": profile["checker_dll_expected_sha256"],
            "solver": "not invoked: resolver-only binding tests"}

def verify_tools_unchanged(toolchain):
    after = {}
    for label, before in toolchain["files_before"].items():
        record = tool_record(before["path"], before["expected_sha256"])
        if not record["match"] or record["resolved"] != before["resolved"]:
            raise GateError("used tool changed during replay: " + label)
        after[label] = record
    if sha_file(REPO_ROOT / PROFILE_REL) != PROFILE_SHA:
        raise GateError("reviewed profile changed during replay")
    return after

def git_blob(path):
    cp = subprocess.run(["/usr/bin/git", "-C", str(REPO_ROOT), "cat-file", "blob", f"{PINNED_COMMIT}:{path}"],
                        capture_output=True, env=clean_env())
    if cp.returncode != 0:
        raise GateError(f"cannot read pinned Git blob {PINNED_COMMIT}:{path}: " + cp.stderr.decode(errors="replace"))
    return cp.stdout

def include_paths(text):
    return re.findall(r'^\s*include\s+"([^"]+)"', text, re.M)

def stage_sources(out):
    tree = out / "stage"
    tree.mkdir(parents=True)
    origins = {}
    # Verify the pin before reading any blob.
    cp = subprocess.run(["/usr/bin/git", "-C", str(REPO_ROOT), "cat-file", "-e", PINNED_COMMIT + "^{commit}"],
                        capture_output=True, env=clean_env())
    if cp.returncode != 0:
        raise GateError("pinned Git commit is unavailable: " + PINNED_COMMIT)
    for rel in PINNED_PATHS:
        data = git_blob(rel)
        dest = tree / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        origins[rel] = {"origin": "git-blob", "commit": PINNED_COMMIT, "sha256": sha_file(dest)}

    basis_path = tree / "formal/crypto/NativeKeccak.dfy"
    if sha_file(basis_path) != NATIVE_BASIS_SHA:
        raise GateError("pinned NativeKeccak basis hash mismatch")
    if sha_bytes(CANDIDATE_PATCH.encode()) != CANDIDATE_PATCH_SHA:
        raise GateError("embedded candidate patch hash mismatch")
    patched = apply_patch_to_text(read_text(basis_path), CANDIDATE_PATCH)
    write_text(basis_path, patched)
    if sha_file(basis_path) != NATIVE_CANDIDATE_SHA:
        raise GateError("patched NativeKeccak candidate hash mismatch")
    origins["formal/crypto/NativeKeccak.dfy"] = {
        "origin": "git-blob+reviewed-patch", "commit": PINNED_COMMIT,
        "patch_sha256": CANDIDATE_PATCH_SHA, "sha256": sha_file(basis_path)}

    for name in OLD_CHECKER_FILES:
        rel = OLD_CHECKER_DIR + "/" + name
        data = git_blob(rel)
        write_text(tree / rel, data.decode())
        origins[rel] = {"origin": "git-blob", "commit": PINNED_COMMIT, "sha256": sha_bytes(data)}
    profile_bytes = git_blob(PROFILE_REL)
    write_text(tree / PROFILE_REL, profile_bytes.decode())
    origins[PROFILE_REL] = {"origin": "git-blob", "commit": PINNED_COMMIT, "sha256": sha_bytes(profile_bytes)}
    old_base = OLD_FIXTURE_REL + "/source-fixtures/formal/"
    pending_old = [old_base + "source/AllTraceRoots.dfy"]
    while pending_old:
        rel = pending_old.pop()
        if rel in origins:
            continue
        if not rel.startswith(old_base):
            raise GateError("retained source include escapes authenticated fixture")
        data = git_blob(rel)
        write_text(tree / rel, data.decode())
        origins[rel] = {"origin": "git-blob", "commit": PINNED_COMMIT, "sha256": sha_bytes(data)}
        for inc in include_paths(data.decode()):
            pending_old.append(posixpath.normpath(posixpath.join(posixpath.dirname(rel), inc)))
    for case in ("pure-call-inline-projection", "pure-call-forged-ghost-local"):
        rel = OLD_FIXTURE_REL + "/controls/callbinding/" + case + "/formal/crypto/NativeKeccak.dfy"
        data = git_blob(rel)
        write_text(tree / rel, data.decode())
        origins[rel] = {"origin": "git-blob", "commit": PINNED_COMMIT, "sha256": sha_bytes(data)}

    # Frozen current fixture and checker inputs (never the author's cache).
    # Keep fixture templates outside the production *.dfy inventory. Only the
    # fresh private stage materializes them as actual Dafny source files.
    for rel, source_rel, expected in (
            (BINDING_REL, BINDING_REL + ".in", BINDING_SHA),
            (BRIDGE_REL, BRIDGE_REL + ".in", BRIDGE_SHA),
            (CHECKER_REL, CHECKER_REL, None),
            (CHECKER_PROJ_REL, CHECKER_PROJ_REL, None),
            (RUNNER_REL, RUNNER_REL, RUNNER_SHA)):
        src = REPO_ROOT / source_rel
        if not src.is_file():
            raise GateError("frozen input is absent: " + rel)
        data = src.read_bytes()
        if expected is not None and sha_bytes(data) != expected:
            raise GateError("frozen input hash mismatch: " + rel)
        dest = tree / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        origins[rel] = {"origin": "frozen-repo-input", "source_path": source_rel,
                        "sha256": sha_file(dest)}

    # Authenticated include closure from the exact staged source.
    pending = [BINDING_REL, "formal/crypto/NativeKeccak.dfy"]
    seen = set()
    while pending:
        rel = pending.pop()
        if rel in seen:
            continue
        seen.add(rel)
        path = tree / rel
        if not path.is_file():
            raise GateError("include closure file is absent: " + rel)
        for inc in include_paths(read_text(path)):
            target = (path.parent / inc).resolve()
            if not is_within(target, tree.resolve()):
                raise GateError("include escapes the staged tree: " + inc + " from " + rel)
            trel = target.relative_to(tree.resolve()).as_posix()
            if trel not in origins:
                data = git_blob(trel)
                dest = tree / trel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                origins[trel] = {"origin": "git-blob", "commit": PINNED_COMMIT, "sha256": sha_file(dest)}
            pending.append(trel)

    # Reject symlinks and verify every closure file is pinned except the
    # reviewed candidate and frozen repo inputs.
    for path in sorted(tree.rglob("*")):
        if path.is_symlink():
            raise GateError("staged source contains a symlink: " + str(path.relative_to(tree)))
    for rel, rec in sorted(origins.items()):
        if rec["origin"] == "git-blob" and sha_file(tree / rel) != rec["sha256"]:
            raise GateError("staged source changed after materialisation: " + rel)
    before = {rel: sha_file(tree / rel) for rel in sorted(origins)}
    write_json(out / "stage-map-before.json", {"root": str(tree), "files": origins, "before": before})
    return tree, origins, before

def verify_stage_unchanged(tree, before, out):
    after = {rel: sha_file(tree / rel) for rel in sorted(before)}
    changed = {k: {"before": before[k], "after": after.get(k)} for k in before if after.get(k) != before[k]}
    extra = sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file() and
                   str(p.relative_to(tree)) not in before)
    write_json(out / "stage-map-after.json", {"root": str(tree), "after": after,
                                              "changed": changed, "extra_files": extra})
    if changed or extra:
        raise GateError("staged source changed during the run")
    return {"before": before, "after": after, "changed": changed, "extra_files": extra}

# ---------------------------------------------------------------------------
# C# builds and Dafny calls
# ---------------------------------------------------------------------------

def run_command(argv, cwd, log_base, env, timeout=240):
    log_base = Path(log_base)
    log_base.parent.mkdir(parents=True, exist_ok=True)
    stdout_path = log_base.with_suffix(".stdout")
    stderr_path = log_base.with_suffix(".stderr")
    combined_path = log_base.with_suffix(".log")
    try:
        cp = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                            env=env, timeout=timeout)
        timed_out = False
        stdout, stderr, rc = cp.stdout, cp.stderr, cp.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        rc = -1
    except FileNotFoundError as exc:
        raise GateError("tool is absent while running: " + " ".join(map(str, argv)) + ": " + str(exc))
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    combined = stdout + stderr
    combined_path.write_text(combined, encoding="utf-8")
    return {"argv": [str(a) for a in argv], "cwd": str(cwd), "exit": rc,
            "timed_out": timed_out,
            "stdout_sha256": sha_bytes(stdout.encode()), "stderr_sha256": sha_bytes(stderr.encode()),
            "log_sha256": sha_bytes(combined.encode()),
            "stdout_path": str(stdout_path), "stderr_path": str(stderr_path),
            "log_path": str(combined_path), "stdout": stdout, "stderr": stderr, "output": combined}

def build_checker(out, stage, source_rel, proj_rel, name):
    build = out / name
    build.mkdir(parents=True)
    names = [Path(source_rel).name, Path(proj_rel).name]
    for rel in [source_rel, proj_rel]:
        shutil.copy2(stage / rel, build / Path(rel).name)
    before = {n: sha_file(build / n) for n in names}
    cp = run_command([str(DOTNET), "build", "-v:q", Path(proj_rel).name,
                      "-p:DafnyHome=" + str(DAFNY.parent),
                      "-p:ImportDirectoryBuildProps=false",
                      "-p:ImportDirectoryBuildTargets=false"],
                     build, out / "logs" / (name + "-build"), clean_env())
    if cp["exit"] != 0:
        raise GateError(name + " build failed; see " + cp["log_path"])
    after = {n: sha_file(build / n) for n in names}
    if before != after:
        raise GateError(name + " build changed its inputs")
    dll = build / "bin/Debug/net6.0" / (Path(proj_rel).stem + ".dll")
    if not dll.is_file():
        raise GateError(name + " DLL is missing: " + str(dll))
    return dll, {"build": str(build), "inputs_before": before, "inputs_after": after,
                 "dll": str(dll), "dll_sha256": sha_file(dll), "command": cp}

def build_old_checker(out, stage):
    build = out / "old-checker-build"
    build.mkdir(parents=True)
    for name in OLD_CHECKER_FILES:
        shutil.copy2(stage / OLD_CHECKER_DIR / name, build / name)
    before = {n: sha_file(build / n) for n in OLD_CHECKER_FILES}
    cp = run_command([str(DOTNET), "build", "-v:q", "SourceCoverage.csproj",
                      "-p:DafnyHome=" + str(DAFNY.parent),
                      "-p:ImportDirectoryBuildProps=false",
                      "-p:ImportDirectoryBuildTargets=false"],
                     build, out / "logs" / "old-checker-build", clean_env())
    if cp["exit"] != 0:
        raise GateError("historical Select checker build failed; see " + cp["log_path"])
    after = {n: sha_file(build / n) for n in OLD_CHECKER_FILES}
    if before != after:
        raise GateError("historical Select checker inputs changed during build")
    dll = build / "bin/Debug/net6.0/SourceCoverage.dll"
    if not dll.is_file():
        raise GateError("historical Select checker DLL is missing")
    return dll, {"build": str(build), "inputs_before": before, "inputs_after": after,
                 "dll": str(dll), "dll_sha256": sha_file(dll), "command": cp}

def copy_tree(stage, dest):
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(stage, dest)
    return dest

def resolve_cmd(tree, dll=None):
    cwd = tree / "formal/source/keccak/controls"
    argv = [str(DAFNY), "resolve", "SnapshotBindingControls.dfy", "--allow-external-contracts"]
    if dll is not None:
        argv += ["--plugin", str(dll)]
    return cwd, argv

# ---------------------------------------------------------------------------
# Gate cases
# ---------------------------------------------------------------------------

class Gate:
    def __init__(self, out):
        self.out = Path(out)
        self.cases = []
        self.failures = 0

    def add(self, name, kind, ok, detail=None, **extra):
        rec = {"name": name, "kind": kind, "status": "passed" if ok else "failed"}
        if detail is not None:
            rec["detail"] = detail
        rec.update(extra)
        self.cases.append(rec)
        if not ok:
            self.failures += 1
        return rec

def run_old_checker_cases(gate, stage, old_dll, out):
    records = {}
    expectations = [("baseline13", 0, "SOURCE-COVERAGE OK"),
                    ("pure-call-inline-projection", 2, "registered pure call must be the direct RHS of one defining assignment"),
                    ("pure-call-forged-ghost-local", 2, "later trace update contains non-approved suffix expression")]
    for name, expected_exit, needle in expectations:
        tree = out / "trees" / ("old-" + name)
        shutil.copytree(stage / OLD_FIXTURE_REL / "source-fixtures/formal", tree / "formal")
        if name != "baseline13":
            shutil.copy2(stage / OLD_FIXTURE_REL / "controls/callbinding" / name / "formal/crypto/NativeKeccak.dfy",
                         tree / "formal/crypto/NativeKeccak.dfy")
        entry = tree / "formal/source/AllTraceRoots.dfy"
        plain = run_command([str(DAFNY), "resolve", str(entry), "--allow-external-contracts"], tree,
                            out / "logs/cases" / ("old-" + name + "-typecheck"), clean_env())
        rec = run_command([str(DAFNY), "resolve", str(entry), "--allow-external-contracts", "--plugin", str(old_dll)],
                          tree, out / "logs/cases" / ("old-" + name), clean_env({"SOURCE_TRACE_ROOTS": OLD_ROOTS}))
        ok = (plain["exit"] == 0 and not plain["timed_out"] and "Error:" not in plain["output"] and
              rec["exit"] == expected_exit and not rec["timed_out"] and
              not GENERIC_BAD.search(rec["output"]) and needle in rec["output"])
        gate.add("old-" + name, "old-checker", ok,
                 "preserved registered retained fixture; no new-protocol admission claim",
                 typed_resolution=plain, resolver=rec, expected_exit=expected_exit, needle=needle)
        records[name] = rec
    return records

def immutable_build_probe(gate, stage, out, original_inputs):
    global REPO_ROOT
    original_root = REPO_ROOT
    fake = out / "consumer-mutated-checkout"
    for rel in (CHECKER_REL, CHECKER_PROJ_REL):
        write_text(fake / rel, (stage / rel).read_text())
    write_text(fake / CHECKER_REL, "#error MUTABLE_CHECKOUT_B_MUST_NOT_BUILD\n")
    try:
        REPO_ROOT = fake
        _, record = build_checker(out, stage, CHECKER_REL, CHECKER_PROJ_REL, "consumer-frozen-build")
        ok = record["inputs_before"] == original_inputs == record["inputs_after"]
        gate.add("immutable-build-input-consumer", "provenance", ok,
                 "checkout B changed after freezing; actual build consumes frozen A",
                 mutable_checkout_sha256=sha_file(fake / CHECKER_REL), frozen_inputs=original_inputs, build=record)
    finally:
        REPO_ROOT = original_root

def run_positive_cases(gate, stage, new_dll, out, env_extra=None, suffix=""):
    name = "positive" + suffix
    tree = copy_tree(stage, out / "trees" / name)
    cwd, argv = resolve_cmd(tree, new_dll)
    rec = run_command(argv, cwd, out / "logs/cases" / name, clean_env(env_extra))
    good = (rec["exit"] == 0 and not rec["timed_out"] and
            rec["output"].count(SUCCESS_LINE) == 1 and "Error:" not in rec["output"])
    for root in ROOTS:
        gate.add("positive-root-" + root.rsplit(".", 1)[-1] + suffix, "positive", good and (ROOT_LINE + root) in rec["output"],
                 "actual resolved AST accepted",
                 command=rec["argv"], cwd=rec["cwd"], exit=rec["exit"],
                 log=rec["log_path"], log_sha256=rec["log_sha256"], resolver=rec, env_extra=env_extra)
    return rec

def run_negative_case(gate, stage, new_dll, out, case):
    name = case["name"]
    tree = copy_tree(stage, out / "trees" / name)
    target_rel = case.get("target", BINDING_REL)
    target = tree / target_rel
    text = read_text(target)
    for old, new in case.get("replacements", []):
        if case.get("root_only_replacement"):
            if old not in text:
                raise GateError("local reset mutation anchor absent")
            text = text.replace(old, new, 1)
        else:
            text = replace_exact(text, old, new, case.get("count"))
    if "insert_before" in case:
        anchor, insert = case["insert_before"]
        text = replace_exact(text, anchor, insert + anchor, 1)
    write_text(target, text)
    target_sha = sha_file(target)

    # First prove the mutation itself resolves/typechecks without the plugin.
    cwd, argv_plain = resolve_cmd(tree, None)
    plain = run_command(argv_plain, cwd, out / "logs/cases" / (name + "-typecheck"), clean_env())
    type_ok = plain["exit"] == 0 and not plain["timed_out"] and "Error:" not in plain["output"]
    if not type_ok:
        gate.add(name, "negative", False, "mutation did not resolve/typecheck",
                 code=case.get("code"), fixture=target_rel, fixture_sha256=target_sha,
                 typecheck=plain, expected=case.get("needle"))
        return
    env_extra = case.get("env")
    cwd, argv = resolve_cmd(tree, new_dll)
    rec = run_command(argv, cwd, out / "logs/cases" / name, clean_env(env_extra))
    expected = (case.get("code", "") + ":") if case.get("code") else None
    error_lines = re.findall(r"Error: ([^\n]+)", rec["output"])
    only_plugin_errors = bool(error_lines) and all(line.startswith("PSB") for line in error_lines)
    ok = (rec["exit"] == 2 and not rec["timed_out"] and
          not GENERIC_BAD.search(rec["output"]) and only_plugin_errors and
          (expected is None or expected in rec["output"]) and
          case["needle"] in rec["output"] and SUCCESS_LINE not in rec["output"])
    gate.add(name, "negative", ok, case.get("why", case.get("needle")),
             code=case.get("code"), needle=case.get("needle"), fixture=target_rel,
             fixture_sha256=target_sha, command=rec["argv"], cwd=rec["cwd"],
             exit=rec["exit"], log=rec["log_path"], log_sha256=rec["log_sha256"],
             typecheck_exit=plain["exit"], typecheck=plain, resolver=rec, env_extra=env_extra)

def input_admission_cases(gate, out):
    global REPO_ROOT, DAFNY
    root_before, dafny_before = REPO_ROOT, DAFNY
    fake = out / "admission-fixtures"
    fake.mkdir()
    original_profile = (root_before / PROFILE_REL).read_bytes()
    try:
        REPO_ROOT = fake
        for name, data in [("missing", None), ("altered", b"{}\n")]:
            if data is not None:
                write_text(fake / PROFILE_REL, data.decode())
            rejected, reason = False, ""
            try:
                freeze_toolchain(out)
            except GateError as exc:
                rejected, reason = True, str(exc)
            gate.add("profile-" + name + "-rejected", "input-admission", rejected,
                     reason, no_tool_execution_expected=True)
        REPO_ROOT = root_before
        bad = fake / "wrong-dafny"
        write_text(bad, "deliberately different launcher bytes\n")
        DAFNY = bad
        rejected, reason = False, ""
        try:
            freeze_toolchain(out)
        except GateError as exc:
            rejected, reason = "tool identity mismatch: dafny" in str(exc), str(exc)
        gate.add("changed-tool-rejected-before-execution", "input-admission", rejected,
                 reason, launcher_sha256=sha_file(bad))
    finally:
        REPO_ROOT, DAFNY = root_before, dafny_before
    if (root_before / PROFILE_REL).read_bytes() != original_profile:
        raise GateError("input-admission tests changed the real profile")

def output_safety_cases(gate, out):
    base = out / "safety"
    base.mkdir(parents=True)
    # Existing file.
    f = base / "existing-file"
    f.write_text("preserve-me", encoding="utf-8")
    before = sha_file(f)
    err = output_admission_error(f)
    gate.add("output-existing-file-rejected", "output-safety", err is not None and sha_file(f) == before,
             err or "existing file was not rejected", path=str(f))
    # Existing directory.
    d = base / "existing-dir"
    d.mkdir()
    err = output_admission_error(d)
    gate.add("output-existing-directory-rejected", "output-safety", err is not None, err)
    # Symlink to a file.
    target = base / "symlink-target"
    target.write_text("target-preserve", encoding="utf-8")
    link = base / "symlink-output"
    link.symlink_to(target)
    before = sha_file(target)
    err = output_admission_error(link)
    gate.add("output-symlink-rejected", "output-safety", err is not None and sha_file(target) == before, err)
    # Dangling symlink.
    dangling = base / "dangling-output"
    dangling.symlink_to(base / "does-not-exist")
    err = output_admission_error(dangling)
    gate.add("output-dangling-symlink-rejected", "output-safety", err is not None, err)
    # Symlink ancestor.
    real = base / "real-ancestor"
    real.mkdir()
    ancestor = base / "link-ancestor"
    ancestor.symlink_to(real)
    nested = ancestor / "child-output"
    err = output_admission_error(nested)
    gate.add("output-symlink-ancestor-rejected", "output-safety",
             err is not None and not (real / "child-output").exists(), err)
    # Repository ancestry.
    repo_probe = REPO_ROOT / "pure-snapshot-output-must-not-exist"
    err = output_admission_error(repo_probe)
    gate.add("output-repo-ancestry-rejected", "output-safety",
             err is not None and not repo_probe.exists(), err)
    # A separate Git worktree is also excluded from deterministic build output.
    other = base / "other-git"
    (other / ".git").mkdir(parents=True)
    candidate = other / "fresh-output"
    err = output_admission_error(candidate)
    gate.add("output-other-git-ancestry-rejected", "output-safety",
             err is not None and not candidate.exists(), err)
    # Fresh path is admitted.
    fresh = base / "fresh-output"
    err = output_admission_error(fresh)
    gate.add("output-fresh-admitted", "output-safety", err is None, err)

# ---------------------------------------------------------------------------
# Typed negative controls
# ---------------------------------------------------------------------------

NEGATIVES = [
    {
        "name": "neg-wrong-private-word",
        "code": "PSB011", "needle": "capture and actual call arguments are not typed-identical",
        "why": "wrong private word with a Rotate trace that can still agree",
        "replacements": [("ghost var callWitness := K.Rotate(word,n);",
                          "ghost var callWitness := K.Rotate(word ^ 1,n);")],
    },
    {
        "name": "neg-wrong-n",
        "code": "PSB011", "needle": "capture and actual call arguments are not typed-identical",
        "why": "wrong public shift argument",
        "replacements": [("ghost var callWitness := K.Rotate(word,n);",
                          "ghost var callWitness := K.Rotate(word,0);")],
    },
    {
        "name": "neg-unreviewed-bv32-conversion",
        "code": "PSB010", "needle": "unreviewed conversion in argument grammar",
        "why": "unreviewed bv32 conversions fail closed; this is a cast-policy control",
        "replacements": [("ghost var callWitness := K.Rotate(word,n);",
                          "ghost var callWitness := K.Rotate((word as bv32) as bv64,n);")],
    },
    {
        "name": "neg-wrong-array-index",
        "code": "PSB011", "needle": "capture and actual call arguments are not typed-identical",
        "why": "wrong array index in the snapshot",
        "replacements": [("ghost var callWitness := K.Rotate(input[j],n);",
                          "ghost var callWitness := K.Rotate(input[0],n);")],
    },
    {
        "name": "neg-wrong-array-alias",
        "code": "PSB011", "needle": "capture and actual call arguments are not typed-identical",
        "why": "wrong array alias in the snapshot",
        "replacements": [("ghost var callWitness := K.Rotate(input[j],n);",
                          "ghost var callWitness := K.Rotate(output[j],n);")],
    },
    {
        "name": "neg-ghost-if-witness-redefinition",
        "code": "PSB004", "needle": "witness callWitness must have exactly one definition",
        "why": "ghost branch redefines the captured witness; every definition must count",
        "insert_before": ("    trace := trace + ST.Call(0,20,2) + callWitness.1;",
                          "    if n == 0 {\n      callWitness := K.Rotate(word,n);\n    }\n"),
    },
    {
        "name": "neg-fabricated-tuple",
        "code": "PSB005", "needle": "witness must capture the full result of the exact pure call directly",
        "why": "fabricated tuple instead of the actual full-tuple call result",
        "replacements": [("ghost var callWitness := K.Rotate(word,n);",
                          "ghost var callWitness := (K.Rotate(word,n).0, ghost K.Rotate(word,n).1);")],
    },
    {
        "name": "neg-dropped-child",
        "code": "PSB015", "needle": "expected exact witness child immediately after the Call event",
        "why": "the sole child .1 projection was dropped",
        "replacements": [("trace := trace + ST.Call(0,20,2) + callWitness.1;",
                          "trace := trace + ST.Call(0,20,2);")],
    },
    {
        "name": "neg-duplicate-child",
        "code": "PSB015", "needle": "unexpected extra trace-packet leaf",
        "why": "duplicated child .1 projection",
        "replacements": [("trace := trace + ST.Call(0,20,2) + callWitness.1;",
                          "trace := trace + ST.Call(0,20,2) + callWitness.1 + callWitness.1;")],
    },
    {
        "name": "neg-child-before-call",
        "code": "PSB015", "needle": "trace packet event order does not match actual runtime evaluation order",
        "why": "child .1 appears before its actual Call event",
        "replacements": [("trace := trace + ST.Call(0,20,2) + callWitness.1;",
                          "trace := trace + callWitness.1 + ST.Call(0,20,2);")],
    },
    {
        "name": "neg-reordered-preceding-array-read",
        "code": "PSB015", "needle": "trace packet Read event does not match the actual array read",
        "why": "preceding array reads are reordered",
        "replacements": [("ST.Read(0,0,0) + ST.Read(1,0,1)",
                          "ST.Read(1,0,1) + ST.Read(0,0,0)")],
    },
    {
        "name": "neg-wrong-callsite",
        "code": "PSB015", "needle": "trace packet Call event is not the exact actual callsite/target/arity",
        "why": "wrong static callsite",
        "replacements": [("ST.Call(0,20,2)", "ST.Call(9,20,2)")],
    },
    {
        "name": "neg-wrong-function-id",
        "code": "PSB015", "needle": "trace packet Call event is not the exact actual callsite/target/arity",
        "why": "wrong resolved target id",
        "replacements": [("ST.Call(0,20,2)", "ST.Call(0,21,2)")],
    },
    {
        "name": "neg-wrong-arity",
        "code": "PSB015", "needle": "trace packet Call event is not the exact actual callsite/target/arity",
        "why": "wrong arity",
        "replacements": [("ST.Call(0,20,2)", "ST.Call(0,20,3)")],
    },
    {
        "name": "neg-wrong-write-index",
        "code": "PSB015", "needle": "trace packet Write event does not match the actual array write",
        "why": "wrong output write address",
        "replacements": [("ST.Write(2,1,i as int)", "ST.Write(2,1,j as int)")],
    },
    {
        "name": "neg-wrong-read-role",
        "code": "PSB015", "needle": "trace packet Read event does not match the actual array read",
        "why": "wrong array read role",
        "replacements": [("ST.Read(0,0,j as int)", "ST.Read(0,1,j as int)")],
    },
    {
        "name": "neg-trace-reset",
        "code": "PSB013", "needle": "trace must be reset exactly once",
        "why": "a second trace reset/reset after the packet",
        "insert_before": ("    value := K.Rotate(word,n).0;", "    trace := [];\n"),
    },
    {
        "name": "neg-interposed-executable-mutation",
        "code": "PSB012", "needle": "executable effect between witness capture and trace packet",
        "why": "executable array mutation interposed between capture and packet",
        "replacements": [("    modifies output\n", "    modifies input, output\n"),
                         ("ghost var callWitness := K.Rotate(input[j],n);\n",
                          "ghost var callWitness := K.Rotate(input[j],n);\n    input[j] := input[j] ^ 1;\n")],
    },
    {
        "name": "neg-unbound-second-call",
        "code": "PSB016", "needle": "exactly one actual non-ghost call is supported per statement",
        "why": "a second unbound inline call in the same statement",
        "replacements": [("value := K.Rotate(word,n).0;",
                          "value := K.Rotate(word,n).0 ^ K.Rotate(word,n).0;")],
    },
    {
        "name": "neg-shadow-rotate",
        "code": "PSB006", "needle": "actual call target is not the exact NativeKeccak.Rotate declaration",
        "why": "a shadow function named Rotate",
        "insert_before": ("  method Local", "  function Rotate(v: bv64, n: T.I): (bv64, ghost seq<int>)\n    requires 0 <= n < 64\n  { (v, ghost []) }\n"),
        "replacements": [("K.Rotate(", "Rotate(")],
        "count": None,
    },
    {
        "name": "neg-by-method-function",
        "code": "PSB007", "needle": "function-by-method",
        "why": "shadow pure target implemented by method",
        "insert_before": ("  method Local", "  function Rotate(v: bv64, n: T.I): (bv64, ghost seq<int>)\n    requires 0 <= n < 64\n  { (v, ghost []) }\n  by method {\n    return (v, ghost []);\n  }\n"),
        "replacements": [("K.Rotate(", "Rotate(")],
        "count": None,
    },
    {
        "name": "neg-pure-target-other-callee",
        "code": "PSB009", "needle": "admitted pure target contains another function call",
        "why": "shadow pure target has another callee",
        "insert_before": ("  method Local", "  function Extra(n: T.I): seq<int> { [] }\n  function Rotate(v: bv64, n: T.I): (bv64, ghost seq<int>)\n    requires 0 <= n < 64\n  { (v, ghost Extra(n)) }\n"),
        "replacements": [("K.Rotate(", "Rotate(")],
        "count": None,
    },
    {
        "name": "neg-exact-target-by-method",
        "code": "PSB007", "needle": "function-by-method",
        "why": "the exact pinned NativeKeccak.Rotate declaration is mutated to a typed by-method function",
        "target": "formal/crypto/NativeKeccak.dfy",
        "replacements": [(
            "  { if n == 0 then (v, ghost ST.Branch(30,true))\n"
            "    else ((v << n) | (v >> (64-n)), ghost ST.Branch(30,false) + ST.Ops(0,1,0,0,0,1,2)) }\n"
            "  function Constant",
            "  { if n == 0 then (v, ghost ST.Branch(30,true))\n"
            "    else ((v << n) | (v >> (64-n)), ghost ST.Branch(30,false) + ST.Ops(0,1,0,0,0,1,2)) }\n"
            "  by method {\n"
            "    if n == 0 {\n"
            "      return (v, ghost ST.Branch(30,true));\n"
            "    } else {\n"
            "      return ((v << n) | (v >> (64-n)), ghost ST.Branch(30,false) + ST.Ops(0,1,0,0,0,1,2));\n"
            "    }\n"
            "  }\n"
            "  function Constant")],
    },
    {
        "name": "neg-exact-target-extern",
        "code": "PSB006", "needle": "extern or missing concrete body",
        "why": "the exact pinned NativeKeccak.Rotate declaration is mutated to an extern bodyless function",
        "target": "formal/crypto/NativeKeccak.dfy",
        "replacements": [(
            "  function Rotate(v: bv64, n: T.I): (bv64, ghost seq<int>)\n"
            "    requires 0 <= n < 64\n"
            "    ensures Rotate(v,n).0 == S.Rotate(v,n as int)\n"
            "    ensures Rotate(v,n).1 == RotateTrace(n)\n"
            "  { if n == 0 then (v, ghost ST.Branch(30,true))\n"
            "    else ((v << n) | (v >> (64-n)), ghost ST.Branch(30,false) + ST.Ops(0,1,0,0,0,1,2)) }",
            "  function {:extern} Rotate(v: bv64, n: T.I): (bv64, ghost seq<int>)\n"
            "    requires 0 <= n < 64\n"
            "    ensures Rotate(v,n).0 == S.Rotate(v,n as int)\n"
            "    ensures Rotate(v,n).1 == RotateTrace(n)")],
    },
    {
        "name": "neg-exact-target-other-callee",
        "code": "PSB009", "needle": "admitted pure target contains another function call",
        "why": "the exact pinned NativeKeccak.Rotate declaration gains another non-marker callee",
        "target": "formal/crypto/NativeKeccak.dfy",
        "insert_before": ("  ghost function RotateTrace", "  function Extra(n: T.I): seq<int> { [] }\n"),
        "replacements": [("ST.Ops(0,1,0,0,0,1,2)", "ST.Ops(0,1,0,0,0,1,2) + Extra(n)")],
        "count": None,
    },
    {
        "name": "neg-conditional-argument",
        "code": "PSB010", "needle": "conditional/ITE argument expression is unsupported",
        "why": "conditional argument expression",
        "replacements": [("K.Rotate(word,n)", "K.Rotate((if n == 0 then word else word),n)")],
        "count": None,
    },
    {
        "name": "neg-stmtexpr-argument",
        "code": "PSB010", "needle": "statement expression is unsupported",
        "why": "statement expression in an argument",
        "replacements": [("K.Rotate(word,n)", "K.Rotate((assert 0 <= n < 64; word),n)")],
        "count": None,
    },
    {
        "name": "neg-nested-call",
        "code": "PSB010", "needle": "nested function call in a witness argument is unsupported",
        "why": "nested pure call in the argument grammar",
        "replacements": [("ghost var callWitness := K.Rotate(word,n);",
                          "ghost var callWitness := K.Rotate(K.Rotate(word,n).0,n);")],
    },
    {
        "name": "neg-unsupported-control-short-circuit",
        "code": "PSB019", "needle": "unsupported executable statement IfStmt",
        "why": "short-circuit/unsupported control flow in the fixed root grammar",
        "insert_before": ("    value := K.Rotate(word,n).0;",
                          "    if n != 0 && word == word {\n      value := word;\n    }\n"),
    },
    {
        "name": "neg-missing-root-around",
        "code": "PSB001", "needle": "missing required root SnapshotBindingControls.Around",
        "why": "fixed inventory cannot be reduced",
        "replacements": [(
            "\n  method Around(a: array<bv64>, n: T.I)\n"
            "      returns (value: bv64, ghost trace: seq<int>)\n"
            "    requires a.Length >= 2 && 0 <= n < 64\n"
            "  {\n"
            "    trace := [];\n"
            "    ghost var callWitness := K.Rotate(a[1],n);\n"
            "    trace := trace + ST.Read(0,0,0) + ST.Read(1,0,1)\n"
            "      + ST.Call(2,20,2) + callWitness.1 + ST.Ops(0,0,0,0,0,1,0);\n"
            "    value := a[0] ^ K.Rotate(a[1],n).0;\n"
            "  }\n", "")],
    },
    {
        "name": "neg-missing-root-with-env-selector",
        "code": "PSB001", "needle": "missing required root SnapshotBindingControls.Around",
        "why": "ambient root selectors cannot reduce the fixed inventory",
        "env": {"SOURCE_TRACE_ROOTS": "NativeKeccak.SetLane"},
        "replacements": [(
            "\n  method Around(a: array<bv64>, n: T.I)\n"
            "      returns (value: bv64, ghost trace: seq<int>)\n"
            "    requires a.Length >= 2 && 0 <= n < 64\n"
            "  {\n"
            "    trace := [];\n"
            "    ghost var callWitness := K.Rotate(a[1],n);\n"
            "    trace := trace + ST.Read(0,0,0) + ST.Read(1,0,1)\n"
            "      + ST.Call(2,20,2) + callWitness.1 + ST.Ops(0,0,0,0,0,1,0);\n"
            "    value := a[0] ^ K.Rotate(a[1],n).0;\n"
            "  }\n", "")],
    },
]

# A faithful runtime arithmetic packet isolates typed comparison from operation
# coverage. The negative differs only in the captured argument's intermediate
# width. Both programs are well-typed and the bounded bv8 cast fits all words.
WIDE_EXPR = "(word%256)+1"
WRAPPED_EXPR = "((((word%256) as bv8)+1) as bv64)"
WIDE_PACKET = ("trace := trace + ST.Ops(0,0,0,0,1,0,0) + ST.Ops(1,0,0,0,0,0,0)"
               " + ST.Call(0,20,2) + callWitness.1;")

NEGATIVES += [
    {"name": "neg-unobserved-prefix-call", "code": "PSB019",
     "needle": "witness must immediately follow the sole initial trace reset",
     "insert_before": ("    ghost var callWitness := K.Rotate(word,n);", "    value := K.Rotate(word,0).0;\n")},
    {"name": "neg-ghost-such-that-prefix", "code": "PSB019",
     "needle": "witness must immediately follow the sole initial trace reset",
     "insert_before": ("    ghost var callWitness := K.Rotate(word,n);", "    trace :| true;\n")},
    {"name": "neg-mixed-width-wrapped-add", "code": "PSB011",
     "needle": "capture and actual call arguments are not typed-identical",
     "replacements": [("ghost var callWitness := K.Rotate(word,n);", "ghost var callWitness := K.Rotate(" + WRAPPED_EXPR + ",n);"),
                      ("value := K.Rotate(word,n).0;", "value := K.Rotate(" + WIDE_EXPR + ",n).0;"),
                      ("trace := trace + ST.Call(0,20,2) + callWitness.1;", WIDE_PACKET)], "count": 1},
    {"name": "neg-unreviewed-real-conversion", "code": "PSB010",
     "needle": "unreviewed conversion in argument grammar",
     "replacements": [("K.Rotate(word,n)", "K.Rotate(((((word as int) as real) as int) as bv64),n)")], "count": 2},
    {"name": "neg-arithmetic-array-lhs", "code": "PSB021",
     "needle": "array assignment index must be a typed literal or non-ghost formal",
     "replacements": [("output[i] := K.Rotate(input[j],n).0;", "output[(i as int)+0] := K.Rotate(input[j],n).0;")]},
    {"name": "neg-nested-read-array-lhs", "code": "PSB021",
     "needle": "array assignment index must be a typed literal or non-ghost formal",
     "replacements": [("output[i] := K.Rotate(input[j],n).0;", "output[(input[0] as int)%output.Length] := K.Rotate(input[j],n).0;")]},
    {"name": "neg-target-anonymous-application", "code": "PSB009",
     "needle": "unsupported resolved body expression", "target": "formal/crypto/NativeKeccak.dfy",
     "replacements": [("then (v, ghost ST.Branch(30,true))", "then (((x: bv64) => x)(v), ghost ST.Branch(30,true))")]},
    {"name": "neg-target-named-function-value-application", "code": "PSB009",
     "needle": "unsupported resolved body expression", "target": "formal/crypto/NativeKeccak.dfy",
     "insert_before": ("  ghost function RotateTrace", "  function Extra(v: bv64): bv64 { v }\n"),
     "replacements": [("then (v, ghost ST.Branch(30,true))", "then ((var f := Extra; f(v)), ghost ST.Branch(30,true))")]},
    {"name": "neg-target-ghost-input", "code": "PSB006",
     "needle": "does not have the exact (bv64,NativeTypes.I) formals", "target": "formal/crypto/NativeKeccak.dfy",
     "replacements": [("function Rotate(v: bv64, n: T.I)", "function Rotate(ghost v: bv64, n: T.I)"),
                      ("then (v, ghost ST.Branch(30,true))", "then (0, ghost ST.Branch(30,true))"),
                      ("else ((v << n) | (v >> (64-n)), ghost", "else ((0 << n) | (0 >> (64-n)), ghost")], "count": 1},
]

NEGATIVES += [
    {"name": "neg-reset-hidden-call-multiassignment", "code": "PSB013",
     "needle": "trace reset must be one ghost assignment to the trace formal",
     "replacements": [("    trace := [];", "    trace, value := [], K.Rotate(word,0).0;")], "count": 1,
     "root_only_replacement": True},
    {"name": "neg-packet-interposed-write-multiassignment", "code": "PSB013",
     "needle": "trace packet must be one ghost assignment to the trace formal",
     "replacements": [("    modifies output", "    modifies input, output"),
         ("    trace := trace + ST.Read(0,0,j as int) + ST.Call(1,20,2)\n      + callWitness.1 + ST.Write(2,1,i as int);",
          "    trace, input[j] := trace + ST.Read(0,0,j as int) + ST.Call(1,20,2)\n      + callWitness.1 + ST.Write(2,1,i as int), input[j]^1;")], "count": 1},
]

def run_wide_positive(gate, stage, dll, out):
    tree = copy_tree(stage, out / "trees/positive-wide-arithmetic")
    path = tree / BINDING_REL
    source = replace_exact(read_text(path), "K.Rotate(word,n)", "K.Rotate(" + WIDE_EXPR + ",n)", 2)
    source = replace_exact(source, "trace := trace + ST.Call(0,20,2) + callWitness.1;", WIDE_PACKET, 1)
    write_text(path, source)
    cwd, argv = resolve_cmd(tree, dll)
    rec = run_command(argv, cwd, out / "logs/cases/positive-wide-arithmetic", clean_env())
    ok = rec["exit"] == 0 and not rec["timed_out"] and rec["output"].count(SUCCESS_LINE) == 1 and "Error:" not in rec["output"]
    gate.add("positive-wide-arithmetic", "positive", ok,
             "same wide arguments and faithful mod/add/call/child packet", resolver=rec,
             fixture_sha256=sha_file(path))

# ---------------------------------------------------------------------------
# Main gate
# ---------------------------------------------------------------------------

def run_gate(out):
    gate = Gate(out)
    result = {
        "schema": "microproxy.pure-snapshot-binding/1",
        "task": "issue117 Task1 focused pure-snapshot binding gate",
        "qualification": False,
        "status": "incomplete",
        "pinned_commit": PINNED_COMMIT,
        "fixed_roots": list(ROOTS),
        "known_limits": [
            "binding-only gate; no full operation, Keccak, NI, codegen or timing claim",
            "no Dafny proofs are run here; root value/stale-value proofs are separate",
            "the checker is a trusted resolved-AST rule, not a verified semantics",
            "the historical Select checker preserves its existing registered positive/negative fixtures, not new protocol admission",
            "canonical SourceTrace/vocabulary semantics are assumed via exact Git pins, not proved by this plugin",
            "some unsupported-callee controls use typed shadows; exact target by-method/extern/higher-order/ghost-input controls are also executed",
        ],
    }
    write_json(out / "result.json", result)
    try:
        result["toolchain"] = freeze_toolchain(out)
        stage, origins, before = stage_sources(out)
        result["stage_origins"] = origins
        new_dll, new_build = build_checker(out, stage, CHECKER_REL, CHECKER_PROJ_REL, "checker-build")
        result["checker"] = new_build
        old_dll, old_build = build_old_checker(out, stage)
        if old_build["dll_sha256"] != result["toolchain"]["old_checker_expected_sha256"]:
            raise GateError("old checker build differs from reviewed DLL")
        result["old_checker"] = old_build

        result["old_registered_controls"] = run_old_checker_cases(gate, stage, old_dll, out)
        immutable_build_probe(gate, stage, out, new_build["inputs_before"])
        run_positive_cases(gate, stage, new_dll, out)
        run_positive_cases(gate, stage, new_dll, out,
                           env_extra={"SOURCE_TRACE_ROOTS": "NativeKeccak.SetLane"},
                           suffix="-env-root-selector")
        run_wide_positive(gate, stage, new_dll, out)
        for case in NEGATIVES:
            run_negative_case(gate, stage, new_dll, out, case)
        input_admission_cases(gate, out)
        output_safety_cases(gate, out)
        stage_check = verify_stage_unchanged(stage, before, out)
        result["stage_check"] = stage_check
        result["toolchain"]["files_after"] = verify_tools_unchanged(result["toolchain"])
        # A little known-boundary accounting: the by-method/extern/read controls
        # that cannot be expressed on the exact Rotate signature are not claimed.
        result["case_counts"] = {
            "total": len(gate.cases),
            "passed": sum(1 for c in gate.cases if c["status"] == "passed"),
            "failed": gate.failures,
        }
        result["cases"] = gate.cases
        result["status"] = "complete" if gate.failures == 0 else "failed"
        result["exit"] = 0 if gate.failures == 0 else 1
        result["argv"] = sys.argv
        write_json(out / "result.json", result)
        print(json.dumps({"status": result["status"], "qualification": False,
                          "case_counts": result["case_counts"], "output": str(out)},
                         sort_keys=True))
        return 0 if gate.failures == 0 else 1
    except Exception as exc:
        result["status"] = "failed"
        result["failure_kind"] = "runner-exception"
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)
        result["traceback"] = traceback.format_exc()
        result["case_counts"] = {"total": len(gate.cases),
                                 "passed": sum(1 for c in gate.cases if c["status"] == "passed"),
                                 "failed": gate.failures}
        result["cases"] = gate.cases
        result["argv"] = sys.argv
        write_json(out / "result.json", result)
        print(json.dumps({"status": "failed", "qualification": False,
                          "error": str(exc), "output": str(out)}, sort_keys=True))
        return 1

def main(argv=None):
    global DAFNY, DOTNET
    parser = argparse.ArgumentParser(description="Focused non-qualifying pure-snapshot binding gate")
    parser.add_argument("--output", required=True, help="absolute fresh output directory")
    parser.add_argument("--dafny", required=True, type=Path, help="qualified Dafny 4.9.1 launcher")
    parser.add_argument("--dotnet", required=True, type=Path, help="qualified .NET SDK 10.0.400 launcher")
    args = parser.parse_args(argv)
    DAFNY, DOTNET = args.dafny.absolute(), args.dotnet.absolute()
    err = output_admission_error(args.output)
    if err is not None:
        print(json.dumps({"status": "rejected", "qualification": False,
                          "error": err, "argv": sys.argv}, sort_keys=True))
        return 2
    out = Path(args.output)
    out.mkdir(parents=True)
    return run_gate(out)

if __name__ == "__main__":
    sys.exit(main())
