#!/usr/bin/env python3
"""Materialize the immutable Git baseline used by the polynomial erasure gate.

This copies historical bytes, not the working tree. The replay independently
authenticates the same files against Git or the reviewed manifest digest.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "formal/source/polynomial-baseline.json"
MANIFEST_SHA256 = "77daf19d88d147086717d86f06cda280e9f16d0e7b2ef769472745a77f256ff0"
COMMIT = "5ce660a69a1dd496dda02705bf1e2b1aa7a2be1d"
TREE = "df8b49bc8d181be18d78a9db7ab0233f23f7346f"


def git(repo, *args):
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120).stdout


def prepare(output, *, repo=ROOT, manifest=MANIFEST):
    output = Path(output)
    if output.is_symlink():
        raise RuntimeError("baseline output is a symlink")
    if output.exists():
        raise FileExistsError("baseline output must not exist: " + str(output))
    raw = Path(manifest).read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise RuntimeError("reviewed baseline manifest digest changed")
    data = json.loads(raw)
    files = data["files"]
    if (data["commit"], data["tree"], len(files)) != (COMMIT, TREE, 20):
        raise RuntimeError("baseline inventory changed")
    if git(repo, "rev-parse", COMMIT + "^{tree}").decode().strip() != TREE:
        raise RuntimeError("baseline Git tree differs")
    blobs = {}
    for name, expected in files.items():
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or "\\" in name
                or path.as_posix() != name):
            raise RuntimeError("unsafe baseline path: " + name)
        contents = git(repo, "show", COMMIT + ":" + name)
        if hashlib.sha256(contents).hexdigest() != expected:
            raise RuntimeError("historical Git bytes differ: " + name)
        blobs[name] = contents
    # Write the qualifying manifest last: a partial copy cannot qualify.
    output.mkdir(parents=True, exist_ok=False)
    for name, contents in blobs.items():
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)
    (output / "manifest.json").write_bytes(raw)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--git-repo", type=Path, default=ROOT)
    args = parser.parse_args()
    print(prepare(args.output, repo=args.git_repo))


if __name__ == "__main__":
    main()
