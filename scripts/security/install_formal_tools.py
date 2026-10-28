#!/usr/bin/env python3
"""Cache pinned proof tools without changing global toolchains."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_download(url, expected, target):
    if target.exists():
        if digest(target) != expected:
            raise RuntimeError(f"Checksum mismatch in cached tool: {target}; remove it explicitly to retry")
        return
    temporary = target.with_suffix(target.suffix + ".part")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "MicroProxy-formal-verification"})
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        if digest(temporary) != expected:
            raise RuntimeError(f"Downloaded tool checksum mismatch: {url}")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def tool_paths(cache):
    manifest = json.loads((ROOT / "formal/tools.json").read_text())
    key = f"{platform.system()}-{platform.machine()}"
    asset = manifest["lean"]["assets"].get(key)
    if asset is None:
        raise RuntimeError(f"No pinned Lean archive for {key}; add a reviewed official asset and checksum")
    return manifest, asset, cache / asset["name"] / "bin/lean", cache / manifest["tlc"]["filename"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path(os.environ.get(
        "MICROPROXY_FORMAL_CACHE", Path.home() / ".cache/microproxy-formal")))
    args = parser.parse_args()
    cache = args.cache.expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True)
    manifest, asset, lean, tlc = tool_paths(cache)
    archive = cache / (asset["name"] + ".tar.zst")
    url = f"https://github.com/leanprover/lean4/releases/download/v{manifest['lean']['version']}/{archive.name}"
    print(f"Verify/download {archive.name}", flush=True)
    checked_download(url, asset["sha256"], archive)
    if not lean.exists():
        if not shutil.which("zstd"):
            raise RuntimeError("Install zstd to unpack the pinned Lean archive")
        subprocess.run(["tar", "--zstd", "-xf", str(archive), "-C", str(cache)], check=True)
    version = subprocess.check_output([str(lean), "--version"], text=True)
    if f"version {manifest['lean']['version']}," not in version:
        raise RuntimeError(f"Wrong Lean version: {version}")
    checked_download(manifest["tlc"]["url"], manifest["tlc"]["sha256"], tlc)
    print(version.strip())
    print(f"Tools ready in {cache}")


if __name__ == "__main__":
    main()
