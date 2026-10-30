"""Install the official checksum-pinned Dafny distribution outside the checkout."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import tempfile
import urllib.request
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_member(member):
    name = PurePosixPath(member.filename)
    mode = member.external_attr >> 16
    if (name.is_absolute() or ".." in name.parts or "\\" in member.filename
            or not name.parts or name.parts[0] != "dafny"
            or mode & 0o170000 == 0o120000):
        raise RuntimeError(f"Unsafe archive member: {member.filename}")


def install(cache):
    manifest = json.loads((HERE / "tools.json").read_text())
    key = f"{platform.system()}-{platform.machine()}"
    if key not in manifest["assets"]:
        raise RuntimeError(f"No reviewed Dafny distribution for {key}")
    asset = manifest["assets"][key]
    cache = cache.expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / asset["archive"]
    if not archive.exists():
        url = f"https://github.com/dafny-lang/dafny/releases/download/v{manifest['version']}/{archive.name}"
        # Unique temporary files avoid sharing a partial download between invocations.
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "MicroProxy-formal-verification"})
                with urllib.request.urlopen(request, timeout=60) as response:
                    shutil.copyfileobj(response, stream)
                stream.flush()
                if digest(temporary) != asset["sha256"]:
                    raise RuntimeError("Downloaded Dafny archive checksum mismatch")
                temporary.replace(archive)
            finally:
                temporary.unlink(missing_ok=True)
    if digest(archive) != asset["sha256"]:
        raise RuntimeError("Cached Dafny archive checksum mismatch; remove it explicitly to retry")

    # Revalidate every extracted file against the archive, including the solver and
    # managed assemblies. A version string alone cannot identify a compiler.
    destination = cache / asset["directory"]
    with ZipFile(archive) as bundle:
        members = bundle.infolist()
        for member in members:
            validate_member(member)
        valid = destination.is_dir()
        expected_files = set()
        for member in members:
            if member.is_dir():
                continue
            expected_files.add(member.filename)
            path = destination / member.filename
            if (not path.is_file() or path.is_symlink()
                    or digest(path) != hashlib.sha256(bundle.read(member)).hexdigest()):
                valid = False
        if destination.exists() and set(str(p.relative_to(destination)) for p in destination.rglob("*")
                                        if p.is_file() or p.is_symlink()) != expected_files:
            valid = False
        if destination.exists() and not valid:
            raise RuntimeError("Extracted Dafny distribution changed; remove it explicitly to reinstall")
        if not destination.exists():
            with tempfile.TemporaryDirectory(dir=cache) as temporary:
                staging = Path(temporary) / "distribution"
                bundle.extractall(staging)
                for member in members:
                    if not member.is_dir():
                        os.chmod(staging / member.filename, (member.external_attr >> 16) & 0o777)
                staging.replace(destination)
    runtime = destination / manifest["runtime"]
    if digest(runtime) != asset["runtime_sha256"]:
        raise RuntimeError("Dafny runtime checksum mismatch")
    return destination / "dafny/dafny", runtime, manifest, asset
