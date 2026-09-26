#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build local DEEP release archives; never publish, tag, or upload anything."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64",
           "darwin/amd64", "darwin/arm64")


def archive_payloads(binary, binary_name):
    payloads = {"bin/" + binary_name: (binary.read_bytes(), 0o755)}
    for name in ("README.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"):
        payloads[name] = ((ROOT / name).read_bytes(), 0o644)
    for path in sorted((ROOT / "docs").glob("*.md")):
        payloads["docs/" + path.name] = (path.read_bytes(), 0o644)
    # Registration is optional; credentials/configuration are never packaged.
    payloads["scripts/register.ps1"] = ((ROOT / "scripts/register.ps1").read_bytes(), 0o644)
    for path in sorted((ROOT / "interop").iterdir()):
        if path.is_file() and path.suffix in {".py", ".md", ".json"}:
            payloads["interop/" + path.name] = (path.read_bytes(), 0o644)
    return payloads


def write_archive(path, payloads, windows):
    if windows:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as archive:
            for name, (data, mode) in sorted(payloads.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = mode << 16
                archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED,
                                 compresslevel=9)
    else:
        with path.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for name, (data, mode) in sorted(payloads.items()):
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.mode, entry.mtime = len(data), mode, 0
                        entry.uid = entry.gid = 0
                        entry.uname = entry.gname = ""
                        archive.addfile(entry, io.BytesIO(data))


def source_payloads():
    payloads = {}
    for path in sorted(ROOT.glob("*.go")):
        payloads[path.name] = (path.read_bytes(), 0o644)
    for name in ("go.mod", ".gitignore", "README.md", "SECURITY.md", "CHANGELOG.md",
                 "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES"):
        payloads[name] = ((ROOT / name).read_bytes(), 0o644)
    for directory in ("cmd", "scripts", "docs", "interop", ".github"):
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix in {
                ".go", ".py", ".ps1", ".md", ".json", ".yml", ".yaml"
            }:
                payloads[path.relative_to(ROOT).as_posix()] = (path.read_bytes(), 0o644)
    return payloads


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "v2.0.0")
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=TARGETS)
    args = parser.parse_args()
    if len(set(args.targets)) != len(args.targets):
        parser.error("targets must be unique")
    version = re.search(r'const Version = "([^"]+)"', (ROOT / "protocol.go").read_text()).group(1)
    toolchain = subprocess.check_output(["go", "version"], cwd=ROOT, text=True).strip()
    parsed = re.search(r"go(\d+)\.(\d+)(?:\.(\d+))?", toolchain)
    if not parsed or tuple(int(n or 0) for n in parsed.groups()) < (1, 27, 1):
        parser.error("Go 1.27.1 or newer is required")
    args.output = args.output.resolve()
    # Exclusive directory creation prevents overwriting a previous release.
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {"version": version, "toolchain": toolchain, "targets": [],
                "scope": "Local builds only. Checksums provide integrity, not publisher authentication.",
                "reproducibility": "Use identical source files, Go toolchain, and Python/zlib versions."}
    hashes = []
    with tempfile.TemporaryDirectory(prefix="deep-release-") as temporary:
        for target in args.targets:
            system, architecture = target.split("/")
            binary_name = "deep.exe" if system == "windows" else "deep"
            binary = Path(temporary) / (system + "-" + architecture + "-" + binary_name)
            env = dict(os.environ, GOOS=system, GOARCH=architecture, CGO_ENABLED="0",
                       GOTOOLCHAIN="local", GOAMD64="v1", GOARM64="v8.0")
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o",
                            str(binary), "./cmd/deep"], cwd=ROOT, env=env, check=True)
            extension = ".zip" if system == "windows" else ".tar.gz"
            archive_name = f"deep-{version}-{system}-{architecture}{extension}"
            archive_path = args.output / archive_name
            write_archive(archive_path, archive_payloads(binary, binary_name), system == "windows")
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            hashes.append(f"{digest}  {archive_name}")
            manifest["targets"].append({"target": target, "archive": archive_name,
                                        "sha256": digest, "execution_tested_by_script": False})
            print(archive_name, flush=True)
    source_name = f"deep-{version}-source.tar.gz"
    source_path = args.output / source_name
    write_archive(source_path, source_payloads(), False)
    source_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    hashes.append(f"{source_digest}  {source_name}")
    manifest["source"] = {"archive": source_name, "sha256": source_digest}
    print(source_name, flush=True)
    manifest_path = args.output / "BUILD-MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    hashes.append(f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  {manifest_path.name}")
    (args.output / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="ascii")
    print(f"Local release artifacts: {args.output}")
    print("Cross-compilation does not establish execution compatibility. Run CI on each supported OS.")


if __name__ == "__main__":
    main()

