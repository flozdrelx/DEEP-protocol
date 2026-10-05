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



def viewer_payloads(directory, version):
    """Package only a clean win-x64 build, excluding profiles/configuration/keys."""
    directory = directory.resolve()
    deps = json.loads((directory / "DEEP.Viewer.deps.json").read_text(encoding="utf-8-sig"))
    if not deps["runtimeTarget"]["name"].endswith("/win-x64") or "DEEP.Viewer/" + version not in deps["libraries"]:
        raise ValueError("Viewer build must match the release version and win-x64 target")
    for required in ("DEEP.Viewer.exe", "DEEP.Viewer.dll", "DEEP.Viewer.runtimeconfig.json", "licenses/DEEP-LICENSE.txt"):
        if not (directory / required).is_file():
            raise ValueError("Incomplete viewer build: " + required)
    result = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(directory)
        if len(relative.parts) == 1 and (path.suffix in {".dll", ".exe", ".dat"} or
                path.name in {"DEEP.Viewer.deps.json", "DEEP.Viewer.runtimeconfig.json"}):
            result["bin/viewer/" + relative.as_posix()] = (path.read_bytes(), 0o755 if path.suffix == ".exe" else 0o644)
        elif relative.parts[0] == "licenses" and path.suffix.lower() == ".txt":
            result["bin/viewer/" + relative.as_posix()] = (path.read_bytes(), 0o644)
    return result


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
    for directory in ("cmd", "scripts", "docs", "interop", ".github", "viewer", "examples/website"):
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and not ({"__pycache__", "bin", "obj"} & set(path.relative_to(ROOT).parts)) and path.suffix in {
                ".go", ".py", ".ps1", ".md", ".json", ".yml", ".yaml", ".cs", ".csproj", ".Config", ".html", ".css", ".js", ".svg"
            }:
                payloads[path.relative_to(ROOT).as_posix()] = (path.read_bytes(), 0o644)
    return payloads


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--windows-viewer", type=Path, help="Matching self-contained win-x64 viewer build; adds a separate desktop ZIP")
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=TARGETS)
    args = parser.parse_args()
    if len(set(args.targets)) != len(args.targets):
        parser.error("targets must be unique")
    version = re.search(r'const Version = "([^"]+)"', (ROOT / "protocol.go").read_text()).group(1)
    desktop = viewer_payloads(args.windows_viewer, version) if args.windows_viewer else None
    if desktop and "windows/amd64" not in args.targets:
        parser.error("--windows-viewer requires the windows/amd64 target")
    toolchain = subprocess.check_output(["go", "version"], cwd=ROOT, text=True).strip()
    parsed = re.search(r"go(\d+)\.(\d+)(?:\.(\d+))?", toolchain)
    if not parsed or tuple(int(n or 0) for n in parsed.groups()) < (1, 27, 1):
        parser.error("Go 1.27.1 or newer is required")
    args.output = (args.output or ROOT / "dist" / ("v" + version)).resolve()
    # Exclusive directory creation prevents overwriting a previous release.
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {"version": version, "wire_version": 2, "config_version": 2, "alpn": "deep/2",
                "application_profile": "app/1", "proxy_profile": "Proxy/1", "toolchain": toolchain, "targets": [],
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
            if desktop and target == "windows/amd64":
                viewer_name = f"deep-{version}-windows-amd64-viewer.zip"
                viewer_archive = args.output / viewer_name
                payloads = archive_payloads(binary, binary_name)
                payloads.update(desktop)
                write_archive(viewer_archive, payloads, True)
                viewer_digest = hashlib.sha256(viewer_archive.read_bytes()).hexdigest()
                hashes.append(f"{viewer_digest}  {viewer_name}")
                manifest["desktop"] = {"target": target, "archive": viewer_name, "sha256": viewer_digest,
                                       "viewer_enabled_by_default": False, "execution_tested_by_script": False}
                print(viewer_name, flush=True)
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

