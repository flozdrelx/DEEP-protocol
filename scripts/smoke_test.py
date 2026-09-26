#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise a built DEEP V2 binary using isolated, real client/server processes.

No compiler is invoked. All generated identities, configurations, content, and
outputs live in one TemporaryDirectory and are removed after servers stop.
Private keys are never read or printed by this script.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time


class SmokeError(Exception):
    """A failed integration assertion."""


PROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def run_command(arguments, label, expect_success=True):
    try:
        result = subprocess.run([str(value) for value in arguments],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                timeout=45, creationflags=PROCESS_FLAGS)
    except subprocess.TimeoutExpired as error:
        raise SmokeError(label + " timed out") from error
    if expect_success and result.returncode != 0:
        # The tested CLI and probe emit diagnostics, never key material.
        raise SmokeError(label + " failed: " + result.stderr.strip()[:2000])
    if not expect_success and result.returncode == 0:
        raise SmokeError(label + " unexpectedly succeeded")
    return result


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def json_result(raw, label):
    try:
        return json.loads(raw)
    except (ValueError, TypeError) as error:
        raise SmokeError(label + " did not return one JSON report") from error


class RunningNode:
    def __init__(self, binary, directory, authority, public=False):
        self.directory = directory
        self.authority = authority
        self.process = None
        self.log = None
        self.reader = None
        self.lines = queue.Queue()
        arguments = [binary, "init", "--authority", authority, "--dir", directory,
                     "--address", "127.0.0.1:9761"]
        if public:
            arguments.append("--public")
        run_command(arguments, "initialize " + ("public" if public else "private") + " node")
        server_path = directory / "server.json"
        config = read_json(server_path)
        config["listen"] = "127.0.0.1:0"
        write_json(server_path, config)
        self.client_config = directory / "client.json"
        self.log_path = directory / "smoke-server.stderr"
        self.log = self.log_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen([str(binary), "serve", "--config", str(server_path)],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=self.log, text=True, encoding="utf-8",
                                            errors="replace", creationflags=PROCESS_FLAGS)
            self.reader = threading.Thread(target=self._read_stdout, daemon=True)
            self.reader.start()
            deadline = time.monotonic() + 20
            self.address = None
            while time.monotonic() < deadline:
                try:
                    line = self.lines.get(timeout=0.1)
                except queue.Empty:
                    if self.process.poll() is not None:
                        self.log.flush()
                        details = self.log_path.read_text(encoding="utf-8")[:2000]
                        raise SmokeError("server stopped during startup: " + details)
                    continue
                match = re.fullmatch(r"DEEP 2\.0\.0 listening on (127\.0\.0\.1:[0-9]+) for deep://"
                                     + re.escape(authority) + r"/\s*", line)
                if match:
                    self.address = match.group(1)
                    break
            if self.address is None:
                raise SmokeError("server did not report its loopback listener before the deadline")
            client = read_json(self.client_config)
            network = authority.rsplit(".", 1)[1]
            client["networks"][network]["endpoints"][authority]["address"] = self.address
            write_json(self.client_config, client)
        except BaseException:
            self.close()
            raise

    def _read_stdout(self):
        for line in self.process.stdout:
            self.lines.put(line)

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            if self.reader is not None:
                self.reader.join(timeout=2)
            if self.process.stdout is not None:
                self.process.stdout.close()
        if self.log is not None:
            self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.close()


def verify_file(path, content):
    if not path.is_file() or path.read_bytes() != content:
        raise SmokeError("downloaded bytes differ from the source")
    return hashlib.sha256(content).hexdigest()


def verify_security(report):
    security = report.get("security", {})
    if (security.get("tls_version") != "TLS 1.3"
            or security.get("key_exchange") != "X25519MLKEM768"
            or security.get("authentication") != "ML-DSA-65"
            or security.get("post_quantum_key_exchange") is not True
            or security.get("post_quantum_authentication") is not True):
        raise SmokeError("native client did not verify the required V2 security profile")
    return security


def assert_no_partial_output(output):
    if output.exists() or list(output.parent.glob(".deep-download-*")):
        raise SmokeError("failed download left output or a partial download behind")


def exercise(args):
    checks = []
    report = {"ok": True, "checks": checks}
    content = bytes(range(256)) * 12289  # 3 MiB plus 256 bytes.
    expected_hash = hashlib.sha256(content).hexdigest()
    with tempfile.TemporaryDirectory(prefix="deep-v2-smoke-") as temporary:
        workspace = Path(temporary).resolve()
        with RunningNode(args.binary, workspace / "private-node", "node.alpha") as node:
            (node.directory / "content" / "payload.bin").write_bytes(content)
            output = workspace / "native.bin"
            result = run_command([args.binary, "fetch", "deep://node.alpha/payload.bin", "--config",
                                  node.client_config, "--output", output, "--info"], "private native transfer")
            native = json_result(result.stderr, "native client")
            report["native_security"] = verify_security(native)
            verify_file(output, content)
            if native.get("size") != len(content) or native.get("sha256") != expected_hash:
                raise SmokeError("native transfer metadata differs from the verified content")
            checks.append("private_native_transfer")
            base_config = read_json(node.client_config)
            anonymous = copy.deepcopy(base_config)
            anonymous.pop("client_identity", None)
            anonymous_path = node.directory / "anonymous.json"
            write_json(anonymous_path, anonymous)
            denied_output = workspace / "denied.bin"
            run_command([args.binary, "fetch", "deep://node.alpha/payload.bin", "--config",
                         anonymous_path, "--output", denied_output], "unauthenticated client", False)
            assert_no_partial_output(denied_output)
            checks.append("unauthenticated_client_rejected_without_output")
            wrong = copy.deepcopy(base_config)
            wrong["networks"]["alpha"]["endpoints"]["node.alpha"]["pin_sha256"] = "0" * 64
            wrong_path = node.directory / "wrong-pin.json"
            write_json(wrong_path, wrong)
            wrong_output = workspace / "wrong-pin.bin"
            run_command([args.binary, "fetch", "deep://node.alpha/payload.bin", "--config",
                         wrong_path, "--output", wrong_output], "wrong server pin", False)
            assert_no_partial_output(wrong_output)
            checks.append("wrong_server_pin_rejected_without_output")
            if args.probe:
                probe_path = Path(__file__).resolve().parents[1] / "interop" / "python_probe.py"
                probe_output = workspace / "python.bin"
                result = run_command([sys.executable, probe_path, "--address", node.address,
                                      "--authority", node.authority, "--cert", node.directory / "identity.crt",
                                      "--client-cert", node.directory / "client.crt",
                                      "--client-key", node.directory / "client.key", "--path", "/payload.bin",
                                      "--repeat", "2", "--output", probe_output], "independent Python TLS probe")
                probe = json_result(result.stdout, "Python probe")
                verify_file(probe_output, content)
                requests = probe.get("requests", [])
                if (probe.get("ok") is not True or probe.get("tls_version") != "TLSv1.3"
                        or probe.get("alpn") != "deep/2"
                        or probe.get("authentication") != "ML-DSA-65 (post-quantum)"
                        or probe.get("client_certificate_configured") is not True
                        or len(requests) != 2 or [item.get("request_id") for item in requests] != [1, 2]
                        or any(item.get("size") != len(content) or item.get("sha256") != expected_hash
                               for item in requests)):
                    raise SmokeError("Python probe did not complete two verified V2 requests")
                report["python_openssl"] = probe.get("openssl")
                report["python_key_exchange_verification"] = probe.get("key_exchange_verification")
                checks.append("python_mutual_tls_two_fetches_one_session")
        if args.public_check:
            with RunningNode(args.binary, workspace / "public-node", "node.beta", public=True) as node:
                if "client_identity" in read_json(node.client_config):
                    raise SmokeError("public initialization unexpectedly created client credentials")
                output = workspace / "public.txt"
                result = run_command([args.binary, "fetch", "deep://node.beta/", "--config",
                                      node.client_config, "--output", output, "--info"], "public native transfer")
                verify_security(json_result(result.stderr, "public client"))
                verify_file(output, (node.directory / "content" / "index.txt").read_bytes())
                checks.append("explicit_public_node_without_client_identity")
    report.update(size=len(content), sha256=expected_hash, cleanup="servers stopped; temporary files removed")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="Existing DEEP V2 executable")
    parser.add_argument("--probe", action="store_true", help="Also require live Python/OpenSSL mutual TLS interoperability")
    parser.add_argument("--public-check", action="store_true", help="Also test a separate explicitly public node")
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    if not args.binary.is_file():
        parser.error("--binary must refer to an existing executable")
    try:
        report = exercise(args)
    except (SmokeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
