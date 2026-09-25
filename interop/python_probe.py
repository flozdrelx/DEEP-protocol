#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent DEEP V1 wire probe; Python is not a DEEP runtime dependency.

Only Python's standard library is used. OpenSSL performs TLS and hybrid key
exchange. Python ssl does not expose the negotiated group: the Go server must
independently enforce and verify X25519MLKEM768 before accepting DEEP frames.
This test trusts an explicitly supplied server certificate, rather than
implementing DEEP's production adapter/SPKI-pin authentication policy.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import sys
import tempfile
import time
from urllib.parse import urlsplit


HEADER = struct.Struct("!4sBBHIII")
MAX_METADATA = 8192
MAX_CHUNK = 65536
MAX_RESOURCE = 1 << 40
HELLO, WELCOME, REQUEST, RESPONSE, DATA, END, ERROR, CLOSE = range(1, 9)
ALPN = "deep/1"
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


class ProbeError(Exception):
    """A failed protocol assertion, with no recovery or insecure fallback."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError("duplicate JSON metadata key")
        result[key] = value
    return result


def reject_constant(value):
    raise ProbeError("non-JSON numeric constant: " + value)


def validate_json_values(value, depth=1):
    if isinstance(value, (dict, list)):
        if depth > 16:
            raise ProbeError("metadata nesting exceeds 16")
        values = list(value.keys()) + list(value.values()) if isinstance(value, dict) else value
        for child in values:
            validate_json_values(child, depth + 1)
    elif isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ProbeError("metadata contains an unpaired Unicode surrogate")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ProbeError("metadata contains an unbounded number")


def metadata_object(raw):
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                            parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ProbeError("invalid JSON metadata") from error
    if type(result) is not dict:
        raise ProbeError("metadata must be a JSON object")
    validate_json_values(result)
    return result


def require_fields(metadata, fields):
    if set(metadata) != set(fields) or any(value is None for value in metadata.values()):
        raise ProbeError("missing, null or unknown metadata field")


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("probe's overall time limit expired")
    return seconds


def receive_exact(connection, length, deadline):
    result = bytearray()
    while len(result) < length:
        connection.settimeout(remaining(deadline))
        part = connection.recv(length - len(result))
        if not part:
            raise ProbeError("connection ended inside a DEEP frame")
        result.extend(part)
    return bytes(result)


def read_frame(connection, deadline):
    header = receive_exact(connection, HEADER.size, deadline)
    magic, version, kind, flags, request_id, meta_size, body_size = HEADER.unpack(header)
    if magic != b"DEEP" or version != 1 or flags != 0 or not HELLO <= kind <= CLOSE:
        raise ProbeError("invalid magic, framing version, type or flags")
    if not 2 <= meta_size <= MAX_METADATA or body_size > MAX_CHUNK:
        raise ProbeError("frame exceeds DEEP size limits")
    if (kind == DATA and body_size == 0) or (kind != DATA and body_size != 0):
        raise ProbeError("invalid frame body length")
    if kind in (HELLO, WELCOME, CLOSE) and request_id != 0:
        raise ProbeError("control frame has a request ID")
    if REQUEST <= kind <= END and request_id == 0:
        raise ProbeError("resource frame is missing a request ID")
    metadata = metadata_object(receive_exact(connection, meta_size, deadline))
    body = receive_exact(connection, body_size, deadline)
    return kind, request_id, metadata, body


def send_frame(connection, kind, request_id, metadata, deadline):
    raw = json.dumps(metadata, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if not 2 <= len(raw) <= MAX_METADATA:
        raise ProbeError("outgoing metadata exceeds the frame limit")
    header = HEADER.pack(b"DEEP", 1, kind, 0, request_id, len(raw), 0)
    connection.settimeout(remaining(deadline))
    connection.sendall(header + raw)


def check_frame(frame, kind, request_id):
    actual_kind, actual_id, metadata, _ = frame
    if actual_id != request_id:
        raise ProbeError("response request ID mismatch")
    if actual_kind == ERROR:
        require_fields(metadata, ("code", "message"))
        code, message = metadata["code"], metadata["message"]
        if type(code) is not str or not 1 <= len(code) <= 64 or type(message) is not str or len(message) > 1024:
            raise ProbeError("invalid remote error")
        raise ProbeError("remote error " + code + ": " + message)
    if actual_kind != kind:
        raise ProbeError("unexpected DEEP frame type")
    return metadata


def fetch(connection, authority, path, request_id, byte_limit, deadline, output):
    send_frame(connection, REQUEST, request_id,
               {"authority": authority, "path": path, "query": "", "operation": "FETCH"}, deadline)
    metadata = check_frame(read_frame(connection, deadline), RESPONSE, request_id)
    require_fields(metadata, ("media_type", "size"))
    size, media_type = metadata["size"], metadata["media_type"]
    if type(size) is not int or not 0 <= size <= min(MAX_RESOURCE, byte_limit):
        raise ProbeError("resource size is invalid or exceeds --max-bytes")
    if type(media_type) is not str or not 1 <= len(media_type) <= 255 or any(not 32 <= ord(char) <= 126 for char in media_type):
        raise ProbeError("invalid resource media type")
    digest = hashlib.sha256()
    received = 0
    while True:
        frame = read_frame(connection, deadline)
        kind, actual_id, metadata, body = frame
        if actual_id != request_id:
            raise ProbeError("response request ID mismatch")
        if kind == DATA:
            require_fields(metadata, ())
            if len(body) > size - received:
                raise ProbeError("server sent more bytes than announced")
            if output is not None:
                output.write(body)
            digest.update(body)
            received += len(body)
        elif kind == END:
            require_fields(metadata, ("size", "sha256"))
            if type(metadata["size"]) is not int or received != size or metadata["size"] != received:
                raise ProbeError("resource size mismatch")
            if type(metadata["sha256"]) is not str or metadata["sha256"] != digest.hexdigest():
                raise ProbeError("resource SHA-256 mismatch")
            return {"request_id": request_id, "size": received,
                    "sha256": digest.hexdigest(), "media_type": media_type}
        else:
            check_frame(frame, END, request_id)


def parse_address(value):
    parsed = urlsplit("//" + value)
    try:
        port = parsed.port
    except ValueError as error:
        raise argparse.ArgumentTypeError("address must be host:port or [IPv6]:port") from error
    if not parsed.hostname or port is None or not 1 <= port <= 65535 or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError("address must be host:port or [IPv6]:port")
    return parsed.hostname, port


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--address", required=True, type=parse_address)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--cert", required=True, type=Path, help="explicitly trusted local server certificate (PEM)")
    parser.add_argument("--path", default="/", help="percent-encoded resource path; queries are not sent")
    parser.add_argument("--output", type=Path, help="save the last verified response to a new file")
    parser.add_argument("--repeat", type=int, default=2, help="FETCH requests on the same session (default: 2, maximum: 16)")
    parser.add_argument("--max-bytes", type=int, default=64 << 20, help="maximum bytes per response (default: 64 MiB)")
    parser.add_argument("--timeout", type=float, default=30, help="overall connection/transfer deadline in seconds (default: 30)")
    args = parser.parse_args(argv)
    if not re.fullmatch(LABEL + r"\." + LABEL, args.authority):
        parser.error("--authority must be canonical lowercase node.network")
    if not args.path.startswith("/") or len(args.path) > 4096 or re.search(r"[^A-Za-z0-9\-._~!$&'()*+,;=:@/%]", args.path) or re.search(r"%(?![0-9A-Fa-f]{2})", args.path):
        parser.error("--path must be a valid percent-encoded DEEP path")
    if not 1 <= args.repeat <= 16:
        parser.error("--repeat must be between 1 and 16")
    if not 0 <= args.max_bytes <= MAX_RESOURCE:
        parser.error("--max-bytes must be between 0 and 1099511627776")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 3600:
        parser.error("--timeout must be greater than zero and at most 3600 seconds")
    return args


def run(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols([ALPN])
    context.load_verify_locations(cafile=str(args.cert))
    # Keep certificate and hostname verification enabled. Do not call
    # set_ecdh_curve: its legacy curve API cannot select X25519MLKEM768.
    deadline = time.monotonic() + args.timeout
    output = None
    temporary = None
    try:
        if args.output is not None:
            if args.output.exists():
                raise ProbeError("--output already exists; refusing to overwrite it")
            output = tempfile.NamedTemporaryFile(mode="w+b", prefix=".deep-probe-",
                                                 dir=args.output.absolute().parent, delete=False)
            temporary = Path(output.name)
        with socket.create_connection(args.address, timeout=remaining(deadline)) as raw:
            raw.settimeout(remaining(deadline))
            with context.wrap_socket(raw, server_hostname=args.authority) as connection:
                if connection.version() != "TLSv1.3" or connection.selected_alpn_protocol() != ALPN:
                    raise ProbeError("TLS 1.3 and DEEP ALPN were not negotiated")
                send_frame(connection, HELLO, 0, {"versions": [1]}, deadline)
                welcome = check_frame(read_frame(connection, deadline), WELCOME, 0)
                require_fields(welcome, ("version", "max_chunk"))
                if type(welcome["version"]) is not int or welcome["version"] != 1 or type(welcome["max_chunk"]) is not int or welcome["max_chunk"] != MAX_CHUNK:
                    raise ProbeError("unsupported application version or chunk size")
                results = []
                for request_id in range(1, args.repeat + 1):
                    destination = output if request_id == args.repeat else None
                    results.append(fetch(connection, args.authority, args.path, request_id,
                                         args.max_bytes, deadline, destination))
                send_frame(connection, CLOSE, 0, {}, deadline)
                report = {"ok": True, "authority": args.authority, "path": args.path,
                          "size": results[-1]["size"], "sha256": results[-1]["sha256"],
                          "tls_version": connection.version(), "alpn": connection.selected_alpn_protocol(),
                          "openssl": ssl.OPENSSL_VERSION, "requests": results,
                          "key_exchange_verification": "not exposed by Python ssl; requires server-side assertion"}
        if output is not None:
            output.close()
            output = None
            # Hard-link publication is atomic and never replaces an existing
            # destination. The temporary file shares its filesystem.
            os.link(temporary, args.output)
            report["output"] = str(args.output)
        return report
    finally:
        if output is not None:
            output.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    args = arguments()
    try:
        report = run(args)
    except (ProbeError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)[:2048],
                          "openssl": ssl.OPENSSL_VERSION}), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
