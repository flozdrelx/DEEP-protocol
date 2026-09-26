# SPDX-License-Identifier: Apache-2.0
"""Independent framing and hostile-peer tests; no sockets or crypto backend needed."""
import io
import json
from pathlib import Path
import struct
import time
import unittest

import python_probe as probe


class FragmentedConnection:
    def __init__(self, raw):
        self.reader = io.BytesIO(raw)
        self.written = bytearray()

    def settimeout(self, value):
        pass

    def recv(self, size):
        return self.reader.read(min(size, 3))

    def sendall(self, data):
        self.written.extend(data)


def wire(kind, request_id, metadata, body=b""):
    raw = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    return probe.HEADER.pack(b"DEEP", 2, kind, 0, request_id, len(raw), len(body)) + raw + body


class ProbeTests(unittest.TestCase):
    def test_shared_vectors(self):
        suite = json.loads(Path(__file__).with_name("frame_vectors.json").read_text())
        self.assertEqual(suite["protocol_version"], probe.PROTOCOL_VERSION)
        for vector in suite["vectors"]:
            with self.subTest(vector["name"]):
                connection = FragmentedConnection(bytes.fromhex(vector["hex"]))
                if not vector["valid"]:
                    with self.assertRaises(probe.ProbeError):
                        probe.read_frame(connection, time.monotonic() + 5)
                    continue
                kind, request_id, metadata, body = probe.read_frame(connection, time.monotonic() + 5)
                self.assertEqual((kind, request_id), (vector["type"], vector["request_id"]))
                self.assertEqual(metadata, vector["metadata"])
                self.assertEqual(body.hex(), vector["body_hex"])
                self.assertEqual(connection.reader.read(), b"")

    def test_error_limits_are_utf8_bytes_and_safe_text(self):
        for code, message in [("BAD", "\u00e9" * 513), ("BAD", "\x1b[2J"), ("BAD", "\u202e"),
                              ("BAD", "\n"), ("bad", "text"), ("A" * 65, "text")]:
            with self.subTest(code=code, message=message[:10]):
                with self.assertRaisesRegex(probe.ProbeError, "invalid remote error"):
                    probe.check_frame((probe.ERROR, 1, {"code": code, "message": message}, b""), probe.END, 1)
        with self.assertRaisesRegex(probe.ProbeError, "remote error BAD"):
            probe.check_frame((probe.ERROR, 1, {"code": "BAD", "message": "\u00e9" * 512}, b""), probe.END, 1)

    def test_hostile_streams_never_complete(self):
        response = wire(probe.RESPONSE, 1, {"size": 1, "media_type": "text/plain"})
        wrong_hash = wire(probe.END, 1, {"size": 1, "sha256": "0" * 64})
        data = wire(probe.DATA, 1, {}, b"x")
        streams = [response + data, response + data + wrong_hash,
                   response + wire(probe.DATA, 2, {}, b"x"),
                   response + wire(probe.DATA, 1, {}, b"xx"),
                   wire(probe.RESPONSE, 1, {"size": True, "media_type": "text/plain"})]
        for raw in streams:
            with self.subTest(raw=raw.hex()[:80]):
                with self.assertRaises(probe.ProbeError):
                    probe.fetch(FragmentedConnection(raw), "node.alpha", "/", 1, 100,
                                time.monotonic() + 5, io.BytesIO())

    def test_valid_empty_resource(self):
        raw = wire(probe.RESPONSE, 1, {"size": 0, "media_type": "text/plain"})
        raw += wire(probe.END, 1, {"size": 0, "sha256": probe.hashlib.sha256(b"").hexdigest()})
        result = probe.fetch(FragmentedConnection(raw), "node.alpha", "/", 1, 100,
                             time.monotonic() + 5, io.BytesIO())
        self.assertEqual(result["size"], 0)

    def test_mldsa_spki_check(self):
        def der(tag, value):
            self.assertLess(len(value), 128)
            return bytes([tag, len(value)]) + value
        def certificate(oid):
            algorithm = der(0x30, der(0x06, oid))
            spki = der(0x30, algorithm + der(0x03, b"\x00key"))
            tbs = der(0x30, der(0x02, b"\x01") + algorithm + der(0x30, b"") * 3 + spki)
            return der(0x30, tbs + algorithm + der(0x03, b"\x00signature"))
        probe.require_mldsa65_certificate(certificate(probe.ML_DSA_65_OID))
        with self.assertRaisesRegex(probe.ProbeError, "ML-DSA-65"):
            probe.require_mldsa65_certificate(certificate(bytes.fromhex("2b6570")))
        for raw in (b"", b"\x30\x80", b"\x30\x01", b"\x30\x81\x01x"):
            with self.assertRaises(probe.ProbeError):
                probe.require_mldsa65_certificate(raw)


if __name__ == "__main__":
    unittest.main()
