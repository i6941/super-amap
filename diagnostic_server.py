"""Private junction diagnostics receiver. Run behind an authenticated HTTPS ingress."""

import argparse
from contextlib import closing
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import sqlite3


MAX_BODY = 128 * 1024
DEVICE_ID = re.compile(r"[a-zA-Z0-9_-]{1,64}")
SHA256 = re.compile(r"[a-f0-9]{64}")
POINTER = r"(?:0x[0-9a-fA-F]{1,16}|\(nil\)|0)"
EVENTS = {
    "session_ms": re.compile("start"),
    "AionCrossExit": re.compile(fr"{POINTER} {POINTER} {POINTER} branch=\d{{1,3}}"),
    "AionCrossHide": re.compile(fr"{POINTER} {POINTER} {POINTER}"),
    "AionFinish": re.compile(fr"{POINTER} [01] \d{{1,10}}"),
    "AionGFrameLife": re.compile(fr"phase=[01] object={POINTER} vtable_low=[a-fA-F0-9]{{3}} state=\d{{1,10}}"),
}


def validate_trace(body):
    data = body.decode("ascii")
    if not data or not data.endswith("\n"):
        raise ValueError("Incomplete batch")
    for line in data.split("\n")[:-1]:
        timestamp, pid, tag, payload = line.split("\t", 3)
        pattern = EVENTS.get(tag)
        time_format = r"\d{13}" if tag == "session_ms" else r"\d{10}\.\d{3,9}"
        if (not pattern or not pattern.fullmatch(payload) or not re.fullmatch(time_format, timestamp)
                or not re.fullmatch(r"[1-9]\d{0,8}", pid)):
            raise ValueError("Unexpected diagnostic event")


class Receiver(ThreadingHTTPServer):
    def __init__(self, address, database, devices):
        self.database = database
        self.devices = devices
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS batches (
                device TEXT NOT NULL, batch TEXT NOT NULL, version INTEGER NOT NULL,
                body BLOB NOT NULL, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (device, batch)
            )""")
        super().__init__(address, Handler)

    def persist(self, device, batch, version, body):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("INSERT OR IGNORE INTO batches (device, batch, version, body) VALUES (?, ?, ?, ?)",
                       (device, batch, version, body))
            recorded = db.execute("SELECT version FROM batches WHERE device=? AND batch=?",
                                  (device, batch)).fetchone()
            return recorded == (version,)


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    def reply(self, status, **fields):
        body = json.dumps(fields, separators=(",", ":")).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/v1/diagnostics":
            return self.reply(404, error="unknown_path")
        device = self.headers.get("X-Device-ID", "")
        bearer = self.headers.get("Authorization", "")
        expected = self.server.devices.get(device)
        if (not expected or not re.fullmatch(r"Bearer [a-zA-Z0-9_-]{32,128}", bearer)
                or not secrets.compare_digest(expected, hashlib.sha256(bearer[7:].encode("ascii")).hexdigest())):
            return self.reply(401, error="unauthorized")
        size = self.headers.get("Content-Length", "")
        version = self.headers.get("X-Version-Code", "")
        batch = self.headers.get("X-Batch-ID", "")
        if (not re.fullmatch(r"[1-9]\d{0,5}", size) or int(size) > MAX_BODY):
            return self.reply(413, error="invalid_length")
        if not SHA256.fullmatch(batch) or not re.fullmatch(r"[1-9]\d{0,9}", version):
            return self.reply(400, error="invalid_metadata")
        body = self.rfile.read(int(size))
        identity = hashlib.sha256(version.encode("ascii") + b"\n" + body).hexdigest()
        if len(body) != int(size) or not secrets.compare_digest(identity, batch):
            return self.reply(400, error="batch_checksum")
        try:
            validate_trace(body)
        except ValueError:
            return self.reply(400, error="invalid_event")
        try:
            if not self.server.persist(device, batch, int(version), body):
                return self.reply(409, error="batch_conflict")
        except sqlite3.Error:
            return self.reply(503, error="storage_unavailable")
        return self.reply(200, batchId=batch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--device-digests", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    devices = json.loads(args.device_digests.read_text(encoding="utf-8"))
    if not isinstance(devices, dict) or not devices or not all(
        DEVICE_ID.fullmatch(device) and isinstance(digest, str) and SHA256.fullmatch(digest)
        for device, digest in devices.items()
    ):
        parser.error("Invalid device digest registry")
    with Receiver(("127.0.0.1", args.port), args.database, devices) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
