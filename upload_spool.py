"""Durably queue junction-only batches and upload them with an idempotent receipt."""

import argparse
import hashlib
from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

from diagnostic_server import DEVICE_ID, MAX_BODY, validate_trace


MAX_PENDING = 128
PENDING = re.compile(r"(?P<version>[1-9]\d{0,9})-(?P<batch>[a-f0-9]{64})\.tsv")


def queue(directory, version, body):
    if not re.fullmatch(r"[1-9]\d{0,9}", str(version)) or not 0 < len(body) <= MAX_BODY:
        raise ValueError("Invalid version or batch size")
    validate_trace(body)
    identity = hashlib.sha256(str(version).encode("ascii") + b"\n" + body).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{version}-{identity}.tsv"
    if target.exists():
        return target
    if len(list(directory.glob("*.tsv"))) >= MAX_PENDING:
        raise RuntimeError("Spool is full; pending batches were retained")
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            stream.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def send(file, endpoint, device, token, connection_factory=HTTPSConnection):
    url = urlsplit(endpoint)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ("", "/", "/v1/diagnostics")):
        raise ValueError("Expected an HTTPS diagnostic receiver")
    if not DEVICE_ID.fullmatch(device) or not re.fullmatch(r"[a-zA-Z0-9_-]{32,128}", token):
        raise ValueError("Invalid diagnostic enrollment")
    metadata = PENDING.fullmatch(file.name)
    if metadata is None:
        raise ValueError("Unexpected pending batch filename")
    with file.open("rb") as stream:
        body = stream.read(MAX_BODY + 1)
    if not 0 < len(body) <= MAX_BODY:
        raise ValueError("Unexpected pending batch size")
    connection = connection_factory(url.hostname, url.port or 443, timeout=15)
    batch = metadata["batch"]
    try:
        connection.request("POST", "/v1/diagnostics", body, {
            "Authorization": f"Bearer {token}", "Content-Type": "text/tab-separated-values",
            "X-Device-ID": device, "X-Version-Code": metadata["version"], "X-Batch-ID": batch,
        })
        response = connection.getresponse()
        raw = response.read(4097)
        if response.status != 200 or len(raw) > 4096:
            raise RuntimeError(f"Receiver did not confirm batch (HTTP {response.status})")
        if json.loads(raw) != {"batchId": batch}:
            raise RuntimeError("Receiver confirmation does not match pending batch")
    finally:
        connection.close()
    file.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spool", required=True, type=Path)
    modes = parser.add_subparsers(dest="mode", required=True)
    add = modes.add_parser("queue")
    add.add_argument("--version-code", required=True, type=int)
    add.add_argument("--trace", required=True, type=Path)
    flush = modes.add_parser("flush")
    flush.add_argument("--endpoint", required=True)
    flush.add_argument("--device", required=True)
    flush.add_argument("--token-file", required=True, type=Path)
    args = parser.parse_args()
    if args.mode == "queue":
        with args.trace.open("rb") as stream:
            file = queue(args.spool, args.version_code, stream.read(MAX_BODY + 1))
        print(f"Queued {file.name}")
    else:
        token = args.token_file.read_text(encoding="ascii").strip()
        for file in sorted(args.spool.glob("*.tsv"), key=lambda candidate: candidate.stat().st_mtime):
            send(file, args.endpoint, args.device, token)
            print(f"Confirmed {file.name}")


if __name__ == "__main__":
    main()
