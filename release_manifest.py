"""Prepare or verify a signed release manifest for a separately supplied APK."""

import argparse
import getpass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

from androguard.core.apk import APK
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from loguru import logger

logger.disable("androguard")


MAX_APK = 512 * 1024 * 1024
MAX_MANIFEST = 16 * 1024
FINGERPRINT = re.compile(r"[a-f0-9]{64}")
APP_ID = re.compile(r"[a-zA-Z]\w*(?:\.[a-zA-Z]\w*)+", re.ASCII)


def run(*command):
    result = subprocess.run(command, capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise ValueError(f"{Path(command[0]).name} rejected the input")
    return result.stdout.decode("utf-8", errors="replace")


def validate(data):
    if set(data) != {"schema", "package", "versionCode", "sha256", "certificateSha256", "size", "url"}:
        raise ValueError("Unexpected manifest fields")
    if (type(data["schema"]) is not int or data["schema"] != 1
            or not APP_ID.fullmatch(data["package"])
            or type(data["versionCode"]) is not int or not 0 < data["versionCode"] <= 2147483647
            or type(data["size"]) is not int or not 0 < data["size"] <= MAX_APK
            or not FINGERPRINT.fullmatch(data["sha256"])
            or not FINGERPRINT.fullmatch(data["certificateSha256"])):
        raise ValueError("Invalid manifest fields")
    url = urlsplit(data["url"])
    if (url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment):
        raise ValueError("Release URL must be HTTPS without embedded credentials or fragment")


def inspect(apk, apksigner):
    size = apk.stat().st_size
    if not 0 < size <= MAX_APK:
        raise ValueError("APK size out of range")
    identity = APK(str(apk))
    signatures = run(*apksigner, "verify", "--min-sdk-version", "27", "--max-sdk-version", "27",
                     "--print-certs", str(apk))
    certificates = re.findall(r"(?m)^Signer #\d+ certificate SHA-256 digest: ([a-f0-9]{64})\s*$", signatures)
    if not identity.get_package() or len(certificates) != 1:
        raise ValueError("Expected one verified APK signer and a valid package identity")
    with apk.open("rb") as stream:
        fingerprint = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"package": identity.get_package(), "versionCode": int(identity.get_androidversion_code()), "sha256": fingerprint,
            "certificateSha256": certificates[0], "size": size}


def create(apk, url, apksigner):
    data = {"schema": 1, "url": url, **inspect(apk, apksigner)}
    validate(data)
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def verify(manifest, signature, public_key, apk, apksigner, package, certificate, installed):
    if manifest.stat().st_size > MAX_MANIFEST or signature.stat().st_size > 1024:
        raise ValueError("Manifest or signature too large")
    key = serialization.load_pem_public_key(public_key.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("Expected an RSA release public key (2048 bits or more)")
    payload = manifest.read_bytes()
    key.verify(signature.read_bytes(), payload, padding.PKCS1v15(), hashes.SHA256())
    data = json.loads(payload)
    validate(data)
    if (data["package"] != package or data["certificateSha256"] != certificate
            or data["versionCode"] <= installed):
        raise ValueError("Wrong update identity or a non-increasing versionCode")
    if any(data.get(field) != value for field, value in inspect(apk, apksigner).items()):
        raise ValueError("APK does not match the approved signed manifest")
    return data["versionCode"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apksigner-jar", required=True, type=Path)
    modes = parser.add_subparsers(dest="mode", required=True)
    make = modes.add_parser("make")
    check = modes.add_parser("verify")
    for mode in (make, check):
        mode.add_argument("--apk", required=True, type=Path)
        mode.add_argument("--manifest", required=True, type=Path)
        mode.add_argument("--signature", required=True, type=Path)
    make.add_argument("--url", required=True)
    make.add_argument("--signing-key", required=True, type=Path)
    check.add_argument("--public-key", required=True, type=Path)
    check.add_argument("--package", required=True)
    check.add_argument("--certificate", required=True)
    check.add_argument("--installed", required=True, type=int)
    args = parser.parse_args()
    signer = ("java", "-jar", str(args.apksigner_jar))
    if args.mode == "make":
        if args.manifest.exists() or args.signature.exists():
            parser.error("Output already exists")
        payload = create(args.apk, args.url, signer)
        key_data = args.signing_key.read_bytes()
        try:
            key = serialization.load_pem_private_key(key_data, password=None)
        except TypeError:
            key = serialization.load_pem_private_key(key_data, password=getpass.getpass().encode("utf-8"))
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("Expected an RSA release signing key (2048 bits or more)")
        signed = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        with args.manifest.open("xb") as stream:
            stream.write(payload)
        with args.signature.open("xb") as stream:
            stream.write(signed)
    else:
        code = verify(args.manifest, args.signature, args.public_key, args.apk, signer,
                      args.package, args.certificate, args.installed)
        print(f"Verified update {code}")


if __name__ == "__main__":
    main()
