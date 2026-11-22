from contextlib import closing
import hashlib
from http.client import HTTPSConnection
import ipaddress
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from diagnostic_server import Receiver
from upload_spool import queue, send


BODY = b"1795326095.538\t123\tAionCrossExit\t0x1000 0x2000 0x0 branch=0\n"
TOKEN = "synthetic_test_credential_not_for_production"


class ReleaseLoopTest(unittest.TestCase):
    def test_https_disconnect_receipt_and_deduplication(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            db = home / "received.sqlite"
            spool = home / "outbox"
            pending = queue(spool, 26000151, BODY)
            with self.assertRaises(ValueError):
                queue(spool, 26000151, BODY.replace(b"branch=0", b"location=example"))
            previous = home / "retry.tsv"
            shutil.copyfile(pending, previous)
            self.assertEqual(queue(spool, 26000151, BODY), pending)
            with socket.socket() as disconnected:
                disconnected.bind(("127.0.0.1", 0))
                unused = disconnected.getsockname()[1]
                with self.assertRaises(OSError):
                    send(pending, f"https://127.0.0.1:{unused}", "test-car", TOKEN)
            self.assertTrue(pending.exists())

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local release loop test")])
            now = datetime.now(timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                           .public_key(key.public_key()).serial_number(x509.random_serial_number())
                           .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                           .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                                          critical=False).sign(key, hashes.SHA256()))
            cert_file, key_file = home / "test-cert.pem", home / "test-key.pem"
            cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert_file, key_file)
            client = ssl.create_default_context(cafile=str(cert_file))

            def connect(host, port, timeout):
                return HTTPSConnection(host, port, timeout=timeout, context=client)

            with Receiver(("127.0.0.1", 0), db,
                          {"test-car": hashlib.sha256(TOKEN.encode("ascii")).hexdigest()}) as server:
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                worker = Thread(target=server.serve_forever, daemon=True)
                worker.start()
                endpoint = f"https://127.0.0.1:{server.server_port}"
                try:
                    with self.assertRaises(RuntimeError):
                        send(pending, endpoint, "test-car", "another_synthetic_credential_01234567", connect)
                    self.assertTrue(pending.exists())
                    send(pending, endpoint, "test-car", TOKEN, connect)
                    self.assertFalse(pending.exists())
                    shutil.copyfile(previous, pending)
                    send(pending, endpoint, "test-car", TOKEN, connect)
                    with closing(sqlite3.connect(db)) as received:
                        self.assertEqual(received.execute("SELECT count(*) FROM batches").fetchone(), (1,))
                        self.assertEqual(received.execute("SELECT version, body FROM batches").fetchone(),
                                         (26000151, BODY))
                finally:
                    server.shutdown()
                    worker.join()


if __name__ == "__main__":
    unittest.main()
