import socket
import ssl
import threading
import tempfile
import os
from datetime import datetime, timezone, timedelta
import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from app.checker import check_ssl

def generate_cert_and_key(common_name: str, valid_days_offset: int, duration_days: int = 30):
    """
    Generates a self-signed RSA key and X.509 certificate.
    valid_days_offset: days from now when validity begins (negative for past).
    duration_days: duration of certificate validity.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    now = datetime.now(timezone.utc)
    not_before = now + timedelta(days=valid_days_offset)
    not_after = not_before + timedelta(days=duration_days)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Bank CA"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name), x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return key_pem, cert_pem

class LocalTLSServer:
    """Spins up a lightweight temporary TLS server on localhost for testing."""
    def __init__(self, key_pem: bytes, cert_pem: bytes):
        self.cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        self.key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")

        self.cert_file.write(cert_pem)
        self.cert_file.flush()
        self.key_file.write(key_pem)
        self.key_file.flush()

        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile=self.cert_file.name, keyfile=self.key_file.name)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self.running = True

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                self.sock.settimeout(0.5)
                client, _ = self.sock.accept()
                try:
                    ssl_client = self.context.wrap_socket(client, server_side=True)
                    # Handshake successful, can close or read
                    ssl_client.close()
                except Exception:
                    try:
                        client.close()
                    except Exception:
                        pass
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=2.0)
        try:
            os.unlink(self.cert_file.name)
            os.unlink(self.key_file.name)
        except Exception:
            pass


def test_self_signed_certificate_checker():
    # Certificate valid starting today for 60 days, self-signed (untrusted CA)
    key_pem, cert_pem = generate_cert_and_key("localhost", valid_days_offset=0, duration_days=60)
    server = LocalTLSServer(key_pem, cert_pem)

    try:
        res = check_ssl(hostname="localhost", port=server.port, timeout=5.0)

        assert res["status"] == "INVALID"
        assert res["chain_trusted"] is False
        assert res["hostname_matches"] is True
        assert res["days_remaining"] is not None
        assert res["days_remaining"] > 50
        assert res["subject_cn"] == "localhost"
        assert "Test Bank CA" in (res["issuer"] or "")
        assert res["sha256_fingerprint"] is not None
        assert res["tls_version"] is not None
        assert res["error_message"] is not None
    finally:
        server.stop()


def test_expired_certificate_checker():
    # Certificate that began 60 days ago and lasted 30 days (expired 30 days ago)
    key_pem, cert_pem = generate_cert_and_key("localhost", valid_days_offset=-60, duration_days=30)
    server = LocalTLSServer(key_pem, cert_pem)

    try:
        res = check_ssl(hostname="localhost", port=server.port, timeout=5.0)

        assert res["status"] == "EXPIRED"
        assert res["days_remaining"] is not None
        assert res["days_remaining"] < 0
        assert res["subject_cn"] == "localhost"
        assert res["sha256_fingerprint"] is not None
        assert res["error_message"] is not None
        assert "expired" in res["error_message"].lower()
    finally:
        server.stop()


def test_unreachable_checker():
    # Pick a port that is not listening
    unused_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    unused_sock.bind(("127.0.0.1", 0))
    unused_port = unused_sock.getsockname()[1]
    unused_sock.close()

    res = check_ssl(hostname="127.0.0.1", port=unused_port, timeout=1.0)
    assert res["status"] == "UNREACHABLE"
    assert res["days_remaining"] is None
    assert res["error_message"] is not None
