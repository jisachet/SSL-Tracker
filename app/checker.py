import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID

def compute_days_remaining(not_after: datetime, now: Optional[datetime] = None) -> int:
    """
    Computes days remaining until not_after.
    Negative if already expired.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    diff = (not_after - now).total_seconds()
    # If positive, round down to complete days; if negative, calculate negative days
    if diff >= 0:
        return int(diff // 86400)
    else:
        # Expired: returns -1, -2, etc.
        return int(diff // 86400)

def match_wildcard_or_name(pattern: str, hostname: str) -> bool:
    """Matches a DNS pattern (possibly wildcard like *.example.com) against a hostname."""
    pattern = pattern.lower().strip()
    hostname = hostname.lower().strip()
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # e.g. .example.com
        if hostname.endswith(suffix):
            prefix = hostname[:-len(suffix)]
            if "." not in prefix and len(prefix) > 0:
                return True
    return False

def check_hostname_against_cert(hostname: str, san_dns_names: List[str], common_name: Optional[str]) -> bool:
    """
    Checks if hostname matches either SANs (preferred) or Subject Common Name.
    """
    hostname = hostname.lower()
    if san_dns_names:
        for san in san_dns_names:
            if match_wildcard_or_name(san, hostname):
                return True
    if common_name and match_wildcard_or_name(common_name, hostname):
        return True
    return False

def determine_status(
    is_unreachable: bool,
    days_remaining: Optional[int],
    chain_trusted: Optional[bool],
    hostname_matches: Optional[bool],
) -> str:
    """
    Status hierarchy according to specification:
    - UNREACHABLE (DNS failure, timeout, connection refused)
    - EXPIRED (certificate past notAfter)
    - INVALID (chain or hostname problem)
    - EXPIRING SOON (30 days or less)
    - OK (> 30 days and valid)
    """
    if is_unreachable:
        return "UNREACHABLE"
    if days_remaining is None:
        return "UNREACHABLE"
    if days_remaining < 0:
        return "EXPIRED"
    if not chain_trusted or not hostname_matches:
        return "INVALID"
    if days_remaining <= 30:
        return "EXPIRING SOON"
    return "OK"

def extract_cert_info(der_bytes: bytes, hostname: str) -> Dict[str, Any]:
    """
    Parses DER-encoded X.509 certificate and extracts relevant fields.
    """
    cert = x509.load_der_x509_certificate(der_bytes)

    # Expiry date
    if hasattr(cert, "not_valid_after_utc"):
        not_after = cert.not_valid_after_utc
    else:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    # Subject Common Name
    subject_cn = None
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        subject_cn = cn_attrs[0].value

    # Issuer
    issuer_parts = []
    issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_org_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if issuer_cn_attrs:
        issuer_parts.append(str(issuer_cn_attrs[0].value))
    if issuer_org_attrs and (not issuer_cn_attrs or issuer_org_attrs[0].value != issuer_cn_attrs[0].value):
        issuer_parts.append(f"({issuer_org_attrs[0].value})")
    issuer = " ".join(issuer_parts) if issuer_parts else "Unknown Issuer"

    # SANs (Subject Alternative Names)
    sans_list: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            sans_list.append(str(name.value))
    except Exception:
        pass

    # SHA-256 Fingerprint
    fingerprint_bytes = cert.fingerprint(hashes.SHA256())
    sha256_fingerprint = ":".join(f"{b:02X}" for b in fingerprint_bytes)

    # Hostname match check
    hostname_matches = check_hostname_against_cert(hostname, sans_list, subject_cn)

    days_left = compute_days_remaining(not_after)

    return {
        "not_after": not_after,
        "days_remaining": days_left,
        "subject_cn": subject_cn,
        "issuer": issuer,
        "sans": sans_list,
        "sha256_fingerprint": sha256_fingerprint,
        "hostname_matches": hostname_matches,
    }

def check_ssl(hostname: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Connects to hostname:port using SNI with timeout.
    Attempts strict certificate verification first.
    If verification fails (e.g., self-signed, expired, hostname mismatch, untrusted CA),
    re-connects without verification to read certificate details instead of crashing.
    """
    check_time = datetime.now(timezone.utc)
    base_result: Dict[str, Any] = {
        "checked_at": check_time,
        "hostname": hostname,
        "port": port,
        "status": "UNREACHABLE",
        "days_remaining": None,
        "not_after": None,
        "issuer": None,
        "subject_cn": None,
        "sans": None,
        "chain_trusted": None,
        "hostname_matches": None,
        "tls_version": None,
        "sha256_fingerprint": None,
        "error_message": None,
    }

    # Attempt 1: Strict TLS handshake with CA verification and hostname checking
    verified_success = False
    tls_version = None
    der_cert = None
    verification_error: Optional[str] = None

    try:
        raw_sock = socket.create_connection((hostname, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with ctx.wrap_socket(raw_sock, server_hostname=hostname) as s:
            tls_version = s.version()
            der_cert = s.getpeercert(binary_form=True)
            verified_success = True
    except (ssl.SSLCertVerificationError, ssl.SSLError) as ssl_err:
        verification_error = str(ssl_err)
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as net_err:
        # If the very first network connection failed (e.g. DNS or socket timeout)
        base_result["error_message"] = f"Network connection failed: {net_err}"
        return base_result
    except Exception as exc:
        verification_error = f"Unexpected SSL error: {exc}"

    # If verified handshake succeeded:
    if verified_success and der_cert:
        try:
            cert_info = extract_cert_info(der_cert, hostname)
            status = determine_status(
                is_unreachable=False,
                days_remaining=cert_info["days_remaining"],
                chain_trusted=True,
                hostname_matches=True,
            )
            base_result.update({
                "status": status,
                "days_remaining": cert_info["days_remaining"],
                "not_after": cert_info["not_after"],
                "issuer": cert_info["issuer"],
                "subject_cn": cert_info["subject_cn"],
                "sans": ", ".join(cert_info["sans"]) if cert_info["sans"] else None,
                "chain_trusted": True,
                "hostname_matches": True,
                "tls_version": tls_version,
                "sha256_fingerprint": cert_info["sha256_fingerprint"],
                "error_message": None,
            })
            return base_result
        except Exception as parse_err:
            base_result["status"] = "INVALID"
            base_result["error_message"] = f"Failed to parse certificate: {parse_err}"
            return base_result

    # Attempt 2: Unverified handshake to read certificate even if verification failed
    try:
        raw_sock = socket.create_connection((hostname, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        unverified_ctx = ssl.create_default_context()
        unverified_ctx.check_hostname = False
        unverified_ctx.verify_mode = ssl.CERT_NONE

        with unverified_ctx.wrap_socket(raw_sock, server_hostname=hostname) as s:
            tls_version = s.version()
            der_cert = s.getpeercert(binary_form=True)

        if not der_cert:
            base_result["status"] = "INVALID"
            base_result["error_message"] = verification_error or "Server did not provide a certificate"
            return base_result

        cert_info = extract_cert_info(der_cert, hostname)
        chain_trusted = False  # Failed earlier verification
        hostname_matches = cert_info["hostname_matches"]

        status = determine_status(
            is_unreachable=False,
            days_remaining=cert_info["days_remaining"],
            chain_trusted=chain_trusted,
            hostname_matches=hostname_matches,
        )

        # Reason for failure
        reasons = []
        if verification_error:
            reasons.append(verification_error)
        if not hostname_matches:
            reasons.append(f"Hostname '{hostname}' does not match certificate SANs or Common Name")
        if cert_info["days_remaining"] < 0:
            reasons.append(f"Certificate expired on {cert_info['not_after'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        base_result.update({
            "status": status,
            "days_remaining": cert_info["days_remaining"],
            "not_after": cert_info["not_after"],
            "issuer": cert_info["issuer"],
            "subject_cn": cert_info["subject_cn"],
            "sans": ", ".join(cert_info["sans"]) if cert_info["sans"] else None,
            "chain_trusted": False,
            "hostname_matches": hostname_matches,
            "tls_version": tls_version,
            "sha256_fingerprint": cert_info["sha256_fingerprint"],
            "error_message": "; ".join(reasons) if reasons else "Certificate validation failed",
        })
        return base_result

    except Exception as exc:
        base_result["status"] = "UNREACHABLE"
        base_result["error_message"] = f"Unreachable: {verification_error or exc}"
        return base_result
