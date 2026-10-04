"""X.509 certificate inspection and certificate-related findings."""

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from .models import CertInfo, Finding


def _name(n: x509.Name) -> str:
    cn = n.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else n.rfc4514_string()


def inspect(der: bytes, now: Optional[datetime] = None) -> CertInfo:
    now = now or datetime.now(timezone.utc)
    cert = x509.load_der_x509_certificate(der)

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_size = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_size = f"EC {key.curve.name}", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_size = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, key_size = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, key_size = "Ed448", 456
    else:
        key_type, key_size = type(key).__name__, 0

    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # unsupported/unknown algorithm
        sig_hash = None
    if sig_hash is None:
        sig_hash = getattr(cert.signature_algorithm_oid, "_name", None)

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []

    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    not_after = cert.not_valid_after_utc
    return CertInfo(
        subject=_name(cert.subject),
        issuer=_name(cert.issuer),
        serial=f"{cert.serial_number:x}",
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=not_after.isoformat(),
        days_left=(not_after - now).days,
        key_type=key_type,
        key_size=key_size,
        sig_hash=sig_hash,
        self_signed=cert.issuer == cert.subject,
        is_ca=is_ca,
        san=list(san_names),
    )


_ROOTS = None


def mozilla_roots() -> list:
    """Mozilla's trusted root CAs (the certifi bundle), the store sslyze also reports on."""
    global _ROOTS
    if _ROOTS is None:
        import warnings

        import certifi
        with open(certifi.where(), "rb") as fh, warnings.catch_warnings():
            warnings.simplefilter("ignore")  # a few old roots have non-RFC serials
            _ROOTS = x509.load_pem_x509_certificates(fh.read())
    return _ROOTS


def verify_chain(chain_der: list, hostname: str, roots=None, now: Optional[datetime] = None) -> tuple:
    """RFC 5280 path validation of leaf + intermediates up to a trusted root.
    Returns (trusted, error_message)."""
    from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

    certs = [x509.load_der_x509_certificate(d) for d in chain_der]
    anchors = mozilla_roots() if roots is None else [x509.load_der_x509_certificate(d) for d in roots]
    builder = PolicyBuilder().store(Store(anchors)).time(now or datetime.now(timezone.utc))
    try:
        verifier = builder.build_server_verifier(x509.DNSName(hostname))
        verifier.verify(certs[0], certs[1:])
        return True, None
    except VerificationError as e:
        return False, str(e)
    except ValueError as e:  # e.g. hostname not a valid DNS name
        return None, str(e)


def hostname_matches(hostname: str, names) -> bool:
    """RFC 6125 style matching: exact, or a single left-most '*' label."""
    host = hostname.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if host.endswith(suffix) and "." not in host[: -len(suffix)]:
                return True
    return False


def cert_findings(chain: list, hostname: Optional[str] = None) -> list:
    """Findings for a certificate chain (list of CertInfo, leaf first)."""
    out = []

    def add(sev, title, detail):
        out.append(Finding(sev, title, detail, side="certificate"))

    for i, c in enumerate(chain):
        label = "Leaf certificate" if i == 0 else f"Chain certificate #{i} ({c.subject})"
        is_root = i > 0 and c.self_signed

        if c.days_left < 0:
            add("CRITICAL", f"{label} expired",
                f"Expired {-c.days_left} days ago (notAfter {c.not_after[:10]}).")
        elif c.days_left <= 30:
            add("MEDIUM", f"{label} expires soon", f"{c.days_left} days left.")
        if c.not_before > datetime.now(timezone.utc).isoformat():
            add("HIGH", f"{label} not yet valid", f"notBefore {c.not_before[:10]}.")

        if c.key_type == "RSA" and c.key_size < 2048:
            add("CRITICAL", f"{label} uses a weak {c.key_size}-bit RSA key",
                "RSA keys below 2048 bits are within reach of factoring attacks (NIST SP 800-131A).")
        elif c.key_type == "DSA":
            add("HIGH", f"{label} uses a DSA key", "DSA is deprecated for TLS certificates.")
        elif c.key_type.startswith("EC") and c.key_size < 224:
            add("HIGH", f"{label} uses a weak {c.key_size}-bit EC key", "Use P-256 or stronger.")

        # A root's own signature is never checked by clients, so skip roots.
        if not is_root and c.sig_hash:
            h = c.sig_hash.lower()
            if h in ("md5", "md2") or h.startswith("md5"):
                add("CRITICAL", f"{label} signed with {c.sig_hash}",
                    "MD5 is broken: chosen-prefix collisions allowed forged CA certificates (2008).")
            elif h == "sha1":
                add("MEDIUM", f"{label} signed with SHA-1",
                    "SHA-1 collisions are practical (SHAttered 2017); browsers reject SHA-1 certificates.")

    if chain:
        leaf = chain[0]
        if leaf.self_signed and len(chain) == 1:
            add("HIGH", "Self-signed certificate",
                "Not issued by a trusted CA, so the server's identity can't be authenticated (MITM risk).")
        if hostname:
            names = leaf.san or [leaf.subject]
            if not hostname_matches(hostname, names):
                add("HIGH", "Certificate hostname mismatch",
                    f"'{hostname}' is not covered by {', '.join(names[:5])}.")
        if not out:
            add("GOOD", "Certificate chain looks healthy",
                f"{leaf.key_type} {leaf.key_size}-bit key, signed with {leaf.sig_hash}, "
                f"{leaf.days_left} days of validity left.")
    return out
