"""Active probe: open one TLS connection to a host and record what was negotiated.

Used to fetch certificates that TLS 1.3 encrypts inside the handshake (so they
are not visible in a pcap), and by the `check` command. Certificate validation
is disabled on purpose: we want to *inspect* expired or self-signed
certificates, not refuse them. Our own checks in certs.py do the judging.
"""

import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

_SSL_VERSIONS = {"SSLv3": 0x0300, "TLSv1": 0x0301, "TLSv1.1": 0x0302,
                 "TLSv1.2": 0x0303, "TLSv1.3": 0x0304}


@dataclass
class ProbeResult:
    host: str
    port: int
    version: Optional[int] = None
    cipher: Optional[int] = None  # IANA code
    cipher_openssl: Optional[str] = None
    chain: list = field(default_factory=list)  # DER certs, leaf first
    error: Optional[str] = None


def _context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # let legacy servers still answer
    except (ssl.SSLError, ValueError):
        pass
    return ctx


def _chain_der(sock: ssl.SSLSocket) -> list:
    getter = getattr(sock, "get_unverified_chain", None)  # Python 3.13+
    if getter is None and getattr(sock, "_sslobj", None) is not None:
        getter = getattr(sock._sslobj, "get_unverified_chain", None)  # 3.10-3.12
    if getter is not None:
        try:
            certs = getter() or []
            der_enc = getattr(ssl._ssl, "ENCODING_DER", 2)
            return [c if isinstance(c, bytes) else c.public_bytes(der_enc) for c in certs]
        except Exception:
            pass
    leaf = sock.getpeercert(binary_form=True)
    return [leaf] if leaf else []


def fetch(host: str, port: int = 443, sni: Optional[str] = None, timeout: float = 5.0) -> ProbeResult:
    res = ProbeResult(host, port)
    ctx = _context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as s:
                res.version = _SSL_VERSIONS.get(s.version())
                name = s.cipher()[0]
                res.cipher_openssl = name
                ids = {c["name"]: c["id"] & 0xFFFF for c in ctx.get_ciphers()}
                res.cipher = ids.get(name)
                res.chain = _chain_der(s)
    except (OSError, ssl.SSLError) as e:
        res.error = f"{type(e).__name__}: {e}"
    return res
