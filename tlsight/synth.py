"""Build synthetic TLS handshakes, certificates and pcaps.

Used by the unit tests and by tools/make_samples.py to produce demo captures
with known-good and known-bad configurations. Nothing here is sent on a network.
"""

import os
import struct
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def u8(n): return struct.pack("!B", n)
def u16(n): return struct.pack("!H", n)
def u24(n): return n.to_bytes(3, "big")
def vec8(b): return u8(len(b)) + b
def vec16(b): return u16(len(b)) + b
def vec24(b): return u24(len(b)) + b


# ---- extensions -------------------------------------------------------------

def ext(etype: int, data: bytes = b"") -> bytes:
    return u16(etype) + vec16(data)


def sni_ext(host: str) -> bytes:
    return ext(0, vec16(u8(0) + vec16(host.encode())))


def groups_ext(groups) -> bytes:
    return ext(10, vec16(b"".join(u16(g) for g in groups)))


def point_formats_ext(fmts) -> bytes:
    return ext(11, vec8(bytes(fmts)))


def alpn_ext(protocols) -> bytes:
    return ext(16, vec16(b"".join(vec8(p.encode()) for p in protocols)))


def client_versions_ext(versions) -> bytes:
    return ext(43, vec8(b"".join(u16(v) for v in versions)))


def server_version_ext(version: int) -> bytes:
    return ext(43, u16(version))


def client_key_share_ext(groups) -> bytes:
    return ext(51, vec16(b"".join(u16(g) + vec16(os.urandom(32)) for g in groups)))


def server_key_share_ext(group: int) -> bytes:
    return ext(51, u16(group) + vec16(os.urandom(32)))


# ---- handshake messages -----------------------------------------------------

def handshake(msg_type: int, body: bytes) -> bytes:
    return u8(msg_type) + vec24(body)


def records(content_type: int, payload: bytes, version: int = 0x0303, max_len: int = 16384) -> bytes:
    """Wrap a payload in one or more TLS records (fragmenting like a real stack)."""
    out = b""
    for i in range(0, len(payload), max_len):
        out += u8(content_type) + u16(version) + vec16(payload[i:i + max_len])
    return out


def client_hello(ciphers, extensions=(), version: int = 0x0303) -> bytes:
    body = (u16(version) + os.urandom(32) + vec8(os.urandom(32))
            + vec16(b"".join(u16(c) for c in ciphers)) + vec8(b"\x00"))
    if extensions is not None:
        body += vec16(b"".join(extensions))
    return handshake(1, body)


def server_hello(cipher: int, extensions=(), version: int = 0x0303) -> bytes:
    body = u16(version) + os.urandom(32) + vec8(os.urandom(32)) + u16(cipher) + u8(0)
    if extensions is not None:
        body += vec16(b"".join(extensions))
    return handshake(2, body)


def certificate(ders) -> bytes:
    return handshake(11, vec24(b"".join(vec24(d) for d in ders)))


def server_key_exchange_dhe(p_bits: int) -> bytes:
    p = b"\xff" * (p_bits // 8)
    return handshake(12, vec16(p) + vec16(b"\x02") + vec16(os.urandom(len(p))) + vec16(os.urandom(64)))


def server_key_exchange_ecdhe(group: int) -> bytes:
    return handshake(12, u8(3) + u16(group) + vec8(b"\x04" + os.urandom(64)) + vec16(os.urandom(64)))


def server_hello_done() -> bytes:
    return handshake(14, b"")


def change_cipher_spec() -> bytes:
    return records(20, b"\x01")


# ---- certificates -----------------------------------------------------------

def make_key(kind: str = "ec", bits: int = 2048):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return ec.generate_private_key(ec.SECP256R1())


def make_cert(cn: str, key=None, issuer_cn: str = None, issuer_key=None, days=(-30, 365),
              hash_alg=None, san=None, ca: bool = False) -> tuple:
    """Return (der, private_key). Self-signed unless issuer_key is given."""
    key = key or make_key()
    issuer_key = issuer_key or key
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)]))
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + timedelta(days=days[0]))
               .not_valid_after(now + timedelta(days=days[1]))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                              critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    if isinstance(hash_alg, hashes.SHA1):
        return _sign_sha1(builder.sign(issuer_key, hashes.SHA256()), issuer_key), key
    cert = builder.sign(issuer_key, hash_alg or hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER), key


# DER-encoded OIDs; both are 11 bytes, so swapping them keeps every length field valid.
_OID_SHA256_RSA = bytes.fromhex("06092A864886F70D01010B")
_OID_SHA1_RSA = bytes.fromhex("06092A864886F70D010105")


def _sign_sha1(cert: x509.Certificate, issuer_key) -> bytes:
    """Re-sign an RSA/SHA-256 certificate as RSA/SHA-1.

    cryptography refuses to *build* SHA-1 certificates (correctly), but the
    analyzer must be tested against them, so swap the signature-algorithm OID
    and replace the signature with an RSA-SHA1 one over the modified TBS."""
    from cryptography.hazmat.primitives.asymmetric import padding

    der = cert.public_bytes(serialization.Encoding.DER)
    tbs = cert.tbs_certificate_bytes.replace(_OID_SHA256_RSA, _OID_SHA1_RSA)
    sig = issuer_key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    assert len(sig) == len(cert.signature)
    der = der[:-len(sig)].replace(_OID_SHA256_RSA, _OID_SHA1_RSA) + sig
    return der


# ---- pcap -------------------------------------------------------------------

def tcp_session(client, server, c2s: bytes, s2c: bytes, mss: int = 1400, t0: float = 1_700_000_000.0):
    """Packets for a TCP handshake followed by one client flight and one server flight."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    (cip, cport), (sip, sport) = client, server
    cseq, sseq = 1000, 50000
    pkts = []

    def mk(src, sport_, dst, dport_, flags, seq, ack, data=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport_, dport=dport_, flags=flags, seq=seq, ack=ack)
        if data:
            p = p / data
        p.time = t0 + len(pkts) * 0.001
        pkts.append(p)

    mk(cip, cport, sip, sport, "S", cseq, 0)
    mk(sip, sport, cip, cport, "SA", sseq, cseq + 1)
    mk(cip, cport, sip, sport, "A", cseq + 1, sseq + 1)
    cseq += 1
    sseq += 1
    for i in range(0, len(c2s), mss):
        mk(cip, cport, sip, sport, "PA", cseq + i, sseq, c2s[i:i + mss])
    cseq += len(c2s)
    for i in range(0, len(s2c), mss):
        mk(sip, sport, cip, cport, "PA", sseq + i, cseq, s2c[i:i + mss])
    return pkts
