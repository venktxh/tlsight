"""IANA cipher suite / version / named-group tables and cipher-name parsing.

Only the suite *names* are hard-coded; every attribute (key exchange, cipher,
mode, MAC, forward secrecy...) is derived from the name by `parse_suite`, so the
rules engine never depends on a hand-maintained attribute table.
"""

from dataclasses import dataclass
from functools import lru_cache

VERSIONS = {
    0x0002: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# RFC 8446 section 4.2.7 + IANA "TLS Supported Groups" registry
GROUPS = {
    19: "secp192r1",
    21: "secp224r1",
    22: "secp256k1",
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
    259: "ffdhe6144",
    260: "ffdhe8192",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}
POST_QUANTUM_GROUPS = {0x11EB, 0x11EC, 0x11ED, 0x6399}
# Approximate classical security of each group in bits (used for weak-curve rules)
GROUP_BITS = {19: 96, 21: 112, 22: 128, 23: 128, 24: 192, 25: 256, 29: 128, 30: 224,
              256: 103, 257: 125, 258: 150, 259: 175, 260: 192}

EXTENSIONS = {
    0: "server_name", 5: "status_request", 10: "supported_groups",
    11: "ec_point_formats", 13: "signature_algorithms", 16: "alpn",
    18: "signed_cert_timestamp", 21: "padding", 23: "extended_master_secret",
    27: "compress_certificate", 35: "session_ticket", 41: "pre_shared_key",
    43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share",
    0xFF01: "renegotiation_info", 0xFE0D: "encrypted_client_hello",
}

SCSV = {0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x5600: "TLS_FALLBACK_SCSV"}

SUITES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
    0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
    0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

_MACS = {"SHA", "SHA256", "SHA384", "MD5", "NULL"}
_BITS = {"3DES": 112, "DES": 56, "DES40": 40, "CHACHA20": 256, "IDEA": 128, "NULL": 0}


@dataclass(frozen=True)
class Suite:
    code: int
    name: str
    kex: str  # RSA, DHE, ECDHE, DH, ECDH, NULL, PSK, TLS13
    auth: str  # RSA, ECDSA, DSS, anon, ...
    cipher: str  # AES, 3DES, RC4, CHACHA20, NULL, ...
    bits: int
    mode: str  # GCM, CCM, CBC, POLY1305, STREAM, NULL
    mac: str  # SHA, SHA256, MD5, AEAD
    forward_secrecy: bool
    aead: bool
    export: bool
    anon: bool
    tls13: bool = False


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0A0A, 0x1A1A, ... 0xFAFA."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def version_name(v) -> str:
    if v is None:
        return "-"
    return VERSIONS.get(v, f"0x{v:04X}")


def group_name(g) -> str:
    if g is None:
        return "-"
    return GROUPS.get(g, f"0x{g:04X}")


def suite_name(code) -> str:
    if code is None:
        return "-"
    return SUITES.get(code) or SCSV.get(code) or f"UNKNOWN_0x{code:04X}"


@lru_cache(maxsize=None)
def lookup(code: int):
    """Return a parsed Suite for an IANA code, or None if unknown / SCSV / GREASE."""
    name = SUITES.get(code)
    return parse_suite(name, code) if name else None


def parse_suite(name: str, code: int = -1) -> Suite:
    body = name.split("_", 1)[1]  # strip TLS_ / SSL_

    if "_WITH_" not in body:
        # TLS 1.3 suite, e.g. AES_128_GCM_SHA256: key exchange is always (EC)DHE
        enc_tokens = body.split("_")
        cipher, mode, bits, mac = _parse_enc(enc_tokens)
        return Suite(code, name, "TLS13", "cert", cipher, bits, mode, "AEAD",
                     forward_secrecy=True, aead=True, export=False, anon=False, tls13=True)

    kex_part, enc_part = body.split("_WITH_", 1)
    kex_tokens = kex_part.split("_")
    kex = kex_tokens[0]
    auth_tokens = [t for t in kex_tokens[1:] if t != "EXPORT"]
    auth = "_".join(auth_tokens) or ("RSA" if kex == "RSA" else kex)
    export = "EXPORT" in kex_tokens
    anon = "anon" in kex_tokens

    cipher, mode, bits, mac = _parse_enc(enc_part.split("_"))
    aead = mode in ("GCM", "CCM", "POLY1305")
    return Suite(code, name, kex, auth, cipher, bits, mode, mac,
                 forward_secrecy=kex in ("DHE", "ECDHE"), aead=aead, export=export, anon=anon)


def _parse_enc(tokens):
    tokens = list(tokens)
    mac = "AEAD"
    if len(tokens) > 1 and tokens[-1] in _MACS:
        mac = tokens.pop()
    cipher = tokens[0]

    if cipher == "NULL":
        return "NULL", "NULL", 0, mac
    if "GCM" in tokens:
        mode = "GCM"
    elif "CCM" in tokens:
        mode = "CCM"
    elif "POLY1305" in tokens:
        mode = "POLY1305"
    elif "CBC" in tokens:
        mode = "CBC"
    else:
        mode = "STREAM"  # RC4

    numeric = [int(t) for t in tokens[1:] if t.isdigit() and int(t) > 8]
    bits = numeric[0] if numeric else _BITS.get(cipher, 0)
    if mode in ("GCM", "CCM", "POLY1305"):
        mac = "AEAD"
    return cipher, mode, bits, mac
