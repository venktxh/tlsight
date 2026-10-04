"""Scoring ruleset: turn a parsed Connection into findings, a score and a grade."""

from . import certs as certs_mod
from .ciphers import (GROUP_BITS, POST_QUANTUM_GROUPS, SCSV, group_name, is_grease,
                      lookup, suite_name, version_name)
from .models import Connection, Finding

PENALTY = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0, "GOOD": 0}


def cipher_issues(code: int) -> list:
    """[(severity, title, detail)] for one cipher suite."""
    s = lookup(code)
    if s is None:
        return []
    out = []
    if s.cipher == "NULL":
        out.append(("CRITICAL", "NULL encryption", "Application data is sent unencrypted."))
    if s.anon:
        out.append(("CRITICAL", "Anonymous key exchange",
                    "The server is never authenticated, so any MITM can impersonate it."))
    if s.export:
        out.append(("CRITICAL", "EXPORT-grade cipher",
                    "Deliberately weakened 40/56-bit crypto from the 1990s (FREAK, Logjam)."))
    if s.cipher == "RC4":
        out.append(("CRITICAL", "RC4 stream cipher",
                    "RC4 keystream biases leak plaintext; RFC 7465 forbids RC4 in TLS."))
    if s.cipher in ("DES", "DES40", "RC2") and not s.export:
        out.append(("CRITICAL", f"{s.cipher} cipher", "56-bit (or smaller) keys can be brute-forced."))
    if s.cipher == "3DES":
        out.append(("HIGH", "3DES cipher (Sweet32)",
                    "64-bit block size: birthday collisions after ~32 GB on one connection (CVE-2016-2183)."))
    if not s.forward_secrecy and not s.anon and s.cipher != "NULL" and s.kex not in ("NULL", "PSK"):
        out.append(("HIGH", "No forward secrecy",
                    f"Static {s.kex} key exchange: anyone who later obtains the server's private key "
                    "can decrypt every recorded session."))
    if s.mode == "CBC":
        out.append(("MEDIUM", "CBC-mode cipher",
                    "MAC-then-encrypt CBC has a history of padding-oracle attacks (BEAST, Lucky13, POODLE)."))
    if s.mac == "MD5" and s.cipher not in ("RC4", "NULL"):
        out.append(("MEDIUM", "HMAC-MD5 record MAC", "Prefer SHA-256 or AEAD ciphers."))
    return out


def _add(findings, sev, title, detail="", side="server"):
    findings.append(Finding(sev, title, detail, side))


def evaluate(conn: Connection) -> Connection:
    f = []
    _client_rules(conn, f)

    if conn.cipher is None:
        _add(f, "INFO", "Handshake incomplete",
             "No ServerHello was captured, so only the client's offer can be judged.")
        conn.findings, conn.score, conn.grade = _sorted(f), None, "N/A"
        return conn

    _version_rules(conn, f)
    _cipher_rules(conn, f)
    _kex_rules(conn, f)
    _extension_rules(conn, f)

    if conn.certs:
        cert_f = certs_mod.cert_findings(conn.certs, conn.sni)
        f.extend(cert_f)
        _trust_rules(conn, f, cert_f)
    elif conn.version == 0x0304:
        _add(f, "INFO", "Certificate not visible (TLS 1.3)",
             "TLS 1.3 encrypts the Certificate message. Re-run with --probe to fetch it.",
             side="certificate")
    else:
        _add(f, "INFO", "Certificate not captured",
             "The Certificate message was missing from the capture (resumed session or lost segments).",
             side="certificate")

    conn.findings = _sorted(f)
    conn.score, conn.grade = score(conn.findings)
    return conn


def score(findings) -> tuple:
    """Grade the server's configuration. Client-side findings are reported but
    don't count: the server can't control what a client offers."""
    graded = [x for x in findings if x.side != "client"]
    points = max(100 - sum(PENALTY[x.severity] for x in graded), 0)
    if any(x.severity == "CRITICAL" for x in graded):
        return points, "F"
    for limit, grade in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if points >= limit:
            return points, grade
    return points, "F"


def _sorted(findings):
    from .models import SEVERITIES
    return sorted(findings, key=lambda x: SEVERITIES.index(x.severity))


def _client_rules(conn: Connection, f):
    if not conn.client_ciphers:
        return
    offered = [c for c in conn.client_ciphers if not is_grease(c) and c not in SCSV]
    weak = [c for c in offered if any(sev in ("CRITICAL", "HIGH") for sev, _, _ in cipher_issues(c))]
    if weak:
        names = ", ".join(suite_name(c) for c in weak[:6]) + (" ..." if len(weak) > 6 else "")
        _add(f, "LOW", f"Client offers {len(weak)} weak cipher suite(s)", names, side="client")

    versions = [v for v in conn.client_versions if not is_grease(v)] or [conn.client_legacy_version]
    top = max(v for v in versions if v is not None)
    if top < 0x0303:
        _add(f, "MEDIUM", f"Client supports at most {version_name(top)}",
             "Client software is outdated and cannot negotiate TLS 1.2+.", side="client")
    if 0x5600 in conn.client_ciphers:
        _add(f, "INFO", "TLS_FALLBACK_SCSV present",
             "The client is retrying with a lower version after a failed handshake (RFC 7507).",
             side="client")
    if any(g in POST_QUANTUM_GROUPS for g in conn.client_key_shares) and \
            conn.key_share_group not in POST_QUANTUM_GROUPS:
        _add(f, "INFO", "Client offered a post-quantum hybrid key share",
             ", ".join(group_name(g) for g in conn.client_key_shares if g in POST_QUANTUM_GROUPS),
             side="client")


def _version_rules(conn: Connection, f):
    v = conn.version
    if v in (0x0002, 0x0300, 0x0301):
        detail = {0x0002: "SSL 2.0 is fundamentally broken (DROWN).",
                  0x0300: "SSL 3.0 is broken by POODLE (RFC 7568).",
                  0x0301: "TLS 1.0 is deprecated (RFC 8996): BEAST, no AEAD, MD5/SHA-1 PRF."}[v]
        _add(f, "CRITICAL", f"{version_name(v)} negotiated", detail)
    elif v == 0x0302:
        _add(f, "HIGH", "TLS 1.1 negotiated", "Deprecated by RFC 8996; no AEAD cipher suites.")
    elif v == 0x0304:
        _add(f, "GOOD", "TLS 1.3 negotiated",
             "Only AEAD ciphers, mandatory forward secrecy, encrypted certificate.")


def _cipher_rules(conn: Connection, f):
    issues = cipher_issues(conn.cipher)
    for sev, title, detail in issues:
        _add(f, sev, title, f"{suite_name(conn.cipher)}: {detail}")
    s = lookup(conn.cipher)
    if s and s.aead and s.forward_secrecy and not issues:
        _add(f, "GOOD", "AEAD cipher with forward secrecy", suite_name(conn.cipher))
    if s is None:
        _add(f, "HIGH", "Unknown cipher suite",
             f"{suite_name(conn.cipher)} is not in TLSight's table, so its strength can't be assessed. "
             "Treated as unsafe until reviewed.")


def _kex_rules(conn: Connection, f):
    s = lookup(conn.cipher)
    if s and s.kex == "DHE" and conn.dh_bits is None:
        _add(f, "INFO", "DH group size unknown",
             "The ServerKeyExchange was not seen (active check). Analyze a pcap of this handshake "
             "to check for weak (<2048-bit) DH groups.")
    if conn.dh_bits is not None:
        if conn.dh_bits < 1024:
            _add(f, "CRITICAL", f"Weak {conn.dh_bits}-bit DH group", "Breakable by Logjam-style precomputation.")
        elif conn.dh_bits < 2048:
            _add(f, "HIGH", f"Weak {conn.dh_bits}-bit DH group",
                 "1024-bit DH is within reach of nation-state precomputation (Logjam).")
    group = conn.key_share_group or conn.ske_group
    if group is not None:
        if group in POST_QUANTUM_GROUPS:
            _add(f, "GOOD", "Post-quantum hybrid key exchange",
                 f"{group_name(group)} combines classical ECDH with ML-KEM (resists "
                 "harvest-now-decrypt-later).")
        elif GROUP_BITS.get(group, 128) < 128:
            _add(f, "MEDIUM", f"Weak key exchange group {group_name(group)}",
                 "Under 128-bit security; prefer x25519 or secp256r1.")


def _trust_rules(conn: Connection, f, cert_f):
    if conn.chain_trusted is True:
        _add(f, "GOOD", "Chain validates to a trusted root",
             "RFC 5280 path validation against Mozilla's root store succeeded.", side="certificate")
    elif conn.chain_trusted is False:
        # Expired / self-signed / wrong-host chains already explain why validation fails.
        if not any(x.severity in ("CRITICAL", "HIGH") for x in cert_f):
            _add(f, "HIGH", "Certificate chain not trusted",
                 f"Path validation against Mozilla's root store failed: {conn.trust_error}. "
                 "Unknown root CA, or the server didn't send its intermediate certificates.",
                 side="certificate")


def _extension_rules(conn: Connection, f):
    if conn.server_extensions is None or conn.version is None or conn.version >= 0x0304:
        return
    if 0xFF01 not in conn.server_extensions:
        _add(f, "MEDIUM", "No secure renegotiation",
             "Server did not send renegotiation_info (RFC 5746): exposed to renegotiation injection.")
    if 23 not in conn.server_extensions and conn.version == 0x0303:
        _add(f, "LOW", "No Extended Master Secret",
             "Without RFC 7627 the session is exposed to triple-handshake attacks.")
