import pytest

from tlsight.ciphers import lookup, parse_suite, suite_name, version_name
from tlsight.rules import cipher_issues


def sevs(code):
    return {sev for sev, _, _ in cipher_issues(code)}


def test_tls13_suite():
    s = lookup(0x1301)
    assert s.tls13 and s.aead and s.forward_secrecy
    assert (s.cipher, s.bits, s.mode) == ("AES", 128, "GCM")
    assert cipher_issues(0x1301) == []


def test_ecdhe_gcm_is_clean():
    s = lookup(0xC02F)
    assert (s.kex, s.auth, s.cipher, s.bits, s.mode, s.mac) == ("ECDHE", "RSA", "AES", 128, "GCM", "AEAD")
    assert s.forward_secrecy and s.aead
    assert cipher_issues(0xC02F) == []


def test_chacha20():
    s = lookup(0xCCA8)
    assert (s.cipher, s.bits, s.mode) == ("CHACHA20", 256, "POLY1305") and s.aead


def test_3des_is_high():
    s = lookup(0x000A)
    assert (s.cipher, s.bits, s.mode) == ("3DES", 112, "CBC")
    assert "HIGH" in sevs(0x000A)
    assert "CRITICAL" not in sevs(0x000A)


@pytest.mark.parametrize("code", [0x0004, 0x0005, 0xC011])  # RC4
def test_rc4_is_critical(code):
    assert lookup(code).mode == "STREAM"
    assert "CRITICAL" in sevs(code)


@pytest.mark.parametrize("code", [0x0003, 0x0008, 0x0011])
def test_export_is_critical(code):
    assert lookup(code).export
    assert "CRITICAL" in sevs(code)


def test_null_and_anon():
    assert lookup(0x0002).cipher == "NULL"
    assert "CRITICAL" in sevs(0x0002)
    assert lookup(0x0034).anon
    assert "CRITICAL" in sevs(0x0034)
    # TLS_ECDH_anon_WITH_AES_256_CBC_SHA: what null.badssl.com negotiated in a real capture
    s = lookup(0xC019)
    assert s.anon and (s.kex, s.cipher, s.bits) == ("ECDH", "AES", 256)
    assert "CRITICAL" in sevs(0xC019)


def test_unknown_suite_cannot_get_an_a():
    from tlsight.models import Connection
    from tlsight.rules import evaluate
    c = evaluate(Connection(1, "a:1", "b:443", version=0x0303, cipher=0xBEEF,
                            server_extensions=[0xFF01, 23]))
    assert c.grade != "A"
    assert any(f.title == "Unknown cipher suite" and f.severity == "HIGH" for f in c.findings)


def test_static_rsa_has_no_forward_secrecy():
    s = lookup(0x009C)  # TLS_RSA_WITH_AES_128_GCM_SHA256
    assert not s.forward_secrecy and s.aead
    titles = [t for _, t, _ in cipher_issues(0x009C)]
    assert titles == ["No forward secrecy"]


def test_ccm_without_mac_token():
    s = parse_suite("TLS_RSA_WITH_AES_128_CCM")
    assert (s.mode, s.mac, s.bits) == ("CCM", "AEAD", 128)
    s8 = lookup(0x1305)
    assert (s8.mode, s8.bits) == ("CCM", 128)


def test_every_table_entry_parses():
    from tlsight.ciphers import SUITES
    for code in SUITES:
        s = lookup(code)
        assert s.cipher and s.kex and s.mode


def test_names():
    assert suite_name(0x5600) == "TLS_FALLBACK_SCSV"
    assert suite_name(0xBEEF) == "UNKNOWN_0xBEEF"
    assert version_name(0x0304) == "TLS 1.3"
    assert lookup(0xBEEF) is None
