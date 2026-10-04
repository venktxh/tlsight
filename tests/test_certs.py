from cryptography.hazmat.primitives import hashes

from tlsight import certs
from tlsight import synth as s


def titles(findings):
    return {(f.severity, f.title) for f in findings}


def test_healthy_ca_signed_chain():
    ca, ca_key = s.make_cert("Root", key=s.make_key("rsa", 2048), ca=True)
    leaf, _ = s.make_cert("a.example", issuer_cn="Root", issuer_key=ca_key, san=["a.example"])
    chain = [certs.inspect(leaf), certs.inspect(ca)]
    assert chain[0].key_type == "EC secp256r1" and chain[0].sig_hash == "sha256"
    assert not chain[0].self_signed and chain[1].self_signed and chain[1].is_ca
    f = certs.cert_findings(chain, "a.example")
    assert [x.severity for x in f] == ["GOOD"]


def test_expired():
    der, _ = s.make_cert("old.example", days=(-400, -10), san=["old.example"])
    info = certs.inspect(der)
    assert info.days_left < 0
    assert ("CRITICAL", "Leaf certificate expired") in titles(certs.cert_findings([info], "old.example"))


def test_expiring_soon():
    der, _ = s.make_cert("soon.example", days=(-300, 10), san=["soon.example"])
    f = certs.cert_findings([certs.inspect(der)])
    assert ("MEDIUM", "Leaf certificate expires soon") in titles(f)


def test_weak_rsa_key_and_self_signed():
    der, _ = s.make_cert("weak.example", key=s.make_key("rsa", 1024))
    info = certs.inspect(der)
    assert (info.key_type, info.key_size) == ("RSA", 1024)
    t = titles(certs.cert_findings([info]))
    assert ("CRITICAL", "Leaf certificate uses a weak 1024-bit RSA key") in t
    assert ("HIGH", "Self-signed certificate") in t


def test_sha1_signature():
    ca, ca_key = s.make_cert("Root", key=s.make_key("rsa", 2048), ca=True)
    leaf, _ = s.make_cert("sha1.example", issuer_cn="Root", issuer_key=ca_key, hash_alg=hashes.SHA1())
    info = certs.inspect(leaf)
    assert info.sig_hash == "sha1"
    assert ("MEDIUM", "Leaf certificate signed with SHA-1") in titles(
        certs.cert_findings([info, certs.inspect(ca)]))


def test_root_signature_hash_is_ignored():
    ca, ca_key = s.make_cert("Old Root", key=s.make_key("rsa", 2048), ca=True, hash_alg=hashes.SHA1())
    leaf, _ = s.make_cert("b.example", issuer_cn="Old Root", issuer_key=ca_key, san=["b.example"])
    f = certs.cert_findings([certs.inspect(leaf), certs.inspect(ca)], "b.example")
    assert [x.severity for x in f] == ["GOOD"]


def test_chain_validation():
    ca, ca_key = s.make_cert("Test Root", key=s.make_key("rsa", 2048), ca=True)
    leaf, _ = s.make_cert("v.example", issuer_cn="Test Root", issuer_key=ca_key, san=["v.example"])
    # trusted when our test root is the trust anchor...
    assert certs.verify_chain([leaf, ca], "v.example", roots=[ca]) == (True, None)
    # ...untrusted against Mozilla's real root store (like untrusted-root.badssl.com)
    ok, err = certs.verify_chain([leaf, ca], "v.example")
    assert ok is False and err
    # wrong hostname also fails validation
    assert certs.verify_chain([leaf, ca], "other.example", roots=[ca])[0] is False


def test_hostname_matching():
    assert certs.hostname_matches("www.example.com", ["*.example.com"])
    assert certs.hostname_matches("Example.COM.", ["example.com"])
    assert not certs.hostname_matches("a.b.example.com", ["*.example.com"])
    assert not certs.hostname_matches("example.com", ["*.example.com"])
    assert not certs.hostname_matches("evilexample.com", ["*.example.com"])
    der, _ = s.make_cert("x", san=["shop.example"])
    t = titles(certs.cert_findings([certs.inspect(der)], "other.example"))
    assert ("HIGH", "Certificate hostname mismatch") in t
