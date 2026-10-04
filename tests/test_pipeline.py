"""End-to-end: synthetic pcap -> reassembly -> parsing -> grading."""

import random

from scapy.utils import wrpcap

from tlsight import synth as s
from tlsight.analyzer import analyze_pcap
from tlsight.models import Connection
from tlsight.reassembly import assemble
from tlsight.rules import evaluate


def test_assemble_handles_reorder_retransmit_and_gaps():
    data = bytes(range(256)) * 20
    segs = {i: data[i:i + 100] for i in range(0, len(data), 100)}
    segs[250] = data[250:400]  # overlapping retransmission
    assert assemble(dict(random.sample(list(segs.items()), len(segs)))) == data
    del segs[1000], segs[250]
    assert assemble(segs) == data[:1000]  # stops at the hole


def _flight(cipher, chain, extra=b"", exts=None, version=0x0303):
    exts = [s.ext(0xFF01, b"\x00"), s.ext(23)] if exts is None else exts
    hs = s.server_hello(cipher, exts, version) + s.certificate(chain) + extra + s.server_hello_done()
    return s.records(22, hs, version) + s.change_cipher_spec()


def test_pcap_end_to_end(tmp_path):
    ca, ca_key = s.make_cert("Root", key=s.make_key("rsa", 2048), ca=True)
    leaf, _ = s.make_cert("good.example", issuer_cn="Root", issuer_key=ca_key, san=["good.example"])
    bad, _ = s.make_cert("bad.example", key=s.make_key("rsa", 1024), days=(-500, -1))

    good_ch = s.client_hello([0x0A0A, 0xC02F, 0x1301],
                             [s.sni_ext("good.example"), s.groups_ext([29]), s.point_formats_ext([0])])
    bad_ch = s.client_hello([0x000A, 0x0005], [s.sni_ext("bad.example")], version=0x0301)

    pkts = s.tcp_session(("10.0.0.2", 40000), ("10.0.0.9", 443), s.records(22, good_ch),
                         _flight(0xC02F, [leaf, ca], s.server_key_exchange_ecdhe(29)), mss=300)
    bad_pkts = s.tcp_session(("10.0.0.2", 40001), ("10.0.0.9", 8443), s.records(22, bad_ch, 0x0301),
                             _flight(0x000A, [bad], exts=[], version=0x0301), mss=300, t0=1.8e9)
    # deliver the server's segments out of order to exercise reassembly
    bad_pkts = bad_pkts[:4] + list(reversed(bad_pkts[4:]))
    noise = s.tcp_session(("10.0.0.2", 40002), ("10.0.0.9", 80), b"GET / HTTP/1.1\r\n\r\n",
                          b"HTTP/1.1 200 OK\r\n\r\n", t0=1.9e9)
    path = tmp_path / "t.pcap"
    wrpcap(str(path), pkts + bad_pkts + noise)

    report = analyze_pcap(str(path))
    assert len(report.connections) == 2  # the plain HTTP flow is ignored
    good, badc = report.connections

    assert good.sni == "good.example" and good.version == 0x0303 and good.cipher == 0xC02F
    assert good.ske_group == 29 and len(good.certs) == 2 and good.cert_source == "pcap"
    assert good.ja3 == "771,49199-4865,0-10-11,29,0"  # GREASE 0x0A0A dropped
    # The test CA is not in Mozilla's root store, so the otherwise-perfect server loses one HIGH.
    assert good.chain_trusted is False
    assert [f.title for f in good.findings if f.severity == "HIGH"] == ["Certificate chain not trusted"]
    assert good.grade == "B"

    assert badc.server == "10.0.0.9:8443" and badc.version == 0x0301
    assert badc.certs[0].key_size == 1024
    assert badc.grade == "F"
    crit = {f.title for f in badc.findings if f.severity == "CRITICAL"}
    assert {"TLS 1.0 negotiated", "Leaf certificate expired",
            "Leaf certificate uses a weak 1024-bit RSA key"} <= crit
    assert any(f.side == "client" and "weak cipher" in f.title for f in badc.findings)


def test_incomplete_handshake_is_not_graded():
    c = evaluate(Connection(1, "a:1", "b:443", client_ciphers=[0x1301], client_legacy_version=0x0303))
    assert c.grade == "N/A" and c.score is None


def test_tls13_without_cert_gets_info_and_a():
    c = evaluate(Connection(1, "a:1", "b:443", version=0x0304, cipher=0x1301,
                            server_extensions=[43, 51], key_share_group=0x11EC))
    assert c.grade == "A"
    titles = {f.title for f in c.findings}
    assert "Certificate not visible (TLS 1.3)" in titles
    assert "Post-quantum hybrid key exchange" in titles


def test_grading_scale():
    # static RSA (HIGH 20) + CBC (MEDIUM 10) + no reneg (MEDIUM 10) + no EMS (LOW 3) = 57 -> D
    c = evaluate(Connection(1, "a:1", "b:443", version=0x0303, cipher=0x002F, server_extensions=[]))
    assert (c.score, c.grade) == (57, "D")
