"""Generate synthetic demo captures in samples/ with known-good and known-bad TLS.

  python tools/make_samples.py

synthetic_mixed.pcap contains five connections:
  1. modern.example     TLS 1.3, X25519MLKEM768 key share, AES-256-GCM      -> A
  2. shop.example       TLS 1.2, ECDHE-RSA AES-128-GCM, demo-CA-signed cert -> B (demo CA untrusted)
  3. legacy.example     TLS 1.2, static RSA + AES-CBC, SHA-1 cert, no reneg  -> D
  4. old-router.local   TLS 1.0, RC4, expired self-signed RSA-1024 cert     -> F
  5. intranet.example   TLS 1.2, DHE-1024 + 3DES, hostname mismatch         -> F
Real captures from Wireshark should be added next to it (see README).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from tlsight import synth as s  # noqa: E402

GREASE = 0x3A3A
MODERN_CIPHERS = [GREASE, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                  0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]


def modern_client_hello(host, key_shares=(0x11EC, 29)):
    return s.client_hello(MODERN_CIPHERS, [
        s.ext(GREASE), s.sni_ext(host), s.ext(23), s.ext(0xFF01, b"\x00"),
        s.groups_ext([GREASE, 0x11EC, 29, 23, 24]), s.point_formats_ext([0]),
        s.ext(35), s.alpn_ext(["h2", "http/1.1"]), s.ext(5, b"\x01\x00\x00\x00\x00"),
        s.ext(13, s.vec16(bytes.fromhex("040308040401050308050501080606010201"))),
        s.ext(18), s.client_key_share_ext(key_shares), s.ext(45, b"\x01\x01"),
        s.client_versions_ext([GREASE, 0x0304, 0x0303]), s.ext(27, b"\x02\x00\x02"),
    ], version=0x0303)


def tls12_server_flight(cipher, chain, extra=b"", exts=None, version=0x0303):
    exts = [s.ext(0xFF01, b"\x00"), s.ext(23), s.point_formats_ext([0])] if exts is None else exts
    hs = s.server_hello(cipher, exts, version=version) + s.certificate(chain) + extra + s.server_hello_done()
    return s.records(22, hs, version=version) + s.change_cipher_spec()


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
    os.makedirs(out_dir, exist_ok=True)
    client = "192.168.1.50"
    pkts = []

    # 1. TLS 1.3 with a post-quantum hybrid key share (certificate is encrypted)
    ch = modern_client_hello("modern.example")
    sh = s.server_hello(0x1302, [s.server_key_share_ext(0x11EC), s.server_version_ext(0x0304)])
    s2c = s.records(22, sh) + s.change_cipher_spec() + s.records(23, os.urandom(3000))
    pkts += s.tcp_session((client, 51001), ("203.0.113.10", 443), s.records(22, ch, 0x0301), s2c, t0=1.7e9)

    # 2. Good TLS 1.2 with a proper CA-signed chain
    ca_der, ca_key = s.make_cert("Demo Root CA", key=s.make_key("rsa", 2048), ca=True, days=(-400, 3000))
    leaf_der, _ = s.make_cert("shop.example", issuer_cn="Demo Root CA", issuer_key=ca_key,
                              san=["shop.example", "www.shop.example"])
    ch = modern_client_hello("shop.example", key_shares=(29,))
    s2c = tls12_server_flight(0xC02F, [leaf_der, ca_der], s.server_key_exchange_ecdhe(29))
    pkts += s.tcp_session((client, 51002), ("203.0.113.20", 443), s.records(22, ch, 0x0301), s2c, t0=1.7e9 + 1)

    # 3. Legacy TLS 1.2: static RSA, CBC, SHA-1 signed leaf, no secure renegotiation
    leaf_der, _ = s.make_cert("legacy.example", issuer_cn="Demo Root CA", issuer_key=ca_key,
                              key=s.make_key("rsa", 2048), hash_alg=hashes.SHA1(), san=["legacy.example"])
    ch = modern_client_hello("legacy.example", key_shares=(29,))
    s2c = tls12_server_flight(0x002F, [leaf_der, ca_der], exts=[s.ext(23)])
    pkts += s.tcp_session((client, 51003), ("203.0.113.30", 443), s.records(22, ch, 0x0301), s2c, t0=1.7e9 + 2)

    # 4. Ancient embedded device: TLS 1.0, RC4, expired self-signed 1024-bit cert
    old_der, _ = s.make_cert("old-router.local", key=s.make_key("rsa", 1024), days=(-2000, -100),
                             san=["old-router.local"])
    ch = s.client_hello([0x0005, 0x0004, 0x000A, 0x002F, 0x0035, 0x00FF],
                        [s.sni_ext("old-router.local")], version=0x0301)
    s2c = tls12_server_flight(0x0005, [old_der], exts=[], version=0x0301)
    pkts += s.tcp_session((client, 51004), ("192.168.1.1", 8443), s.records(22, ch, 0x0301),
                          s2c, t0=1.7e9 + 3)

    # 5. Intranet server: DHE with a 1024-bit group, 3DES, cert for the wrong name
    leaf_der, _ = s.make_cert("wiki.corp.example", issuer_cn="Demo Root CA", issuer_key=ca_key,
                              san=["wiki.corp.example"])
    ch = modern_client_hello("intranet.example", key_shares=(29,))
    s2c = tls12_server_flight(0x0016, [leaf_der, ca_der], s.server_key_exchange_dhe(1024))
    pkts += s.tcp_session((client, 51005), ("10.0.0.5", 443), s.records(22, ch, 0x0301), s2c, t0=1.7e9 + 4)

    path = os.path.join(out_dir, "synthetic_mixed.pcap")
    wrpcap(path, pkts)
    print(f"wrote {path} ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
