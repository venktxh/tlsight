from tlsight import parser
from tlsight import synth as s


def test_client_hello_fields():
    ch_bytes = s.client_hello([0x1301, 0xC02F], [
        s.sni_ext("example.com"), s.groups_ext([29, 23]), s.point_formats_ext([0]),
        s.alpn_ext(["h2"]), s.client_versions_ext([0x0304, 0x0303]),
        s.client_key_share_ext([29]),
    ])
    msgs = parser.handshake_messages(s.records(22, ch_bytes, 0x0301))
    assert [m[0] for m in msgs] == [parser.CLIENT_HELLO]
    ch = parser.parse_client_hello(msgs[0][1])
    assert ch.legacy_version == 0x0303
    assert ch.ciphers == [0x1301, 0xC02F]
    assert ch.extensions == [0, 10, 11, 16, 43, 51]
    assert ch.sni == "example.com"
    assert ch.groups == [29, 23]
    assert ch.point_formats == [0]
    assert ch.alpn == ["h2"]
    assert ch.supported_versions == [0x0304, 0x0303]
    assert ch.key_share_groups == [29]


def test_tls13_server_hello_uses_supported_versions():
    sh_bytes = s.server_hello(0x1301, [s.server_key_share_ext(29), s.server_version_ext(0x0304)])
    stream = s.records(22, sh_bytes) + s.change_cipher_spec() + s.records(23, b"\x00" * 100)
    msgs = parser.handshake_messages(stream)
    assert len(msgs) == 1  # stops at ChangeCipherSpec, never touches encrypted data
    sh = parser.parse_server_hello(msgs[0][1])
    assert sh.legacy_version == 0x0303
    assert sh.version == 0x0304
    assert sh.key_share_group == 29
    assert not sh.is_hrr


def test_hello_retry_request_then_real_server_hello():
    hrr = bytearray(s.server_hello(0x1301, [s.server_key_share_ext(23), s.server_version_ext(0x0304)]))
    hrr[6:38] = parser.HRR_RANDOM  # 4-byte handshake header + 2-byte version, then random
    real = s.server_hello(0x1301, [s.server_key_share_ext(23), s.server_version_ext(0x0304)])
    stream = (s.records(22, bytes(hrr)) + s.change_cipher_spec() + s.records(22, real)
              + s.records(23, b"\x00" * 50))
    msgs = parser.handshake_messages(stream)
    assert [m[0] for m in msgs] == [2, 2]
    first, second = (parser.parse_server_hello(m[1]) for m in msgs)
    assert first.is_hrr and not second.is_hrr and second.key_share_group == 23


def test_tls12_change_cipher_spec_still_stops_parsing():
    flight = s.records(22, s.server_hello(0xC02F, []))
    stream = flight + s.change_cipher_spec() + s.records(22, b"\x02\x00\x00\x10" + b"\xAA" * 16)
    assert [m[0] for m in parser.handshake_messages(stream)] == [2]  # encrypted Finished ignored


def test_server_hello_without_extensions():
    sh = parser.parse_server_hello(s.server_hello(0x0005, None, version=0x0301)[4:])
    assert sh.version == 0x0301 and sh.cipher == 0x0005 and sh.extensions == []


def test_message_split_across_records_and_packed_messages():
    der, _ = s.make_cert("example.com")
    flight = s.server_hello(0xC02F, []) + s.certificate([der, der]) + s.server_hello_done()
    stream = s.records(22, flight, max_len=100)  # force many small records
    msgs = parser.handshake_messages(stream)
    assert [m[0] for m in msgs] == [2, 11, 14]
    assert parser.parse_certificate(msgs[1][1]) == [der, der]


def test_server_key_exchange():
    ske = parser.parse_server_key_exchange(s.server_key_exchange_dhe(1024)[4:], "DHE")
    assert ske.dh_bits == 1024
    ske = parser.parse_server_key_exchange(s.server_key_exchange_ecdhe(23)[4:], "ECDHE")
    assert ske.group == 23


def test_truncated_and_garbage_input():
    ch_bytes = s.records(22, s.client_hello([0x1301], [s.sni_ext("x.org")]))
    assert parser.handshake_messages(ch_bytes[:20]) == []  # message incomplete
    assert not parser.looks_like_tls(b"GET / HTTP/1.1\r\n")
    assert parser.handshake_messages(b"\x17\x03\x03\x00\x05hello") == []
