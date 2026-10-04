"""Minimal TLS record / handshake parser (RFC 5246 and RFC 8446 wire formats).

Works on a reassembled byte stream for one direction of a TCP connection. Only
the plaintext part of the handshake is parsed: ClientHello, ServerHello,
Certificate and ServerKeyExchange. Parsing stops at the first non-handshake
record (ChangeCipherSpec, Alert or encrypted ApplicationData), because anything
after that point is encrypted.
"""

from dataclasses import dataclass, field
from typing import Optional

# Record content types
CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA = 20, 21, 22, 23
# Handshake message types
CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, SERVER_KEY_EXCHANGE = 1, 2, 11, 12

# RFC 8446 4.1.3: a ServerHello with this random value is a HelloRetryRequest
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


class TLSParseError(ValueError):
    pass


class Reader:
    """Cursor over a byte string with TLS-style length-prefixed vectors."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n > self.remaining():
            raise TLSParseError(f"need {n} bytes, have {self.remaining()}")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def u8(self) -> int:
        return self.uint(1)

    def u16(self) -> int:
        return self.uint(2)

    def u24(self) -> int:
        return self.uint(3)

    def vec(self, len_size: int) -> "Reader":
        return Reader(self.take(self.uint(len_size)))

    def u16_list(self, len_size: int) -> list:
        r = self.vec(len_size)
        return [r.u16() for _ in range(r.remaining() // 2)]


@dataclass
class ClientHello:
    legacy_version: int
    ciphers: list
    extensions: list  # extension type ids, in wire order (needed for JA3)
    sni: Optional[str] = None
    groups: list = field(default_factory=list)
    point_formats: list = field(default_factory=list)
    supported_versions: list = field(default_factory=list)
    key_share_groups: list = field(default_factory=list)
    alpn: list = field(default_factory=list)


@dataclass
class ServerHello:
    legacy_version: int
    cipher: int
    extensions: list
    selected_version: Optional[int] = None
    key_share_group: Optional[int] = None
    alpn: list = field(default_factory=list)
    is_hrr: bool = False

    @property
    def version(self) -> int:
        return self.selected_version or self.legacy_version


@dataclass
class ServerKeyExchange:
    dh_bits: Optional[int] = None  # finite-field DHE prime size
    group: Optional[int] = None  # ECDHE named curve


def looks_like_tls(stream: bytes) -> bool:
    return len(stream) >= 6 and stream[0] == HANDSHAKE and stream[1] == 3 and stream[2] <= 4


def _split_messages(buf: bytes) -> list:
    msgs = []
    h = Reader(buf)
    while h.remaining() >= 4:
        mtype = h.u8()
        mlen = h.u24()
        if mlen > h.remaining():
            break
        msgs.append((mtype, h.take(mlen)))
    return msgs


def _ends_with_hrr(buf: bytes) -> bool:
    msgs = _split_messages(buf)
    return bool(msgs) and msgs[-1][0] == SERVER_HELLO and msgs[-1][1][2:34] == HRR_RANDOM


def handshake_messages(stream: bytes) -> list:
    """Return [(msg_type, body), ...] from the plaintext handshake records at the
    start of `stream`. Handles messages split across records and several
    messages packed into one record. Stops at the first non-handshake record,
    except the ChangeCipherSpec a TLS 1.3 server sends right after a
    HelloRetryRequest: the real ServerHello still follows in plaintext."""
    buf = bytearray()
    r = Reader(stream)
    while r.remaining() >= 5:
        ctype = r.u8()
        major, _minor = r.u8(), r.u8()
        length = r.u16()
        if major != 3 or length > 18432:
            break
        if ctype == CHANGE_CIPHER_SPEC and length <= r.remaining() and _ends_with_hrr(bytes(buf)):
            r.take(length)
            continue
        if ctype != HANDSHAKE:
            break
        if length > r.remaining():
            buf += r.take(r.remaining())  # truncated capture: keep what we have
            break
        buf += r.take(length)
    return _split_messages(bytes(buf))


def _parse_alpn(data: Reader) -> list:
    lst = data.vec(2)
    out = []
    while lst.remaining():
        out.append(lst.vec(1).data.decode("ascii", "replace"))
    return out


def parse_client_hello(body: bytes) -> ClientHello:
    r = Reader(body)
    legacy_version = r.u16()
    r.take(32)  # random
    r.vec(1)  # legacy_session_id
    ciphers = r.u16_list(2)
    r.vec(1)  # compression methods
    ch = ClientHello(legacy_version, ciphers, [])
    if not r.remaining():
        return ch

    exts = r.vec(2)
    while exts.remaining() >= 4:
        etype = exts.u16()
        data = exts.vec(2)
        ch.extensions.append(etype)
        try:
            if etype == 0:  # server_name
                names = data.vec(2)
                while names.remaining():
                    name_type = names.u8()
                    name = names.vec(2).data
                    if name_type == 0:
                        ch.sni = name.decode("ascii", "replace")
            elif etype == 10:  # supported_groups
                ch.groups = data.u16_list(2)
            elif etype == 11:  # ec_point_formats
                ch.point_formats = list(data.vec(1).data)
            elif etype == 16:  # alpn
                ch.alpn = _parse_alpn(data)
            elif etype == 43:  # supported_versions
                ch.supported_versions = data.u16_list(1)
            elif etype == 51:  # key_share
                shares = data.vec(2)
                while shares.remaining():
                    ch.key_share_groups.append(shares.u16())
                    shares.vec(2)
        except TLSParseError:
            pass  # malformed extension body: keep the id, skip its contents
    return ch


def parse_server_hello(body: bytes) -> ServerHello:
    r = Reader(body)
    legacy_version = r.u16()
    random = r.take(32)
    r.vec(1)  # session id
    cipher = r.u16()
    r.u8()  # compression
    sh = ServerHello(legacy_version, cipher, [], is_hrr=(random == HRR_RANDOM))
    if not r.remaining():
        return sh

    exts = r.vec(2)
    while exts.remaining() >= 4:
        etype = exts.u16()
        data = exts.vec(2)
        sh.extensions.append(etype)
        try:
            if etype == 43:
                sh.selected_version = data.u16()
            elif etype == 51:
                sh.key_share_group = data.u16()  # (HRR carries only the group)
            elif etype == 16:
                sh.alpn = _parse_alpn(data)
        except TLSParseError:
            pass
    return sh


def parse_certificate(body: bytes) -> list:
    """TLS <= 1.2 Certificate message -> list of DER certificates, leaf first."""
    r = Reader(body)
    chain = r.vec(3)
    certs = []
    while chain.remaining() >= 3:
        certs.append(chain.vec(3).data)
    return certs


def parse_server_key_exchange(body: bytes, kex: str) -> ServerKeyExchange:
    """Extract the key-exchange strength. `kex` is "DHE" or "ECDHE" (from the cipher)."""
    r = Reader(body)
    if kex == "ECDHE":
        curve_type = r.u8()
        if curve_type == 3:  # named_curve
            return ServerKeyExchange(group=r.u16())
        return ServerKeyExchange()
    if kex == "DHE":
        p = r.vec(2).data.lstrip(b"\x00")
        return ServerKeyExchange(dh_bits=len(p) * 8)
    return ServerKeyExchange()
