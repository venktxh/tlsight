"""Group pcap packets into TCP flows and rebuild each direction's byte stream.

TLS messages (especially the Certificate) span several TCP segments, so the
handshake can only be parsed after reassembly. Only the first `max_bytes` of
each direction are kept, which is plenty for the plaintext handshake.
"""

from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

Endpoint = tuple  # (ip, port)


@dataclass
class TCPFlow:
    a: Endpoint  # endpoint that sent the first packet we saw
    b: Endpoint
    first_ts: float
    # (src, dst) -> {relative seq: payload}
    segments: dict = field(default_factory=dict)
    _base: dict = field(default_factory=dict)
    _size: dict = field(default_factory=dict)

    def add(self, src, dst, seq: int, payload: bytes, max_bytes: int):
        key = (src, dst)
        if self._size.get(key, 0) >= max_bytes:
            return
        base = self._base.setdefault(key, seq)
        # signed 32-bit distance from the first seq seen, so wraparound and
        # out-of-order first packets both work
        rel = ((seq - base + 2**31) % 2**32) - 2**31
        segs = self.segments.setdefault(key, {})
        if len(payload) > len(segs.get(rel, b"")):
            segs[rel] = payload
            self._size[key] = self._size.get(key, 0) + len(payload)

    def stream(self, src, dst) -> bytes:
        return assemble(self.segments.get((src, dst), {}))


def assemble(segments: dict) -> bytes:
    """Concatenate {seq: payload} in order, trimming retransmitted overlap and
    stopping at the first gap (a missing segment)."""
    if not segments:
        return b""
    items = sorted(segments.items())
    expected = items[0][0]
    out = bytearray()
    for seq, payload in items:
        if seq > expected:
            break  # gap: lost segment, the rest can't be trusted
        overlap = expected - seq
        if overlap < len(payload):
            out += payload[overlap:]
            expected = seq + len(payload)
    return bytes(out)


def _tcp_payload(pkt) -> bytes:
    """TCP payload without Ethernet trailer padding."""
    tcp = pkt[TCP]
    raw = bytes(tcp.payload)
    if IP in pkt:
        ip = pkt[IP]
        length = ip.len - ip.ihl * 4 - tcp.dataofs * 4
    else:
        length = pkt[IPv6].plen - tcp.dataofs * 4
    return raw[:max(length, 0)]


def load_flows(path: str, max_bytes: int = 65536) -> list:
    flows = {}
    with PcapReader(path) as reader:
        for pkt in reader:
            if TCP not in pkt or (IP not in pkt and IPv6 not in pkt):
                continue
            ip = pkt[IP] if IP in pkt else pkt[IPv6]
            tcp = pkt[TCP]
            src, dst = (ip.src, tcp.sport), (ip.dst, tcp.dport)
            key = frozenset((src, dst))
            flow = flows.get(key)
            if flow is None:
                flow = flows[key] = TCPFlow(src, dst, float(pkt.time))
            payload = _tcp_payload(pkt)
            if payload:
                flow.add(src, dst, tcp.seq, payload, max_bytes)
    return sorted(flows.values(), key=lambda f: f.first_ts)
