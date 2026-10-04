"""Plain data containers shared by the parser, rules engine and reports."""

from dataclasses import asdict, dataclass, field
from typing import Optional

# Ordered most to least severe. GOOD marks a positive observation (no penalty).
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "GOOD")


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    side: str = "server"  # "server", "client" or "certificate"


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    days_left: int
    key_type: str
    key_size: int
    sig_hash: Optional[str]
    self_signed: bool
    is_ca: bool
    san: list = field(default_factory=list)


@dataclass
class Connection:
    id: int
    client: str  # "ip:port"
    server: str  # "ip:port"
    sni: Optional[str] = None
    alpn: list = field(default_factory=list)

    # From the ClientHello (empty when a connection comes from an active probe)
    client_legacy_version: Optional[int] = None
    client_versions: list = field(default_factory=list)
    client_ciphers: list = field(default_factory=list)
    client_extensions: list = field(default_factory=list)
    client_groups: list = field(default_factory=list)
    client_point_formats: list = field(default_factory=list)
    client_key_shares: list = field(default_factory=list)

    # From the ServerHello / ServerKeyExchange
    version: Optional[int] = None
    cipher: Optional[int] = None
    server_extensions: Optional[list] = None  # None = unknown (probe), [] = none sent
    key_share_group: Optional[int] = None
    ske_group: Optional[int] = None
    dh_bits: Optional[int] = None

    certs: list = field(default_factory=list)  # list[CertInfo], leaf first
    cert_source: Optional[str] = None  # "pcap", "probe" or None
    chain_trusted: Optional[bool] = None  # None = not checked (no certs or no hostname)
    trust_error: Optional[str] = None

    ja3: Optional[str] = None
    ja3_hash: Optional[str] = None
    ja3s: Optional[str] = None
    ja3s_hash: Optional[str] = None

    findings: list = field(default_factory=list)
    score: Optional[int] = None
    grade: str = "N/A"
    notes: list = field(default_factory=list)

    @property
    def target(self) -> str:
        return self.sni or self.server


@dataclass
class Report:
    source: str
    generated_at: str
    connections: list = field(default_factory=list)

    def summary(self) -> dict:
        grades = {}
        for c in self.connections:
            grades[c.grade] = grades.get(c.grade, 0) + 1
        return {"connections": len(self.connections), "grades": grades}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary()
        return d
