"""Glue: pcap -> flows -> parsed handshakes -> graded Connections."""

from datetime import datetime, timezone

from . import certs, ja3, parser, probe, rules
from .ciphers import group_name, lookup
from .models import Connection, Report
from .reassembly import load_flows


def _fmt(ep) -> str:
    ip, port = ep
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def connection_from_flow(flow, conn_id: int):
    """Build a Connection from a TCP flow, or None if it isn't a TLS handshake."""
    for client, server in ((flow.a, flow.b), (flow.b, flow.a)):
        c_stream = flow.stream(client, server)
        if not parser.looks_like_tls(c_stream):
            continue
        msgs = parser.handshake_messages(c_stream)
        if not msgs or msgs[0][0] != parser.CLIENT_HELLO:
            continue
        try:
            ch = parser.parse_client_hello(msgs[0][1])
        except parser.TLSParseError:
            continue
        conn = Connection(conn_id, _fmt(client), _fmt(server), sni=ch.sni, alpn=ch.alpn,
                          client_legacy_version=ch.legacy_version,
                          client_versions=ch.supported_versions, client_ciphers=ch.ciphers,
                          client_extensions=ch.extensions, client_groups=ch.groups,
                          client_point_formats=ch.point_formats,
                          client_key_shares=ch.key_share_groups)
        _apply_server_side(conn, flow.stream(server, client))
        return conn
    return None


def _apply_server_side(conn: Connection, s_stream: bytes):
    if not parser.looks_like_tls(s_stream):
        return
    sh, chain, ske_body, hrr_group = None, [], None, None
    for mtype, body in parser.handshake_messages(s_stream):
        try:
            if mtype == parser.SERVER_HELLO:
                sh = parser.parse_server_hello(body)  # the last one wins after a HelloRetryRequest
                if sh.is_hrr:
                    hrr_group = sh.key_share_group
            elif mtype == parser.CERTIFICATE:
                chain = parser.parse_certificate(body)
            elif mtype == parser.SERVER_KEY_EXCHANGE:
                ske_body = body
        except parser.TLSParseError as e:
            conn.notes.append(f"parse error in handshake type {mtype}: {e}")
    if sh is None:
        return
    if sh.is_hrr:
        conn.notes.append("HelloRetryRequest seen; the client's retry was not captured")
    elif hrr_group is not None:
        conn.notes.append(f"server sent a HelloRetryRequest asking for a {group_name(hrr_group)} key share")

    conn.version, conn.cipher = sh.version, sh.cipher
    conn.server_extensions = sh.extensions
    conn.key_share_group = sh.key_share_group
    if sh.alpn:
        conn.alpn = sh.alpn

    suite = lookup(sh.cipher)
    # anonymous suites (DH_anon / ECDH_anon) send the same ephemeral parameters, unsigned
    ske_kex = {"DHE": "DHE", "ECDHE": "ECDHE", "DH": "DHE", "ECDH": "ECDHE"}.get(suite.kex) if suite else None
    if suite and suite.kex in ("DH", "ECDH") and not suite.anon:
        ske_kex = None  # static (EC)DH: parameters are in the certificate, no ServerKeyExchange
    if ske_body and ske_kex:
        try:
            ske = parser.parse_server_key_exchange(ske_body, ske_kex)
            conn.dh_bits, conn.ske_group = ske.dh_bits, ske.group
        except parser.TLSParseError:
            pass

    _set_certs(conn, chain, "pcap")
    conn.ja3s = ja3.ja3s_string(sh.legacy_version, sh.cipher, sh.extensions)
    conn.ja3s_hash = ja3.md5(conn.ja3s)


def _set_certs(conn: Connection, chain_der, source: str):
    infos = []
    for der in chain_der:
        try:
            infos.append(certs.inspect(der))
        except Exception as e:  # malformed DER
            conn.notes.append(f"could not parse certificate: {e}")
    if infos:
        conn.certs, conn.cert_source = infos, source
        if conn.sni:
            try:
                conn.chain_trusted, conn.trust_error = certs.verify_chain(chain_der, conn.sni)
            except Exception as e:  # unparseable chain
                conn.chain_trusted, conn.trust_error = None, str(e)


def finalize(conn: Connection) -> Connection:
    if conn.client_ciphers:
        conn.ja3 = ja3.ja3_string(conn.client_legacy_version, conn.client_ciphers,
                                  conn.client_extensions, conn.client_groups,
                                  conn.client_point_formats)
        conn.ja3_hash = ja3.md5(conn.ja3)
    return rules.evaluate(conn)


def analyze_pcap(path: str, do_probe: bool = False, max_bytes: int = 65536) -> Report:
    conns = []
    for flow in load_flows(path, max_bytes):
        conn = connection_from_flow(flow, len(conns) + 1)
        if conn is not None:
            conns.append(conn)

    if do_probe:
        cache = {}
        for conn in conns:
            if conn.certs or conn.version is None or not conn.sni:
                continue
            port = int(conn.server.rsplit(":", 1)[1])
            key = (conn.sni, port)
            if key not in cache:
                cache[key] = probe.fetch(conn.sni, port)
            res = cache[key]
            if res.error:
                conn.notes.append(f"probe failed: {res.error}")
            else:
                _set_certs(conn, res.chain, "probe")

    for conn in conns:
        finalize(conn)
    return Report(path, datetime.now(timezone.utc).isoformat(timespec="seconds"), conns)


def check_host(host: str, port: int = 443) -> Report:
    """Actively connect to one server and grade what it negotiates."""
    res = probe.fetch(host, port)
    conn = Connection(1, "local", f"{host}:{port}", sni=host)
    if res.error:
        conn.notes.append(f"connection failed: {res.error}")
    else:
        conn.version, conn.cipher = res.version, res.cipher
        if res.cipher is None:
            conn.notes.append(f"unmapped OpenSSL cipher name {res.cipher_openssl}")
        _set_certs(conn, res.chain, "probe")
    finalize(conn)
    return Report(f"{host}:{port}", datetime.now(timezone.utc).isoformat(timespec="seconds"), [conn])
