# TLSight: TLS Handshake & Cipher Suite Analyzer

TLSight reads a packet capture and finds every TLS handshake in it. For each one it checks the
**protocol version, cipher suite, key exchange (forward secrecy, DH/curve strength) and
certificate chain**, and gives the server's configuration a grade from **A to F** with a reason for
each point lost. It also computes **JA3 / JA3S** fingerprints, which identify client and server
software from the handshake alone.

Everything is passive. It only reads captures of your own traffic, and the optional `--probe` /
`check` modes make one ordinary TLS connection, just like a browser would.

## Setup

```
pip install -r requirements.txt
python tools/make_samples.py        # writes samples/synthetic_mixed.pcap
python -m pytest                    # 43 tests
```

## Usage

```
python cli.py analyze samples/synthetic_mixed.pcap            # table + findings
python cli.py analyze capture.pcapng --probe --json out.json  # fetch TLS 1.3 certs, save JSON
python cli.py check example.com                               # grade one live server
python cli.py check tls-v1-2.badssl.com:1012 --all            # --all also shows GOOD findings
python -m streamlit run dashboard.py                          # web dashboard
```

## How it works

```
pcap --> reassembly.py --> parser.py --> analyzer.py --> rules.py --> report.py / dashboard.py
         TCP streams        ClientHello    builds a        findings,
         per direction      ServerHello    Connection,     score, grade
                            Certificate    JA3/JA3S,
                            ServerKeyEx.   cert checks
```

| Module          | What it does                                                                                                                                                                                                                                               |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `reassembly.py` | Groups packets into TCP flows and rebuilds each direction's byte stream. Segments are ordered by sequence number, retransmitted overlap is trimmed, and reassembly stops at gaps. Certificates span several segments, so per-packet parsing is not enough. |
| `parser.py`     | Hand-written TLS record and handshake parser (RFC 5246 / 8446). It stops at the first non-handshake record, because everything after ChangeCipherSpec is encrypted.                                                                                        |
| `ciphers.py`    | IANA tables for cipher suites, versions and groups. Suite attributes (key exchange, cipher, mode, MAC, forward secrecy) are **derived from the suite name**, not hard-coded.                                                                               |
| `ja3.py`        | JA3 = `Version,Ciphers,Extensions,Curves,PointFormats`, JA3S = `Version,Cipher,Extensions`, with GREASE removed, then MD5.                                                                                                                                 |
| `certs.py`      | X.509 checks with `cryptography`: expiry, key type/size, signature hash, self-signed, hostname (SAN, wildcard rules), and full RFC 5280 path validation against Mozilla's root store (`certifi`).                                                          |
| `probe.py`      | Fetches the negotiated parameters and certificate chain with Python's `ssl` module.                                                                                                                                                                        |
| `rules.py`      | The ruleset and grading.                                                                                                                                                                                                                                   |

### Ruleset

| Severity (penalty) | Rules                                                                                                                                                                                                     |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CRITICAL (any → F) | SSL 2/3 or TLS 1.0 negotiated; NULL, anonymous, EXPORT, RC4, DES/RC2 ciphers; expired certificate; RSA key < 2048; MD5-signed certificate; DH group < 1024                                                |
| HIGH (-20)         | TLS 1.1; 3DES (Sweet32); static RSA key exchange (no forward secrecy); DH group < 2048 (Logjam); self-signed; hostname mismatch; chain not trusted by Mozilla's root store; DSA key; unknown cipher suite |
| MEDIUM (-10)       | CBC-mode suites; SHA-1 signed certificate; certificate expiring within 30 days; no secure renegotiation (RFC 5746); curves under 128-bit security                                                         |
| LOW (-3)           | TLS 1.2 without Extended Master Secret (RFC 7627)                                                                                                                                                         |
| GOOD               | TLS 1.3; AEAD cipher with forward secrecy; post-quantum hybrid key exchange (X25519MLKEM768); healthy certificate chain                                                                                   |

Score = 100 − penalties. A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, otherwise F.
**Client-side findings** (weak suites the client offers, outdated client versions, fallback SCSV)
are reported but do not affect the server's grade.

### Things worth explaining in the viva

- **TLS 1.3 hides the certificate.** After the ServerHello everything is encrypted, so a pcap
  shows only the version, cipher and key share. `--probe` fetches the certificate with a separate
  connection.
- **TLS 1.3 lies about its version.** The ServerHello's `legacy_version` field says TLS 1.2
  (0x0303); the real version is in the `supported_versions` extension. Naive tools misreport this.
- **Forward secrecy.** With `TLS_RSA_*` suites the client encrypts the premaster secret to the
  server's RSA key, so anyone who later steals that key can decrypt every recorded session. ECDHE/DHE
  use ephemeral keys, and TLS 1.3 removed static RSA entirely.
- **Post-quantum key exchange.** Current Chrome and Firefox send an `X25519MLKEM768` key share
  (hybrid ECDH + ML-KEM). You will see it in real captures of Google and Cloudflare sites.

## Real-traffic results (already in `samples/`)

| File                                       | What it is                                                                                                                                          |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `synthetic_mixed.pcap`                     | 5 generated handshakes with known answers (`tools/make_samples.py`)                                                                                 |
| `normal_recorded.pcap`                     | 7 real sites (google, github, wikipedia, cloudflare, microsoft, amazon.in, example.com) × 2 real clients (Python/OpenSSL and Windows curl/Schannel) |
| `badssl_recorded.pcap`                     | 18 badssl.com test servers, Python client in permissive "legacy" mode                                                                               |
| `badssl_curl_recorded.pcap`                | Same 18 servers with Windows curl, which refuses most legacy servers                                                                                |
| `sslyze_results.json`, `sslyze_output.txt` | sslyze 6.3.1 scan of 14 of the same hosts                                                                                                           |
| `comparison.md`                            | Side-by-side TLSight vs sslyze: **43 checks agree, 0 disagree**                                                                                     |

Highlights:

- All 14 real-site connections: TLS 1.3, AEAD, x25519/secp256r1, chain trusted → **A**.
- JA3 tells the two clients apart: `304734bb1c08…` (Python/OpenSSL) vs `2e6c64f66822…` (curl/Schannel).
- badssl: expired → F, anonymous ECDH (null.) → F, SHA-1 intermediate (expired) → F; self-signed,
  wrong host, untrusted root, static RSA, DH-1024, TLS 1.1 → C; RC4/3DES/TLS 1.0 → N/A because the
  client refused to negotiate them (sslyze, which bundles a legacy OpenSSL, confirms they're accepted).
- Real traffic found three bugs that synthetic tests missed, now fixed and covered by tests: an
  anonymous suite missing from the table (was graded A), no trust-store validation (untrusted root
  was graded A), and parsing stopping after a TLS 1.3 HelloRetryRequest.

### How the recordings were made (`tools/record_tls.py`)

Wireshark needs the Npcap driver and admin rights. `record_tls.py` needs neither: it runs a local
TCP relay between a real TLS client and the real server, saves every byte relayed, and writes them
to a pcap with the real server IP. **TLS payload bytes are exactly what went over the wire; the TCP/IP
headers are synthesized** (sequence numbers and a placeholder client IP 192.168.1.100). Say this in
the report.

```
python tools/record_tls.py --out samples/normal_recorded.pcap --client both google.com github.com
python tools/record_tls.py --out samples/badssl_recorded.pcap --client legacy expired.badssl.com dh1024.badssl.com
```

### Re-running the sslyze comparison

Install sslyze in its own virtual environment (it pins its own `cryptography` version):

```
python -m venv sslyze-venv
sslyze-venv\Scripts\python -m pip install sslyze
sslyze-venv\Scripts\python -m sslyze --certinfo --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 ^
    --elliptic_curves --json_out samples/sslyze_results.json example.com static-rsa.badssl.com ...
python tools/compare_sslyze.py samples/sslyze_results.json samples/badssl_recorded.json samples/normal_recorded.json
```

Per host it checks that TLSight's negotiated version and cipher are among those sslyze says the
server accepts, and that DH size, trust and expiry verdicts match.

**Why they differ (viva point):** sslyze is _active_. It tries every version and suite and lists
everything a server **accepts**, so it found that example.com and github.com still accept static-RSA
suites. TLSight is _passive_. It sees what was **actually negotiated** in real traffic (always
TLS 1.3 there), plus who negotiated it (JA3). One audits server configuration, the other audits
real-world usage.

### Capturing with Wireshark instead (needs admin for Npcap)

1. Install Wireshark with Npcap. Disable QUIC in Chrome (`chrome://flags/#enable-quic`) so Google
   sites use TLS over TCP.
2. Capture filter `tcp port 443 or tcp port 1010 or tcp port 1011`. Browse normal sites and the
   badssl.com subdomains above.
3. Save as `samples/<name>.pcapng` and run `python cli.py analyze samples/<name>.pcapng --probe`.

## Known limitations

- `check` mode sees only what Python's `ssl` exposes. It can't see the DH group size (reported as
  INFO) or the ECDHE curve, and your local OpenSSL build may refuse to negotiate RC4/3DES/TLS 1.0.
  Analyze a pcap for those.
- Trust is checked against Mozilla's root store only. Missing intermediates are not fetched (AIA),
  so a server that omits its intermediate shows as "not trusted", which browsers usually tolerate.
- SSLv2-format ClientHellos, QUIC (HTTP/3 over UDP) and DTLS are not parsed. Chrome uses QUIC for
  Google sites, so disable it at `chrome://flags/#enable-quic` to get TLS-over-TCP captures.
- Live sniffing is not built in: capture with Wireshark, then analyze the file.

## Team split

| Member | Area                                                           |
| ------ | -------------------------------------------------------------- |
| A      | `reassembly.py`, `parser.py`                                   |
| B      | `ciphers.py`, `rules.py`, grading                              |
| C      | `certs.py`, `probe.py`, `ja3.py`                               |
| D      | `cli.py`, `report.py`, `dashboard.py`, captures, report/slides |
