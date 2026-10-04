"""Record real TLS handshakes into a pcap without a capture driver.

  python tools/record_tls.py --out samples/normal_recorded.pcap --client both github.com example.com
  python tools/record_tls.py --out samples/badssl_recorded.pcap --client legacy expired.badssl.com tls-v1-0.badssl.com:1010

Wireshark/Npcap (or pktmon) need admin rights. This tool needs none: it runs a
local TCP relay between a real TLS client and the real server and saves every
byte relayed in each direction. Those bytes are then written to a pcap with the
real server IP. TLS payloads are exactly what the client and server sent; only
the TCP/IP headers are synthesized (sequence numbers, a local client address).

Clients:
  python  - Python's ssl module with default (secure) settings, like a normal app
  legacy  - Python's ssl with SECLEVEL=0 and the lowest protocol version, to coax
            weak servers into answering
  curl    - Windows curl (Schannel TLS stack), giving a second real JA3 fingerprint
"""

import argparse
import os
import select
import socket
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tlsight  # noqa: E402,F401  (silences scapy warnings)
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

MAX_BYTES = 200_000  # per direction; the plaintext handshake is far smaller
CLIENT_IP = "192.168.1.100"  # placeholder for the local machine


class Relay:
    """Accept one connection on 127.0.0.1 and pipe it to host:port, recording chunks."""

    def __init__(self, host: str, port: int):
        self.upstream = socket.create_connection((host, port), timeout=10)
        self.server_ip = self.upstream.getpeername()[0]
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.local_port = self.listener.getsockname()[1]
        self.chunks = []  # (time, "c2s" | "s2c", bytes)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.listener.settimeout(20)
        try:
            client, _ = self.listener.accept()
        except OSError:
            self.upstream.close()
            return
        sizes = {"c2s": 0, "s2c": 0}
        socks = {client: ("c2s", self.upstream), self.upstream: ("s2c", client)}
        deadline = time.time() + 20
        try:
            while time.time() < deadline:
                ready, _, _ = select.select(list(socks), [], [], 1.0)
                for s in ready:
                    direction, other = socks[s]
                    data = s.recv(65536)
                    if not data:
                        return
                    if sizes[direction] < MAX_BYTES:
                        self.chunks.append((time.time(), direction, data))
                        sizes[direction] += len(data)
                    other.sendall(data)
        except OSError:
            pass
        finally:
            client.close()
            self.upstream.close()
            self.listener.close()

    def wait(self):
        self.thread.join(timeout=25)


def python_client(host, port, local_port, legacy: bool):
    if legacy:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # still record handshakes with bad certs
    ctx.set_alpn_protocols(["http/1.1"])
    try:
        with socket.create_connection(("127.0.0.1", local_port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                s.recv(4096)
                return f"ok {s.version()} {s.cipher()[0]}"
    except (OSError, ssl.SSLError) as e:
        return f"failed: {type(e).__name__}: {str(e)[:80]}"


def curl_client(host, port, local_port):
    cmd = ["curl", "-sk", "-o", os.devnull, "-I", "--max-time", "10",
           "--connect-to", f"{host}:{port}:127.0.0.1:{local_port}", f"https://{host}:{port}/"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return "ok" if r.returncode == 0 else f"failed: curl exit {r.returncode}"


def to_packets(chunks, server_ip, server_port, client_port, mss=1460):
    cseq, sseq = 1_000_000 + client_port, 7_000_000 + client_port
    t0 = chunks[0][0] - 0.03 if chunks else time.time()
    pkts = []

    def mk(t, src, sp, dst, dp, flags, seq, ack, data=b""):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
        if data:
            p = p / data
        p.time = t
        pkts.append(p)

    mk(t0, CLIENT_IP, client_port, server_ip, server_port, "S", cseq, 0)
    mk(t0 + 0.01, server_ip, server_port, CLIENT_IP, client_port, "SA", sseq, cseq + 1)
    mk(t0 + 0.02, CLIENT_IP, client_port, server_ip, server_port, "A", cseq + 1, sseq + 1)
    cseq, sseq = cseq + 1, sseq + 1
    for t, direction, data in chunks:
        for i in range(0, len(data), mss):
            part = data[i:i + mss]
            if direction == "c2s":
                mk(t, CLIENT_IP, client_port, server_ip, server_port, "PA", cseq, sseq, part)
                cseq += len(part)
            else:
                mk(t, server_ip, server_port, CLIENT_IP, client_port, "PA", sseq, cseq, part)
                sseq += len(part)
    return pkts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="+", help="host or host:port")
    ap.add_argument("--out", required=True)
    ap.add_argument("--client", choices=["python", "legacy", "curl", "both"], default="both",
                    help="'both' = python + curl")
    args = ap.parse_args()

    clients = ["python", "curl"] if args.client == "both" else [args.client]
    packets, client_port = [], 50000
    for target in args.targets:
        host, _, port = target.partition(":")
        port = int(port or 443)
        for client in clients:
            try:
                relay = Relay(host, port)
            except OSError as e:
                print(f"{target:<34} {client:<7} cannot connect: {e}")
                continue
            if client == "curl":
                status = curl_client(host, port, relay.local_port)
            else:
                status = python_client(host, port, relay.local_port, legacy=(client == "legacy"))
            relay.wait()
            client_port += 1
            packets += to_packets(relay.chunks, relay.server_ip, port, client_port)
            print(f"{target:<34} {client:<7} {relay.server_ip:<16} {status}")

    wrpcap(args.out, packets)
    print(f"\nwrote {args.out} ({len(packets)} packets)")


if __name__ == "__main__":
    main()
