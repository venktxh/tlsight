"""Cross-check TLSight reports against an sslyze scan of the same hosts.

  python -m sslyze --certinfo --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 \
      --elliptic_curves --json_out samples/sslyze_results.json host1 host2 ...
  python tools/compare_sslyze.py samples/sslyze_results.json samples/badssl_recorded.json \
      samples/normal_recorded.json --out samples/comparison.md

The tools answer different questions. TLSight sees the one version/cipher that
was actually negotiated in captured traffic; sslyze actively tries everything
and lists what the server *accepts*. So the checks are:
  version  - TLSight's negotiated version is one sslyze says the server accepts
  cipher   - TLSight's negotiated suite is in sslyze's accepted list
  DH size  - TLSight's DH group size (from the ServerKeyExchange) matches sslyze's
  trust    - TLSight's chain validation agrees with sslyze's Mozilla trust store result
  expiry   - both agree on whether the leaf certificate is expired
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tlsight.ciphers import SUITES, suite_name, version_name  # noqa: E402
from tlsight.rules import cipher_issues  # noqa: E402

SSLYZE_VERSIONS = [("ssl_3_0_cipher_suites", 0x0300), ("tls_1_0_cipher_suites", 0x0301),
                   ("tls_1_1_cipher_suites", 0x0302), ("tls_1_2_cipher_suites", 0x0303),
                   ("tls_1_3_cipher_suites", 0x0304)]
NAME_TO_CODE = {name: code for code, name in SUITES.items()}


def sslyze_facts(result: dict) -> dict:
    sr = result.get("scan_result") or {}
    facts = {"versions": [], "suites": set(), "weak": set(), "dh_sizes": set(),
             "trusted": None, "trust_error": None, "expired": None}
    for key, ver in SSLYZE_VERSIONS:
        res = (sr.get(key) or {}).get("result") or {}
        accepted = res.get("accepted_cipher_suites") or []
        if accepted:
            facts["versions"].append(ver)
        for a in accepted:
            name = a["cipher_suite"]["name"]
            facts["suites"].add(name)
            code = NAME_TO_CODE.get(name)
            if code is not None and any(s in ("CRITICAL", "HIGH") for s, _, _ in cipher_issues(code)):
                facts["weak"].add(name)
            if a.get("cipher_suite", {}).get("is_anonymous"):
                facts["weak"].add(name)
            ek = a.get("ephemeral_key") or {}
            if ek.get("type_name") == "DH":
                facts["dh_sizes"].add(ek["size"])

    cert = (sr.get("certificate_info") or {}).get("result") or {}
    deps = cert.get("certificate_deployments") or []
    if deps:
        for pv in deps[0].get("path_validation_results", []):
            if pv["trust_store"]["name"] == "Mozilla":
                facts["trusted"] = pv["was_validation_successful"]
                facts["trust_error"] = pv.get("validation_error")
        chain = deps[0].get("received_certificate_chain") or []
        if chain:
            not_after = datetime.fromisoformat(chain[0]["not_valid_after"].replace("Z", "+00:00"))
            facts["expired"] = not_after < datetime.now(timezone.utc)
    return facts


def load_tlsight(paths) -> dict:
    """(sni, port) -> best connection (a completed handshake preferred)."""
    best = {}
    for p in paths:
        for c in json.load(open(p, encoding="utf-8"))["connections"]:
            if not c.get("sni"):
                continue
            key = (c["sni"], int(c["server"].rsplit(":", 1)[1]))
            if key not in best or (best[key]["cipher"] is None and c["cipher"] is not None):
                best[key] = c
    return best


def mark(ok) -> str:
    return {True: "agree", False: "**DISAGREE**", None: "n/a"}[ok]


def compare(host, port, s, t) -> dict:
    row = {"host": f"{host}" + (f":{port}" if port != 443 else "")}
    sv = ", ".join(version_name(v) for v in s["versions"]) or "none"
    weak = ", ".join(sorted(s["weak"])[:3]) + (" ..." if len(s["weak"]) > 3 else "")
    sslyze_bits = [f"accepts {sv}"]
    if s["dh_sizes"]:
        sslyze_bits.append("DH " + "/".join(map(str, sorted(s["dh_sizes"]))))
    if weak:
        sslyze_bits.append(f"weak suites: {weak}")
    if s["trusted"] is not None:
        sslyze_bits.append("Mozilla-trusted" if s["trusted"] else "NOT Mozilla-trusted")
    if s["expired"]:
        sslyze_bits.append("cert expired")
    row["sslyze"] = "; ".join(sslyze_bits)

    checks = {}
    if t is None or t["cipher"] is None:
        row["tlsight"] = "no completed handshake (client could not negotiate)" if t else "not captured"
        row["grade"] = t["grade"] if t else "-"
        checks["handshake"] = None
    else:
        crit = [f["title"] for f in t["findings"] if f["severity"] in ("CRITICAL", "HIGH")
                and f["side"] != "client"]
        row["tlsight"] = (f"{version_name(t['version'])}, {suite_name(t['cipher'])}"
                          + (f"; DH {t['dh_bits']}" if t.get("dh_bits") else "")
                          + (f"; {'; '.join(crit)}" if crit else ""))
        row["grade"] = t["grade"]
        checks["version"] = t["version"] in s["versions"] if s["versions"] else None
        checks["cipher"] = suite_name(t["cipher"]) in s["suites"] if s["suites"] else None
        checks["DH size"] = (t["dh_bits"] in s["dh_sizes"]) if t.get("dh_bits") and s["dh_sizes"] else None
        checks["trust"] = (t["chain_trusted"] == s["trusted"]) \
            if t.get("chain_trusted") is not None and s["trusted"] is not None else None
        if t["certs"] and s["expired"] is not None:
            checks["expiry"] = (t["certs"][0]["days_left"] < 0) == s["expired"]
    row["checks"] = checks
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sslyze_json")
    ap.add_argument("tlsight_json", nargs="+")
    ap.add_argument("--out", default="samples/comparison.md")
    args = ap.parse_args()

    scan = json.load(open(args.sslyze_json, encoding="utf-8"))
    tl = load_tlsight(args.tlsight_json)
    rows = []
    for r in scan["server_scan_results"]:
        loc = r["server_location"]
        host, port = loc["hostname"], loc["port"]
        if r.get("scan_status") != "COMPLETED" or r.get("connectivity_status") != "COMPLETED":
            rows.append({"host": f"{host}:{port}", "tlsight": (tl.get((host, port)) or {}).get("grade", "-"),
                         "grade": "-", "sslyze": "scan failed: server not reachable with any TLS version",
                         "checks": {}})
            continue
        rows.append(compare(host, port, sslyze_facts(r), tl.get((host, port))))

    agree = sum(v is True for r in rows for v in r["checks"].values())
    disagree = sum(v is False for r in rows for v in r["checks"].values())
    lines = [f"# TLSight vs sslyze ({scan.get('sslyze_version', '?')})", "",
             f"Scan date: {scan.get('date_scans_started', '?')[:10]}.  "
             f"Checks agreeing: **{agree}**, disagreeing: **{disagree}**.", "",
             "| Host | TLSight (negotiated) | Grade | sslyze (everything accepted) | Checks |",
             "|---|---|---|---|---|"]
    for r in rows:
        checks = ", ".join(f"{k}: {mark(v)}" for k, v in r["checks"].items() if v is not None) or "-"
        lines.append(f"| {r['host']} | {r['tlsight']} | {r['grade']} | {r['sslyze']} | {checks} |")
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwritten to {args.out}")


if __name__ == "__main__":
    main()
