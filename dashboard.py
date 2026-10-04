"""TLSight dashboard:  python -m streamlit run dashboard.py"""

import os
import tempfile

import pandas as pd
import streamlit as st

from tlsight.analyzer import analyze_pcap, check_host
from tlsight.ciphers import suite_name, version_name
from tlsight.report import cert_label, kex_label, to_json

GRADE_COLORS = {"A": "#2e9e5b", "B": "#7bb661", "C": "#e0b000", "D": "#e07b00", "F": "#d33", "N/A": "#999"}
SEV_ICON = {"CRITICAL": ":red[**CRITICAL**]", "HIGH": ":red[HIGH]", "MEDIUM": ":orange[MEDIUM]",
            "LOW": ":blue[LOW]", "INFO": ":gray[INFO]", "GOOD": ":green[GOOD]"}

st.set_page_config(page_title="TLSight", layout="wide")
st.title("TLSight: TLS Handshake & Cipher Suite Analyzer")

mode = st.sidebar.radio("Input", ["Upload pcap", "Sample pcap", "Check a host"])
probe = st.sidebar.checkbox("Probe TLS 1.3 servers for certificates", value=False)
show_good = st.sidebar.checkbox("Show positive findings", value=True)


@st.cache_data(show_spinner="Analyzing capture...")
def run_pcap(data: bytes, do_probe: bool):
    fd, path = tempfile.mkstemp(suffix=".pcap")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        return analyze_pcap(path, do_probe=do_probe)
    finally:
        os.remove(path)


report = None
if mode == "Upload pcap":
    up = st.file_uploader("Wireshark capture (.pcap / .pcapng)", type=["pcap", "pcapng", "cap"])
    if up:
        report = run_pcap(up.getvalue(), probe)
        report.source = up.name
elif mode == "Sample pcap":
    sample_dir = os.path.join(os.path.dirname(__file__), "samples")
    files = sorted(f for f in os.listdir(sample_dir) if f.endswith((".pcap", ".pcapng"))) \
        if os.path.isdir(sample_dir) else []
    if files:
        name = st.selectbox("Sample", files)
        with open(os.path.join(sample_dir, name), "rb") as fh:
            report = run_pcap(fh.read(), probe)
        report.source = name
    else:
        st.info("No samples yet. Run `python tools/make_samples.py`.")
else:
    target = st.text_input("Host[:port]", "example.com")
    if st.button("Check") and target:
        host, _, port = target.partition(":")
        with st.spinner(f"Connecting to {target}..."):
            report = check_host(host, int(port or 443))

if report is None:
    st.stop()
if not report.connections:
    st.warning("No TLS handshakes found in this capture.")
    st.stop()

conns = report.connections
df = pd.DataFrame([{
    "#": c.id, "Server": c.target, "Endpoint": c.server, "Version": version_name(c.version),
    "Cipher suite": suite_name(c.cipher), "Key exchange": kex_label(c), "Certificate": cert_label(c),
    "ALPN": ",".join(c.alpn), "JA3": c.ja3_hash or "", "JA3S": c.ja3s_hash or "",
    "Score": c.score, "Grade": c.grade,
    "Critical": sum(f.severity == "CRITICAL" for f in c.findings),
    "High": sum(f.severity == "HIGH" for f in c.findings),
} for c in conns])

cols = st.columns(5)
cols[0].metric("TLS connections", len(conns))
cols[1].metric("Grade A", int((df["Grade"] == "A").sum()))
cols[2].metric("Grade F", int((df["Grade"] == "F").sum()))
cols[3].metric("Critical findings", int(df["Critical"].sum()))
cols[4].metric("Unique client fingerprints", df["JA3"].replace("", pd.NA).nunique())

c1, c2, c3 = st.columns(3)
with c1:
    st.subheader("Grades")
    order = [g for g in GRADE_COLORS if g in set(df["Grade"])]
    st.bar_chart(df["Grade"].value_counts().reindex(order))
with c2:
    st.subheader("Protocol versions")
    st.bar_chart(df["Version"].value_counts())
with c3:
    st.subheader("Key exchange")
    st.bar_chart(df["Key exchange"].value_counts())


def color_grade(v):
    return f"background-color: {GRADE_COLORS.get(v, '')}; color: white; font-weight: bold"


st.subheader("Connections")
st.dataframe(df.style.map(color_grade, subset=["Grade"]), hide_index=True, width="stretch")

st.subheader("Findings")
for c in conns:
    shown = [f for f in c.findings if show_good or f.severity != "GOOD"]
    with st.expander(f"#{c.id}  {c.target}  ({version_name(c.version)}, {suite_name(c.cipher)})  "
                     f"grade {c.grade}", expanded=c.grade in ("D", "F")):
        for f in shown:
            st.markdown(f"{SEV_ICON[f.severity]} `{f.side}` **{f.title}**  \n{f.detail}")
        if c.certs:
            st.markdown(f"**Certificate chain** (from {c.cert_source})")
            st.table(pd.DataFrame([{
                "Subject": x.subject, "Issuer": x.issuer, "Key": f"{x.key_type} {x.key_size}",
                "Signature": x.sig_hash, "Expires": x.not_after[:10], "Days left": x.days_left,
                "SAN": ", ".join(x.san[:4]),
            } for x in c.certs]))
        if c.ja3:
            st.code(f"JA3  {c.ja3_hash}  {c.ja3}\nJA3S {c.ja3s_hash}  {c.ja3s}", language=None)
        for note in c.notes:
            st.caption(note)

st.subheader("Client fingerprints (JA3)")
ja3_df = df[df["JA3"] != ""].groupby("JA3").agg(
    connections=("#", "count"), servers=("Server", lambda s: ", ".join(sorted(set(s))[:5])))
st.dataframe(ja3_df, width="stretch")

st.download_button("Download JSON report", to_json(report), file_name="tlsight_report.json",
                   mime="application/json")
