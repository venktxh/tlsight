"""TLSight - passive TLS handshake & cipher suite analyzer with JA3 fingerprinting."""

__version__ = "0.1.0"

import logging

# Scapy warns about missing libpcap / routes on import; we only read pcap files.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
