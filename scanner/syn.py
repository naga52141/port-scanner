"""
SYN ("half-open") scanning with scapy.

Instead of completing the TCP handshake, we send a raw SYN packet and look at
the reply:
    SYN-ACK  -> port open   (our OS kernel then sends RST, so no connection
                             is ever established - this is why it's "stealthier")
    RST      -> port closed
    nothing  -> filtered by a firewall

Crafting raw packets needs root/administrator rights.
"""

import os


def syn_available():
    """Return (ok, reason) describing whether a SYN scan can run here."""
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        return False, "scapy is not installed (pip install -r requirements.txt)"
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return False, "SYN scan needs root - run with sudo"
    return True, ""


def syn_scan(host, ports, timeout, on_progress=None, stop=None, batch=256):
    """
    Returns (open_ports, fingerprint) where fingerprint holds the TTL and TCP
    window size of the first SYN-ACK seen (used for OS detection).
    """
    from scapy.all import IP, TCP, RandShort, conf, sr

    conf.verb = 0
    open_ports, fingerprint = set(), None
    for i in range(0, len(ports), batch):
        if stop is not None and stop.is_set():
            break
        chunk = ports[i:i + batch]
        packets = IP(dst=host) / TCP(sport=RandShort(), dport=chunk, flags="S")
        answered, _ = sr(packets, timeout=max(timeout, 1.0), retry=1)
        for sent, reply in answered:
            if reply.haslayer(TCP) and (int(reply[TCP].flags) & 0x12) == 0x12:
                open_ports.add(sent[TCP].dport)
                if fingerprint is None:
                    fingerprint = {"ttl": reply[IP].ttl, "window": reply[TCP].window}
        if on_progress:
            on_progress(len(chunk))
    return sorted(open_ports), fingerprint
