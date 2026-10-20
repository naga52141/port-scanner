"""
Passive-style OS fingerprinting.

Every OS starts packets with a default TTL (Time To Live) that each router
decrements by 1:
    64  -> Linux, macOS, Android, *BSD
    128 -> Windows
    255 -> routers/switches (Cisco etc.), Solaris
So a reply with TTL 116 most likely came from Windows, 12 hops away.

We combine three clues, weakest to strongest:
    1. ICMP ping TTL               (works without root)
    2. TCP SYN-ACK window + TTL    (only available from a SYN scan)
    3. Service banners             (e.g. "OpenSSH_8.2p1 Ubuntu")
"""

import platform
import re
import subprocess

BANNER_HINTS = [
    ("ubuntu", "Linux (Ubuntu)"),
    ("debian", "Linux (Debian)"),
    ("centos", "Linux (CentOS)"),
    ("red hat", "Linux (Red Hat)"),
    ("fedora", "Linux (Fedora)"),
    ("raspbian", "Linux (Raspberry Pi OS)"),
    ("alpine", "Linux (Alpine)"),
    ("freebsd", "FreeBSD"),
    ("microsoft", "Windows"),
    ("win32", "Windows"),
    ("win64", "Windows"),
    ("windows", "Windows"),
    ("darwin", "macOS"),
    ("mac os", "macOS"),
]


def ping_ttl(host, timeout=1.0):
    """Ping once with the system ping command and return the reply TTL."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    elif system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout + 3).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
    return int(match.group(1)) if match else None


def family_from_ttl(ttl):
    """Return (initial_ttl, os_family) for an observed TTL."""
    if ttl <= 64:
        return 64, "Linux / Unix / macOS"
    if ttl <= 128:
        return 128, "Windows"
    return 255, "Network device (router/switch) or Solaris"


def family_from_window(window, ttl):
    initial, family = family_from_ttl(ttl)
    if initial == 64:
        if window == 65535:
            return "macOS / FreeBSD"
        if window in (5840, 14600, 29200, 64240, 65160):
            return "Linux"
    return family


def detect_os(host, results=(), syn_fingerprint=None, timeout=1.0):
    evidence = []
    guess, confidence = "Unknown", "none"

    ttl = ping_ttl(host, timeout)
    if ttl:
        initial, family = family_from_ttl(ttl)
        evidence.append(f"Ping TTL {ttl} (starts at {initial}, ~{initial - ttl} hop(s) "
                        f"away) -> {family}")
        guess, confidence = family, "low"

    if syn_fingerprint:
        win, sttl = syn_fingerprint["window"], syn_fingerprint["ttl"]
        family = family_from_window(win, sttl)
        evidence.append(f"SYN-ACK window {win}, TTL {sttl} -> {family}")
        guess, confidence = family, "medium"

    for r in results:
        banner = (r.get("banner") or "").lower()
        hit = next(((k, name) for k, name in BANNER_HINTS if k in banner), None)
        if hit:
            evidence.append(f"Banner on {r['protocol']}/{r['port']} mentions "
                            f"'{hit[0]}' -> {hit[1]}")
            guess, confidence = hit[1], "high"
            break

    if not evidence:
        evidence.append("No ping reply and no identifying banners "
                        "(the host may block ICMP)")
    return {"guess": guess, "confidence": confidence, "ttl": ttl, "evidence": evidence}
