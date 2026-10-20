"""Target/port parsing and the low-level TCP and UDP probes."""

import ipaddress
import socket

# Well-known TCP ports most worth checking first.
TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 514, 587, 631, 993, 995, 1433, 1521, 1723,
    2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5984, 6379, 7000, 8000,
    8080, 8443, 8888, 9200, 11211, 27017,
]

# UDP services that are common and/or frequently abused.
TOP_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520,
                 1900, 4500, 5353, 11211]

# Short security notes shown next to open ports in the report.
TCP_RISK_NOTES = {
    21: "FTP - credentials sent in plaintext; prefer SFTP/FTPS",
    23: "Telnet - unencrypted remote login; disable and use SSH",
    25: "SMTP - check it is not an open relay",
    135: "MS RPC - frequent exploitation target; block at firewall",
    139: "NetBIOS - leaks host info; should not be internet-facing",
    445: "SMB - target of WannaCry/EternalBlue; never expose publicly",
    1433: "MSSQL - database should not be publicly reachable",
    2375: "Docker API (no TLS) - allows full host takeover",
    3306: "MySQL - database should not be publicly reachable",
    3389: "RDP - brute-force target; restrict with VPN/firewall",
    5432: "PostgreSQL - database should not be publicly reachable",
    5900: "VNC - often weak/no password; restrict access",
    6379: "Redis - often runs without auth; bind to localhost",
    9200: "Elasticsearch - often runs without auth; data leak risk",
    11211: "Memcached - used in DDoS amplification; bind to localhost",
    27017: "MongoDB - often runs without auth; data leak risk",
}

UDP_RISK_NOTES = {
    53: "DNS - if it is an open resolver it can be abused for DDoS amplification",
    69: "TFTP - no authentication; can leak device config files",
    123: "NTP - 'monlist' is abused for DDoS amplification",
    137: "NetBIOS name service - leaks host and user names",
    161: "SNMP - default 'public' community leaks device details",
    1900: "SSDP/UPnP - DDoS amplification; should never face the internet",
    5353: "mDNS - leaks device info; should not face the internet",
    11211: "Memcached UDP - massive DDoS amplification vector",
}

# Protocols where the server waits for the client to speak first.
HTTP_PORTS = {80, 443, 3000, 5000, 7000, 8000, 8080, 8443, 8888, 9200}


def parse_ports(spec):
    """Turn '22,80,100-105' or 'top' or 'all' into a sorted list of ports."""
    spec = spec.strip().lower()
    if spec == "top":
        return list(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start, end = (int(x) for x in part.split("-", 1))
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise ValueError(f"Invalid port value: '{part}'")

    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Ports must be between 1 and 65535 (got {bad[:5]})")
    return sorted(ports)


def parse_udp_ports(spec):
    return list(TOP_UDP_PORTS) if spec.strip().lower() == "top" else parse_ports(spec)


def parse_targets(target):
    """Turn a hostname, IP, or CIDR network into a list of IP strings."""
    target = target.strip()
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid network: {e}")
        hosts = [str(ip) for ip in network.hosts()]
        return hosts or [str(network.network_address)]
    try:
        return [socket.gethostbyname(target)]
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {target}")


def get_service_name(port, protocol="tcp"):
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def risk_note(port, protocol):
    notes = UDP_RISK_NOTES if protocol == "udp" else TCP_RISK_NOTES
    return notes.get(port, "")


def make_result(host, port, protocol, state, banner=""):
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "state": state,
        "service": get_service_name(port, protocol),
        "banner": banner,
        "risk": risk_note(port, protocol),
        "cves": [],
        "cve_total": 0,
    }


# ---------------------------------------------------------------- TCP ----

def grab_banner(sock, port, host, timeout):
    """Try to read an identifying banner from an open TCP port."""
    probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
    try:
        sock.settimeout(timeout)
        if port in HTTP_PORTS:
            sock.sendall(probe)
            data = sock.recv(1024)
        else:
            # Many services (SSH, FTP, SMTP) announce themselves on connect.
            # If this one stays silent, it may be a web server on an odd port.
            try:
                data = sock.recv(1024)
            except socket.timeout:
                sock.sendall(probe)
                data = sock.recv(1024)
        if not data:
            return ""
        text = data.decode(errors="ignore").strip()
        if text.startswith("HTTP/"):
            # Return just the status line and Server header, if any.
            lines = text.splitlines()
            keep = [lines[0]] if lines else []
            keep += [l for l in lines if l.lower().startswith("server:")]
            return " | ".join(keep)
        return text.splitlines()[0][:120] if text else ""
    except (socket.timeout, OSError):
        return ""


def scan_tcp_port(host, port, timeout, banners):
    """TCP connect scan of one port. Returns a result dict or None if closed."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return None
        banner = grab_banner(sock, port, host, timeout) if banners else ""
    return make_result(host, port, "tcp", "open", banner)


def tcp_banner(host, port, timeout):
    """Connect to a port already known to be open and return its banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return grab_banner(sock, port, host, timeout)
    except OSError:
        return ""


# ---------------------------------------------------------------- UDP ----

def _dns_query(name="example.com"):
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + b"\x00\x01\x00\x01"  # type A, class IN


# Protocol-correct payloads: UDP services usually ignore garbage, so to get a
# reply (and prove the port is open) we have to "speak their language".
UDP_PROBES = {
    53: _dns_query(),
    5353: _dns_query(),
    123: b"\x1b" + b"\x00" * 47,  # NTP v3 client request
    161: bytes.fromhex(  # SNMPv1 GET sysDescr.0, community "public"
        "302602010004067075626c6963a019020101020100020100"
        "300e300c06082b060102010101000500"),
    137: (b"\x80\xf0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
          + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"),  # NBSTAT
    1900: (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"),
    11211: b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n",
}


def _describe_udp_reply(port, data):
    if port in (53, 5353):
        return f"DNS response ({len(data)} bytes)"
    if port == 123:
        return f"NTP response (stratum {data[1]})" if len(data) > 1 else "NTP response"
    printable = "".join(c if 32 <= ord(c) < 127 else " " for c in data.decode("latin-1"))
    return " ".join(printable.split())[:120] or f"{len(data)} bytes"


def scan_udp_port(host, port, timeout):
    """
    UDP scan of one port.
      reply received          -> open
      ICMP port unreachable   -> closed (returns None)
      no reply before timeout -> open|filtered (can't tell; firewall or silent service)
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            sock.send(UDP_PROBES.get(port, b"\r\n"))
            data = sock.recv(2048)
            return make_result(host, port, "udp", "open", _describe_udp_reply(port, data))
        except ConnectionRefusedError:
            return None
        except socket.timeout:
            return make_result(host, port, "udp", "open|filtered")
        except OSError:
            return None
