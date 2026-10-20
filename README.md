# Port Scanner: Cyber Security Mini Project

**Live demo:** [https://naga52141.github.io/port-scanner](https://naga52141.github.io/port-scanner/) (replays a recorded scan; the real scanner runs locally)

A network port scanner written in Python. It finds open TCP and UDP ports, identifies the running services and their versions, looks up known vulnerabilities (CVEs), guesses the operating system, and tracks changes between scans. It has three interfaces: a command-line tool, a desktop GUI and a web dashboard.

> **Legal notice:** Only scan systems you own or have written permission to test. Unauthorised port scanning can break the law (for example, the Computer Misuse Act in the UK or the CFAA in the US) and network policies. Safe targets: `127.0.0.1`, your own home lab or VMs, and `scanme.nmap.org`, which the Nmap project provides for testing.

## Features

| Feature | What it does |
|---|---|
| TCP connect scan | Multithreaded full-handshake scan; needs no special privileges |
| SYN (half-open) scan | Raw-packet scan with scapy; stealthier and faster, needs root |
| UDP scan | Sends protocol-correct probes (DNS, NTP, SNMP, NetBIOS, SSDP, Memcached) |
| Banner grabbing | Reads service greetings and HTTP `Server:` headers to find software versions |
| Risk notes | Flags dangerous exposed services (Telnet, SMB, RDP, Redis, SNMP and others) |
| CVE lookup | Matches detected versions against the NIST NVD database and ranks CVEs by CVSS score |
| OS fingerprinting | Guesses the OS from ping TTL, TCP window size and banners, and shows the evidence |
| Scan history and comparison | Saves every scan and reports new, closed or changed ports since the last one |
| Reports | JSON or CSV export |
| Interfaces | Command line, Tkinter desktop GUI, Flask web dashboard |

## Setup (one time)

```bash
git clone https://github.com/naga52141/port-scanner.git
cd port-scanner
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # scapy (SYN scan) + flask (web dashboard)
```

The command-line tool and GUI also run without these packages. Only the SYN scan needs scapy, and only the web dashboard needs Flask.

## 1. Command line

```bash
source .venv/bin/activate

python port_scanner.py 127.0.0.1                         # TCP ports 1-1024
python port_scanner.py 127.0.0.1 -p top -A               # common ports + UDP + OS + CVEs
python port_scanner.py scanme.nmap.org -p top --cve -o report.json
python port_scanner.py 192.168.1.0/24 -p 22,80,443 --os  # whole home network
python port_scanner.py 127.0.0.1 --udp --udp-ports 53,123,161
python port_scanner.py 127.0.0.1 --compare last          # what changed since last scan?
sudo .venv/bin/python port_scanner.py 192.168.1.10 --syn # SYN scan (needs root)
```

| Option | Description | Default |
|---|---|---|
| `target` | IP, hostname, or CIDR range | required |
| `-p, --ports` | TCP ports: `22,80`, `1-1024`, `top`, `all`, or `""` for none | `1-1024` |
| `-u, --udp` | Also scan UDP | off |
| `--udp-ports` | UDP ports to scan | common UDP services |
| `-s, --syn` | SYN scan instead of connect scan (sudo) | off |
| `-O, --os` | OS fingerprinting | off |
| `-c, --cve` | CVE lookup (needs internet) | off |
| `-A, --all-checks` | Same as `--udp --os --cve` | off |
| `-t, --threads` | Concurrent connections | `200` |
| `--timeout` | Seconds to wait per connection | `0.5` |
| `--no-banner` | Skip banner grabbing | off |
| `-o, --output` | Save report (`.json` or `.csv`) | none |
| `--compare` | Compare with `OLD.json`, or `last` (previous scan of the same target) | none |
| `--no-history` | Don't save this scan to `scans/` | off |

Press **Ctrl+C** to stop a scan early. Results found so far are still saved.

## 2. Desktop GUI

```bash
python gui.py
```

Fill in the target and ports, tick the checks you want, and press **Start scan**. Rows are coloured by risk: red for a critical CVE (CVSS 9+), orange for a high CVE or risky service, and grey for open|filtered. Click a row to see its details, the OS evidence and CVEs; each CVE is a clickable link to the NVD page. Use **Save report...** to export, and **Compare with earlier scan...** to see the changes.

## 3. Web dashboard

```bash
python web_app.py
# then open http://127.0.0.1:5050
```

The dashboard shows live progress, summary cards (open ports, risky services, known CVEs, critical CVEs), a results table with CVE badges, OS fingerprints, automatic **changes since the last scan of this target**, and a scan history with download and compare.

For safety, the dashboard only listens on `127.0.0.1`. It also rejects requests with a foreign `Host` header (protection against DNS rebinding) and non-JSON requests (so other websites can't start scans through your browser).

## How it works

### TCP connect scan
The scanner completes a normal three-way handshake (`SYN`, `SYN-ACK`, `ACK`) with `connect_ex()`. If the handshake succeeds, the port is **open**. A `RST` reply means it is **closed**, and no reply before the timeout means it is **filtered** by a firewall. A thread pool runs hundreds of connections in parallel, so 1,024 ports take under a second on localhost.

### SYN scan ([scanner/syn.py](scanner/syn.py))
The scanner sends only a raw `SYN` packet. A `SYN-ACK` reply means the port is open, and the OS kernel answers it with `RST`, so the connection never completes and the target application never logs it. Building raw packets needs root.

| | Connect scan | SYN scan |
|---|---|---|
| Handshake | Full | Half (SYN, SYN-ACK, RST) |
| Needs root | No | Yes |
| Logged by target app | Yes | Usually not |

### UDP scan ([scanner/core.py](scanner/core.py))
UDP has no handshake, so the results are less certain:
- A reply means the port is **open**.
- An ICMP "port unreachable" means it is **closed**.
- Silence means **open|filtered**: either a firewall dropped the probe or the service ignored it.

To get replies, the scanner sends real protocol messages: a DNS query to port 53, an NTP request to 123, and an SNMP `GET` with the community string `public` to 161.

### Banner grabbing and CVE lookup ([scanner/cve.py](scanner/cve.py))
`SSH-2.0-OpenSSH_8.2p1` is parsed to the CPE `cpe:2.3:a:openbsd:openssh:8.2` and sent to the NVD API. The scanner keeps only CVEs where that product itself is marked vulnerable; for example, it drops bugs in apps that merely run *on* Python. Results are sorted by CVSS score and cached for a week in `.cve_cache.json`. Without an API key, NVD allows about 5 requests every 30 seconds, so lookups wait about 6 seconds between products. A free key from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) removes most of that wait:

```bash
export NVD_API_KEY=your-key
```

### OS fingerprinting ([scanner/osdetect.py](scanner/osdetect.py))
Each OS sends packets with a default TTL, and each router on the way subtracts 1:

| Initial TTL | OS family |
|---|---|
| 64 | Linux, macOS, Android, BSD |
| 128 | Windows |
| 255 | Routers/switches, Solaris |

A reply with TTL 116 is therefore most likely Windows, 12 hops away. The scanner combines three clues, from weakest to strongest: ping TTL, the SYN-ACK window size (SYN scan only), and banners that name the OS (`Ubuntu`, `Microsoft-IIS`). It reports the guess with a confidence level and its evidence.

### Scan comparison ([scanner/compare.py](scanner/compare.py))
Every scan is saved in `scans/`. Comparing two scans lists **new** ports (a possible backdoor or misconfiguration), **closed** ports, and **changed** banners (software updated or replaced). This is how real attack-surface monitoring works.

## Project structure

```
port-scanner/
├── port_scanner.py      command-line interface
├── gui.py               Tkinter desktop GUI
├── web_app.py           Flask web dashboard
├── templates/index.html dashboard page
├── scanner/
│   ├── core.py          port/target parsing, TCP + UDP probes, banners, risk notes
│   ├── syn.py           SYN scan (scapy)
│   ├── osdetect.py      OS fingerprinting
│   ├── cve.py           NVD CVE lookup
│   ├── compare.py       scan diffing
│   ├── report.py        JSON/CSV export and history
│   └── engine.py        runs a scan; shared by all three interfaces
├── docs/                GitHub Pages demo site (replays a recorded scan)
├── requirements.txt
└── scans/               saved scan history (created automatically)
```

## Defending against port scans

- Close or disable services you don't use, to reduce the attack surface.
- Use a firewall with default-deny rules and expose only the ports you need.
- Bind databases and caches (MySQL, Redis, MongoDB, Memcached) to `127.0.0.1`.
- Patch software. The CVE lookup shows why version banners matter.
- Hide or minimise version banners (for example, `ServerTokens Prod` in Apache, `server_tokens off` in nginx).
- Use an IDS/IPS such as Snort or Suricata to detect scans, and `fail2ban` to block repeat offenders.
- Monitor your own attack surface by scanning regularly and comparing results.

## Limitations

- OS detection is a best guess. Firewalls, NAT and VMs can change the TTL.
- UDP results are often `open|filtered`, because silence is ambiguous.
- CVE matching relies on version banners. Linux distributions backport security fixes without changing the version number (for example, Ubuntu's `OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` may already be patched), so treat the matches as leads to check, not proof.
- SYN scans of `127.0.0.1` may not work on macOS because of how loopback works there. Scan another machine or a VM instead.
