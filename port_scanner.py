#!/usr/bin/env python3
"""
Port Scanner - Cyber Security Mini Project (command-line version)

Features: TCP connect scan, SYN scan (scapy, root), UDP scan, banner grabbing,
service names, risk notes, OS fingerprinting, CVE lookup (NVD), scan history
and comparison, JSON/CSV reports.

ONLY scan hosts you own or have written permission to test.
"""

import argparse
import sys
import threading

from scanner import ScanOptions, run_scan, validate
from scanner.compare import compare_reports, format_diff, load_report
from scanner.report import previous_scan, save_report, save_to_history


def print_host_table(host, os_info, results):
    if os_info:
        print(f"\n  OS guess: {os_info['guess']}  (confidence: {os_info['confidence']})")
        for line in os_info["evidence"]:
            print(f"    - {line}")
    if not results:
        print(f"\n  No open ports found on {host}.\n")
        return
    print(f"\n  {'PORT':<11}{'STATE':<15}{'SERVICE':<16}BANNER / NOTES")
    print("  " + "-" * 78)
    pad = " " * 42
    for r in results:
        port = f"{r['port']}/{r['protocol']}"
        print(f"  {port:<11}{r['state']:<15}{r['service']:<16}{r['banner']}")
        if r["risk"]:
            print(f"  {pad}!! {r['risk']}")
        if r.get("cve_total"):
            print(f"  {pad}{r['cve_total']} known CVE(s) for "
                  f"{', '.join(r.get('software', []))}. Most severe:")
            for c in r["cves"][:5]:
                print(f"  {pad}  {c['id']:<17} {c['score']:>4} {c['severity']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded port scanner (educational use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python port_scanner.py 127.0.0.1
  python port_scanner.py scanme.nmap.org -p top -A -o report.json
  python port_scanner.py 192.168.1.0/24 -p 22,80,443 --os
  sudo .venv/bin/python port_scanner.py 192.168.1.10 --syn
  python port_scanner.py 127.0.0.1 --compare last""",
    )
    parser.add_argument("target", help="IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="TCP ports: '22,80', '1-1024', 'top', 'all', or '' for none "
                             "(default 1-1024)")
    parser.add_argument("-u", "--udp", action="store_true", help="also scan UDP ports")
    parser.add_argument("--udp-ports", default="top",
                        help="UDP ports to scan with --udp (default: common UDP services)")
    parser.add_argument("-s", "--syn", action="store_true",
                        help="SYN (half-open) scan with scapy - needs sudo")
    parser.add_argument("-O", "--os", action="store_true", help="guess the operating system")
    parser.add_argument("-c", "--cve", action="store_true",
                        help="look up known CVEs for detected software versions (internet)")
    parser.add_argument("-A", "--all-checks", action="store_true",
                        help="shortcut for --udp --os --cve")
    parser.add_argument("-t", "--threads", type=int, default=200,
                        help="concurrent connections (default 200)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="seconds to wait per connection (default 0.5)")
    parser.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    parser.add_argument("-o", "--output", help="save report to .json or .csv")
    parser.add_argument("--compare", metavar="OLD.json|last",
                        help="compare with an earlier report ('last' = previous scan "
                             "of the same target)")
    parser.add_argument("--no-history", action="store_true",
                        help="don't keep a copy of this scan in scans/")
    args = parser.parse_args()

    if args.all_checks:
        args.udp = args.os = args.cve = True

    opts = ScanOptions(
        target=args.target, ports=args.ports, udp=args.udp, udp_ports=args.udp_ports,
        syn=args.syn, threads=args.threads, timeout=args.timeout,
        banners=not args.no_banner, os_detect=args.os, cve=args.cve,
    )

    try:
        validate(opts)
    except (ValueError, RuntimeError) as e:
        parser.error(str(e))

    # Load the comparison baseline before this scan is saved to history.
    baseline = None
    if args.compare:
        path = previous_scan(args.target) if args.compare == "last" else args.compare
        if not path:
            parser.error(f"No earlier saved scan of {args.target} to compare with")
        try:
            baseline = load_report(path)
        except (OSError, ValueError) as e:
            parser.error(f"Cannot read report to compare with: {e}")

    print("=" * 64)
    print("  PORT SCANNER  -  scan only systems you are authorized to test")
    print("=" * 64)

    tty = sys.stdout.isatty()

    def log(msg):
        print(("\r" + " " * 40 + "\r" if tty else "") + msg)

    def on_result(r):
        log(f"  [+] {r['port']:>5}/{r['protocol']} {r['state']:<13} {r['service']}")

    def on_progress(done, total):
        if tty and (done % 25 == 0 or done == total):
            print(f"\r  progress: {done}/{total} ({100 * done // max(total, 1)}%)",
                  end="", flush=True)

    outcome, stop = {}, threading.Event()

    def worker():
        try:
            outcome["report"] = run_scan(opts, log, on_result, on_progress,
                                         print_host_table, stop)
        except Exception as e:  # reported in the main thread
            outcome["error"] = e

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            thread.join(0.2)
    except KeyboardInterrupt:
        print("\n[!] Stopping scan (Ctrl+C) ...")
        stop.set()
        thread.join()

    if "error" in outcome:
        parser.error(str(outcome["error"]))
    report = outcome["report"]

    if not args.no_history:
        print(f"[*] Saved to history: {save_to_history(report)}")
    if args.output:
        print(f"[*] Report saved to {save_report(report, args.output)}")
    if baseline:
        print()
        print(format_diff(compare_reports(baseline, report)))


if __name__ == "__main__":
    main()
