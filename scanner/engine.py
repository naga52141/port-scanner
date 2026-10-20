"""
The scan engine shared by the CLI, the Tkinter GUI and the web dashboard.

Front-ends pass callbacks to receive live updates:
    log(message)                      - status text
    on_result(result)                 - an open port was found
    on_progress(done, total)          - probes completed so far
    on_host(host, os_info, results)   - a host finished (results include CVEs)
and an optional threading.Event `stop` to cancel the scan.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime

from .core import (make_result, parse_ports, parse_targets, parse_udp_ports,
                   scan_tcp_port, scan_udp_port, tcp_banner)
from .cve import enrich_with_cves
from .osdetect import detect_os
from .syn import syn_available, syn_scan

VERSION = "2.0"


@dataclass
class ScanOptions:
    target: str
    ports: str = "1-1024"      # TCP ports; "" to skip TCP
    udp: bool = False
    udp_ports: str = "top"
    syn: bool = False          # SYN scan instead of connect scan (needs root)
    threads: int = 200
    timeout: float = 0.5
    banners: bool = True
    os_detect: bool = False
    cve: bool = False


def _noop(*args, **kwargs):
    pass


def _run_pool(func, ports, threads, stop, tick, on_result):
    found = []
    pool = ThreadPoolExecutor(max_workers=max(1, threads))
    try:
        futures = [pool.submit(func, p) for p in ports]
        for future in as_completed(futures):
            if stop.is_set():
                break
            tick()
            result = future.result()
            if result:
                found.append(result)
                on_result(result)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return found


def validate(opts):
    """Parse and check options up front; raises ValueError/RuntimeError."""
    tcp_ports = parse_ports(opts.ports) if opts.ports.strip() else []
    udp_ports = parse_udp_ports(opts.udp_ports) if opts.udp else []
    if not tcp_ports and not udp_ports:
        raise ValueError("Nothing to scan - give TCP ports and/or enable UDP")
    if not 1 <= opts.threads <= 2000:
        raise ValueError("Threads must be between 1 and 2000")
    if not 0.05 <= opts.timeout <= 30:
        raise ValueError("Timeout must be between 0.05 and 30 seconds")
    if opts.syn:
        ok, reason = syn_available()
        if not ok:
            raise RuntimeError(reason)
    hosts = parse_targets(opts.target)
    return hosts, tcp_ports, udp_ports


def run_scan(opts, log=_noop, on_result=_noop, on_progress=_noop, on_host=_noop,
             stop=None):
    stop = stop or threading.Event()
    hosts, tcp_ports, udp_ports = validate(opts)

    total = len(hosts) * (len(tcp_ports) + len(udp_ports))
    done, lock = [0], threading.Lock()

    def tick(n=1):
        with lock:
            done[0] += n
            on_progress(done[0], total)

    started, t0 = datetime.now(), time.perf_counter()
    log(f"[*] Target {opts.target}: {len(hosts)} host(s), {len(tcp_ports)} TCP / "
        f"{len(udp_ports)} UDP port(s), mode={'SYN' if opts.syn else 'connect'}")

    all_results, host_info = [], []
    for host in hosts:
        if stop.is_set():
            break
        log(f"[*] Scanning {host} ...")
        results, fingerprint = [], None

        if tcp_ports and opts.syn:
            open_ports, fingerprint = syn_scan(host, tcp_ports, opts.timeout, tick, stop)
            for port in open_ports:
                banner = tcp_banner(host, port, opts.timeout) if opts.banners else ""
                result = make_result(host, port, "tcp", "open", banner)
                results.append(result)
                on_result(result)
        elif tcp_ports:
            results += _run_pool(
                lambda p: scan_tcp_port(host, p, opts.timeout, opts.banners),
                tcp_ports, opts.threads, stop, tick, on_result)

        if udp_ports and not stop.is_set():
            # UDP needs a longer wait: silence is the normal answer.
            udp_timeout = max(opts.timeout, 1.0)
            results += _run_pool(lambda p: scan_udp_port(host, p, udp_timeout),
                                 udp_ports, min(opts.threads, 50), stop, tick, on_result)

        results.sort(key=lambda r: (r["protocol"], r["port"]))

        if opts.cve and results and not stop.is_set():
            log(f"[*] Looking up CVEs for detected software on {host} ...")
            enrich_with_cves(results, log)

        os_info = None
        if opts.os_detect and not stop.is_set():
            os_info = detect_os(host, results, fingerprint)
            log(f"[*] OS guess for {host}: {os_info['guess']} "
                f"(confidence: {os_info['confidence']})")

        host_info.append({
            "host": host,
            "os": os_info,
            "open_ports": sum(r["state"] == "open" for r in results),
        })
        on_host(host, os_info, results)
        all_results += results

    elapsed = time.perf_counter() - t0
    log(f"[*] Finished: {sum(h['open_ports'] for h in host_info)} open port(s) on "
        f"{len(host_info)} host(s) in {elapsed:.2f}s" + (" (stopped early)" if stop.is_set() else ""))

    return {
        "scan": {
            "tool": f"port-scanner {VERSION}",
            "target": opts.target,
            "started": started.isoformat(timespec="seconds"),
            "duration_seconds": round(elapsed, 2),
            "stopped_early": stop.is_set(),
            "options": asdict(opts),
            "tcp_ports_scanned": len(tcp_ports),
            "udp_ports_scanned": len(udp_ports),
        },
        "hosts": host_info,
        "results": all_results,
    }
