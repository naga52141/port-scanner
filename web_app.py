#!/usr/bin/env python3
"""
Port Scanner - web dashboard (Flask).

Run:  python web_app.py   then open http://127.0.0.1:5050

The server listens on 127.0.0.1 only. A web page that can scan arbitrary
hosts must never be exposed to other machines on the network.
"""

import os
import threading
import uuid

from flask import Flask, abort, jsonify, render_template, request, send_from_directory

from scanner import ScanOptions, run_scan, validate
from scanner.compare import compare_reports, load_report
from scanner.report import HISTORY_DIR, list_history, previous_scan, save_to_history
from scanner.syn import syn_available

app = Flask(__name__)
jobs = {}
jobs_lock = threading.Lock()


@app.before_request
def only_local_requests():
    # Blocks DNS-rebinding attacks: a malicious site pointing its own domain
    # at 127.0.0.1 would send a foreign Host header.
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        abort(403)


def _history_path(name):
    """Resolve a history file name safely (no path traversal)."""
    if name not in list_history():
        abort(404)
    return os.path.join(HISTORY_DIR, name)


@app.get("/")
def index():
    syn_ok, syn_reason = syn_available()
    return render_template("index.html", syn_ok=syn_ok, syn_reason=syn_reason)


@app.post("/api/scans")
def start_scan():
    # Requiring a real JSON content type stops other websites from starting
    # scans through the browser (cross-site requests can't send it without
    # a CORS preflight, which this server never approves).
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="Expected a JSON body"), 400
    try:
        opts = ScanOptions(
            target=str(body.get("target", "")),
            ports=str(body.get("ports", "1-1024")),
            udp=bool(body.get("udp")),
            udp_ports=str(body.get("udp_ports", "top")),
            syn=bool(body.get("syn")),
            threads=int(body.get("threads", 200)),
            timeout=float(body.get("timeout", 0.5)),
            banners=bool(body.get("banners", True)),
            os_detect=bool(body.get("os_detect")),
            cve=bool(body.get("cve")),
        )
        validate(opts)
    except (ValueError, RuntimeError, TypeError) as e:
        return jsonify(error=str(e)), 400

    job_id = uuid.uuid4().hex[:12]
    job = {"status": "running", "done": 0, "total": 0, "log": [], "results": [],
           "hosts": {}, "report": None, "diff": None, "error": None,
           "stop": threading.Event()}
    with jobs_lock:
        jobs[job_id] = job

    def on_host(host, os_info, results):
        with jobs_lock:
            job["hosts"][host] = os_info
            job["results"] = [r for r in job["results"] if r["host"] != host] + results

    def on_result(r):
        with jobs_lock:
            job["results"].append(r)

    def on_progress(done, total):
        job["done"], job["total"] = done, total

    def worker():
        try:
            baseline = previous_scan(opts.target)
            report = run_scan(opts, log=job["log"].append, on_result=on_result,
                              on_progress=on_progress, on_host=on_host, stop=job["stop"])
            job["saved_as"] = os.path.basename(save_to_history(report))
            if baseline:
                job["diff"] = compare_reports(load_report(baseline), report)
            job["report"] = report
            job["status"] = "stopped" if report["scan"]["stopped_early"] else "finished"
        except Exception as e:
            job["error"], job["status"] = str(e), "error"

    threading.Thread(target=worker, daemon=True).start()
    return jsonify(id=job_id)


@app.get("/api/scans/<job_id>")
def scan_status(job_id):
    job = jobs.get(job_id) or abort(404)
    since = request.args.get("log_from", 0, type=int)
    with jobs_lock:
        return jsonify(
            status=job["status"], done=job["done"], total=job["total"],
            log=job["log"][since:], log_next=len(job["log"]),
            results=job["results"], hosts=job["hosts"], diff=job["diff"],
            error=job["error"], saved_as=job.get("saved_as"),
            summary=job["report"]["scan"] if job["report"] else None)


@app.post("/api/scans/<job_id>/stop")
def stop_scan(job_id):
    job = jobs.get(job_id) or abort(404)
    job["stop"].set()
    return jsonify(ok=True)


@app.get("/api/history")
def history():
    items = []
    for name in list_history()[:50]:
        try:
            report = load_report(os.path.join(HISTORY_DIR, name))
            items.append({"name": name, "target": report["scan"]["target"],
                          "started": report["scan"]["started"],
                          "open": sum(r["state"] == "open" for r in report["results"])})
        except (OSError, ValueError, KeyError):
            continue
    return jsonify(items)


@app.get("/api/history/<name>")
def download(name):
    _history_path(name)
    return send_from_directory(HISTORY_DIR, name, as_attachment=True)


@app.get("/api/compare")
def compare():
    old = load_report(_history_path(request.args.get("old", "")))
    new = load_report(_history_path(request.args.get("new", "")))
    return jsonify(compare_reports(old, new))


if __name__ == "__main__":
    print("Dashboard running at http://127.0.0.1:5050  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
