"""Saving scan reports as JSON or CSV."""

import csv
import json
import os
from datetime import datetime

HISTORY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "scans")


def save_report(report, path):
    if path.lower().endswith(".csv"):
        fields = ["host", "port", "protocol", "state", "service", "banner", "risk",
                  "cve_total", "top_cves"]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for r in report["results"]:
                top = "; ".join(f"{c['id']} ({c['score']})" for c in r.get("cves", []))
                writer.writerow({**r, "top_cves": top})
    else:
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
    return path


def save_to_history(report):
    """Keep a copy of every scan in scans/ so later scans can be compared."""
    os.makedirs(HISTORY_DIR, exist_ok=True)
    safe_target = "".join(c if c.isalnum() or c in ".-" else "_"
                          for c in report["scan"]["target"])
    name = f"{datetime.now():%Y%m%d-%H%M%S}_{safe_target}.json"
    return save_report(report, os.path.join(HISTORY_DIR, name))


def list_history():
    if not os.path.isdir(HISTORY_DIR):
        return []
    return sorted((f for f in os.listdir(HISTORY_DIR) if f.endswith(".json")), reverse=True)


def previous_scan(target, exclude=None):
    """Path of the most recent saved scan of the same target, if any."""
    for name in list_history():
        path = os.path.join(HISTORY_DIR, name)
        if path == exclude:
            continue
        try:
            with open(path) as f:
                if json.load(f)["scan"]["target"] == target:
                    return path
        except (OSError, ValueError, KeyError):
            continue
    return None
