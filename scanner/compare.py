"""Compare two scan reports to spot newly opened or closed ports."""

import json


def load_report(path):
    with open(path) as f:
        return json.load(f)


def _index(report):
    return {(r["host"], r.get("protocol", "tcp"), r["port"]): r
            for r in report.get("results", [])}


def compare_reports(old, new):
    """
    Returns a dict with:
        opened  - ports open now that were not open before   (possible new risk!)
        closed  - ports that were open before but are gone now
        changed - same port, but the banner/version changed  (software updated?)
    """
    before, after = _index(old), _index(new)
    opened = [after[k] for k in sorted(after.keys() - before.keys())]
    closed = [before[k] for k in sorted(before.keys() - after.keys())]
    changed = []
    for key in sorted(before.keys() & after.keys()):
        old_banner, new_banner = before[key].get("banner", ""), after[key].get("banner", "")
        if old_banner != new_banner:
            changed.append({**after[key], "old_banner": old_banner})
    return {
        "old_scan": old.get("scan", {}).get("started", "?"),
        "new_scan": new.get("scan", {}).get("started", "?"),
        "opened": opened,
        "closed": closed,
        "changed": changed,
    }


def format_diff(diff):
    lines = [f"Comparing scan {diff['old_scan']}  ->  {diff['new_scan']}"]
    if not (diff["opened"] or diff["closed"] or diff["changed"]):
        lines.append("  No changes - same open ports and banners.")
        return "\n".join(lines)
    for r in diff["opened"]:
        risk = f"   !! {r['risk']}" if r.get("risk") else ""
        lines.append(f"  [+] NEW    {r['host']} {r['port']}/{r.get('protocol', 'tcp')} "
                     f"{r['service']}{risk}")
    for r in diff["closed"]:
        lines.append(f"  [-] CLOSED {r['host']} {r['port']}/{r.get('protocol', 'tcp')} "
                     f"{r['service']}")
    for r in diff["changed"]:
        lines.append(f"  [~] CHANGED {r['host']} {r['port']}/{r.get('protocol', 'tcp')}: "
                     f"'{r['old_banner']}' -> '{r['banner']}'")
    return "\n".join(lines)
