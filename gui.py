#!/usr/bin/env python3
"""
Port Scanner - desktop GUI (Tkinter).

Run:  python gui.py
The scan runs in a background thread; it talks to the window through a
queue, because Tkinter widgets may only be touched from the main thread.
"""

import json
import os
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from scanner import ScanOptions, run_scan, validate
from scanner.compare import compare_reports, format_diff, load_report
from scanner.report import HISTORY_DIR, save_report, save_to_history
from scanner.syn import syn_available

COLUMNS = [("host", "Host", 110), ("port", "Port", 60), ("protocol", "Proto", 55),
           ("state", "State", 100), ("service", "Service", 110),
           ("banner", "Banner", 320), ("cves", "CVEs", 70), ("risk", "Risk", 300)]


class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner - Cyber Security Mini Project")
        self.geometry("1200x760")
        self.minsize(900, 600)

        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.report = None
        self.rows = {}        # tree item id -> result dict
        self.host_os = {}     # host -> os info

        self._build_form()
        self._build_results()
        self.after(100, self._drain_events)

    # ------------------------------------------------------------ layout ---

    def _build_form(self):
        form = ttk.LabelFrame(self, text="Scan settings", padding=10)
        form.pack(fill="x", padx=10, pady=(10, 5))

        self.target = tk.StringVar(value="127.0.0.1")
        self.ports = tk.StringVar(value="1-1024")
        self.udp_ports = tk.StringVar(value="top")
        self.threads = tk.IntVar(value=200)
        self.timeout = tk.DoubleVar(value=0.5)

        fields = [("Target (IP / host / CIDR)", self.target, 28),
                  ("TCP ports", self.ports, 16),
                  ("UDP ports", self.udp_ports, 12),
                  ("Threads", self.threads, 6),
                  ("Timeout (s)", self.timeout, 6)]
        for col, (label, var, width) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=0, column=col, sticky="w", padx=4)
            ttk.Entry(form, textvariable=var, width=width).grid(row=1, column=col,
                                                                 sticky="we", padx=4)
        form.columnconfigure(0, weight=1)

        checks = ttk.Frame(form)
        checks.grid(row=2, column=0, columnspan=5, sticky="w", pady=(8, 0))
        self.banners = tk.BooleanVar(value=True)
        self.udp = tk.BooleanVar(value=False)
        self.syn = tk.BooleanVar(value=False)
        self.os_detect = tk.BooleanVar(value=True)
        self.cve = tk.BooleanVar(value=False)
        syn_ok, syn_reason = syn_available()
        for text, var, enabled in [("Banner grabbing", self.banners, True),
                                   ("UDP scan", self.udp, True),
                                   ("SYN scan" + ("" if syn_ok else f"  ({syn_reason})"),
                                    self.syn, syn_ok),
                                   ("OS detection", self.os_detect, True),
                                   ("CVE lookup (internet)", self.cve, True)]:
            cb = ttk.Checkbutton(checks, text=text, variable=var)
            cb.pack(side="left", padx=(0, 14))
            if not enabled:
                cb.state(["disabled"])

        buttons = ttk.Frame(form)
        buttons.grid(row=3, column=0, columnspan=5, sticky="we", pady=(10, 0))
        self.start_btn = ttk.Button(buttons, text="Start scan", command=self.start_scan)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(buttons, text="Stop", command=self.stop_scan,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(buttons, text="Save report...", command=self.save).pack(side="left", padx=6)
        ttk.Button(buttons, text="Compare with earlier scan...",
                   command=self.compare).pack(side="left", padx=6)

        self.progress = ttk.Progressbar(buttons, mode="determinate", length=220)
        self.progress.pack(side="right")
        self.status = tk.StringVar(value="Ready. Only scan systems you are authorized to test.")
        ttk.Label(buttons, textvariable=self.status).pack(side="right", padx=10)

    def _build_results(self):
        panes = ttk.PanedWindow(self, orient="vertical")
        panes.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        table = ttk.Frame(panes)
        self.tree = ttk.Treeview(table, columns=[c[0] for c in COLUMNS], show="headings")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self._sort(k))
            self.tree.column(key, width=width, anchor="w",
                             stretch=key in ("banner", "risk"))
        self.tree.tag_configure("critical", background="#f8c9c9")
        self.tree.tag_configure("risky", background="#fde7c4")
        self.tree.tag_configure("filtered", foreground="#888888")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show_details)
        panes.add(table, weight=3)

        self.tabs = ttk.Notebook(panes)
        self.log_box = self._text_tab("Log")
        self.details_box = self._text_tab("Details")
        self.details_box.tag_configure("link", foreground="#1a5fb4", underline=True)
        self.details_box.tag_bind("link", "<Button-1>", self._open_link)
        self.details_box.tag_bind("link", "<Enter>",
                                  lambda e: self.details_box.config(cursor="hand2"))
        self.details_box.tag_bind("link", "<Leave>",
                                  lambda e: self.details_box.config(cursor=""))
        panes.add(self.tabs, weight=2)

    def _text_tab(self, title):
        frame = ttk.Frame(self.tabs)
        box = tk.Text(frame, wrap="word", height=10, font=("Menlo", 11), state="disabled")
        scroll = ttk.Scrollbar(frame, command=box.yview)
        box.configure(yscrollcommand=scroll.set)
        box.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tabs.add(frame, text=title)
        return box

    # ------------------------------------------------------------- scan ----

    def start_scan(self):
        try:
            opts = ScanOptions(
                target=self.target.get(), ports=self.ports.get(), udp=self.udp.get(),
                udp_ports=self.udp_ports.get(), syn=self.syn.get(),
                threads=int(self.threads.get()), timeout=float(self.timeout.get()),
                banners=self.banners.get(), os_detect=self.os_detect.get(),
                cve=self.cve.get())
            validate(opts)
        except (ValueError, RuntimeError, tk.TclError) as e:
            messagebox.showerror("Invalid settings", str(e))
            return

        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.host_os.clear()
        self.report = None
        self._write(self.log_box, "", clear=True)
        self.progress["value"] = 0
        self.stop_event.clear()
        self.start_btn.state(["disabled"])
        self.stop_btn.state(["!disabled"])
        self.status.set("Scanning...")

        put = self.events.put
        self.worker = threading.Thread(target=self._run, daemon=True, args=(opts, put))
        self.worker.start()

    def _run(self, opts, put):
        try:
            report = run_scan(
                opts,
                log=lambda m: put(("log", m)),
                on_result=lambda r: put(("result", r)),
                on_progress=lambda d, t: put(("progress", (d, t))),
                on_host=lambda h, os_info, results: put(("host", (h, os_info, results))),
                stop=self.stop_event)
            put(("done", report))
        except Exception as e:
            put(("error", e))

    def stop_scan(self):
        self.stop_event.set()
        self.status.set("Stopping...")

    def _drain_events(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "log":
                    self._write(self.log_box, data + "\n")
                elif kind == "result":
                    self._add_row(data)
                elif kind == "progress":
                    done, total = data
                    self.progress["maximum"] = total
                    self.progress["value"] = done
                elif kind == "host":
                    host, os_info, results = data
                    self.host_os[host] = os_info
                    for item, r in list(self.rows.items()):
                        if r["host"] == host:
                            self.tree.delete(item)
                            del self.rows[item]
                    for r in results:
                        self._add_row(r)
                elif kind == "done":
                    self._finished(data)
                elif kind == "error":
                    self._finished(None)
                    messagebox.showerror("Scan failed", str(data))
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _finished(self, report):
        self.start_btn.state(["!disabled"])
        self.stop_btn.state(["disabled"])
        if report is None:
            self.status.set("Scan failed.")
            return
        self.report = report
        path = save_to_history(report)
        self._write(self.log_box, f"[*] Saved to history: {path}\n")
        n_open = sum(r["state"] == "open" for r in report["results"])
        n_cve = sum(r.get("cve_total", 0) for r in report["results"])
        self.status.set(f"Done: {n_open} open port(s), {n_cve} CVE(s) in "
                        f"{report['scan']['duration_seconds']}s")

    # ---------------------------------------------------------- results ----

    def _add_row(self, r):
        top = max((c["score"] for c in r.get("cves", [])), default=0)
        tag = ("critical" if top >= 9 else "risky" if (top >= 7 or r["risk"]) else
               "filtered" if r["state"] != "open" else "")
        values = [r["host"], r["port"], r["protocol"], r["state"], r["service"],
                  r["banner"], r.get("cve_total") or "", r["risk"]]
        item = self.tree.insert("", "end", values=values, tags=(tag,))
        self.rows[item] = r

    def _sort(self, key):
        items = list(self.rows.items())
        numeric = key in ("port", "cves")
        field = "cve_total" if key == "cves" else key
        items.sort(key=lambda kv: kv[1].get(field) or (0 if numeric else ""))
        for index, (item, _) in enumerate(items):
            self.tree.move(item, "", index)

    def _show_details(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        r = self.rows[selected[0]]
        box = self.details_box
        self._write(box, "", clear=True)
        self._write(box, f"{r['host']}  {r['port']}/{r['protocol']}  {r['state']}  "
                         f"({r['service']})\n\n")
        self._write(box, f"Banner: {r['banner'] or '-'}\n")
        if r.get("software"):
            self._write(box, f"Software: {', '.join(r['software'])}\n")
        if r["risk"]:
            self._write(box, f"Risk: {r['risk']}\n")
        os_info = self.host_os.get(r["host"])
        if os_info:
            self._write(box, f"\nOS guess: {os_info['guess']} "
                             f"(confidence: {os_info['confidence']})\n")
            for line in os_info["evidence"]:
                self._write(box, f"  - {line}\n")
        if r.get("cves"):
            self._write(box, f"\n{r['cve_total']} known CVE(s). Most severe "
                             f"(click to open on NVD):\n")
            for c in r["cves"]:
                box.configure(state="normal")
                box.insert("end", f"  {c['id']}", ("link", c["url"]))
                box.insert("end", f"  {c['score']} {c['severity']}\n    {c['summary']}\n")
                box.configure(state="disabled")
        self.tabs.select(1)

    def _open_link(self, event):
        index = self.details_box.index(f"@{event.x},{event.y}")
        for tag in self.details_box.tag_names(index):
            if tag.startswith("http"):
                webbrowser.open(tag)

    @staticmethod
    def _write(box, text, clear=False):
        box.configure(state="normal")
        if clear:
            box.delete("1.0", "end")
        box.insert("end", text)
        box.see("end")
        box.configure(state="disabled")

    # ------------------------------------------------- save / compare ----

    def save(self):
        if not self.report:
            messagebox.showinfo("Nothing to save", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if path:
            save_report(self.report, path)
            self.status.set(f"Report saved to {os.path.basename(path)}")

    def compare(self):
        start_dir = HISTORY_DIR if os.path.isdir(HISTORY_DIR) else os.getcwd()
        old_path = filedialog.askopenfilename(
            title="Choose the EARLIER scan report", initialdir=start_dir,
            filetypes=[("JSON report", "*.json")])
        if not old_path:
            return
        new = self.report
        if new is None:
            new_path = filedialog.askopenfilename(
                title="Choose the NEWER scan report", initialdir=start_dir,
                filetypes=[("JSON report", "*.json")])
            if not new_path:
                return
            new = load_report(new_path)
        try:
            text = format_diff(compare_reports(load_report(old_path), new))
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
            messagebox.showerror("Compare failed", f"Not a valid scan report: {e}")
            return
        window = tk.Toplevel(self)
        window.title("Scan comparison")
        box = tk.Text(window, wrap="word", width=100, height=20, font=("Menlo", 11))
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=10, pady=10)


if __name__ == "__main__":
    PortScannerApp().mainloop()
