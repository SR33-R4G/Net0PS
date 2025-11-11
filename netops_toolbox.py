#!/usr/bin/env python3
"""
NetOps Toolbox — Attractive GUI Edition (Full) with Speedtest

• Cross‑platform (Linux / Windows / macOS) — Python 3.8+
• Modern Tk/ttk UI: toolbar, light/dark theme toggle, status bar, toasts
• Background command execution (no UI freezes)
• Tabs: Connectivity, DNS, Host Info, HTTP, Ports, Wi‑Fi/LAN, Speedtest, Misc

Licensed to Sreerag M S — Owner & Author. All rights reserved.
"""

import os
import sys
import socket
import subprocess
import threading
import queue
import shutil
import time
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception:
    print("Tkinter is required to run this app.")
    raise

# -------------------- Platform/Config --------------------
IS_WINDOWS = os.name == "nt"
DEFAULT_TIMEOUT = 10
APP_TITLE = "NetOps Toolbox"

TOP_COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139,
    143, 161, 179, 389, 443, 445, 465, 514, 563, 587, 631, 993, 995,
    1080, 1194, 1433, 1521, 2049, 2083, 2375, 2376, 2483, 2484, 3000,
    3128, 3306, 3389, 3478, 3690, 4000, 4100, 4369, 4444, 4567, 4657,
    5000, 5001, 5060, 5061, 5432, 5631, 5672, 5900, 5985, 5986, 6379,
    6443, 7001, 7002, 7077, 7199, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9042, 9092, 9200, 9300, 9418, 10000
]

# -------------------- Utilities --------------------

def which(cmd: str):
    return shutil.which(cmd)

def nowstamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_cmd(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> str:
    start = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        out = proc.stdout or ""
        err = proc.stderr or ""
        rc = proc.returncode
        dur = time.time() - start
        header = f"$ {' '.join(cmd)}\n(exit {rc}, {dur:.2f}s)\n"
        body = out if out.strip() else err
        return header + body
    except subprocess.TimeoutExpired:
        return f"$ {' '.join(cmd)}\n[TIMEOUT after {timeout}s]\n"

# -------------------- Networking Actions --------------------

def do_ping(host: str, count: int = 4, timeout: int = DEFAULT_TIMEOUT) -> str:
    if not host:
        return "[PING] Please enter a target host/IP.\n"
    if IS_WINDOWS:
        cmd = ["ping", host, "-n", str(count)]
    else:
        cmd = ["ping", "-c", str(count), "-i", "0.3", host]
    return run_cmd(cmd, timeout=max(timeout, count + 2))

def do_traceroute(host: str, max_hops: int = 30, timeout: int = 30) -> str:
    if not host:
        return "[TRACEROUTE] Please enter a target host/IP.\n"
    tracer = "tracert" if IS_WINDOWS else ("traceroute" if which("traceroute") else "tracepath")
    if tracer == "tracert":
        cmd = ["tracert", "-d", "-h", str(max_hops), host]
    elif tracer == "traceroute":
        cmd = ["traceroute", "-n", "-m", str(max_hops), host]
    else:
        cmd = ["tracepath", "-n", host]
    return run_cmd(cmd, timeout=timeout)

def do_dns_lookup(name: str, record: str = "A", timeout: int = DEFAULT_TIMEOUT) -> str:
    if not name:
        return "[DNS] Please enter a domain.\n"
    if which("dig"):
        cmd = ["dig", "+short", name, record]
    else:
        cmd = ["nslookup", "-type=" + record, name]
    return run_cmd(cmd, timeout=timeout)

def do_reverse_dns(ip: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    if not ip:
        return "[rDNS] Please enter an IP.\n"
    if which("dig"):
        cmd = ["dig", "+short", "-x", ip]
    else:
        cmd = ["nslookup", ip]
    return run_cmd(cmd, timeout=timeout)

def do_if_addrs(timeout: int = DEFAULT_TIMEOUT) -> str:
    if IS_WINDOWS:
        cmd = ["ipconfig", "/all"]
    else:
        cmd = ["ip", "addr"] if which("ip") else ["ifconfig", "-a"]
    return run_cmd(cmd, timeout=timeout)

def do_default_route(timeout: int = DEFAULT_TIMEOUT) -> str:
    if IS_WINDOWS:
        cmd = ["route", "print", "0.0.0.0"]
    else:
        cmd = ["ip", "route", "show", "default"] if which("ip") else ["route", "-n"]
    return run_cmd(cmd, timeout=timeout)

def do_arp_table(timeout: int = DEFAULT_TIMEOUT) -> str:
    if IS_WINDOWS:
        cmd = ["arp", "-a"]
    else:
        cmd = ["ip", "neigh", "show"] if which("ip") else ["arp", "-an"]
    return run_cmd(cmd, timeout=timeout)

def do_wifi_info(timeout: int = DEFAULT_TIMEOUT) -> str:
    if IS_WINDOWS:
        cmd = ["netsh", "wlan", "show", "interfaces"]
        return run_cmd(cmd, timeout=timeout)
    if which("nmcli"):
        out = run_cmd(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY", "dev", "wifi"], timeout=timeout)
        current = run_cmd(["nmcli", "-t", "-f", "GENERAL.STATE,GENERAL.CONNECTION", "-m", "multiline", "device", "show"], timeout=timeout)
        return out + "\n---\n" + current
    if which("iwconfig"):
        return run_cmd(["iwconfig"], timeout=timeout)
    return "Wi‑Fi info: no nmcli/iwconfig found.\n"

def do_http_head(url: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    if not url:
        return "[HTTP] Enter a URL (e.g., https://example.com).\n"
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if which("curl"):
        cmd = ["curl", "-I", "--max-time", str(timeout), url]
        return run_cmd(cmd, timeout=timeout + 2)
    try:
        import requests
    except Exception:
        return "Install curl or Python 'requests' for HTTP HEAD.\n"
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        return f"HTTP/1.x {resp.status_code}\n{headers}\n"
    except Exception as e:
        return f"[HTTP ERROR] {e}\n"

def do_public_ip(timeout: int = DEFAULT_TIMEOUT) -> str:
    for svc in ("https://ifconfig.me", "https://ipinfo.io/ip", "https://api.ipify.org"):
        if which("curl"):
            out = run_cmd(["curl", "-sS", "--max-time", str(timeout), svc], timeout=timeout)
            text = out.split("\n", 1)[-1].strip()
            if text and "ERROR" not in text and "TIMEOUT" not in text:
                return f"Public IP: {text}\n"
    try:
        import requests
        r = requests.get("https://api.ipify.org", timeout=timeout)
        return f"Public IP: {r.text.strip()}\n"
    except Exception:
        return "Could not determine public IP (need curl or requests).\n"

def do_port_check(host: str, port: int, timeout: int = 2) -> str:
    if not host:
        return "[PORT] Please enter a target host/IP.\n"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return f"TCP {host}:{port} is OPEN (≤{timeout}s).\n"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return f"TCP {host}:{port} appears CLOSED/filtered ({e}).\n"

def do_port_scan(host: str, ports: list[int] | None = None, timeout_per_port: float = 0.5) -> str:
    if not host:
        return "[SCAN] Enter a target host/IP.\n"
    ports = ports or TOP_COMMON_PORTS
    open_ports = []
    start = time.time()
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout_per_port):
                open_ports.append(p)
        except Exception:
            pass
    dur = time.time() - start
    if open_ports:
        return f"Open ports on {host}: {open_ports} (scanned {len(ports)} ports in {dur:.1f}s)\n"
    return f"No open common ports found on {host} (scanned {len(ports)} ports in {dur:.1f}s).\n"

def do_speedtest() -> str:
    # Prefer Ookla speedtest if available, otherwise speedtest-cli
    if which("speedtest"):
        # simple text output; users can install Ookla CLI from speedtest.net
        return run_cmd(["speedtest", "--simple"], timeout=180)
    if which("speedtest-cli"):
        return run_cmd(["speedtest-cli", "--simple"], timeout=180)
    return "Speedtest not found. Install with: sudo apt install speedtest-cli\n"

# -------------------- Theming --------------------

LIGHT = {
    "bg": "#f5f7fb",
    "card": "#ffffff",
    "fg": "#111827",
    "muted": "#6b7280",
    "accent": "#2563eb",
    "accent_fg": "#ffffff",
    "border": "#e5e7eb",
    "console_bg": "#0b1220",
    "console_fg": "#e5e7eb",
}

DARK = {
    "bg": "#0b1220",
    "card": "#101826",
    "fg": "#e5e7eb",
    "muted": "#9ca3af",
    "accent": "#60a5fa",
    "accent_fg": "#0b1220",
    "border": "#1f2937",
    "console_bg": "#0b1220",
    "console_fg": "#e5e7eb",
}

class Theme:
    def __init__(self, root: tk.Tk, palette: dict):
        self.root = root
        self.palette = palette
        self.apply()

    def apply(self):
        p = self.palette
        style = ttk.Style(self.root)
        base = "clam" if "clam" in style.theme_names() else style.theme_use()
        style.theme_use(base)
        self.root.configure(bg=p["bg"])
        style.configure("TFrame", background=p["bg"])
        style.configure("Card.TFrame", background=p["card"], relief="flat")
        style.configure("TLabel", background=p["bg"], foreground=p["fg"])
        style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"])
        style.configure("Title.TLabel", background=p["bg"], foreground=p["fg"], font=("Segoe UI", 14, "bold"))
        style.configure("TButton", padding=8)
        style.configure("Accent.TButton", padding=8, background=p["accent"], foreground=p["accent_fg"])
        style.map("Accent.TButton", background=[("active", p["accent"])])
        style.configure("Toolbar.TFrame", background=p["card"])
        style.configure("Status.TFrame", background=p["card"])
        style.configure("Divider.TFrame", background=p["border"])
        style.configure("TNotebook", background=p["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 6), background=p["card"], foreground=p["fg"])
        style.map("TNotebook.Tab", background=[("selected", p["bg"])])
        style.configure("TEntry", fieldbackground=p["card"], foreground=p["fg"], padding=6)
        style.configure("TCombobox", fieldbackground=p["card"], foreground=p["fg"], padding=6)
        # Text defaults (console)
        self.root.option_add("*Text.background", p["console_bg"])
        self.root.option_add("*Text.foreground", p["console_fg"])
        self.root.option_add("*Text.font", "Consolas 10" if IS_WINDOWS else "Monospace 10")
        self.root.option_add("*Text.highlightThickness", 0)

# -------------------- Worker --------------------

class Worker:
    def __init__(self, output_callback, busy_setter):
        self.q = queue.Queue()
        self.output_callback = output_callback
        self.busy_setter = busy_setter
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def run(self, fn, *args, **kwargs):
        self.q.put((fn, args, kwargs))

    def _loop(self):
        while True:
            fn, args, kwargs = self.q.get()
            try:
                self.busy_setter(True)
                result = fn(*args, **kwargs)
            except Exception as e:
                result = f"[ERROR] {e}"
            finally:
                self.busy_setter(False)
            if result is not None:
                self.output_callback(result)
            self.q.task_done()

# -------------------- GUI --------------------

class NetOpsApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1120x760")
        self.minsize(980, 640)

        # Theme state
        self.theme_name = tk.StringVar(value="dark")
        self.theme = Theme(self, DARK if self.theme_name.get()=="dark" else LIGHT)

        # Status
        self.is_busy = tk.BooleanVar(value=False)

        # Worker
        self.worker = Worker(self.append_output, self._set_busy)

        # Menu
        self._build_menubar()

        # Toolbar
        self._build_toolbar()

        # Body with panes
        self._build_body()

        # Status bar
        self._build_statusbar()

        # Shortcuts
        self.bind_all("<Control-s>", lambda e: self.save_output())
        self.bind_all("<Control-S>", lambda e: self.save_output())
        self.bind_all("<Control-l>", lambda e: self.clear_output())
        self.bind_all("<Control-L>", lambda e: self.clear_output())
        self.bind_all("<Control-t>", lambda e: self.toggle_theme())
        self.bind_all("<F5>", lambda e: self.worker.run(self._ping))
        self.bind_all("<F6>", lambda e: self.worker.run(self._traceroute))

    # ---------- Menus ----------
    def _build_menubar(self):
        mb = tk.Menu(self)
        filem = tk.Menu(mb, tearoff=False)
        filem.add_command(label="Save Output", accelerator="Ctrl+S", command=self.save_output)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.destroy)
        mb.add_cascade(label="File", menu=filem)

        viewm = tk.Menu(mb, tearoff=False)
        viewm.add_command(label="Toggle Theme", accelerator="Ctrl+T", command=self.toggle_theme)
        mb.add_cascade(label="View", menu=viewm)

        helpm = tk.Menu(mb, tearoff=False)
        helpm.add_command(label="About", command=self._about)
        mb.add_cascade(label="Help", menu=helpm)
        self.config(menu=mb)

    # ---------- Toolbar ----------
    def _build_toolbar(self):
        bar = ttk.Frame(self, style="Toolbar.TFrame")
        bar.pack(fill=tk.X, padx=10, pady=(10, 6))

        ttk.Label(bar, text="Target:").pack(side=tk.LEFT)
        self.target_var = tk.StringVar()
        tgt = ttk.Entry(bar, textvariable=self.target_var, width=44)
        tgt.pack(side=tk.LEFT, padx=(6, 12))

        ttk.Label(bar, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.IntVar(value=80)
        ttk.Entry(bar, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=(6, 12))

        btn = ttk.Button
        btn(bar, text="🔍 Ping", command=lambda: self.worker.run(self._ping)).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🧭 Trace", command=lambda: self.worker.run(self._traceroute)).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🌍 Public IP", command=lambda: self.worker.run(do_public_ip)).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🧾 HEAD", command=lambda: self.worker.run(self._http_head)).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🔓 Port", command=lambda: self.worker.run(self._port_check)).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🧰 Scan", command=lambda: self.worker.run(self._port_scan_quick)).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🚀 Speedtest", command=lambda: self.worker.run(do_speedtest)).pack(side=tk.LEFT, padx=3)

        ttk.Frame(bar).pack(side=tk.LEFT, expand=True)

        btn(bar, text="💾 Save", command=self.save_output).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🧹 Clear", command=self.clear_output).pack(side=tk.LEFT, padx=3)
        btn(bar, text="🌓 Theme", command=self.toggle_theme).pack(side=tk.LEFT, padx=3)

    # ---------- Body ----------
    def _build_body(self):
        paned = ttk.Panedwindow(self, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))

        top = ttk.Frame(paned)
        bottom = ttk.Frame(paned)
        paned.add(top, weight=3)
        paned.add(bottom, weight=2)

        card = ttk.Frame(top, style="Card.TFrame")
        card.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        nb = ttk.Notebook(card)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.nb = nb

        nb.add(self._tab_connectivity(nb), text="Connectivity")
        nb.add(self._tab_dns(nb), text="DNS")
        nb.add(self._tab_host(nb), text="Host Info")
        nb.add(self._tab_http(nb), text="HTTP")
        nb.add(self._tab_ports(nb), text="Ports")
        nb.add(self._tab_wifi(nb), text="Wi‑Fi / LAN")
        nb.add(self._tab_speedtest(nb), text="Speedtest")
        nb.add(self._tab_misc(nb), text="Misc")

        outcard = ttk.Frame(bottom, style="Card.TFrame")
        outcard.pack(fill=tk.BOTH, expand=True)

        head = ttk.Frame(outcard, style="Card.TFrame")
        head.pack(fill=tk.X, padx=10, pady=(10, 6))
        ttk.Label(head, text="Output", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(head, text="(double‑click to copy all)", style="Muted.TLabel").pack(side=tk.LEFT, padx=10)

        sc = ttk.Scrollbar(outcard)
        self.output = tk.Text(outcard, height=12, wrap="word", undo=True, yscrollcommand=sc.set)
        sc.config(command=self.output.yview)
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=(0, 10))
        sc.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=(0, 10))

        self.output.bind("<Double-Button-1>", lambda e: self._copy_all())

    # ---------- Tabs ----------
    def _tab_connectivity(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="Quick connectivity tests", style="Muted.TLabel").pack(anchor=tk.W, pady=8, padx=8)
        grid = ttk.Frame(f)
        grid.pack(anchor=tk.W, padx=8, pady=2)
        ttk.Button(grid, text="Ping x4", command=lambda: self.worker.run(self._ping)).grid(row=0, column=0, padx=4, pady=4)
        ttk.Button(grid, text="Traceroute", command=lambda: self.worker.run(self._traceroute)).grid(row=0, column=1, padx=4, pady=4)
        ttk.Button(grid, text="Default Route", command=lambda: self.worker.run(do_default_route)).grid(row=0, column=2, padx=4, pady=4)
        ttk.Button(grid, text="ARP Table", command=lambda: self.worker.run(do_arp_table)).grid(row=0, column=3, padx=4, pady=4)
        ttk.Button(grid, text="Public IP", command=lambda: self.worker.run(do_public_ip)).grid(row=0, column=4, padx=4, pady=4)
        return f

    def _tab_dns(self, parent):
        f = ttk.Frame(parent)
        row = 0
        ttk.Label(f, text="DNS tools", style="Muted.TLabel").grid(row=row, column=0, sticky=tk.W, pady=8, padx=8)
        row += 1
        ttk.Label(f, text="Record:").grid(row=row, column=0, sticky=tk.W, padx=8)
        self.record_var = tk.StringVar(value="A")
        ttk.Combobox(f, textvariable=self.record_var, values=["A","AAAA","CNAME","MX","NS","TXT","SOA"], width=7, state="readonly").grid(row=row, column=1, sticky=tk.W)
        ttk.Button(f, text="Lookup", command=lambda: self.worker.run(self._dns_lookup)).grid(row=row, column=2, padx=6)
        row += 1
        ttk.Label(f, text="Reverse DNS (enter IP in Target)").grid(row=row, column=0, sticky=tk.W, padx=8, pady=(10,0))
        ttk.Button(f, text="Reverse Lookup", command=lambda: self.worker.run(self._reverse_dns)).grid(row=row, column=2, padx=6, pady=(10,0))
        for i in range(3):
            f.columnconfigure(i, weight=0)
        return f

    def _tab_host(self, parent):
        f = ttk.Frame(parent)
        ttk.Button(f, text="IP Addresses", command=lambda: self.worker.run(do_if_addrs)).grid(row=0, column=0, padx=8, pady=8)
        ttk.Button(f, text="Default Route", command=lambda: self.worker.run(do_default_route)).grid(row=0, column=1, padx=8, pady=8)
        ttk.Button(f, text="ARP Table", command=lambda: self.worker.run(do_arp_table)).grid(row=0, column=2, padx=8, pady=8)
        for i in range(3):
            f.columnconfigure(i, weight=0)
        return f

    def _tab_http(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="HTTP utilities for the target URL", style="Muted.TLabel").grid(row=0, column=0, sticky=tk.W, pady=8, padx=8)
        ttk.Button(f, text="HEAD Request", command=lambda: self.worker.run(self._http_head)).grid(row=0, column=1, padx=8)
        return f

    def _tab_ports(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="Port tools for the target host", style="Muted.TLabel").grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=8, padx=8)
        ttk.Button(f, text="Check Single Port", command=lambda: self.worker.run(self._port_check)).grid(row=1, column=0, padx=8, pady=6)
        ttk.Button(f, text="Quick Scan (100 common)", command=lambda: self.worker.run(self._port_scan_quick)).grid(row=1, column=1, padx=8, pady=6)
        ttk.Button(f, text="Custom Scan…", command=self._custom_scan_dialog).grid(row=1, column=2, padx=8, pady=6)
        return f

    def _tab_wifi(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="Wi‑Fi / LAN info", style="Muted.TLabel").grid(row=0, column=0, sticky=tk.W, pady=8, padx=8)
        ttk.Button(f, text="Wi‑Fi Details", command=lambda: self.worker.run(do_wifi_info)).grid(row=0, column=1, padx=8)
        ttk.Button(f, text="ARP Table", command=lambda: self.worker.run(do_arp_table)).grid(row=0, column=2, padx=8)
        return f

    def _tab_speedtest(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="Run Internet speed test (Ookla CLI / speedtest-cli)", style="Muted.TLabel").pack(anchor=tk.W, pady=8, padx=8)
        ttk.Button(f, text="Run Speedtest", command=lambda: self.worker.run(do_speedtest)).pack(pady=10)
        return f

    def _tab_misc(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="Miscellaneous", style="Muted.TLabel").pack(anchor=tk.W, pady=8, padx=8)
        ttk.Button(f, text="Insert Timestamp", command=lambda: self.append_output(f"\n--- {nowstamp()} ---\n")).pack(anchor=tk.W, padx=8)
        return f

    # ---------- Status bar ----------
    def _build_statusbar(self):
        status = ttk.Frame(self, style="Status.TFrame")
        status.pack(fill=tk.X, padx=10, pady=(0,10))
        self.status_lbl = ttk.Label(status, text="Ready")
        self.status_lbl.pack(side=tk.LEFT)
        ttk.Frame(status).pack(side=tk.LEFT, padx=10)
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=160)
        self.progress.pack(side=tk.RIGHT)

    def _set_busy(self, flag: bool):
        if flag:
            self.status_lbl.config(text="Running…")
            self.progress.start(18)
        else:
            self.status_lbl.config(text=f"Ready — {nowstamp()}")
            self.progress.stop()

    # ---------- Actions bound to worker ----------
    def _ping(self):
        tgt = self.target_var.get().strip()
        return do_ping(tgt)

    def _traceroute(self):
        tgt = self.target_var.get().strip()
        return do_traceroute(tgt)

    def _dns_lookup(self):
        name = self.target_var.get().strip()
        rec = self.record_var.get().strip() or "A"
        return do_dns_lookup(name, rec)

    def _reverse_dns(self):
        ip = self.target_var.get().strip()
        return do_reverse_dns(ip)

    def _http_head(self):
        url = self.target_var.get().strip()
        return do_http_head(url)

    def _port_check(self):
        tgt = self.target_var.get().strip()
        try:
            port = int(self.port_var.get())
        except Exception:
            return "[PORT] Invalid port.\n"
        return do_port_check(tgt, port)

    def _port_scan_quick(self):
        tgt = self.target_var.get().strip()
        return do_port_scan(tgt)

    # ---------- UI helpers ----------
    def append_output(self, text: str):
        self.output.insert(tk.END, text)
        if not text.endswith("\n"):
            self.output.insert(tk.END, "\n")
        self.output.see(tk.END)

    def clear_output(self):
        self.output.delete("1.0", tk.END)
        self.toast("Cleared output")

    def save_output(self):
        data = self.output.get("1.0", tk.END)
        if not data.strip():
            self.toast("Nothing to save")
            return
        default_name = f"netops_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = filedialog.asksaveasfilename(
            title="Save Output",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text", "*.txt"), ("All Files", "*.*")],
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(data)
                self.toast(f"Saved to {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _copy_all(self):
        data = self.output.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(data)
        self.toast("Output copied to clipboard")

    def toggle_theme(self):
        name = self.theme_name.get()
        self.theme_name.set("light" if name=="dark" else "dark")
        self.theme = Theme(self, DARK if self.theme_name.get()=="dark" else LIGHT)
        self.toast(f"Theme: {self.theme_name.get().title()}")

    def toast(self, msg: str, ms: int = 1500):
        tw = tk.Toplevel(self)
        tw.overrideredirect(True)
        tw.attributes("-topmost", True)
        frm = ttk.Frame(tw, style="Card.TFrame")
        ttk.Label(frm, text=msg).pack(padx=14, pady=10)
        frm.pack()
        self.update_idletasks()
        x = self.winfo_rootx() + self.winfo_width() - tw.winfo_reqwidth() - 24
        y = self.winfo_rooty() + self.winfo_height() - tw.winfo_reqheight() - 24
        tw.geometry(f"+{x}+{y}")
        tw.after(ms, tw.destroy)

    def _custom_scan_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Custom Port Scan")
        dlg.geometry("380x190")
        ttk.Label(dlg, text="Ports (e.g., 22,80,443 or 1-1024)").pack(anchor=tk.W, padx=12, pady=(12,4))
        ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(dlg, textvariable=ports_var).pack(fill=tk.X, padx=12)

        ttk.Label(dlg, text="Per-port timeout (seconds)").pack(anchor=tk.W, padx=12, pady=(10,4))
        tmo_var = tk.DoubleVar(value=0.3)
        ttk.Entry(dlg, textvariable=tmo_var, width=10).pack(anchor=tk.W, padx=12)

        def parse_ports(text: str) -> list[int]:
            result: list[int] = []
            for part in text.split(','):
                part = part.strip()
                if not part:
                    continue
                if '-' in part:
                    a, b = part.split('-', 1)
                    try:
                        start = int(a); end = int(b)
                        if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                            result.extend(range(start, end+1))
                    except Exception:
                        pass
                else:
                    try:
                        p = int(part)
                        if 1 <= p <= 65535:
                            result.append(p)
                    except Exception:
                        pass
            return sorted(set(result))

        def go():
            ports = parse_ports(ports_var.get())
            if not ports:
                messagebox.showerror("Ports", "No valid ports parsed.")
                return
            try:
                tmo = float(tmo_var.get())
                tmo = max(0.05, min(5.0, tmo))
            except Exception:
                tmo = 0.3
            tgt = self.target_var.get().strip()
            self.worker.run(lambda: do_port_scan(tgt, ports=ports, timeout_per_port=tmo))
            dlg.destroy()

        row = ttk.Frame(dlg)
        row.pack(pady=12)
        ttk.Button(row, text="Scan", command=go).pack(side=tk.LEFT, padx=6)
        ttk.Button(row, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT, padx=6)

    def _about(self):
        messagebox.showinfo("About", f"{APP_TITLE}\nAttractive GUI Edition (Full)\nLicensed to Sreerag M S — All rights reserved.")

# -------------------- Main --------------------

def main():
    app = NetOpsApp()
    app.mainloop()

if __name__ == "__main__":
    main()
