"""
IP Geolocation Intelligence — live lookup via ip-api.com + offline fallback.
"""
import tkinter as tk
from tkinter import filedialog, messagebox
import re, os, threading, urllib.request, json
from modules.gui_theme import (COLORS, heading, label, btn, entry,
                                scrolled_tree, separator, card_frame)

# ── Offline fallback DB (well-known IPs) ─────────────────────────────────────
IP_DB = {
    "185.220.101.9":  {"country":"Netherlands","city":"Amsterdam","isp":"Tor Project",   "threat":"Known Tor Exit Node",  "risk":"CRITICAL"},
    "104.21.5.9":     {"country":"Germany",    "city":"Frankfurt","isp":"Cloudflare",     "threat":"Suspicious Hosting",   "risk":"HIGH"},
    "45.142.212.100": {"country":"Russia",     "city":"Moscow",   "isp":"BV-Networks",   "threat":"C2 Infrastructure",    "risk":"CRITICAL"},
    "192.168.4.87":   {"country":"LAN",        "city":"Private",  "isp":"Private",       "threat":"Attacker Origin (LAN)","risk":"HIGH"},
    "10.0.0.1":       {"country":"LAN",        "city":"Private",  "isp":"Private",       "threat":"Target Host",          "risk":"MEDIUM"},
    "8.8.8.8":        {"country":"United States","city":"Mountain View","isp":"Google LLC","threat":"None (Google DNS)",  "risk":"CLEAN"},
    "1.1.1.1":        {"country":"Australia",  "city":"Sydney",   "isp":"Cloudflare",    "threat":"None (Cloudflare DNS)","risk":"CLEAN"},
}
RISK_COLORS = {
    "CRITICAL": COLORS["red"],  "HIGH":    COLORS["amber"],
    "MEDIUM":   COLORS["purple"],"CLEAN":  COLORS["green"],
    "UNKNOWN":  COLORS["txt2"],
}

THREAT_KEYWORDS = {
    "tor":        ("Tor / Anonymization Network", "CRITICAL"),
    "vpn":        ("VPN Provider",                "HIGH"),
    "proxy":      ("Proxy Service",               "HIGH"),
    "hosting":    ("Hosting / Data Center",        "MEDIUM"),
    "digitalocean":("DigitalOcean Hosting",        "HIGH"),
    "linode":     ("Linode Cloud Hosting",         "HIGH"),
    "vultr":      ("Vultr Hosting",               "HIGH"),
    "ovh":        ("OVH Cloud Hosting",           "MEDIUM"),
    "hetzner":    ("Hetzner Hosting",             "MEDIUM"),
}

def _classify_threat(data: dict) -> tuple:
    """Assign risk based on live API data."""
    isp    = (data.get("isp","") + " " + data.get("org","") + " " + data.get("as","")).lower()
    is_prv = data.get("privacy", {})

    # ip-api returns these directly in some plans; use ISP heuristic otherwise
    for kw, (threat, risk) in THREAT_KEYWORDS.items():
        if kw in isp:
            return threat, risk

    # Private / RFC1918
    ip = data.get("query","")
    if ip.startswith(("192.168.","10.","172.16.","172.17.","172.18.",
                       "172.19.","172.2","172.30.","172.31.","127.")):
        return "Private / LAN Address", "MEDIUM"

    return "No known threat", "CLEAN"


def live_lookup(ip: str) -> dict:
    """
    Query ip-api.com (free, no key required, 45 req/min).
    Returns a unified dict matching our IP_DB format.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") != "success":
            return None
        threat, risk = _classify_threat(data)
        # Override with our known-bad list
        if ip in IP_DB:
            threat = IP_DB[ip]["threat"]
            risk   = IP_DB[ip]["risk"]
        return {
            "country":  data.get("country","Unknown"),
            "region":   data.get("regionName",""),
            "city":     data.get("city","Unknown"),
            "zip":      data.get("zip",""),
            "lat":      data.get("lat",""),
            "lon":      data.get("lon",""),
            "isp":      data.get("isp","Unknown"),
            "org":      data.get("org",""),
            "as":       data.get("as",""),
            "threat":   threat,
            "risk":     risk,
            "source":   "LIVE (ip-api.com)",
        }
    except Exception as e:
        return {"error": str(e)}


class IPGeoTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody   = custody
        self._lookup_in_progress = False
        self._build()

    def _build(self):
        heading(self, "IP Geolocation Intelligence").pack(anchor="w", padx=16, pady=(14,4))
        label(self,
              "Enter any IP address for a LIVE lookup (ip-api.com).  "
              "Works for any real public IP — no API key needed.",
              small=True).pack(anchor="w", padx=16)

        # ── Single live lookup card ───────────────────────────────────────
        cf = card_frame(self)
        cf.pack(fill="x", padx=16, pady=(10,4))

        tk.Label(cf, text="LIVE IP LOOKUP", bg=COLORS["bg2"], fg=COLORS["txt3"],
                 font=("Consolas",8)).pack(anchor="w", padx=10, pady=(8,2))

        row = tk.Frame(cf, bg=COLORS["bg2"])
        row.pack(fill="x", padx=10, pady=(0,6))

        self.ip_entry = entry(row, width=26, placeholder="Enter any IP e.g. 8.8.8.8")
        self.ip_entry.pack(side="left", padx=(0,8))
        self.ip_entry.bind("<Return>", lambda _: self._do_lookup())

        self.lookup_btn = btn(row, "Lookup Live", self._do_lookup, color=COLORS["green"])
        self.lookup_btn.pack(side="left", padx=4)
        btn(row, "My Public IP", self._lookup_self, color=COLORS["accent"]).pack(side="left", padx=4)
        btn(row, "Clear", self._clear_result, color=COLORS["txt2"]).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="")
        tk.Label(cf, textvariable=self.status_var, bg=COLORS["bg2"],
                 fg=COLORS["amber"], font=("Consolas",9)).pack(anchor="w", padx=10, pady=2)

        self.result_frame = tk.Frame(cf, bg=COLORS["bg2"])
        self.result_frame.pack(fill="x", padx=10, pady=(0,10))

        # ── History of lookups ────────────────────────────────────────────
        separator(self).pack(fill="x", padx=16, pady=8)

        hrow = tk.Frame(self, bg=COLORS["bg"])
        hrow.pack(fill="x", padx=16, pady=2)
        tk.Label(hrow, text="LOOKUP HISTORY", bg=COLORS["bg"], fg=COLORS["txt3"],
                 font=("Consolas",8)).pack(side="left")
        btn(hrow, "Clear History", self._clear_hist, color=COLORS["red"]).pack(side="right")

        h_cols  = ("ip","country","city","isp","threat","risk","source")
        h_heads = ("IP Address","Country","City","ISP","Threat","Risk","Source")
        hf, self.hist_tree = scrolled_tree(self, h_cols, h_heads, heights=6)
        self.hist_tree.column("ip",      width=120)
        self.hist_tree.column("country", width=110)
        self.hist_tree.column("city",    width=100)
        self.hist_tree.column("isp",     width=170)
        self.hist_tree.column("threat",  width=195)
        self.hist_tree.column("risk",    width=80)
        self.hist_tree.column("source",  width=120)
        hf.pack(fill="x", padx=16, pady=(4,6))

        # ── Batch from log ────────────────────────────────────────────────
        separator(self).pack(fill="x", padx=16, pady=6)

        bf = card_frame(self)
        bf.pack(fill="both", expand=True, padx=16, pady=(0,12))

        brow = tk.Frame(bf, bg=COLORS["bg2"])
        brow.pack(fill="x", padx=10, pady=8)
        tk.Label(brow, text="BATCH IP FREQUENCY FROM LOG FILE",
                 bg=COLORS["bg2"], fg=COLORS["txt3"], font=("Consolas",8)).pack(side="left")
        btn(brow, "Upload Log File", self._upload_log,  color=COLORS["accent"]).pack(side="right")
        btn(brow, "Load Demo",       self._load_demo,   color=COLORS["txt2"]).pack(side="right", padx=4)

        b_cols  = ("ip","count","country","isp","threat","risk")
        b_heads = ("IP Address","Count","Country","ISP","Threat","Risk")
        tf, self.batch_tree = scrolled_tree(bf, b_cols, b_heads, heights=10)
        self.batch_tree.column("ip",      width=130)
        self.batch_tree.column("count",   width=60)
        self.batch_tree.column("country", width=130)
        self.batch_tree.column("isp",     width=160)
        self.batch_tree.column("threat",  width=200)
        self.batch_tree.column("risk",    width=90)
        tf.pack(fill="both", expand=True, padx=10, pady=(0,10))

    # ── Handlers ─────────────────────────────────────────────────────────────
    def _do_lookup(self):
        ip = self.ip_entry.get().strip()
        if not ip or ip.startswith("Enter"):
            messagebox.showwarning("Input", "Please enter an IP address first.")
            return
        # Basic format check
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            messagebox.showwarning("Invalid", f"'{ip}' does not look like a valid IPv4 address.")
            return
        if self._lookup_in_progress:
            return
        self._start_lookup(ip)

    def _lookup_self(self):
        """Resolve caller's own public IP via ip-api.com."""
        if self._lookup_in_progress:
            return
        self._start_lookup("")  # empty = caller's IP

    def _start_lookup(self, ip: str):
        self._lookup_in_progress = True
        self.lookup_btn.config(state="disabled")
        self.status_var.set("⏳  Querying ip-api.com …")
        for w in self.result_frame.winfo_children():
            w.destroy()

        def worker():
            result = live_lookup(ip)
            self.after(0, lambda: self._show_result(ip, result))

        threading.Thread(target=worker, daemon=True).start()

    def _show_result(self, ip: str, data: dict):
        self._lookup_in_progress = False
        self.lookup_btn.config(state="normal")

        if data is None or "error" in data:
            err = (data or {}).get("error","No response from server")
            self.status_var.set(f"⚠  Error: {err}")
            # Fall back to offline DB
            data = IP_DB.get(ip, {"country":"Unknown","city":"Unknown",
                                   "isp":"Unknown","threat":"Lookup failed","risk":"UNKNOWN"})
            data["source"] = "OFFLINE (no internet)"

        resolved_ip = self.ip_entry.get().strip() if ip else "Your Public IP"
        self.status_var.set(f"✔  Lookup complete — {data.get('source','live')}")

        color = RISK_COLORS.get(data.get("risk","UNKNOWN"), COLORS["txt2"])

        for w in self.result_frame.winfo_children():
            w.destroy()

        fields = [
            ("IP Address",   resolved_ip,                       COLORS["accent"]),
            ("Risk Level",   data.get("risk","UNKNOWN"),        color),
            ("Country",      data.get("country","Unknown"),     COLORS["txt"]),
            ("Region",       data.get("region",""),             COLORS["txt"]),
            ("City",         data.get("city","Unknown"),        COLORS["txt"]),
            ("ZIP / Post",   data.get("zip",""),                COLORS["txt2"]),
            ("ISP",          data.get("isp","Unknown"),         COLORS["txt"]),
            ("Organisation", data.get("org",""),                COLORS["txt"]),
            ("ASN",          data.get("as",""),                 COLORS["txt2"]),
            ("Coordinates",  f"{data.get('lat','')}°, {data.get('lon','')}°", COLORS["txt2"]),
            ("Threat Intel", data.get("threat","—"),            color),
            ("Data Source",  data.get("source",""),             COLORS["txt3"]),
        ]
        for k, v, vc in fields:
            if not v:
                continue
            r = tk.Frame(self.result_frame, bg=COLORS["bg2"])
            r.pack(fill="x", pady=1)
            tk.Label(r, text=f"{k}:", bg=COLORS["bg2"], fg=COLORS["txt3"],
                     font=("Consolas",9), width=16, anchor="w").pack(side="left")
            tk.Label(r, text=str(v), bg=COLORS["bg2"], fg=vc,
                     font=("Consolas",10,"bold"), anchor="w").pack(side="left")

        # Add to history
        actual_ip = resolved_ip
        self.hist_tree.insert("","0",
            values=(actual_ip,
                    data.get("country","?"),
                    data.get("city","?"),
                    data.get("isp","?")[:30],
                    data.get("threat","?"),
                    data.get("risk","?"),
                    data.get("source","?")),
            tags=(data.get("risk",""),))
        self.custody.log("IP_LOOKUP", actual_ip,
                         f"Risk={data.get('risk')} ISP={data.get('isp','')} Source={data.get('source','')}")

    def _clear_result(self):
        for w in self.result_frame.winfo_children():
            w.destroy()
        self.status_var.set("")
        self.ip_entry.delete(0,"end")

    def _clear_hist(self):
        self.hist_tree.delete(*self.hist_tree.get_children())

    # ── Batch ─────────────────────────────────────────────────────────────────
    def _upload_log(self):
        path = filedialog.askopenfilename(
            filetypes=[("Log files","*.log *.txt *.csv"),("All","*.*")])
        if not path:
            return
        with open(path,"r",errors="ignore") as f:
            text = f.read()
        self._analyze_ips(text, os.path.basename(path))

    def _analyze_ips(self, text, source="input"):
        from collections import Counter
        ips  = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
        freq = Counter(ips)
        self.batch_tree.delete(*self.batch_tree.get_children())
        for ip, count in freq.most_common(50):
            d   = IP_DB.get(ip, {"country":"Unknown","isp":"Unknown","threat":"—","risk":"UNKNOWN"})
            tag = d["risk"] if d["risk"] in ("CRITICAL","HIGH") else ""
            self.batch_tree.insert("","end",
                values=(ip, count, d["country"], d["isp"], d["threat"], d["risk"]),
                tags=(tag,))
        self.custody.log("IP_BATCH", source, f"{len(freq)} unique IPs")

    def _load_demo(self):
        self._analyze_ips(
            "192.168.4.87 185.220.101.9 185.220.101.9 185.220.101.9 "
            "45.142.212.100 104.21.5.9 8.8.8.8 192.168.4.87 192.168.4.87",
            "demo_log.txt")
