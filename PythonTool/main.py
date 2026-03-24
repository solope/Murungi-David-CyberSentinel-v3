"""
CyberSentinel v3 — Murungi Unified Digital Forensics & OSINT Platform
Run:  python main.py
Requires: Python 3.8+  (tkinter ships with Python on Windows/macOS)
Optional: pip install pillow reportlab
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.gui_theme      import apply_theme, COLORS
from modules.custody_log    import CustodyLog

# ── Tabs ──────────────────────────────────────────────────────────────────────
from modules.tab_timeline   import TimelineTab
from modules.tab_ipgeo      import IPGeoTab
from modules.tab_cdr        import CDRTab          # improved: manual number entry
from modules.tab_email      import EmailTab
from modules.tab_fileid     import FileIDTab        # improved: universal metadata
from modules.tab_hash       import HashTab          # improved: merged hashgenerator.py
from modules.tab_encoding   import EncodingTab
from modules.tab_keywords   import KeywordsTab
from modules.tab_powershell import PowerShellTab
from modules.tab_network    import NetworkTab       # improved: browser history
from modules.tab_social     import SocialTab
from modules.tab_custody    import CustodyTab
from modules.tab_report     import ReportTab

# ── Removed tabs: Crypto Wallet, Steganography ───────────────────────────────


class CyberSentinel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Murungi CyberSentinel v3 — Murungi Unified Digital Forensics & OSINT Platform")
        self.geometry("1300x840")
        self.minsize(1100, 700)
        apply_theme(self)

        self.custody = CustodyLog()
        self._build_topbar()
        self._build_notebook()
        self._build_statusbar()
        self.after(500, self._tick)

    # ── TOP BAR ──────────────────────────────────────────────────────────────
    def _build_topbar(self):
        bar = tk.Frame(self, bg=COLORS["bg2"], height=50)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        # Accent line at bottom
        line = tk.Frame(bar, bg=COLORS["accent"], height=2)
        line.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        tk.Label(bar, text="Murungi CyberSentinel", bg=COLORS["bg2"],
                 fg=COLORS["accent"], font=("Consolas", 16, "bold")).pack(
                     side="left", padx=(16, 2), pady=12)
        tk.Label(bar, text="v3  |  Murungi Unified Digital Forensics & OSINT",
                 bg=COLORS["bg2"], fg=COLORS["txt2"],
                 font=("Consolas", 9)).pack(side="left", pady=12)

        self.threat_var = tk.StringVar(value="THREAT LEVEL: --")
        tk.Label(bar, textvariable=self.threat_var, bg=COLORS["bg2"],
                 fg=COLORS["red"], font=("Consolas", 10, "bold")).pack(side="right", padx=16)
        self.clock_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self.clock_var, bg=COLORS["bg2"],
                 fg=COLORS["txt3"], font=("Consolas", 9)).pack(side="right", padx=8)

    # ── NOTEBOOK ──────────────────────────────────────────────────────────────
    def _build_notebook(self):
        outer = tk.Frame(self, bg=COLORS["bg"])
        outer.pack(fill="both", expand=True)

        self.nb = ttk.Notebook(outer)
        self.nb.pack(fill="both", expand=True)

        shared = {"custody": self.custody, "root": self}

        def add(label, cls, icon=""):
            frame    = tk.Frame(self.nb, bg=COLORS["bg"])
            instance = cls(frame, **shared)
            instance.pack(fill="both", expand=True)
            self.nb.add(frame, text=f" {icon} {label} ")

        # Dashboard
        add("Dashboard",         DashboardTab,   "⬛")
        # Core
        add("Log Timeline",      TimelineTab,    "📋")
        # OSINT & Identity
        add("IP Geolocation",    IPGeoTab,       "🌐")
        add("CDR Analyzer",      CDRTab,         "📞")
        add("Email Header",      EmailTab,       "✉")
        add("Network + Browser", NetworkTab,     "🕸")
        add("Social Feed",       SocialTab,      "💬")
        # File & Evidence
        add("File ID + Metadata",FileIDTab,      "🔍")
        add("Hash Verifier",     HashTab,        "🔒")
        # Document Intel
        add("Encoding Detect",   EncodingTab,    "🔤")
        add("Keyword Scanner",   KeywordsTab,    "🔎")
        add("PowerShell",        PowerShellTab,  "⚡")
        # Output
        add("Custody Log",       CustodyTab,     "📑")
        add("Report",            ReportTab,      "📄")

    # ── STATUS BAR ────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self, bg=COLORS["bg3"], height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.status_var = tk.StringVar(
            value="Ready — select a module tab and upload files to begin analysis")
        tk.Label(bar, textvariable=self.status_var, bg=COLORS["bg3"],
                 fg=COLORS["txt2"], font=("Consolas", 9), anchor="w").pack(
                     side="left", padx=8)
        self.custody_count_var = tk.StringVar(value="Custody: 0 entries")
        tk.Label(bar, textvariable=self.custody_count_var, bg=COLORS["bg3"],
                 fg=COLORS["txt3"], font=("Consolas", 9)).pack(side="right", padx=8)

    def set_status(self, msg):
        self.status_var.set(msg)
        self.custody_count_var.set(f"Custody: {len(self.custody.entries)} entries")

    def _tick(self):
        import datetime
        self.clock_var.set(datetime.datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick)


# ── Dashboard ─────────────────────────────────────────────────────────────────
class DashboardTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self._build()

    def _build(self):
        from modules.gui_theme import heading, label, card_frame

        heading(self, "Murungi CyberSentinel v3").pack(anchor="w", padx=20, pady=(16, 2))
        label(self,
              "Unified Digital Forensics & OSINT Platform  —  "
              "Select a module tab above to begin analysis.",
              small=True).pack(anchor="w", padx=20, pady=(0, 14))

        grid = tk.Frame(self, bg=COLORS["bg"])
        grid.pack(fill="x", padx=20, pady=4)

        modules = [
            ("📋  Log Timeline",       "Upload auth.log, syslog, EVTX exports",                   COLORS["accent"]),
            ("🌐  IP Geolocation",     "Single lookup or batch-extract IPs from log files",        COLORS["teal"]),
            ("📞  CDR Analyzer",       "Upload CSV  OR  enter numbers manually — finds top pairs", COLORS["green"]),
            ("✉   Email Header",       "Upload .eml — traces phishing origin, SPF/DKIM/DMARC",    COLORS["amber"]),
            ("🕸  Network + Browser",  "Suspect network graph  +  Chrome/Firefox/Edge history",    COLORS["purple"]),
            ("💬  Social Feed",        "Upload JSON/CSV social exports — keyword flagging",         COLORS["red"]),
            ("🔍  File ID + Metadata", "Magic bytes + EXIF/GPS, PDF, Office, ID3, PE metadata",   COLORS["orange"]),
            ("🔒  Hash Verifier",      "SHA-256/MD5/SHA-1/SHA-512, SQLite DB, PDF report",         COLORS["green"]),
            ("🔤  Encoding Detect",    "Upload text — decodes Base64, Hex, Binary, ROT13, URL",    COLORS["accent"]),
            ("🔎  Keyword Scanner",    "Upload documents — terrorism, narcotics, cyber keywords",  COLORS["red"]),
            ("⚡  PowerShell Detect",  "Upload event logs — APT indicators, AMSI bypass",          COLORS["red"]),
            ("📑  Custody Log",        "Auto-logged actions — export to CSV",                       COLORS["green"]),
        ]

        for i, (name, desc, color) in enumerate(modules):
            col = i % 3
            row = i // 3
            cf = card_frame(grid)
            cf.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            tk.Label(cf, text=name, bg=COLORS["bg2"], fg=color,
                     font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 2))
            tk.Label(cf, text=desc, bg=COLORS["bg2"], fg=COLORS["txt2"],
                     font=("Segoe UI", 9), wraplength=250,
                     justify="left").pack(anchor="w", padx=10, pady=(0, 10))

        for c in range(3):
            grid.columnconfigure(c, weight=1)


if __name__ == "__main__":
    app = CyberSentinel()
    app.mainloop()
