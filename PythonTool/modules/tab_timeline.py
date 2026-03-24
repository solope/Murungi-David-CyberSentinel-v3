"""Log & Auth Timeline Analyzer — parses syslog, auth.log, EVTX text exports."""
import tkinter as tk
from tkinter import filedialog, messagebox
import re, os
from modules.gui_theme import (COLORS, heading, label, btn, section_label,
                                scrolled_tree, separator, text_area, card_frame)

CRIT_PAT = [
    (re.compile(r"failed password|authentication failure|brute.?force|invalid user", re.I), "Authentication Attack"),
    (re.compile(r"sudo.*COMMAND|privilege.?escal|su\[", re.I), "Privilege Escalation"),
    (re.compile(r"rm\s+-rf|shred|log.*clear|evidence.*destroy", re.I), "Evidence Destruction"),
    (re.compile(r"useradd|adduser|new user", re.I), "Account Creation"),
    (re.compile(r"nc\s|netcat|reverse.?shell|/bin/bash.*-i", re.I), "Shell Activity"),
    (re.compile(r"cron.*payload|\.hidden", re.I), "Persistence Mechanism"),
    (re.compile(r"EncodedCommand|-enc\s|AMSI|IEX\s*\(", re.I), "PowerShell Attack"),
]
WARN_PAT = [
    (re.compile(r"outbound|upload|transfer|wget|curl|scp", re.I), "Data Transfer"),
    (re.compile(r"nmap|masscan|port.?scan", re.I), "Reconnaissance"),
    (re.compile(r"iptables.*flush|firewall.*off", re.I), "Firewall Tamper"),
    (re.compile(r"ssh.*accept|new session", re.I), "Session Event"),
    (re.compile(r"error|warning|denied|refused", re.I), "System Warning"),
]
INFO_PAT = [
    (re.compile(r"systemd|service.*start|service.*stop", re.I), "Service Event"),
    (re.compile(r"\blogin\b|\blogout\b", re.I), "Login Event"),
]


def parse_log(text: str) -> list:
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        sev, et = None, ""
        for pat, name in CRIT_PAT:
            if pat.search(line):
                sev, et = "CRITICAL", name
                break
        if not sev:
            for pat, name in WARN_PAT:
                if pat.search(line):
                    sev, et = "WARNING", name
                    break
        if not sev:
            for pat, name in INFO_PAT:
                if pat.search(line):
                    sev, et = "INFO", name
                    break
        if not sev:
            continue
        m = re.search(r"\d{2}:\d{2}:\d{2}", line)
        ts = m.group(0) if m else "--:--:--"
        desc = re.sub(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s*", "", line)[:220]
        events.append((sev, ts, et, desc))
    return events


class TimelineTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody      = custody
        self.root         = root
        self.all_events   = []
        self._loaded_files = []
        self._build()

    def _build(self):
        # Header row
        top = tk.Frame(self, bg=COLORS["bg"])
        top.pack(fill="x", padx=16, pady=(14, 4))
        heading(top, "Log & Auth Timeline Analyzer").pack(side="left")
        btn(top, "Upload Log File(s)", self._upload,     color=COLORS["green"]).pack(side="right", padx=4)
        btn(top, "Paste Text",         self._show_paste, color=COLORS["accent"]).pack(side="right", padx=4)
        btn(top, "Load Demo",          self._load_demo,  color=COLORS["txt2"]).pack(side="right", padx=4)
        btn(top, "Clear All",          self._clear,      color=COLORS["red"]).pack(side="right", padx=4)

        label(self,
              "Upload auth.log · syslog · .evtx text exports · Apache/Nginx logs — multiple files at once. "
              "Click  Clear All  to start a fresh analysis.",
              small=True).pack(anchor="w", padx=16, pady=(0, 4))

        # Loaded files status bar
        self.loaded_var = tk.StringVar(value="No files loaded yet.")
        tk.Label(self, textvariable=self.loaded_var,
                 bg=COLORS["bg"], fg=COLORS["teal"],
                 font=("Consolas", 9)).pack(anchor="w", padx=16, pady=(0, 6))

        # Filter row
        frow = tk.Frame(self, bg=COLORS["bg"])
        frow.pack(fill="x", padx=16, pady=4)
        label(frow, "Filter:", small=True).pack(side="left")
        self.sev_var = tk.StringVar(value="ALL")
        for sev in ("ALL", "CRITICAL", "WARNING", "INFO"):
            c = {"ALL": COLORS["txt2"], "CRITICAL": COLORS["red"],
                 "WARNING": COLORS["amber"], "INFO": COLORS["accent"]}[sev]
            tk.Radiobutton(frow, text=sev, variable=self.sev_var, value=sev,
                           command=self._render, bg=COLORS["bg"], fg=c,
                           selectcolor=COLORS["bg3"], activebackground=COLORS["bg"],
                           font=("Consolas", 9)).pack(side="left", padx=6)

        self.count_var = tk.StringVar(value="0 events")
        label(frow, "", color=COLORS["txt3"], small=True).pack(side="right")
        tk.Label(frow, textvariable=self.count_var, bg=COLORS["bg"],
                 fg=COLORS["txt3"], font=("Consolas", 9)).pack(side="right", padx=8)

        separator(self).pack(fill="x", padx=16, pady=4)

        # Tree
        cols = ("sev", "time", "type", "description")
        heads = ("Severity", "Time", "Event Type", "Description")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=24)
        self.tree.column("sev",  width=90,  minwidth=80)
        self.tree.column("time", width=85,  minwidth=75)
        self.tree.column("type", width=170, minwidth=140)
        self.tree.column("description", width=600, minwidth=300)
        tf.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        # Paste area (hidden)
        self.paste_frame = tk.Frame(self, bg=COLORS["bg"])
        pf, self.paste_text = text_area(self.paste_frame, height=7, width=100)
        pf.pack(fill="x", padx=0, pady=4)
        btn(self.paste_frame, "Parse Text", self._parse_paste,
            color=COLORS["green"]).pack(anchor="e", pady=4)

    def _show_paste(self):
        if self.paste_frame.winfo_ismapped():
            self.paste_frame.pack_forget()
        else:
            self.paste_frame.pack(fill="x", padx=16, pady=4,
                                  before=self.tree.master.master)

    def _upload(self):
        paths = filedialog.askopenfilenames(
            title="Select log files",
            filetypes=[("Log files", "*.log *.txt *.evtx *.csv"),
                       ("All files", "*.*")])
        if not paths:
            return
        count = 0
        for p in paths:
            try:
                with open(p, "r", errors="ignore") as f:
                    evs = parse_log(f.read())
                self.all_events.extend(evs)
                count += len(evs)
                self._loaded_files.append(f"{os.path.basename(p)} ({len(evs)} events)")
                self.custody.log("LOG_FILE_UPLOADED", os.path.basename(p),
                                 f"{len(evs)} events parsed")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        self._update_loaded_label()
        self._render()
        if hasattr(self.root, "set_status"):
            self.root.set_status(f"Parsed {count} events from {len(paths)} file(s)")

    def _parse_paste(self):
        text = self.paste_text.get("1.0", "end").strip()
        if not text:
            return
        evs = parse_log(text)
        self.all_events.extend(evs)
        self._loaded_files.append(f"pasted text ({len(evs)} events)")
        self.custody.log("LOG_PASTED", "text_input", f"{len(evs)} events")
        self._update_loaded_label()
        self._render()
        self.paste_frame.pack_forget()

    def _update_loaded_label(self):
        if not self._loaded_files:
            self.loaded_var.set("No files loaded yet.")
        else:
            self.loaded_var.set(
                f"Loaded: {', '.join(self._loaded_files[-3:])}  "
                f"({len(self.all_events)} total events)")

    def _render(self):
        self.tree.delete(*self.tree.get_children())
        sev = self.sev_var.get()
        evs = [e for e in self.all_events if sev == "ALL" or e[0] == sev]
        for s, ts, et, desc in evs:
            tag = s
            self.tree.insert("", "end", values=(s, ts, et, desc), tags=(tag,))
        self.count_var.set(f"{len(evs)} events")

    def _clear(self):
        if self.all_events:
            from tkinter import messagebox as mb
            if not mb.askyesno("Clear All",
                               f"Remove all {len(self.all_events)} events and start fresh?"):
                return
        self.all_events.clear()
        self._loaded_files.clear()
        self._update_loaded_label()
        self._render()

    def _load_demo(self):
        demo = """Nov 08 02:14:38 ubuntu sshd[1342]: Failed password for root from 192.168.4.87 port 54210 ssh2
Nov 08 02:14:41 ubuntu sshd[1342]: Failed password for root from 192.168.4.87 port 54211 ssh2
Nov 08 02:14:44 ubuntu sshd[1342]: Failed password for root from 192.168.4.87 port 54212 ssh2
Nov 08 02:18:11 ubuntu sshd[1501]: Accepted password for deploy from 192.168.4.87 port 54301 ssh2
Nov 08 02:21:05 ubuntu sudo[2201]: deploy : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash
Nov 08 02:21:07 ubuntu su[2203]: Successful su for root by deploy
Nov 08 02:33:17 ubuntu cron[2401]: (root) CMD crontab /tmp/.hidden/payload.sh
Nov 08 03:01:44 ubuntu kernel: outbound connection to 185.220.101.9:443 size=482MB
Nov 08 04:02:09 ubuntu bash[3101]: root rm -rf /var/log/auth.log
Nov 08 04:18:33 ubuntu useradd[3401]: new user: name=backdoor_usr, UID=1337
Nov 08 05:01:44 ubuntu kernel: iptables rules flushed - firewall off
Nov 08 05:15:09 ubuntu sshd[4001]: Accepted password for backdoor_usr from 185.220.101.9"""
        self.all_events = parse_log(demo)
        self._loaded_files = [f"demo auth.log ({len(self.all_events)} events)"]
        self.custody.log("DEMO_LOADED", "log_timeline", f"{len(self.all_events)} events")
        self._update_loaded_label()
        self._render()
