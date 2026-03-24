"""CDR Pattern Analyzer — upload CSV or manually enter call records."""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import re, os, datetime
from collections import Counter
from modules.gui_theme import (COLORS, heading, label, btn, entry,
                                scrolled_tree, separator, text_area)


class CDRTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self.records  = []   # list of (caller, recipient, duration, timestamp)
        self._build()

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build(self):
        heading(self, "CDR Pattern Analyzer").pack(anchor="w", padx=16, pady=(14, 4))
        label(self,
              "Upload a CSV file  OR  manually enter call records below. "
              "Format: CALLER, RECIPIENT, DURATION(s), TIMESTAMP",
              small=True).pack(anchor="w", padx=16)

        # ── Top button row ─────────────────────────────────────────────────
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload CDR CSV",  self._upload,      color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo Data",  self._demo,        color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Clear All",       self._clear,       color=COLORS["red"]).pack(side="left", padx=4)
        btn(tr, "Paste Text",      self._toggle_paste,color=COLORS["accent"]).pack(side="left", padx=4)

        # ── Paste area (hidden by default) ─────────────────────────────────
        self.paste_frame = tk.Frame(self, bg=COLORS["bg"])
        pf, self.paste_txt = text_area(self.paste_frame, height=4)
        pf.pack(fill="x")
        btn(self.paste_frame, "Parse & Add", self._parse_paste,
            color=COLORS["green"]).pack(anchor="e", pady=4)

        separator(self).pack(fill="x", padx=16, pady=6)

        # ── Manual entry card ──────────────────────────────────────────────
        mc = tk.LabelFrame(self, text="  Add Individual Call Record  ",
                           bg=COLORS["bg2"], fg=COLORS["accent"],
                           font=("Consolas", 9), bd=1,
                           highlightbackground=COLORS["border2"])
        mc.pack(fill="x", padx=16, pady=4)

        inner = tk.Frame(mc, bg=COLORS["bg2"])
        inner.pack(fill="x", padx=10, pady=8)

        # Row 1 — numbers
        r1 = tk.Frame(inner, bg=COLORS["bg2"])
        r1.pack(fill="x", pady=3)
        label(r1, "Caller Number:", bg=COLORS["bg2"]).grid(row=0, column=0, sticky="w", padx=(0,6))
        self.caller_var = tk.StringVar()
        self._make_entry(r1, self.caller_var, "+256700000000", 20).grid(row=0, column=1, padx=(0,16))
        label(r1, "Recipient Number:", bg=COLORS["bg2"]).grid(row=0, column=2, sticky="w", padx=(0,6))
        self.recip_var = tk.StringVar()
        self._make_entry(r1, self.recip_var, "+256701000000", 20).grid(row=0, column=3, padx=(0,16))

        # Row 2 — duration + timestamp
        r2 = tk.Frame(inner, bg=COLORS["bg2"])
        r2.pack(fill="x", pady=3)
        label(r2, "Duration (seconds):", bg=COLORS["bg2"]).grid(row=0, column=0, sticky="w", padx=(0,6))
        self.dur_var = tk.StringVar(value="120")
        self._make_entry(r2, self.dur_var, "", 8).grid(row=0, column=1, padx=(0,16))
        label(r2, "Timestamp:", bg=COLORS["bg2"]).grid(row=0, column=2, sticky="w", padx=(0,6))
        self.ts_var = tk.StringVar(value=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self._make_entry(r2, self.ts_var, "", 22).grid(row=0, column=3, padx=(0,16))

        # Add button
        btn(inner, "➕  Add Record", self._add_manual,
            color=COLORS["green"]).pack(anchor="e", pady=(6, 0))

        separator(self).pack(fill="x", padx=16, pady=6)

        # ── Stats bar ─────────────────────────────────────────────────────
        sbar = tk.Frame(self, bg=COLORS["bg"])
        sbar.pack(fill="x", padx=16, pady=2)
        self.info_var = tk.StringVar(value="No records loaded")
        tk.Label(sbar, textvariable=self.info_var, bg=COLORS["bg"],
                 fg=COLORS["txt2"], font=("Consolas", 9)).pack(side="left")
        btn(sbar, "Analyze", self._analyze, color=COLORS["amber"]).pack(side="right")

        # ── Results tree ──────────────────────────────────────────────────
        cols  = ("rank", "pair", "calls", "total_dur", "bar")
        heads = ("#", "Communication Pair", "Calls", "Total Duration", "Frequency")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=16)
        self.tree.column("rank",      width=40,  minwidth=35)
        self.tree.column("pair",      width=330, minwidth=200)
        self.tree.column("calls",     width=70,  minwidth=60)
        self.tree.column("total_dur", width=110, minwidth=90)
        self.tree.column("bar",       width=260, minwidth=120)
        tf.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        # ── Raw records tree ──────────────────────────────────────────────
        lf = tk.LabelFrame(self, text="  Loaded Call Records  ",
                           bg=COLORS["bg2"], fg=COLORS["txt2"],
                           font=("Consolas", 9), bd=1)
        lf.pack(fill="x", padx=16, pady=(0, 12))
        rcols  = ("caller", "recipient", "duration", "timestamp")
        rheads = ("Caller", "Recipient", "Duration (s)", "Timestamp")
        rf, self.raw_tree = scrolled_tree(lf, rcols, rheads, heights=6)
        self.raw_tree.column("caller",    width=170)
        self.raw_tree.column("recipient", width=170)
        self.raw_tree.column("duration",  width=100)
        self.raw_tree.column("timestamp", width=160)
        rf.pack(fill="x", padx=6, pady=6)

    def _make_entry(self, parent, var, placeholder, width):
        e = tk.Entry(parent, textvariable=var,
                     bg=COLORS["bg3"], fg=COLORS["txt"],
                     insertbackground=COLORS["accent"],
                     font=("Consolas", 10), relief="flat", bd=4,
                     highlightbackground=COLORS["border2"],
                     highlightthickness=1, width=width)
        if placeholder and not var.get():
            var.set(placeholder)
        return e

    # ── Actions ───────────────────────────────────────────────────────────────
    def _toggle_paste(self):
        if self.paste_frame.winfo_ismapped():
            self.paste_frame.pack_forget()
        else:
            self.paste_frame.pack(fill="x", padx=16, pady=4)

    def _add_manual(self):
        caller = self.caller_var.get().strip()
        recip  = self.recip_var.get().strip()
        dur_s  = self.dur_var.get().strip()
        ts     = self.ts_var.get().strip()

        if not caller or not recip:
            messagebox.showwarning("Missing", "Please enter both caller and recipient numbers.")
            return
        # Validate duration is a number
        try:
            dur = int(dur_s)
            if dur < 0:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Invalid", "Duration must be a positive integer (seconds).")
            return

        if not ts:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.records.append((caller, recip, dur, ts))
        self.raw_tree.insert("", "end", values=(caller, recip, dur, ts))
        self._update_info()
        # Auto-analyze when records exist
        if len(self.records) >= 2:
            self._analyze()
        self.custody.log("CDR_MANUAL_ENTRY", f"{caller}→{recip}",
                         f"Duration={dur}s ts={ts}")

    def _upload(self):
        path = filedialog.askopenfilename(
            filetypes=[("CSV/Text", "*.csv *.txt"), ("All", "*.*")])
        if not path:
            return
        with open(path, "r", errors="ignore") as f:
            self._parse_text(f.read(), os.path.basename(path))

    def _parse_paste(self):
        self._parse_text(self.paste_txt.get("1.0", "end"), "pasted")
        self.paste_frame.pack_forget()

    def _demo(self):
        demo = """+256700111222,+256701999888,342,2024-11-08 01:14:22
+256701999888,+256700111222,78,2024-11-08 01:55:44
+256700111222,+256702555444,19,2024-11-08 02:10:05
+256701999888,+256703777666,211,2024-11-08 02:22:18
+256700111222,+256701999888,445,2024-11-08 02:45:33
+256702555444,+256700111222,133,2024-11-08 03:01:09
+256701999888,+256700111222,290,2024-11-08 03:18:55
+256700111222,+256702555444,88,2024-11-08 03:44:00
+256703777666,+256701999888,512,2024-11-08 04:00:44
+256700111222,+256701999888,167,2024-11-08 04:15:12
+256702555444,+256704123456,44,2024-11-08 04:30:01
+256701999888,+256700111222,380,2024-11-08 05:00:22
+256700111222,+256705000111,22,2024-11-08 05:30:15
+256703777666,+256702555444,190,2024-11-08 06:01:00
+256701999888,+256705000111,67,2024-11-08 06:45:33
+256700111222,+256701999888,520,2024-11-08 07:10:44"""
        self._parse_text(demo, "demo_cdr")

    def _parse_text(self, text, source):
        added = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("caller"):
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            caller = parts[0].strip()
            recip  = parts[1].strip()
            try:
                dur = int(parts[2].strip()) if len(parts) > 2 else 0
            except ValueError:
                dur = 0
            ts = parts[3].strip() if len(parts) > 3 else ""
            self.records.append((caller, recip, dur, ts))
            self.raw_tree.insert("", "end", values=(caller, recip, dur, ts))
            added += 1
        self._update_info()
        self._analyze()
        self.custody.log("CDR_LOADED", source, f"{added} records added")

    def _analyze(self):
        if not self.records:
            return
        pairs_calls = Counter()
        pairs_dur   = Counter()
        for caller, recip, dur, _ in self.records:
            key = tuple(sorted([caller, recip]))
            pairs_calls[key] += 1
            pairs_dur[key]   += dur

        self.tree.delete(*self.tree.get_children())
        max_c = max(pairs_calls.values(), default=1)
        for rank, (key, count) in enumerate(pairs_calls.most_common(30), 1):
            pair_str  = f"{key[0]}  ↔  {key[1]}"
            total_sec = pairs_dur[key]
            dur_str   = f"{total_sec//60}m {total_sec%60}s"
            bar       = "█" * int(count / max_c * 28)
            tag = "CRITICAL" if rank == 1 else "WARNING" if rank <= 3 else ""
            self.tree.insert("", "end",
                             values=(rank, pair_str, count, dur_str, bar),
                             tags=(tag,))

    def _clear(self):
        self.records.clear()
        self.tree.delete(*self.tree.get_children())
        self.raw_tree.delete(*self.raw_tree.get_children())
        self._update_info()

    def _update_info(self):
        self.info_var.set(
            f"{len(self.records)} total records  |  "
            f"{len({tuple(sorted([c,r])) for c,r,_,_ in self.records})} unique pairs")
