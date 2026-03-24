"""
Hash Generator & Evidence Verifier
Merged with uploaded hashgenerator.py:
  - SQLite persistent hash records database
  - MD5 / SHA1 / SHA256 / SHA512
  - File metadata (size, created, modified, accessed, extension)
  - Preview window
  - PDF report via reportlab
  - Verify against stored hash (authentic / modified)
  - Known-hash comparison field
"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib, os, sqlite3, datetime
from modules.gui_theme import (COLORS, heading, label, btn, entry,
                                scrolled_tree, separator, text_area)

# ── DB setup (created next to the script) ─────────────────────────────────────
_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "hash_records.db")

def _get_conn():
    conn = sqlite3.connect(_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            filename  TEXT,
            md5       TEXT,
            sha1      TEXT,
            sha256    TEXT,
            sha512    TEXT,
            timestamp TEXT,
            size      INTEGER,
            created   TEXT,
            modified  TEXT,
            accessed  TEXT,
            extension TEXT
        )""")
    conn.commit()
    return conn


# ── Pure logic (no GUI) ───────────────────────────────────────────────────────
def compute_hashes(path: str) -> dict:
    algos = {a: hashlib.new(a) for a in ("md5","sha1","sha256","sha512")}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for h in algos.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in algos.items()}


def get_file_meta(path: str) -> dict:
    s   = os.stat(path)
    fmt = lambda ts: datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "size":      s.st_size,
        "created":   fmt(s.st_ctime),
        "modified":  fmt(s.st_mtime),
        "accessed":  fmt(s.st_atime),
        "extension": os.path.splitext(path)[1],
    }


def save_to_db(path: str, hashes: dict, meta: dict) -> str:
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = _get_conn()
    conn.execute("""
        INSERT INTO records
        (filename,md5,sha1,sha256,sha512,timestamp,size,created,modified,accessed,extension)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (path, hashes["md5"], hashes["sha1"], hashes["sha256"], hashes["sha512"],
         ts, meta["size"], meta["created"], meta["modified"], meta["accessed"],
         meta["extension"]))
    conn.commit()
    conn.close()
    return ts


def load_history() -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id,filename,sha256,timestamp,size,extension FROM records ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return rows


def lookup_stored_sha256(path: str):
    conn = _get_conn()
    row  = conn.execute(
        "SELECT sha256 FROM records WHERE filename=? ORDER BY id DESC LIMIT 1", (path,)
    ).fetchone()
    conn.close()
    return row[0] if row else None


# ── PDF report ────────────────────────────────────────────────────────────────
def _generate_pdf(path, hashes, meta, ts):
    try:
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        messagebox.showerror("Missing library",
                             "reportlab is required for PDF export.\n"
                             "Run:  pip install reportlab")
        return

    base     = os.path.basename(path)
    safe     = base.replace(" ", "_").replace(".", "_")
    time_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    default  = f"Integrity_Report_{safe}_{time_str}.pdf"

    save_path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        initialfile=default,
        filetypes=[("PDF files", "*.pdf")])
    if not save_path:
        return

    styles = getSampleStyleSheet()
    doc    = SimpleDocTemplate(save_path)
    els    = []

    els.append(Paragraph("<b>Digital Evidence Integrity Report</b>", styles["Title"]))
    els.append(Spacer(1, 20))
    els.append(Paragraph(f"File: {path}", styles["Normal"]))
    els.append(Paragraph(f"Generated: {ts}", styles["Normal"]))
    els.append(Spacer(1, 15))

    els.append(Paragraph("<b>Hash Values</b>", styles["Heading2"]))
    for k, v in hashes.items():
        els.append(Paragraph(f"{k.upper()}: {v}", styles["Normal"]))
    els.append(Spacer(1, 15))

    els.append(Paragraph("<b>File Metadata</b>", styles["Heading2"]))
    els.append(Paragraph(f"Size: {meta['size']:,} bytes", styles["Normal"]))
    els.append(Paragraph(f"Type/Extension: {meta['extension']}", styles["Normal"]))
    els.append(Paragraph(f"Created:  {meta['created']}", styles["Normal"]))
    els.append(Paragraph(f"Modified: {meta['modified']}", styles["Normal"]))
    els.append(Paragraph(f"Accessed: {meta['accessed']}", styles["Normal"]))

    doc.build(els)
    messagebox.showinfo("Saved", f"PDF report saved:\n{save_path}")


# ── Preview popup (matches original hashgenerator.py style) ──────────────────
def _show_preview(root_win, path, hashes, meta, ts):
    win = tk.Toplevel(root_win)
    win.title("Forensic Hash Preview")
    win.geometry("720x560")
    win.configure(bg=COLORS["bg"])

    txt = tk.Text(win, bg=COLORS["bg3"], fg=COLORS["txt"],
                  font=("Consolas", 9), wrap="word", relief="flat", bd=8)
    sb  = ttk.Scrollbar(win, command=txt.yview)
    txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    txt.pack(side="left", fill="both", expand=True)

    content  = f"FILE      : {path}\n"
    content += f"TIMESTAMP : {ts}\n"
    content += "─" * 70 + "\n"
    content += "HASH VALUES\n"
    for k, v in hashes.items():
        content += f"  {k.upper():<8}: {v}\n"
    content += "─" * 70 + "\n"
    content += "FILE METADATA\n"
    content += f"  Size      : {meta['size']:,} bytes  ({meta['size']/1024:.1f} KB)\n"
    content += f"  Extension : {meta['extension']}\n"
    content += f"  Created   : {meta['created']}\n"
    content += f"  Modified  : {meta['modified']}\n"
    content += f"  Accessed  : {meta['accessed']}\n"
    content += "─" * 70 + "\n"

    txt.insert("end", content)
    txt.configure(state="disabled")

    btn_frame = tk.Frame(win, bg=COLORS["bg"])
    btn_frame.pack(fill="x", pady=8, padx=8)
    btn(btn_frame, "Generate PDF Report",
        lambda: _generate_pdf(path, hashes, meta, ts),
        color=COLORS["green"]).pack(side="right", padx=6)
    btn(btn_frame, "Close", win.destroy,
        color=COLORS["red"]).pack(side="right", padx=6)


# ── Tab class ─────────────────────────────────────────────────────────────────
class HashTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody  = custody
        self.root_win = root
        self._build()

    def _build(self):
        heading(self, "Hash Generator & Evidence Verifier").pack(
            anchor="w", padx=16, pady=(14, 4))
        label(self,
              "Upload any file to compute MD5 / SHA-1 / SHA-256 / SHA-512 + metadata. "
              "Records are saved to a local database for later verification.",
              small=True).pack(anchor="w", padx=16)

        # ── Action buttons ────────────────────────────────────────────────
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Select File & Analyze", self._process,  color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Verify File",           self._verify,   color=COLORS["accent"]).pack(side="left", padx=4)
        btn(tr, "Refresh History",       self._load_hist,color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Export PDF",            self._export_pdf_from_sel,
            color=COLORS["amber"]).pack(side="left", padx=4)

        # ── Known hash comparison ─────────────────────────────────────────
        krow = tk.Frame(self, bg=COLORS["bg"])
        krow.pack(fill="x", padx=16, pady=4)
        label(krow, "Known SHA-256 to compare (optional):").pack(side="left")
        self.known_var = tk.StringVar()
        tk.Entry(krow, textvariable=self.known_var,
                 bg=COLORS["bg3"], fg=COLORS["txt"],
                 insertbackground=COLORS["accent"],
                 font=("Consolas", 9), relief="flat", bd=4,
                 highlightbackground=COLORS["border2"], highlightthickness=1,
                 width=68).pack(side="left", padx=8)

        separator(self).pack(fill="x", padx=16, pady=4)

        # ── Current result ────────────────────────────────────────────────
        lf = tk.LabelFrame(self, text="  Current File Analysis  ",
                           bg=COLORS["bg2"], fg=COLORS["accent"],
                           font=("Consolas", 9), bd=1)
        lf.pack(fill="x", padx=16, pady=4)

        cur_cols  = ("algo", "hash_value")
        cur_heads = ("Algorithm", "Hash Value")
        cf, self.cur_tree = scrolled_tree(lf, cur_cols, cur_heads, heights=5)
        self.cur_tree.column("algo",       width=90)
        self.cur_tree.column("hash_value", width=580)
        cf.pack(fill="x", padx=6, pady=6)

        self.meta_var = tk.StringVar(value="No file analyzed yet.")
        tk.Label(lf, textvariable=self.meta_var, bg=COLORS["bg2"],
                 fg=COLORS["txt2"], font=("Consolas", 9),
                 justify="left", anchor="w").pack(anchor="w", padx=10, pady=(0, 8))

        separator(self).pack(fill="x", padx=16, pady=4)

        # ── History ───────────────────────────────────────────────────────
        tk.Label(self, text="HASH DATABASE — ALL RECORDS",
                 bg=COLORS["bg"], fg=COLORS["txt3"],
                 font=("Consolas", 8)).pack(anchor="w", padx=18)

        h_cols  = ("id", "filename", "sha256", "timestamp", "size", "ext")
        h_heads = ("#", "Filename", "SHA-256", "Timestamp", "Size", "Ext")
        hf, self.hist_tree = scrolled_tree(self, h_cols, h_heads, heights=10)
        self.hist_tree.column("id",        width=40)
        self.hist_tree.column("filename",  width=180)
        self.hist_tree.column("sha256",    width=260)
        self.hist_tree.column("timestamp", width=140)
        self.hist_tree.column("size",      width=90)
        self.hist_tree.column("ext",       width=60)
        hf.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        self._load_hist()
        # store last analyzed for PDF export
        self._last = None

    # ── Handlers ─────────────────────────────────────────────────────────────
    def _process(self):
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if not path:
            return
        try:
            hashes = compute_hashes(path)
            meta   = get_file_meta(path)
            ts     = save_to_db(path, hashes, meta)
            self._last = (path, hashes, meta, ts)

            # Display current result
            self.cur_tree.delete(*self.cur_tree.get_children())
            for algo, val in hashes.items():
                # check against known hash
                known = self.known_var.get().strip().lower()
                if known and algo == "sha256":
                    tag = "OK" if val == known else "CRITICAL"
                else:
                    tag = ""
                self.cur_tree.insert("", "end",
                                     values=(algo.upper(), val),
                                     tags=(tag,))
            self.meta_var.set(
                f"File: {os.path.basename(path)}  |  "
                f"Size: {meta['size']:,} bytes  |  "
                f"Ext: {meta['extension']}  |  "
                f"Modified: {meta['modified']}  |  "
                f"Created: {meta['created']}"
            )

            # Verdict if known hash provided
            known = self.known_var.get().strip().lower()
            if known:
                match = (hashes["sha256"] == known)
                if match:
                    messagebox.showinfo("Integrity Check", "✔  File is AUTHENTIC — hash matches.")
                else:
                    messagebox.showwarning("Integrity Check",
                                           "✘  HASH MISMATCH — file may have been tampered with!")

            self._load_hist()
            self.custody.log("HASH_COMPUTED", os.path.basename(path),
                             f"SHA256={hashes['sha256'][:16]}…")

            # Show preview popup
            _show_preview(self.root_win, path, hashes, meta, ts)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _verify(self):
        """Re-hash a file and compare against the most recent DB record."""
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if not path:
            return
        try:
            hashes  = compute_hashes(path)
            stored  = lookup_stored_sha256(path)
            if stored is None:
                messagebox.showerror("Not Found",
                                     "No stored record found for this file.\n"
                                     "Analyze it first to create a baseline.")
                return
            if hashes["sha256"] == stored:
                messagebox.showinfo("Verification", "✔  File is AUTHENTIC — matches stored hash.")
                self.custody.log("HASH_VERIFY", os.path.basename(path), "AUTHENTIC")
            else:
                messagebox.showwarning("Verification",
                                       "✘  File has been MODIFIED — hash differs from stored record!")
                self.custody.log("HASH_VERIFY", os.path.basename(path), "MISMATCH — TAMPERED")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _export_pdf_from_sel(self):
        if not self._last:
            messagebox.showinfo("No file", "Analyze a file first, then export its PDF.")
            return
        path, hashes, meta, ts = self._last
        _generate_pdf(path, hashes, meta, ts)

    def _load_hist(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        for row in load_history():
            rid, filename, sha256, ts, size, ext = row
            self.hist_tree.insert("", "end",
                                  values=(rid,
                                          os.path.basename(filename),
                                          sha256[:40] + "…",
                                          ts,
                                          f"{size:,}",
                                          ext))
