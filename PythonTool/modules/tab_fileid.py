"""
File Type ID  +  Universal Metadata Extractor
Detects real file type via magic bytes.
Extracts metadata from ANY file:
  images (EXIF/GPS), PDF, Office (docx/xlsx/pptx), audio/video, ZIP/archives,
  executables (PE header), and generic file system metadata for everything else.
"""
import tkinter as tk
from tkinter import filedialog, messagebox
import os, struct, zipfile, datetime
from modules.gui_theme import (COLORS, heading, label, btn,
                                scrolled_tree, separator, text_area)

# ── Magic byte map ─────────────────────────────────────────────────────────────
MAGIC_MAP = [
    (b"\xff\xd8\xff",       "JPEG Image",          "image"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image",            "image"),
    (b"GIF87a",             "GIF Image (87a)",      "image"),
    (b"GIF89a",             "GIF Image (89a)",      "image"),
    (b"BM",                 "BMP Image",            "image"),
    (b"II\x2a\x00",        "TIFF Image (LE)",       "image"),
    (b"MM\x00\x2a",        "TIFF Image (BE)",       "image"),
    (b"%PDF",               "PDF Document",         "pdf"),
    (b"PK\x03\x04",        "ZIP / Office Archive",  "zip"),
    (b"PK\x05\x06",        "ZIP Archive (empty)",   "zip"),
    (b"\x1f\x8b",          "GZIP Archive",          "archive"),
    (b"7z\xbc\xaf",        "7-Zip Archive",         "archive"),
    (b"Rar!",               "RAR Archive",           "archive"),
    (b"MZ",                 "Windows PE (EXE/DLL)",  "pe"),
    (b"\x7fELF",           "Linux ELF Executable",  "elf"),
    (b"\xca\xfe\xba\xbe",  "Java Class File",       "java"),
    (b"OggS",               "OGG Audio/Video",       "media"),
    (b"fLaC",               "FLAC Audio",            "media"),
    (b"ID3",                "MP3 Audio (ID3)",       "media"),
    (b"\xff\xfb",          "MP3 Audio",              "media"),
    (b"\x00\x00\x00\x18ftyp","MP4 Video",           "media"),
    (b"\x00\x00\x00\x20ftyp","MP4 Video",           "media"),
    (b"RIFF",               "WAV / AVI (RIFF)",      "media"),
    (b"\x00\x00\x01\xba",  "MPEG Video",             "media"),
    (b"\x1a\x45\xdf\xa3",  "MKV / WebM Video",      "media"),
    (b"SQLite format 3",    "SQLite Database",       "sqlite"),
    (b"\xd0\xcf\x11\xe0",  "MS Office 97-2003",     "mso"),
    (b"<?xml",              "XML Document",          "xml"),
    (b"{\n",                "JSON (likely)",         "text"),
    (b"{\"",               "JSON (likely)",          "text"),
    (b"#!",                 "Script (shebang)",      "script"),
]

EXT_EXPECTED = {
    ".jpg":"JPEG",".jpeg":"JPEG",".png":"PNG",".gif":"GIF",".bmp":"BMP",
    ".tif":"TIFF",".tiff":"TIFF",".pdf":"PDF",".zip":"ZIP",".exe":"Windows PE",
    ".dll":"Windows PE",".elf":"Linux ELF",".mp3":"MP3",".mp4":"MP4",".mkv":"MKV",
    ".avi":"WAV / AVI",".wav":"WAV",".flac":"FLAC",".ogg":"OGG",".7z":"7-Zip",
    ".rar":"RAR",".gz":"GZIP",".docx":"ZIP",".xlsx":"ZIP",".pptx":"ZIP",
    ".sqlite":"SQLite",".db":"SQLite",".xml":"XML",".json":"JSON",
}

def detect_magic(data: bytes) -> tuple:
    """Returns (detected_type_str, category_str)."""
    for sig, name, cat in MAGIC_MAP:
        if data[:len(sig)] == sig:
            return name, cat
    # Printable ASCII heuristic → text
    try:
        data[:512].decode("utf-8")
        return "Plain Text / Unknown", "text"
    except Exception:
        return "Unknown Binary", "binary"


# ── Metadata extractors ────────────────────────────────────────────────────────

def _fs_meta(path: str) -> dict:
    """Always-available file system metadata."""
    s   = os.stat(path)
    fmt = lambda ts: datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "Filename":       os.path.basename(path),
        "Full Path":      path,
        "File Size":      f"{s.st_size:,} bytes  ({s.st_size/1024:.1f} KB)",
        "Extension":      os.path.splitext(path)[1] or "(none)",
        "Created":        fmt(s.st_ctime),
        "Modified":       fmt(s.st_mtime),
        "Accessed":       fmt(s.st_atime),
    }


def _exif_meta(path: str) -> dict:
    """JPEG/PNG/TIFF EXIF including GPS."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        img  = Image.open(path)
        raw  = img._getexif()
        if not raw:
            return {"EXIF": "No EXIF data found"}
        out  = {}
        gps  = {}
        for tid, val in raw.items():
            tag = TAGS.get(tid, str(tid))
            if tag == "GPSInfo":
                for gid, gval in val.items():
                    gps[GPSTAGS.get(gid, str(gid))] = str(gval)[:120]
            else:
                out[f"EXIF:{tag}"] = str(val)[:120]
        if gps:
            out["GPS Data"] = str(gps)
        return out
    except ImportError:
        return {"EXIF": "Install Pillow for full EXIF  (pip install pillow)"}
    except Exception as e:
        return {"EXIF Error": str(e)}


def _pdf_meta(path: str) -> dict:
    """Basic PDF metadata via raw parsing (no external lib needed)."""
    try:
        with open(path, "rb") as f:
            data = f.read(8192).decode("latin-1", errors="replace")
        out = {}
        for key in ("Title","Author","Subject","Creator","Producer","CreationDate","ModDate"):
            m = __import__("re").search(rf"/{key}\s*\(([^)]*)\)", data)
            if m:
                out[f"PDF:{key}"] = m.group(1).strip()
        if not out:
            out["PDF"] = "No metadata found in first 8 KB"
        return out
    except Exception as e:
        return {"PDF Error": str(e)}


def _office_meta(path: str) -> dict:
    """OOXML (docx/xlsx/pptx) metadata from [Content_Types].xml and core.xml."""
    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            out   = {"Office:Parts": str(len(names)) + " parts in archive"}
            if "docProps/core.xml" in names:
                import xml.etree.ElementTree as ET
                xml_data = z.read("docProps/core.xml").decode("utf-8","replace")
                root     = ET.fromstring(xml_data)
                ns = {"dc": "http://purl.org/dc/elements/1.1/",
                      "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                      "dcterms":"http://purl.org/dc/terms/"}
                for tag, label in [
                    (".//dc:creator",        "Author"),
                    (".//dc:title",          "Title"),
                    (".//dc:subject",        "Subject"),
                    (".//dc:description",    "Description"),
                    (".//cp:lastModifiedBy", "Last Modified By"),
                    (".//cp:revision",       "Revision"),
                    (".//dcterms:created",   "Created"),
                    (".//dcterms:modified",  "Modified"),
                ]:
                    el = root.find(tag, ns)
                    if el is not None and el.text:
                        out[f"Office:{label}"] = el.text.strip()
            if "docProps/app.xml" in names:
                import xml.etree.ElementTree as ET
                xml_data = z.read("docProps/app.xml").decode("utf-8","replace")
                root     = ET.fromstring(xml_data)
                for child in root:
                    tag = child.tag.split("}")[-1]
                    if child.text and tag not in ("TitlesOfParts","HeadingPairs"):
                        out[f"Office:{tag}"] = child.text.strip()
            return out
    except Exception as e:
        return {"Office Error": str(e)}


def _audio_meta(path: str) -> dict:
    """ID3 tags from MP3 files (manual parsing, no mutagen needed)."""
    try:
        with open(path,"rb") as f:
            header = f.read(10)
        if header[:3] != b"ID3":
            return {}
        out = {"ID3:Version": f"2.{header[3]}.{header[4]}"}
        # Rough tag scan
        with open(path,"rb") as f:
            data = f.read(8192)
        for tag, name in [(b"TIT2","Title"),(b"TPE1","Artist"),
                          (b"TALB","Album"),(b"TDRC","Year"),
                          (b"TRCK","Track"),(b"TCON","Genre")]:
            idx = data.find(tag)
            if idx >= 0:
                size = struct.unpack(">I", data[idx+4:idx+8])[0]
                try:
                    val = data[idx+10:idx+10+min(size,100)].decode("utf-8","replace").strip("\x00")
                    if val:
                        out[f"ID3:{name}"] = val
                except Exception:
                    pass
        return out
    except Exception as e:
        return {"ID3 Error": str(e)}


def _pe_meta(path: str) -> dict:
    """PE header info from Windows EXE/DLL."""
    try:
        with open(path,"rb") as f:
            dos = f.read(64)
        if dos[:2] != b"MZ":
            return {}
        e_lfanew = struct.unpack_from("<I", dos, 60)[0]
        with open(path,"rb") as f:
            f.seek(e_lfanew)
            pe = f.read(24)
        if pe[:4] != b"PE\x00\x00":
            return {"PE":"Not a valid PE file"}
        machine = struct.unpack_from("<H", pe, 4)[0]
        ts      = struct.unpack_from("<I", pe, 8)[0]
        machine_map = {0x14c:"x86 (32-bit)",0x8664:"x64 (64-bit)",
                       0xaa64:"ARM64",0x1c0:"ARM"}
        ts_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "—"
        return {
            "PE:Architecture": machine_map.get(machine, f"Unknown (0x{machine:04X})"),
            "PE:Compile Time":  ts_str,
        }
    except Exception as e:
        return {"PE Error": str(e)}


def _sqlite_meta(path: str) -> dict:
    """SQLite database info."""
    try:
        conn   = sqlite3.connect(path)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        conn.close()
        return {"SQLite:Tables": ", ".join(t[0] for t in tables) or "(empty)"}
    except Exception as e:
        return {"SQLite Error": str(e)}


def extract_metadata(path: str) -> dict:
    """Main dispatcher — always returns FS meta + type-specific meta."""
    with open(path,"rb") as f:
        header = f.read(32)
    detected, cat = detect_magic(header)

    meta = {"Detected Type": detected}
    meta.update(_fs_meta(path))

    if cat == "image":
        meta.update(_exif_meta(path))
    elif cat == "pdf":
        meta.update(_pdf_meta(path))
    elif cat == "zip":
        # Could be Office OOXML
        ext = os.path.splitext(path)[1].lower()
        if ext in (".docx",".xlsx",".pptx",".odt",".ods",".odp"):
            meta.update(_office_meta(path))
        else:
            try:
                with zipfile.ZipFile(path) as z:
                    meta["ZIP:Contents"] = f"{len(z.namelist())} files"
                    meta["ZIP:Files (first 5)"] = ", ".join(z.namelist()[:5])
                    meta.update(_office_meta(path))   # try anyway
            except Exception:
                pass
    elif cat == "media":
        meta.update(_audio_meta(path))
    elif cat == "pe":
        meta.update(_pe_meta(path))
    elif cat == "sqlite":
        meta.update(_sqlite_meta(path))

    return meta


# ── Tab class ──────────────────────────────────────────────────────────────────
class FileIDTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody = custody
        self._build()

    def _build(self):
        heading(self, "File Type Identifier  +  Universal Metadata Extractor").pack(
            anchor="w", padx=16, pady=(14, 4))
        label(self,
              "Upload ANY file. Detects real type via magic bytes and extracts metadata "
              "(EXIF/GPS for images, PDF properties, Office author/revision, ID3 tags, "
              "PE compile time, SQLite tables, ZIP contents, and filesystem info).",
              small=True).pack(anchor="w", padx=16)

        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload File(s)", self._upload, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Clear",          self._clear,  color=COLORS["red"]).pack(side="left", padx=4)

        separator(self).pack(fill="x", padx=16, pady=4)

        # ── Summary table ──────────────────────────────────────────────────
        tk.Label(self, text="FILE SUMMARY", bg=COLORS["bg"], fg=COLORS["txt3"],
                 font=("Consolas",8)).pack(anchor="w", padx=18)
        s_cols  = ("filename","ext","detected","status","size")
        s_heads = ("Filename","Extension","Detected Type","Status","Size")
        sf, self.sum_tree = scrolled_tree(self, s_cols, s_heads, heights=6)
        self.sum_tree.column("filename", width=190)
        self.sum_tree.column("ext",      width=70)
        self.sum_tree.column("detected", width=190)
        self.sum_tree.column("status",   width=130)
        self.sum_tree.column("size",     width=100)
        sf.pack(fill="x", padx=16, pady=(4,0))
        self.sum_tree.bind("<<TreeviewSelect>>", self._on_select)

        separator(self).pack(fill="x", padx=16, pady=4)

        # ── Detail area ────────────────────────────────────────────────────
        tk.Label(self, text="FULL METADATA  (select a file above)",
                 bg=COLORS["bg"], fg=COLORS["txt3"],
                 font=("Consolas",8)).pack(anchor="w", padx=18)
        d_cols  = ("key","value")
        d_heads = ("Metadata Field","Value")
        df, self.det_tree = scrolled_tree(self, d_cols, d_heads, heights=14)
        self.det_tree.column("key",   width=220)
        self.det_tree.column("value", width=560)
        df.pack(fill="both", expand=True, padx=16, pady=(4,12))

        self._file_meta_store = {}   # path -> meta dict

    def _upload(self):
        paths = filedialog.askopenfilenames(filetypes=[("All files","*.*")])
        if not paths: return
        for path in paths:
            try:
                meta      = extract_metadata(path)
                detected  = meta.get("Detected Type","Unknown")
                ext       = os.path.splitext(path)[1].lower()
                expected  = EXT_EXPECTED.get(ext,"")
                mismatch  = (expected and
                             not any(e.lower() in detected.lower()
                                     for e in [expected, expected[:3]]))
                status    = "MISMATCH — SUSPICIOUS" if mismatch else "Type OK"
                size_str  = meta.get("File Size","—")
                tag       = "SUS" if mismatch else "OK"

                self.sum_tree.insert("","end",
                    values=(os.path.basename(path), ext, detected, status, size_str),
                    tags=(tag,))
                self._file_meta_store[os.path.basename(path)] = (path, meta)

                self.custody.log("FILE_ANALYZED", os.path.basename(path),
                                 f"{detected} — {status}")
            except Exception as e:
                self.sum_tree.insert("","end",
                    values=(os.path.basename(path),"","ERROR",str(e),"—"))

    def _on_select(self, _event):
        sel = self.sum_tree.selection()
        if not sel: return
        fname = self.sum_tree.item(sel[0])["values"][0]
        if fname not in self._file_meta_store: return
        _path, meta = self._file_meta_store[fname]

        self.det_tree.delete(*self.det_tree.get_children())
        for k, v in meta.items():
            tag = ""
            if "GPS" in k:            tag = "WARNING"
            if "EXIF" in k:           tag = "INFO"
            if "Detected" in k:       tag = "INFO"
            if "MISMATCH" in str(v):  tag = "CRITICAL"
            self.det_tree.insert("","end", values=(k, v), tags=(tag,))

    def _clear(self):
        self.sum_tree.delete(*self.sum_tree.get_children())
        self.det_tree.delete(*self.det_tree.get_children())
        self._file_meta_store.clear()
