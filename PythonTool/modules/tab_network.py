"""
Network Graph + Browser History Fetcher
Fetches visited URLs from Chrome, Firefox, and Edge SQLite history databases.
Also loads CSV connection files for the suspect network graph.
"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os, shutil, sqlite3, datetime, re
from modules.gui_theme import (COLORS, heading, label, btn,
                                scrolled_tree, separator, card_frame)

# ── Browser profile paths (Windows + Linux + macOS) ───────────────────────────
def _browser_paths():
    """
    Returns dict of {display_name: path}.
    Opera has several install locations depending on version and platform.
    We scan ALL of them so at least one will match.
    """
    home = os.path.expanduser("~")
    paths = {
        # ── Chrome ──────────────────────────────────────────────────────────
        "Chrome (Windows)":
            os.path.join(home, "AppData","Local","Google","Chrome","User Data","Default","History"),
        "Chrome (Linux)":
            os.path.join(home, ".config","google-chrome","Default","History"),
        "Chrome (macOS)":
            os.path.join(home, "Library","Application Support","Google","Chrome","Default","History"),
        # Chrome Canary
        "Chrome Canary (Windows)":
            os.path.join(home, "AppData","Local","Google","Chrome SxS","User Data","Default","History"),

        # ── Microsoft Edge ───────────────────────────────────────────────────
        "Edge (Windows)":
            os.path.join(home, "AppData","Local","Microsoft","Edge","User Data","Default","History"),
        "Edge (Linux)":
            os.path.join(home, ".config","microsoft-edge","Default","History"),
        "Edge (macOS)":
            os.path.join(home, "Library","Application Support","Microsoft Edge","Default","History"),

        # ── Brave ────────────────────────────────────────────────────────────
        "Brave (Windows)":
            os.path.join(home, "AppData","Local","BraveSoftware","Brave-Browser","User Data","Default","History"),
        "Brave (macOS)":
            os.path.join(home, "Library","Application Support","BraveSoftware","Brave-Browser","Default","History"),
        "Brave (Linux)":
            os.path.join(home, ".config","BraveSoftware","Brave-Browser","Default","History"),

        # ── Opera — multiple install paths across versions ────────────────────
        # Classic Opera (Roaming — most common on Windows)
        "Opera (Windows — Roaming)":
            os.path.join(home, "AppData","Roaming","Opera Software","Opera Stable","History"),
        # Opera installed via Opera installer into AppData\Local
        "Opera (Windows — Local)":
            os.path.join(home, "AppData","Local","Opera Software","Opera Stable","History"),
        # Opera One / Opera GX — uses a different subfolder
        "Opera GX (Windows)":
            os.path.join(home, "AppData","Roaming","Opera Software","Opera GX Stable","History"),
        "Opera One (Windows)":
            os.path.join(home, "AppData","Roaming","Opera Software","Opera One","History"),
        # Opera on macOS
        "Opera (macOS)":
            os.path.join(home, "Library","Application Support","com.operasoftware.Opera","History"),
        # Opera on Linux
        "Opera (Linux)":
            os.path.join(home, ".config","opera","History"),
        "Opera GX (Linux)":
            os.path.join(home, ".config","opera-gx","History"),

        # ── Vivaldi ───────────────────────────────────────────────────────────
        "Vivaldi (Windows)":
            os.path.join(home, "AppData","Local","Vivaldi","User Data","Default","History"),
        "Vivaldi (macOS)":
            os.path.join(home, "Library","Application Support","Vivaldi","Default","History"),
        "Vivaldi (Linux)":
            os.path.join(home, ".config","vivaldi","Default","History"),

        # ── Firefox handled separately via _find_firefox_history() ───────────
    }
    return paths


def _find_firefox_history():
    """Find Firefox places.sqlite across all profiles."""
    home = os.path.expanduser("~")
    roots = [
        os.path.join(home, "AppData","Roaming","Mozilla","Firefox","Profiles"),
        os.path.join(home, ".mozilla","firefox"),
        os.path.join(home, "Library","Application Support","Firefox","Profiles"),
    ]
    found = []
    for root in roots:
        if os.path.isdir(root):
            for profile in os.listdir(root):
                p = os.path.join(root, profile, "places.sqlite")
                if os.path.isfile(p):
                    found.append(("Firefox — " + profile[:20], p))
    return found


def _chrome_epoch_to_dt(microseconds: int) -> str:
    """Chrome stores timestamps as microseconds since 1601-01-01."""
    try:
        epoch = datetime.datetime(1601, 1, 1)
        dt    = epoch + datetime.timedelta(microseconds=microseconds)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "—"


def fetch_chromium_history(db_path: str, limit: int = 500) -> list:
    """Read Chrome/Edge/Brave/Opera SQLite history (copies DB to avoid lock)."""
    tmp = db_path + "_cs_tmp"
    try:
        shutil.copy2(db_path, tmp)
        conn = sqlite3.connect(tmp)
        rows = conn.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT ?""", (limit,)).fetchall()
        conn.close()
        os.remove(tmp)
        result = []
        for url, title, count, ts in rows:
            result.append({
                "url":   url,
                "title": (title or "")[:100],
                "count": count,
                "ts":    _chrome_epoch_to_dt(ts),
            })
        return result
    except Exception as e:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except: pass
        return [{"url": f"ERROR: {e}", "title": "", "count": 0, "ts": ""}]


def fetch_firefox_history(db_path: str, limit: int = 500) -> list:
    """Read Firefox places.sqlite."""
    tmp = db_path + "_cs_tmp"
    try:
        shutil.copy2(db_path, tmp)
        conn = sqlite3.connect(tmp)
        rows = conn.execute("""
            SELECT p.url, p.title, p.visit_count,
                   datetime(h.visit_date/1000000, 'unixepoch') as visited
            FROM moz_places p
            LEFT JOIN moz_historyvisits h ON p.id = h.place_id
            ORDER BY h.visit_date DESC
            LIMIT ?""", (limit,)).fetchall()
        conn.close()
        os.remove(tmp)
        return [{"url":r[0],"title":(r[1] or "")[:100],"count":r[2],"ts":r[3] or "—"}
                for r in rows]
    except Exception as e:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except: pass
        return [{"url": f"ERROR: {e}", "title": "", "count": 0, "ts": ""}]


# ── Graph helpers ──────────────────────────────────────────────────────────────
DEMO_NODES = [
    {"id":0,"label":"shadow_0x4a","role":"primary","x":320,"y":150},
    {"id":1,"label":"suspect_chan","role":"associate","x":175,"y":255},
    {"id":2,"label":"anon_buyer","role":"associate","x":460,"y":255},
    {"id":3,"label":"+256700111222","role":"contact","x":110,"y":385},
    {"id":4,"label":"+256701999888","role":"contact","x":310,"y":415},
    {"id":5,"label":"185.220.101.9","role":"primary","x":545,"y":160},
    {"id":6,"label":"throwaway_8871","role":"associate","x":205,"y":115},
    {"id":7,"label":"+256702555444","role":"unknown","x":55,"y":285},
]
DEMO_EDGES = [(0,1),(0,2),(0,6),(1,3),(1,4),(2,5),(3,7),(4,3),(0,5)]
NODE_COLORS = {
    "primary":   "#ff4466",
    "associate": "#ffaa00",
    "contact":   "#00d4ff",
    "unknown":   "#00ff88",
}


class NetworkTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody    = custody
        self.nodes      = []
        self.edges      = []
        self._drag_node = None
        self._drag_off  = (0, 0)
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────
    def _build(self):
        heading(self, "Network Graph  +  Browser History Fetcher").pack(
            anchor="w", padx=16, pady=(14, 4))

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=6)

        # Tab 1 — Network Graph
        gf = tk.Frame(nb, bg=COLORS["bg"])
        nb.add(gf, text="  🕸  Criminal Network Graph  ")
        self._build_graph_tab(gf)

        # Tab 2 — Browser History
        bf = tk.Frame(nb, bg=COLORS["bg"])
        nb.add(bf, text="  🌐  Browser History  ")
        self._build_browser_tab(bf)

    # ── Graph tab ─────────────────────────────────────────────────────────────
    def _build_graph_tab(self, parent):
        tr = tk.Frame(parent, bg=COLORS["bg"])
        tr.pack(fill="x", padx=12, pady=8)
        btn(tr, "Upload CSV Connections", self._upload_graph, color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo Graph",        self._demo_graph,   color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Reset Layout",           self._reset_graph,  color=COLORS["red"]).pack(side="left", padx=4)

        label(parent,
              "CSV format: NODE_A, NODE_B, ROLE, WEIGHT  —  "
              "Drag nodes to explore connections.", small=True).pack(anchor="w", padx=12)

        self.canvas = tk.Canvas(parent, bg="#0b1018", bd=0, highlightthickness=0, height=300)
        self.canvas.pack(fill="both", expand=True, padx=12, pady=6)
        self.canvas.bind("<ButtonPress-1>",   self._on_press)
        self.canvas.bind("<B1-Motion>",       self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)

        legend = tk.Frame(parent, bg=COLORS["bg"])
        legend.pack(fill="x", padx=12, pady=4)
        for role, col in NODE_COLORS.items():
            f = tk.Frame(legend, bg=COLORS["bg"])
            f.pack(side="left", padx=10)
            tk.Canvas(f, width=12, height=12, bg=col,
                      highlightthickness=0).pack(side="left", padx=(0,4))
            tk.Label(f, text=role.capitalize(), bg=COLORS["bg"],
                     fg=COLORS["txt2"], font=("Segoe UI", 9)).pack(side="left")

        self.graph_info = tk.StringVar(value="Click a node to view details. Drag to reposition.")
        tk.Label(parent, textvariable=self.graph_info, bg=COLORS["bg"],
                 fg=COLORS["txt3"], font=("Consolas", 9)).pack(anchor="w", padx=12, pady=4)

    # ── Browser tab ───────────────────────────────────────────────────────────
    def _build_browser_tab(self, parent):
        info = tk.Frame(parent, bg=COLORS["bg"])
        info.pack(fill="x", padx=12, pady=8)
        label(info,
              "Automatically detects Chrome, Edge, Firefox, and Brave history databases on this machine.",
              small=True).pack(side="left")

        tr = tk.Frame(parent, bg=COLORS["bg"])
        tr.pack(fill="x", padx=12, pady=4)

        btn(tr, "Auto-Detect All Browsers", self._auto_detect,   color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Upload DB File Manually",  self._upload_db,     color=COLORS["accent"]).pack(side="left", padx=4)
        btn(tr, "Load Demo History",        self._demo_history,  color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Clear",                    self._clear_history, color=COLORS["red"]).pack(side="left", padx=4)

        # Filter
        frow = tk.Frame(parent, bg=COLORS["bg"])
        frow.pack(fill="x", padx=12, pady=4)
        label(frow, "Filter URL/Title:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", lambda *_: self._apply_filter())
        tk.Entry(frow, textvariable=self.filter_var,
                 bg=COLORS["bg3"], fg=COLORS["txt"],
                 insertbackground=COLORS["accent"],
                 font=("Consolas", 10), relief="flat", bd=4,
                 highlightbackground=COLORS["border2"], highlightthickness=1,
                 width=40).pack(side="left", padx=8)
        self.sus_only = tk.BooleanVar()
        tk.Checkbutton(frow, text="Suspicious only", variable=self.sus_only,
                       command=self._apply_filter,
                       bg=COLORS["bg"], fg=COLORS["txt2"],
                       selectcolor=COLORS["bg3"], activebackground=COLORS["bg"],
                       font=("Segoe UI",9)).pack(side="left", padx=8)
        self.hist_count_var = tk.StringVar(value="0 records")
        tk.Label(frow, textvariable=self.hist_count_var, bg=COLORS["bg"],
                 fg=COLORS["txt3"], font=("Consolas",9)).pack(side="right", padx=8)

        # Detected browsers list
        det_frame = card_frame(parent)
        det_frame.pack(fill="x", padx=12, pady=4)
        tk.Label(det_frame, text="DETECTED BROWSER DATABASES", bg=COLORS["bg2"],
                 fg=COLORS["txt3"], font=("Consolas",8)).pack(anchor="w", padx=8, pady=(6,2))
        self.browser_list = tk.Listbox(det_frame, bg=COLORS["bg3"], fg=COLORS["txt"],
                                       font=("Consolas",9), height=4,
                                       selectbackground=COLORS["bg4"],
                                       relief="flat", bd=4,
                                       highlightbackground=COLORS["border2"],
                                       highlightthickness=1)
        self.browser_list.pack(fill="x", padx=8, pady=(0,6))
        btn(det_frame, "Load Selected Browser",
            self._load_selected_browser, color=COLORS["accent"]).pack(anchor="e", padx=8, pady=(0,6))

        self._detected_browsers = {}  # name -> (type, path)

        # History treeview
        h_cols  = ("ts","browser","url","title","visits")
        h_heads = ("Timestamp","Browser","URL","Title","Visits")
        hf, self.hist_tree = scrolled_tree(parent, h_cols, h_heads, heights=14)
        self.hist_tree.column("ts",      width=135)
        self.hist_tree.column("browser", width=100)
        self.hist_tree.column("url",     width=310)
        self.hist_tree.column("title",   width=200)
        self.hist_tree.column("visits",  width=55)
        hf.pack(fill="both", expand=True, padx=12, pady=(4,12))

        self._all_history = []  # raw list of dicts

    # ── Graph actions ─────────────────────────────────────────────────────────
    def _upload_graph(self):
        path = filedialog.askopenfilename(filetypes=[("CSV","*.csv *.txt"),("All","*.*")])
        if not path: return
        nodes_d, edges = {}, []
        with open(path,"r",errors="ignore") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 2: continue
                a, b   = parts[0].strip(), parts[1].strip()
                role   = parts[2].strip() if len(parts) > 2 else "unknown"
                if a not in nodes_d:
                    import random
                    nodes_d[a] = {"id":len(nodes_d),"label":a,"role":role,
                                  "x":random.randint(80,580),"y":random.randint(60,260)}
                if b not in nodes_d:
                    import random
                    nodes_d[b] = {"id":len(nodes_d),"label":b,"role":"contact",
                                  "x":random.randint(80,580),"y":random.randint(60,260)}
                edges.append((nodes_d[a]["id"], nodes_d[b]["id"]))
        self.nodes = list(nodes_d.values())
        self.edges = edges
        self._draw_graph()
        self.custody.log("GRAPH_LOADED", os.path.basename(path),
                         f"{len(self.nodes)} nodes, {len(edges)} edges")

    def _demo_graph(self):
        import copy
        self.nodes = copy.deepcopy(DEMO_NODES)
        self.edges = list(DEMO_EDGES)
        self._draw_graph()
        self.custody.log("DEMO_GRAPH","demo",f"{len(self.nodes)} nodes")

    def _reset_graph(self):
        self._demo_graph()

    def _draw_graph(self):
        c = self.canvas
        c.delete("all")
        W = c.winfo_width()  or 660
        H = c.winfo_height() or 300

        # edges
        for a_id, b_id in self.edges:
            a = next((n for n in self.nodes if n["id"]==a_id), None)
            b = next((n for n in self.nodes if n["id"]==b_id), None)
            if a and b:
                c.create_line(a["x"], a["y"], b["x"], b["y"],
                              fill="#1c3a55", width=1.5)

        # nodes
        for n in self.nodes:
            col = NODE_COLORS.get(n.get("role","unknown"), "#888")
            r   = 18 if n.get("role") == "primary" else 14
            c.create_oval(n["x"]-r, n["y"]-r, n["x"]+r, n["y"]+r,
                          outline=col, fill=col+"22", width=2, tags=("node",f"n{n['id']}"))
            c.create_text(n["x"], n["y"], text=str(n["id"]),
                          fill="white", font=("Consolas",9,"bold"))
            c.create_text(n["x"], n["y"]+r+10,
                          text=n["label"][:16],
                          fill=col, font=("Consolas",8))

    def _on_press(self, event):
        for n in self.nodes:
            r = 18 if n.get("role")=="primary" else 14
            if abs(event.x - n["x"]) < r+4 and abs(event.y - n["y"]) < r+4:
                self._drag_node = n
                self._drag_off  = (event.x - n["x"], event.y - n["y"])
                edges_count = sum(1 for a,b in self.edges if a==n["id"] or b==n["id"])
                self.graph_info.set(
                    f"Node {n['id']}: {n['label']}  |  Role: {n.get('role','?')}  "
                    f"|  Connections: {edges_count}")
                return

    def _on_drag(self, event):
        if self._drag_node:
            self._drag_node["x"] = event.x - self._drag_off[0]
            self._drag_node["y"] = event.y - self._drag_off[1]
            self._draw_graph()

    def _on_release(self, _event):
        self._drag_node = None

    # ── Browser history actions ───────────────────────────────────────────────
    def _auto_detect(self):
        self._detected_browsers.clear()
        self.browser_list.delete(0, "end")

        # Chromium-based
        for name, path in _browser_paths().items():
            if "Firefox" not in name and os.path.isfile(path):
                self._detected_browsers[name] = ("chromium", path)
                self.browser_list.insert("end", f"✔  {name}")

        # Firefox profiles
        for name, path in _find_firefox_history():
            self._detected_browsers[name] = ("firefox", path)
            self.browser_list.insert("end", f"✔  {name}")

        if not self._detected_browsers:
            self.browser_list.insert("end", "No browser history databases found on this machine.")
            messagebox.showinfo("Auto-Detect",
                                "No browser databases found.\n"
                                "Try 'Upload DB File Manually' to point to a history file.")
        else:
            count = len(self._detected_browsers)
            messagebox.showinfo("Auto-Detect",
                                f"Found {count} browser database(s).\n"
                                "Select one in the list and click 'Load Selected Browser'.")
        self.custody.log("BROWSER_DETECT","auto",
                         f"{len(self._detected_browsers)} databases found")

    def _load_selected_browser(self):
        sel = self.browser_list.curselection()
        if not sel:
            messagebox.showwarning("Select", "Click a browser in the list first.")
            return
        name = self.browser_list.get(sel[0]).replace("✔  ","").strip()
        if name not in self._detected_browsers:
            return
        btype, path = self._detected_browsers[name]
        self._load_db(btype, path, name)

    def _upload_db(self):
        path = filedialog.askopenfilename(
            title="Select browser history database",
            filetypes=[("SQLite DB","*.sqlite *.db History places.sqlite"),("All","*.*")])
        if not path: return
        # Guess type by filename
        btype = "firefox" if "places" in os.path.basename(path).lower() else "chromium"
        self._load_db(btype, path, os.path.basename(path))

    def _load_db(self, btype, path, browser_name):
        if btype == "firefox":
            records = fetch_firefox_history(path)
        else:
            records = fetch_chromium_history(path)

        for r in records:
            r["browser"] = browser_name

        self._all_history.extend(records)
        self._apply_filter()
        self.custody.log("BROWSER_HISTORY_LOADED", browser_name,
                         f"{len(records)} records")
        messagebox.showinfo("Loaded", f"Loaded {len(records)} history records from:\n{browser_name}")

    def _apply_filter(self, *_):
        query  = self.filter_var.get().strip().lower()
        sus    = self.sus_only.get()

        SUS_DOMAINS = {"tor","onion","darkweb","exfil","payload","c2","hacker",
                       "exploit","nulled","cracked","leaked","ransomware","protonmail",
                       "tutanota","riseup"}

        self.hist_tree.delete(*self.hist_tree.get_children())
        shown = 0
        for r in self._all_history:
            url   = (r.get("url")   or "").lower()
            title = (r.get("title") or "").lower()
            is_sus = any(d in url for d in SUS_DOMAINS)

            if sus and not is_sus:
                continue
            if query and query not in url and query not in title:
                continue

            tag = "CRITICAL" if is_sus else ""
            self.hist_tree.insert("", "end",
                values=(r.get("ts","—"),
                        r.get("browser","?"),
                        r.get("url","")[:120],
                        r.get("title",""),
                        r.get("count",0)),
                tags=(tag,))
            shown += 1

        self.hist_count_var.set(f"{shown} / {len(self._all_history)} records")

    def _demo_history(self):
        demo = [
            {"ts":"2024-11-08 01:14:22","browser":"Chrome","url":"https://www.google.com/search?q=how+to+hack+SSH","title":"How to hack SSH — Google","count":3},
            {"ts":"2024-11-08 01:30:44","browser":"Chrome","url":"https://null-byte.wonderhowto.com/how-to/brute-force-ssh/","title":"Brute Force SSH Tutorial","count":2},
            {"ts":"2024-11-08 01:55:00","browser":"Firefox","url":"https://protonmail.com/login","title":"ProtonMail — Secure Email","count":5},
            {"ts":"2024-11-08 02:00:11","browser":"Chrome","url":"https://kali.org/tools/nmap/","title":"Nmap Network Scanner","count":1},
            {"ts":"2024-11-08 02:10:05","browser":"Chrome","url":"http://185.220.101.9/stager.ps1","title":"","count":1},
            {"ts":"2024-11-08 02:22:18","browser":"Firefox","url":"https://blockchain.com/btc/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf","title":"Bitcoin Address — Blockchain.com","count":4},
            {"ts":"2024-11-08 02:45:33","browser":"Edge","url":"https://github.com/rapid7/metasploit-framework","title":"Metasploit Framework — GitHub","count":2},
            {"ts":"2024-11-08 03:01:09","browser":"Chrome","url":"https://exfil-drop.onion.to/upload","title":"Drop Server","count":1},
            {"ts":"2024-11-08 03:20:00","browser":"Firefox","url":"https://tutanota.com","title":"Tutanota Encrypted Email","count":3},
            {"ts":"2024-11-08 04:00:44","browser":"Chrome","url":"https://www.youtube.com","title":"YouTube — Home","count":12},
            {"ts":"2024-11-08 04:15:12","browser":"Chrome","url":"https://accounts.google.com","title":"Google Account","count":7},
            {"ts":"2024-11-08 05:00:22","browser":"Edge","url":"https://riseup.net","title":"Riseup — Privacy Tools","count":2},
            {"ts":"2024-11-08 06:01:00","browser":"Chrome","url":"https://darkweb-links.org","title":"Darkweb Directory","count":1},
            {"ts":"2024-11-08 07:10:44","browser":"Firefox","url":"https://cracked.io/forum","title":"Cracked — Hacking Forum","count":3},
        ]
        for r in demo:
            r.setdefault("browser","Demo")
        self._all_history.extend(demo)
        self._apply_filter()
        self.custody.log("DEMO_HISTORY","demo",f"{len(demo)} records loaded")

    def _clear_history(self):
        self._all_history.clear()
        self.hist_tree.delete(*self.hist_tree.get_children())
        self.hist_count_var.set("0 records")
