"""Shared theme, colors, and widget helpers for CyberSentinel GUI."""
import tkinter as tk
from tkinter import ttk

COLORS = {
    "bg":      "#060a0f",
    "bg2":     "#0b1018",
    "bg3":     "#0f1822",
    "bg4":     "#142030",
    "border":  "#1c2d42",
    "border2": "#243850",
    "txt":     "#c0d8f0",
    "txt2":    "#6090b8",
    "txt3":    "#304860",
    "accent":  "#00d4ff",
    "green":   "#00cc6a",
    "amber":   "#ffaa00",
    "red":     "#ff4466",
    "purple":  "#aa66ff",
    "teal":    "#00ffcc",
    "orange":  "#ff6622",
}


def apply_theme(root):
    root.configure(bg=COLORS["bg"])
    style = ttk.Style(root)
    style.theme_use("clam")

    # Notebook
    style.configure("TNotebook", background=COLORS["bg2"], borderwidth=0)
    style.configure("TNotebook.Tab",
                    background=COLORS["bg3"], foreground=COLORS["txt2"],
                    padding=[10, 5], font=("Segoe UI", 9))
    style.map("TNotebook.Tab",
              background=[("selected", COLORS["bg4"])],
              foreground=[("selected", COLORS["accent"])])

    # Treeview
    style.configure("Treeview",
                    background=COLORS["bg3"], foreground=COLORS["txt"],
                    fieldbackground=COLORS["bg3"], borderwidth=0,
                    rowheight=24, font=("Consolas", 9))
    style.configure("Treeview.Heading",
                    background=COLORS["bg2"], foreground=COLORS["txt2"],
                    font=("Consolas", 9, "bold"), relief="flat")
    style.map("Treeview", background=[("selected", COLORS["bg4"])],
              foreground=[("selected", COLORS["accent"])])

    # Scrollbar
    style.configure("Vertical.TScrollbar", background=COLORS["bg3"],
                    troughcolor=COLORS["bg2"], borderwidth=0, arrowsize=12)
    style.configure("Horizontal.TScrollbar", background=COLORS["bg3"],
                    troughcolor=COLORS["bg2"], borderwidth=0, arrowsize=12)

    # Progressbar
    style.configure("green.Horizontal.TProgressbar",
                    background=COLORS["green"], troughcolor=COLORS["bg3"])
    style.configure("red.Horizontal.TProgressbar",
                    background=COLORS["red"], troughcolor=COLORS["bg3"])


# ── Widget helpers ────────────────────────────────────────────────────────────

def heading(parent, text, color=None):
    return tk.Label(parent, text=text, bg=COLORS["bg"],
                    fg=color or COLORS["accent"],
                    font=("Consolas", 13, "bold"))


def label(parent, text, color=None, small=False, bg=None):
    return tk.Label(parent, text=text,
                    bg=bg or COLORS["bg"],
                    fg=color or COLORS["txt2"],
                    font=("Segoe UI", 9 if small else 10),
                    justify="left", anchor="w")


def card_frame(parent, bg=None):
    f = tk.Frame(parent, bg=bg or COLORS["bg2"],
                 highlightbackground=COLORS["border2"],
                 highlightthickness=1, bd=0)
    return f


def section_label(parent, text):
    return tk.Label(parent, text=text.upper(), bg=COLORS["bg"],
                    fg=COLORS["txt3"], font=("Consolas", 8),
                    anchor="w")


def btn(parent, text, command, color=None, width=None):
    c = color or COLORS["accent"]
    b = tk.Button(parent, text=text, command=command,
                  bg=COLORS["bg3"], fg=c,
                  activebackground=COLORS["bg4"], activeforeground=c,
                  font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                  padx=12, pady=5, cursor="hand2",
                  highlightbackground=COLORS["border2"], highlightthickness=1)
    if width:
        b.config(width=width)
    return b


def entry(parent, textvariable=None, width=30, placeholder=""):
    e = tk.Entry(parent, bg=COLORS["bg3"], fg=COLORS["txt"],
                 insertbackground=COLORS["accent"],
                 font=("Consolas", 10), relief="flat", bd=4,
                 highlightbackground=COLORS["border2"], highlightthickness=1,
                 width=width)
    if textvariable:
        e.config(textvariable=textvariable)
    if placeholder:
        e.insert(0, placeholder)
        e.config(fg=COLORS["txt3"])
        def on_focus_in(event):
            if e.get() == placeholder:
                e.delete(0, "end")
                e.config(fg=COLORS["txt"])
        def on_focus_out(event):
            if not e.get():
                e.insert(0, placeholder)
                e.config(fg=COLORS["txt3"])
        e.bind("<FocusIn>",  on_focus_in)
        e.bind("<FocusOut>", on_focus_out)
    return e


def text_area(parent, height=8, width=80, mono=True):
    frame = tk.Frame(parent, bg=COLORS["bg3"],
                     highlightbackground=COLORS["border2"], highlightthickness=1)
    t = tk.Text(frame, bg=COLORS["bg3"], fg=COLORS["txt"],
                insertbackground=COLORS["accent"],
                font=("Consolas" if mono else "Segoe UI", 9),
                relief="flat", bd=4, height=height, width=width,
                wrap="word", selectbackground=COLORS["bg4"],
                selectforeground=COLORS["accent"])
    sb = ttk.Scrollbar(frame, command=t.yview)
    t.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    t.pack(side="left", fill="both", expand=True)
    return frame, t


def scrolled_tree(parent, columns, headings, heights=18):
    frame = tk.Frame(parent, bg=COLORS["bg"])
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=heights)
    for col, head in zip(columns, headings):
        tree.heading(col, text=head)
        tree.column(col, width=120, anchor="w")
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    hsb.pack(side="bottom", fill="x")
    vsb.pack(side="right",  fill="y")
    tree.pack(side="left",  fill="both", expand=True)
    # row tags
    tree.tag_configure("CRITICAL", foreground=COLORS["red"])
    tree.tag_configure("WARNING",  foreground=COLORS["amber"])
    tree.tag_configure("INFO",     foreground=COLORS["accent"])
    tree.tag_configure("OK",       foreground=COLORS["green"])
    tree.tag_configure("SUS",      foreground=COLORS["red"])
    return frame, tree


def pill_label(parent, text, color):
    return tk.Label(parent, text=f" {text} ", bg=parent.cget("bg"),
                    fg=color, font=("Consolas", 8, "bold"),
                    relief="groove", bd=1, padx=2)


def separator(parent):
    return tk.Frame(parent, bg=COLORS["border"], height=1)


def scrolled_frame(parent):
    """Returns (outer_frame, inner_frame) — pack content into inner_frame."""
    canvas = tk.Canvas(parent, bg=COLORS["bg"], highlightthickness=0, bd=0)
    vsb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, bg=COLORS["bg"])
    inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=inner, anchor="nw")
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    canvas.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
    return canvas, inner
