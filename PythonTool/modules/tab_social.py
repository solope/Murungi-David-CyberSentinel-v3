"""
Social Media Evidence Feed
- Accepts ANY platform (not just twitter/telegram/reddit)
- Manual add with free-text platform field
- Upload JSON/CSV
- Flagged keyword detection
- Clear All button
- Per-platform filter
"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os, json, datetime, re
from modules.gui_theme import (COLORS, heading, label, btn, entry,
                                scrolled_tree, separator, text_area, card_frame)

SUSP_KW = [
    "exfil","payload","shell","exploit","backdoor","ransom","rootkit","keylog",
    "c2","wiped","mission done","stay dark","bomb","weapon","cocaine","crypto wallet",
    "kill","attack","target","delete evidence","wipe","cover tracks","money laundering",
    "darkweb","tor","onion","hitman","assassination","hide","dispose",
]

PLATFORM_COLORS = {
    "twitter":   ("#1da1f2", "TW"),
    "x":         ("#1da1f2", "X"),
    "telegram":  ("#0088cc", "TG"),
    "whatsapp":  ("#25d366", "WA"),
    "facebook":  ("#1877f2", "FB"),
    "instagram": ("#e1306c", "IG"),
    "tiktok":    ("#ff0050", "TK"),
    "reddit":    ("#ff4500", "RD"),
    "youtube":   ("#ff0000", "YT"),
    "snapchat":  ("#fffc00", "SC"),
    "discord":   ("#5865f2", "DS"),
    "signal":    ("#3a76f0", "SG"),
    "linkedin":  ("#0a66c2", "LI"),
    "wechat":    ("#07c160", "WC"),
    "viber":     ("#7360f2", "VB"),
    "email":     ("#888888", "EM"),
}

def _plat_tag(platform: str) -> tuple:
    """Return (color, short_tag) for a platform name."""
    key = platform.lower().strip()
    return PLATFORM_COLORS.get(key, (COLORS["txt2"], platform[:2].upper()))


class SocialTab(tk.Frame):
    def __init__(self, parent, custody, root):
        super().__init__(parent, bg=COLORS["bg"])
        self.custody   = custody
        self.all_msgs  = []
        self._build()

    def _build(self):
        heading(self, "Social Media Evidence Feed").pack(anchor="w", padx=16, pady=(14,4))
        label(self,
              "Upload a JSON/CSV export  OR  add messages manually. "
              "Any platform is supported — type the name freely.",
              small=True).pack(anchor="w", padx=16)

        # ── Top action bar ────────────────────────────────────────────────
        tr = tk.Frame(self, bg=COLORS["bg"])
        tr.pack(fill="x", padx=16, pady=8)
        btn(tr, "Upload JSON/CSV",  self._upload,      color=COLORS["green"]).pack(side="left", padx=4)
        btn(tr, "Load Demo",        self._demo,        color=COLORS["txt2"]).pack(side="left", padx=4)
        btn(tr, "Clear All",        self._clear_all,   color=COLORS["red"]).pack(side="left", padx=4)

        # ── Filter bar ────────────────────────────────────────────────────
        fbar = tk.Frame(self, bg=COLORS["bg"])
        fbar.pack(fill="x", padx=16, pady=2)
        label(fbar, "Filter platform:").pack(side="left")
        self.plat_filter = tk.StringVar(value="ALL")
        self._plat_menu  = ttk.Combobox(fbar, textvariable=self.plat_filter,
                                         state="readonly", width=14,
                                         font=("Segoe UI",9))
        self._plat_menu["values"] = ["ALL"]
        self._plat_menu.pack(side="left", padx=6)
        self._plat_menu.bind("<<ComboboxSelected>>", lambda _: self._render())

        self.flag_only = tk.BooleanVar()
        tk.Checkbutton(fbar, text="Flagged only", variable=self.flag_only,
                       command=self._render, bg=COLORS["bg"], fg=COLORS["txt2"],
                       selectcolor=COLORS["bg3"], activebackground=COLORS["bg"],
                       font=("Segoe UI",9)).pack(side="left", padx=8)

        self.kw_filter = tk.StringVar()
        self.kw_filter.trace("w", lambda *_: self._render())
        label(fbar, "Search:").pack(side="left", padx=(12,4))
        tk.Entry(fbar, textvariable=self.kw_filter,
                 bg=COLORS["bg3"], fg=COLORS["txt"],
                 insertbackground=COLORS["accent"],
                 font=("Consolas",9), relief="flat", bd=4,
                 highlightbackground=COLORS["border2"], highlightthickness=1,
                 width=24).pack(side="left")

        self.count_var = tk.StringVar(value="0 messages")
        tk.Label(fbar, textvariable=self.count_var, bg=COLORS["bg"],
                 fg=COLORS["txt3"], font=("Consolas",9)).pack(side="right", padx=8)

        separator(self).pack(fill="x", padx=16, pady=6)

        # ── Manual add card ────────────────────────────────────────────────
        mc = tk.LabelFrame(self, text="  Add Message Manually  ",
                           bg=COLORS["bg2"], fg=COLORS["accent"],
                           font=("Consolas",9), bd=1,
                           highlightbackground=COLORS["border2"])
        mc.pack(fill="x", padx=16, pady=4)

        inner = tk.Frame(mc, bg=COLORS["bg2"])
        inner.pack(fill="x", padx=10, pady=8)

        # Row 1 — platform + username
        r1 = tk.Frame(inner, bg=COLORS["bg2"])
        r1.pack(fill="x", pady=3)
        tk.Label(r1, text="Platform:", bg=COLORS["bg2"], fg=COLORS["txt2"],
                 font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
        self.plat_var = tk.StringVar(value="WhatsApp")
        plat_entry = tk.Entry(r1, textvariable=self.plat_var,
                              bg=COLORS["bg3"], fg=COLORS["txt"],
                              insertbackground=COLORS["accent"],
                              font=("Consolas",10), relief="flat", bd=4,
                              highlightbackground=COLORS["border2"],
                              highlightthickness=1, width=16)
        plat_entry.pack(side="left", padx=(0,16))

        # Platform quick-pick buttons
        for p in ("WhatsApp","Telegram","Twitter","Facebook","Instagram","Signal","Discord"):
            tk.Button(r1, text=p, bg=COLORS["bg3"], fg=COLORS["txt2"],
                      relief="flat", bd=0, font=("Segoe UI",8),
                      cursor="hand2",
                      command=lambda v=p: self.plat_var.set(v)).pack(side="left", padx=2)

        # Row 2 — username
        r2 = tk.Frame(inner, bg=COLORS["bg2"])
        r2.pack(fill="x", pady=3)
        tk.Label(r2, text="Username:", bg=COLORS["bg2"], fg=COLORS["txt2"],
                 font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
        self.user_var = tk.StringVar(value="@suspect")
        tk.Entry(r2, textvariable=self.user_var,
                 bg=COLORS["bg3"], fg=COLORS["txt"],
                 insertbackground=COLORS["accent"],
                 font=("Consolas",10), relief="flat", bd=4,
                 highlightbackground=COLORS["border2"], highlightthickness=1,
                 width=26).pack(side="left")

        # Row 3 — message
        r3 = tk.Frame(inner, bg=COLORS["bg2"])
        r3.pack(fill="x", pady=3)
        tk.Label(r3, text="Message:", bg=COLORS["bg2"], fg=COLORS["txt2"],
                 font=("Segoe UI",10), width=10, anchor="w").pack(side="left")
        self.msg_var = tk.StringVar()
        tk.Entry(r3, textvariable=self.msg_var,
                 bg=COLORS["bg3"], fg=COLORS["txt"],
                 insertbackground=COLORS["accent"],
                 font=("Consolas",10), relief="flat", bd=4,
                 highlightbackground=COLORS["border2"], highlightthickness=1,
                 width=70).pack(side="left", padx=(0,8))
        btn(r3, "➕ Add", self._add_manual, color=COLORS["green"]).pack(side="left")

        separator(self).pack(fill="x", padx=16, pady=6)

        # ── Feed tree ─────────────────────────────────────────────────────
        cols  = ("platform","username","timestamp","flagged","keywords","message")
        heads = ("Platform","Username","Timestamp","Flagged","Keywords","Message")
        tf, self.tree = scrolled_tree(self, cols, heads, heights=18)
        self.tree.column("platform",  width=100)
        self.tree.column("username",  width=130)
        self.tree.column("timestamp", width=140)
        self.tree.column("flagged",   width=70)
        self.tree.column("keywords",  width=160)
        self.tree.column("message",   width=340)
        tf.pack(fill="both", expand=True, padx=16, pady=(4,12))

    # ── Keyword helpers ───────────────────────────────────────────────────────
    def _is_flagged(self, text: str) -> bool:
        return any(k in text.lower() for k in SUSP_KW)

    def _get_kw(self, text: str) -> str:
        return ", ".join(k for k in SUSP_KW if k in text.lower())

    # ── Rendering ─────────────────────────────────────────────────────────────
    def _render(self):
        fo     = self.flag_only.get()
        plat_f = self.plat_filter.get()
        search = self.kw_filter.get().strip().lower()

        self.tree.delete(*self.tree.get_children())
        shown = 0
        for m in self.all_msgs:
            if fo and not m["flagged"]:
                continue
            if plat_f != "ALL" and m["platform"].lower() != plat_f.lower():
                continue
            if search and search not in m["message"].lower() and search not in m["username"].lower():
                continue
            tag = "CRITICAL" if m["flagged"] else ""
            self.tree.insert("","end",
                values=(m["platform"], m["username"], m.get("ts",""),
                        "⚠ YES" if m["flagged"] else "—",
                        m.get("keywords",""), m["message"][:160]),
                tags=(tag,))
            shown += 1
        self.count_var.set(f"{shown} / {len(self.all_msgs)} messages")

    def _update_platform_filter(self):
        platforms = sorted({m["platform"] for m in self.all_msgs})
        self._plat_menu["values"] = ["ALL"] + platforms

    # ── Actions ───────────────────────────────────────────────────────────────
    def _add_manual(self):
        plat = self.plat_var.get().strip() or "Unknown"
        user = self.user_var.get().strip() or "unknown"
        msg  = self.msg_var.get().strip()
        if not msg:
            messagebox.showwarning("Empty", "Please type a message before adding.")
            return
        flagged  = self._is_flagged(msg)
        keywords = self._get_kw(msg)
        ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.all_msgs.append({
            "platform": plat, "username": user,
            "message": msg, "ts": ts,
            "flagged": flagged, "keywords": keywords,
        })
        self.msg_var.set("")
        self._update_platform_filter()
        self._render()
        action = "FLAGGED_MESSAGE" if flagged else "MESSAGE_ADDED"
        self.custody.log(action, f"{plat}/{user}", msg[:60])
        if flagged:
            messagebox.showwarning("Flagged",
                                   f"Message flagged! Keywords detected:\n{keywords}")

    def _upload(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON/CSV","*.json *.csv *.txt"),("All","*.*")])
        if not path:
            return
        with open(path,"r",errors="ignore") as f:
            content = f.read()
        msgs = []
        # Try JSON
        try:
            data  = json.loads(content)
            items = data if isinstance(data, list) else data.get("messages", [])
            for item in items:
                msg  = item.get("message") or item.get("text") or item.get("content","")
                plat = item.get("platform") or item.get("source","Unknown")
                user = item.get("username") or item.get("user") or item.get("sender","unknown")
                ts   = item.get("ts") or item.get("timestamp") or item.get("date","")
                msgs.append({"platform":plat,"username":user,"message":msg,"ts":ts})
        except Exception:
            # Try CSV / line-separated
            for line in content.splitlines():
                p = line.split(",", 3)
                if len(p) >= 2:
                    msg = p[-1].strip()
                    msgs.append({
                        "platform": p[0].strip() or "Unknown",
                        "username": p[1].strip() if len(p) > 1 else "unknown",
                        "message":  msg,
                        "ts":       p[2].strip() if len(p) > 2 else "",
                    })

        for m in msgs:
            m["flagged"]  = self._is_flagged(m["message"])
            m["keywords"] = self._get_kw(m["message"])
        self.all_msgs.extend(msgs)
        self._update_platform_filter()
        self._render()
        flagged_n = sum(1 for m in msgs if m["flagged"])
        self.custody.log("SOCIAL_UPLOADED", os.path.basename(path),
                         f"{len(msgs)} messages, {flagged_n} flagged")
        messagebox.showinfo("Loaded",
                            f"Loaded {len(msgs)} messages\n"
                            f"Flagged: {flagged_n}")

    def _demo(self):
        demo = [
            {"platform":"WhatsApp",  "username":"suspect_A",     "message":"mission done. files are out. cleaning now","ts":"2024-11-08 02:17"},
            {"platform":"Telegram",  "username":"suspect_chan",   "message":"uploaded exfil_v2.zip to drop. stay dark","ts":"2024-11-08 02:19"},
            {"platform":"Reddit",    "username":"u/throwaway_8871","message":"logs wiped clean. rootkit via cron.","ts":"2024-11-08 02:45"},
            {"platform":"Facebook",  "username":"john.doe.981",   "message":"payment sent to crypto wallet address","ts":"2024-11-08 03:04"},
            {"platform":"Instagram", "username":"@shadow_0x4a",   "message":"exploit worked. backdoor planted","ts":"2024-11-08 02:22"},
            {"platform":"Signal",    "username":"anon_buyer",     "message":"send me the payload shell when ready","ts":"2024-11-08 01:30"},
            {"platform":"Discord",   "username":"hax0r#1337",     "message":"c2 server is live. keylogger active","ts":"2024-11-08 04:00"},
            {"platform":"TikTok",    "username":"@normal_user",   "message":"great day at the beach! #fun","ts":"2024-11-08 08:00"},
            {"platform":"Twitter",   "username":"@news_bot",      "message":"latest cybersecurity news update","ts":"2024-11-08 09:00"},
            {"platform":"WhatsApp",  "username":"suspect_B",      "message":"next target queued. supply chain attack ready","ts":"2024-11-08 05:00"},
        ]
        for m in demo:
            m["flagged"]  = self._is_flagged(m["message"])
            m["keywords"] = self._get_kw(m["message"])
        self.all_msgs.extend(demo)
        self._update_platform_filter()
        self._render()
        self.custody.log("DEMO_SOCIAL","demo",f"{len(demo)} messages")

    def _clear_all(self):
        if self.all_msgs and not messagebox.askyesno(
                "Clear All", "Remove all loaded messages?"):
            return
        self.all_msgs.clear()
        self._plat_menu["values"] = ["ALL"]
        self.plat_filter.set("ALL")
        self.kw_filter.set("")
        self.flag_only.set(False)
        self._render()
        self.custody.log("SOCIAL_CLEARED","social_feed","all messages removed")
