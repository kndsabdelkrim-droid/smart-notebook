# -*- coding: utf-8 -*-
"""
بنك المعلومات الذكي - Smart Notebook
تطبيق سطح مكتب (Tkinter + SQLite) متوافق مع Windows 7 وما فوق (Python 3.8).
- حماية بكلمة سر (PBKDF2-HMAC-SHA256 مع salt عشوائي)
- قاعدة بيانات محلية: %APPDATA%\\SmartNotebook\\kb.db
- بحث فوري بترتيب BM25 مع تطبيع عربي وتجذيع خفيف
- استخراج الأفكار الرئيسية والكلمات المفتاحية (TF-IDF) دون اتصال بالإنترنت
ملاحظة: كلمة السر تحمي الدخول إلى التطبيق؛ ملف قاعدة البيانات نفسه غير مشفّر.
"""
import os
import re
import math
import time
import hmac
import hashlib
import secrets
import sqlite3
from collections import Counter
import sys
import ssl
import json
import queue
import threading
import subprocess
import webbrowser
import urllib.request

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

APP_NAME = "SmartNotebook"
APP_TITLE = "بنك المعلومات الذكي"
FONT = ("Tahoma", 11)
FONT_BOLD = ("Tahoma", 11, "bold")
PBKDF2_ITERS = 200000
GITHUB_REPO = "kndsabdelkrim-droid/smart-notebook"
BUILD = 0  # يُستبدل تلقائياً برقم البناء أثناء GitHub Actions


# ======================================================================
#  معالجة النصوص
# ======================================================================
AR_DIAC = re.compile(r"[\u0617-\u061A\u064B-\u0652\u0640\u0670]")
TOKEN_RE = re.compile(r"\w+", re.UNICODE)
AR_CHARS = re.compile(r"[\u0600-\u06FF]")
SENT_SPLIT = re.compile(r"(?<=[\.\!\?\u061F\u061B])\s+|\n+")
_MAP = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي", "ة": "ه"})

AR_PREFIXES = ("وال", "بال", "كال", "فال", "لل", "ال")
AR_SUFFIXES = ("ات", "ون", "ين", "ان", "ها", "هم", "ه", "ي")


def normalize(text):
    text = AR_DIAC.sub("", text.lower())
    return text.translate(_MAP)


def stem(tok):
    if AR_CHARS.search(tok):
        for p in AR_PREFIXES:
            if tok.startswith(p) and len(tok) - len(p) >= 3:
                tok = tok[len(p):]
                break
        for s in AR_SUFFIXES:
            if tok.endswith(s) and len(tok) - len(s) >= 3:
                tok = tok[:-len(s)]
                break
        return tok
    if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss"):
        return tok[:-1]
    return tok


_STOP_RAW = """
في من على الى إلى عن مع هذا هذه ذلك تلك هو هي هم هن أن ان إن كان كانت يكون
التي الذي الذين اللذين ما لا لم لن قد كل بعد قبل بين حتى أو او ثم إذا اذا لكن
كما أي اي هنا هناك عند منذ خلال انا أنا نحن انت أنت كانوا يمكن ايضا أيضا فقط
the a an and or of to in on at for with by is are was were be been this that
these those it its as from but not no if then so than into about over under
"""
STOP = set()
for _w in _STOP_RAW.split():
    _n = normalize(_w)
    STOP.add(_n)
    STOP.add(stem(_n))


def analyze(text):
    """يرجع قائمة (جذع، الكلمة الأصلية) بعد حذف كلمات الوقف."""
    out = []
    for m in TOKEN_RE.finditer(text):
        surface = m.group()
        n = normalize(surface)
        if len(n) < 2 or n.isdigit() or n in STOP:
            continue
        s = stem(n)
        if s in STOP:
            continue
        out.append((s, surface))
    return out


def tokenize(text):
    return [s for s, _ in analyze(text)]


def split_sentences(text):
    return [p.strip() for p in SENT_SPLIT.split(text) if p and p.strip()]


# ======================================================================
#  قاعدة البيانات
# ======================================================================
def data_dir():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


class DB:
    def __init__(self, path):
        self.con = sqlite3.connect(path)
        self.con.row_factory = sqlite3.Row
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS notes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "title TEXT NOT NULL DEFAULT '',"
            "content TEXT NOT NULL DEFAULT '',"
            "tags TEXT NOT NULL DEFAULT '',"
            "created TEXT, updated TEXT)")
        self.con.commit()

    def get_setting(self, key):
        r = self.con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def set_setting(self, key, value):
        self.con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))
        self.con.commit()

    def all_notes(self):
        return self.con.execute(
            "SELECT * FROM notes ORDER BY updated DESC, id DESC").fetchall()

    def add(self, title, content, tags):
        t = now()
        cur = self.con.execute(
            "INSERT INTO notes(title,content,tags,created,updated) VALUES(?,?,?,?,?)",
            (title, content, tags, t, t))
        self.con.commit()
        return cur.lastrowid

    def update(self, nid, title, content, tags):
        self.con.execute(
            "UPDATE notes SET title=?, content=?, tags=?, updated=? WHERE id=?",
            (title, content, tags, now(), nid))
        self.con.commit()

    def delete(self, nid):
        self.con.execute("DELETE FROM notes WHERE id=?", (nid,))
        self.con.commit()


# ======================================================================
#  كلمة السر
# ======================================================================
def _hash_pw(pw, salt, iters):
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters)


def set_password(db, pw):
    salt = secrets.token_bytes(16)
    db.set_setting("pw_salt", salt.hex())
    db.set_setting("pw_iters", str(PBKDF2_ITERS))
    db.set_setting("pw_hash", _hash_pw(pw, salt, PBKDF2_ITERS).hex())


def verify_password(db, pw):
    try:
        salt = bytes.fromhex(db.get_setting("pw_salt"))
        iters = int(db.get_setting("pw_iters"))
        stored = bytes.fromhex(db.get_setting("pw_hash"))
    except Exception:
        return False
    return hmac.compare_digest(_hash_pw(pw, salt, iters), stored)


# ======================================================================
#  محرك البحث واستخراج الأفكار
# ======================================================================
class Engine:
    K1 = 1.5
    B = 0.75

    def __init__(self, db):
        self.db = db
        self.reload()

    def reload(self):
        self.notes = [dict(r) for r in self.db.all_notes()]
        self.by_id = {n["id"]: n for n in self.notes}
        self.docs = []
        self.hay = []
        df = Counter()
        for n in self.notes:
            toks = (tokenize(n["title"]) * 3 + tokenize(n["tags"]) * 2
                    + tokenize(n["content"]))
            c = Counter(toks)
            self.docs.append((c, len(toks)))
            df.update(c.keys())
            self.hay.append(normalize(n["title"] + " " + n["tags"] + " " + n["content"]))
        self.df = df
        self.N = len(self.notes)
        total = sum(l for _, l in self.docs)
        self.avg = (total / self.N) if self.N and total else 1.0

    def idf(self, term):
        d = self.df.get(term, 0)
        return math.log(1 + (self.N - d + 0.5) / (d + 0.5))

    def search(self, query):
        q = query.strip()
        if not q:
            return [(n, 0.0) for n in self.notes]
        nq = normalize(q)
        terms = set()
        for t in tokenize(q):
            if t in self.df:
                terms.add(t)
            elif len(t) >= 2:
                terms.update(v for v in self.df if v.startswith(t))
        out = []
        for n, (c, length), hay in zip(self.notes, self.docs, self.hay):
            score = 0.0
            for t in terms:
                f = c.get(t, 0)
                if f:
                    score += self.idf(t) * (f * (self.K1 + 1)) / (
                        f + self.K1 * (1 - self.B + self.B * length / self.avg))
            if nq in hay:
                score += 1.5
            if score > 0:
                out.append((n, score))
        out.sort(key=lambda x: -x[1])
        return out

    def key_ideas(self, text, n=5):
        sents = [s for s in split_sentences(text) if len(s) >= 8]
        if not sents:
            return []
        if len(sents) <= n:
            return sents
        toks = [tokenize(s) for s in sents]
        tf = Counter(t for ts in toks for t in ts)
        scores = []
        for i, ts in enumerate(toks):
            if not ts:
                scores.append(0.0)
                continue
            sc = sum((1 + math.log(tf[t])) * self.idf(t) for t in set(ts)) / math.sqrt(len(ts))
            if i == 0:
                sc *= 1.2
            scores.append(sc)
        top = sorted(range(len(sents)), key=lambda i: -scores[i])[:n]
        return [sents[i] for i in sorted(top)]

    def keywords(self, text, k=8):
        pairs = analyze(text)
        if not pairs:
            return []
        tf = Counter(s for s, _ in pairs)
        surf = {}
        for s, w in pairs:
            surf.setdefault(s, Counter())[w] += 1
        ranked = sorted(tf, key=lambda s: -(1 + math.log(tf[s])) * self.idf(s))
        return [surf[s].most_common(1)[0][0] for s in ranked[:k]]

    def ask(self, query, top_notes=6, per_note=2):
        res = self.search(query)[:top_notes]
        qt = set(tokenize(query))
        items = []
        for n, sc in res:
            ranked = []
            for s in split_sentences(n["content"]):
                ts = set(tokenize(s))
                ov = sum(self.idf(t) for t in ts
                         if t in qt or any(t.startswith(x) for x in qt))
                if ov > 0:
                    ranked.append((ov, s))
            ranked.sort(key=lambda x: -x[0])
            picks = [s for _, s in ranked[:per_note]]
            if not picks:
                picks = self.key_ideas(n["content"], 1)
            items.append((n, sc, picks))
        return items


# ======================================================================
#  واجهات
# ======================================================================
def _ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def fetch_latest_release():
    """يجلب آخر إصدار منشور على GitHub. يرجع dict أو None."""
    url = "https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO
    req = urllib.request.Request(url, headers={
        "User-Agent": APP_NAME, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=10, context=_ssl_context()) as r:
        data = json.loads(r.read().decode("utf-8"))
    m = re.search(r"(\d+)\s*$", data.get("tag_name", ""))
    if not m:
        return None
    asset = None
    for a in data.get("assets", []):
        if a.get("name", "").lower() == "smartnotebook.exe":
            asset = a.get("browser_download_url")
    return {"build": int(m.group(1)),
            "page": data.get("html_url") or "https://github.com/%s/releases" % GITHUB_REPO,
            "asset": asset}


UPDATE_BAT = """@echo off
chcp 65001 >nul
cd /d "%~dp0"
set n=0
:retry
set /a n+=1
ping 127.0.0.1 -n 2 >nul
move /y "{new}" "{exe}" >nul 2>&1
if errorlevel 1 if %n% lss 30 goto retry
start "" "{exe}"
del "%~f0"
"""


def center(win, w, h):
    win.update_idletasks()
    x = (win.winfo_screenwidth() - w) // 2
    y = (win.winfo_screenheight() - h) // 2
    win.geometry("%dx%d+%d+%d" % (w, h, x, y))


def setup_style(root):
    style = ttk.Style(root)
    for th in ("vista", "xpnative", "clam"):
        try:
            style.theme_use(th)
            break
        except tk.TclError:
            continue
    style.configure(".", font=FONT)
    style.configure("Treeview", font=FONT, rowheight=26)
    style.configure("Treeview.Heading", font=FONT_BOLD)
    style.configure("Accent.TButton", font=FONT_BOLD)


def run_login(db):
    win = tk.Tk()
    win.title(APP_TITLE)
    win.resizable(False, False)
    setup_style(win)
    center(win, 380, 270)
    first = not db.get_setting("pw_hash")
    state = {"ok": False, "tries": 0}

    frm = ttk.Frame(win, padding=24)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text=APP_TITLE, font=("Tahoma", 16, "bold")).pack(pady=(0, 6))
    ttk.Label(frm, text="إنشاء كلمة سر جديدة" if first else "أدخل كلمة السر للمتابعة").pack(pady=(0, 12))

    e1 = ttk.Entry(frm, show="•", justify="center", font=FONT)
    e1.pack(fill="x", pady=4)
    e2 = None
    if first:
        e2 = ttk.Entry(frm, show="•", justify="center", font=FONT)
        e2.pack(fill="x", pady=4)
        ttk.Label(frm, text="(أعد كتابة كلمة السر للتأكيد)", foreground="#666").pack()
    msg = ttk.Label(frm, text="", foreground="#b00020")
    msg.pack(pady=6)

    def submit(event=None):
        pw = e1.get()
        if first:
            if len(pw) < 4:
                msg.config(text="كلمة السر قصيرة جداً (4 أحرف على الأقل)")
                return
            if pw != e2.get():
                msg.config(text="كلمتا السر غير متطابقتين")
                return
            set_password(db, pw)
            state["ok"] = True
            win.destroy()
            return
        if verify_password(db, pw):
            state["ok"] = True
            win.destroy()
            return
        state["tries"] += 1
        e1.delete(0, "end")
        if state["tries"] >= 5:
            win.destroy()
            return
        msg.config(text="كلمة السر غير صحيحة (%d/5)" % state["tries"])

    ttk.Button(frm, text="إنشاء وفتح" if first else "دخول", style="Accent.TButton",
               command=submit).pack(fill="x", pady=4)
    win.bind("<Return>", submit)
    e1.focus_set()
    win.mainloop()
    return state["ok"]


class App:
    def __init__(self, root, db):
        self.root = root
        self.db = db
        self.engine = Engine(db)
        self.current_id = None
        self.snapshot = ("", "", "")
        self._loading = False
        self._after = None

        root.title(APP_TITLE)
        setup_style(root)
        center(root, 1100, 680)
        root.minsize(900, 560)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.search_var = tk.StringVar()
        self.title_var = tk.StringVar()
        self.tags_var = tk.StringVar()
        self.status_var = tk.StringVar()
        self.build_ui()
        self.refresh_list()
        # اختصارات لوحة المفاتيح تعمل بغض النظر عن لغة لوحة المفاتيح (عربي/فرنسي/إنجليزي)
        root.bind_all("<Control-KeyPress>", self.on_ctrl_key)
        # قائمة النقر بالزر الأيمن: قص / نسخ / لصق / تحديد الكل
        for cls in ("Text", "Entry", "TEntry"):
            root.bind_class(cls, "<Button-3>", self.show_menu)
        # التحديث التلقائي: فحص عند التشغيل ثم كل 20 دقيقة
        self.update_q = queue.Queue()
        self.update_info = None
        self.dismissed = 0
        root.after(1000, self.poll_update)
        root.after(3000, self.periodic_update)

    # ------------------------------------------------------------ UI
    def build_ui(self):
        top = ttk.Frame(self.root, padding=(10, 8))
        top.pack(fill="x")
        self.top = top
        # شريط إشعار التحديث (مخفي حتى يوجد إصدار جديد)
        self.banner = tk.Frame(self.root, background="#fff3cd", padx=10, pady=6)
        self.banner_label = tk.Label(self.banner, background="#fff3cd", font=FONT_BOLD, anchor="e")
        self.btn_update = ttk.Button(self.banner, text="تحديث الآن", style="Accent.TButton",
                                     command=self.apply_update)
        self.btn_later = ttk.Button(self.banner, text="لاحقاً", command=self.hide_banner)
        self.btn_update.pack(side="left", padx=3)
        self.btn_later.pack(side="left", padx=3)
        self.banner_label.pack(side="right", fill="x", expand=True)
        ttk.Button(top, text="ملاحظة جديدة", command=self.new_note).pack(side="right", padx=3)
        ttk.Button(top, text="أفكار من البحث", style="Accent.TButton",
                   command=self.show_search_ideas).pack(side="right", padx=3)
        ttk.Button(top, text="مسح", width=6, command=self.clear_search).pack(side="right", padx=3)
        self.search_entry = ttk.Entry(top, textvariable=self.search_var, justify="right", font=FONT)
        self.search_entry.pack(side="right", fill="x", expand=True, padx=6)
        ttk.Label(top, text="بحث:").pack(side="right")
        self.search_entry.bind("<KeyRelease>", self.on_search_key)
        self.search_entry.bind("<Return>", lambda e: self.show_search_ideas())

        pw = ttk.PanedWindow(self.root, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        # --- المحرر (يسار)
        left = ttk.Frame(pw, padding=(0, 0, 8, 0))
        pw.add(left, weight=3)
        r1 = ttk.Frame(left)
        r1.pack(fill="x", pady=2)
        ttk.Entry(r1, textvariable=self.title_var, justify="right", font=FONT).pack(
            side="right", fill="x", expand=True, padx=4)
        ttk.Label(r1, text="العنوان:", width=9, anchor="e").pack(side="right")
        r2 = ttk.Frame(left)
        r2.pack(fill="x", pady=2)
        ttk.Entry(r2, textvariable=self.tags_var, justify="right", font=FONT).pack(
            side="right", fill="x", expand=True, padx=4)
        ttk.Label(r2, text="وسوم:", width=9, anchor="e").pack(side="right")

        ef = ttk.Frame(left)
        ef.pack(fill="both", expand=True, pady=4)
        sb = ttk.Scrollbar(ef)
        sb.pack(side="left", fill="y")
        self.text = tk.Text(ef, wrap="word", font=("Tahoma", 12), undo=True,
                            yscrollcommand=sb.set, height=10, padx=6, pady=6)
        self.text.pack(side="right", fill="both", expand=True)
        sb.config(command=self.text.yview)
        self.text.tag_configure("rtl", justify="right")
        self.text.bind("<KeyRelease>", lambda e: self.text.tag_add("rtl", "1.0", "end"))

        br = ttk.Frame(left)
        br.pack(fill="x", pady=2)
        ttk.Button(br, text="حفظ  (Ctrl+S)", style="Accent.TButton",
                   command=self.save_note).pack(side="right", padx=3)
        ttk.Button(br, text="حذف", command=self.delete_note).pack(side="right", padx=3)
        ttk.Button(br, text="أفكار الملاحظة", command=self.show_note_ideas).pack(side="right", padx=3)
        ttk.Button(br, text="تصدير الكل", command=self.export_all).pack(side="left", padx=3)
        ttk.Button(br, text="تغيير كلمة السر", command=self.change_password).pack(side="left", padx=3)
        ttk.Button(br, text="تحقق من التحديث (رقم %d)" % BUILD,
                   command=lambda: self.check_update(True)).pack(side="left", padx=3)

        ttk.Label(left, text="الأفكار الرئيسية:", font=FONT_BOLD, anchor="e").pack(fill="x", pady=(6, 0))
        of = ttk.Frame(left)
        of.pack(fill="both", expand=True, pady=2)
        sb2 = ttk.Scrollbar(of)
        sb2.pack(side="left", fill="y")
        self.out = tk.Text(of, wrap="word", font=FONT, height=9, state="disabled",
                           background="#f7f9fc", yscrollcommand=sb2.set, padx=6, pady=6)
        self.out.pack(side="right", fill="both", expand=True)
        sb2.config(command=self.out.yview)
        self.out.tag_configure("rtl", justify="right")
        self.out.tag_configure("h", font=FONT_BOLD, foreground="#0b4f8a", spacing1=6)
        self.out.tag_configure("b", lmargin1=6, lmargin2=6, spacing1=2)
        self.out.tag_configure("k", foreground="#2e7d32")

        # --- القائمة (يمين)
        right = ttk.Frame(pw, padding=(8, 0, 0, 0))
        pw.add(right, weight=1)
        self.tree = ttk.Treeview(right, columns=("t",), show="headings", selectmode="browse")
        self.tree.heading("t", text="الملاحظات", anchor="e")
        self.tree.column("t", anchor="e", width=260)
        tsb = ttk.Scrollbar(right, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tsb.set)
        tsb.pack(side="left", fill="y")
        self.tree.pack(side="right", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        ttk.Label(self.root, textvariable=self.status_var, anchor="e", relief="sunken",
                  padding=(8, 2)).pack(fill="x", side="bottom")

    # ------------------------------------------------------------ التحديث التلقائي
    def periodic_update(self):
        self.check_update(False)
        self.root.after(20 * 60 * 1000, self.periodic_update)

    def check_update(self, manual=False):
        def work():
            try:
                self.update_q.put(("ok", fetch_latest_release(), manual))
            except Exception as ex:
                self.update_q.put(("err", str(ex), manual))
        threading.Thread(target=work, daemon=True).start()

    def poll_update(self):
        try:
            while True:
                kind, payload, manual = self.update_q.get_nowait()
                self.handle_update_msg(kind, payload, manual)
        except queue.Empty:
            pass
        self.root.after(700, self.poll_update)

    def handle_update_msg(self, kind, payload, manual):
        if kind == "err":
            if manual:
                messagebox.showwarning(APP_TITLE, "تعذر الاتصال بـ GitHub. تحقق من الإنترنت.")
        elif kind == "ok":
            info = payload
            if info and info["build"] > BUILD:
                self.update_info = info
                if manual or info["build"] != self.dismissed:
                    self.show_banner("🔔 يوجد تحديث جديد للمفكرة (الإصدار %d)" % info["build"])
            elif manual:
                messagebox.showinfo(APP_TITLE, "أنت تستخدم أحدث إصدار (رقم %d)." % BUILD)
        elif kind == "prog":
            self.banner_label.config(text="جارٍ تنزيل التحديث... %d%%" % payload)
        elif kind == "done":
            self.finish_update(payload)
        elif kind == "dlerr":
            self.btn_update.config(state="normal")
            self.show_banner("فشل التنزيل التلقائي، سيُفتح موقع التحميل.")
            if self.update_info:
                webbrowser.open(self.update_info["page"])

    def show_banner(self, text):
        self.banner_label.config(text=text)
        if not self.banner.winfo_ismapped():
            self.banner.pack(fill="x", before=self.top)

    def hide_banner(self):
        if self.update_info:
            self.dismissed = self.update_info["build"]
        self.banner.pack_forget()

    def apply_update(self):
        info = self.update_info
        if not info:
            return
        # عند التشغيل من الشيفرة المصدرية أو بدون ملف جاهز: افتح صفحة التحميل
        if not getattr(sys, "frozen", False) or not info.get("asset"):
            webbrowser.open(info["page"])
            return
        if not self.confirm_discard():
            return
        new = sys.executable + ".new"
        self.btn_update.config(state="disabled")
        self.banner_label.config(text="جارٍ تنزيل التحديث... 0%")

        def work():
            try:
                req = urllib.request.Request(info["asset"], headers={"User-Agent": APP_NAME})
                with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as r, \
                        open(new, "wb") as f:
                    total = int(r.headers.get("Content-Length") or 0)
                    got = 0
                    while True:
                        chunk = r.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        got += len(chunk)
                        if total:
                            self.update_q.put(("prog", int(got * 100 / total), False))
                with open(new, "rb") as f:
                    head = f.read(2)
                if head != b"MZ" or (total and got != total):
                    raise IOError("bad download")
                self.update_q.put(("done", new, False))
            except Exception as ex:
                try:
                    if os.path.exists(new):
                        os.remove(new)
                except Exception:
                    pass
                self.update_q.put(("dlerr", str(ex), False))
        threading.Thread(target=work, daemon=True).start()

    def finish_update(self, new):
        exe = sys.executable
        folder = os.path.dirname(exe)
        bat = os.path.join(folder, "_update.bat")
        try:
            with open(bat, "w", encoding="utf-8") as f:
                f.write(UPDATE_BAT.format(new=os.path.basename(new), exe=os.path.basename(exe)))
            env = {k: v for k, v in os.environ.items() if k != "_MEIPASS2"}
            env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
            subprocess.Popen(["cmd", "/c", bat], cwd=folder, env=env,
                             creationflags=0x08000000, close_fds=True)
        except Exception:
            self.btn_update.config(state="normal")
            self.show_banner("تعذر تطبيق التحديث، سيُفتح موقع التحميل.")
            if self.update_info:
                webbrowser.open(self.update_info["page"])
            return
        self.root.destroy()

    # ------------------------------------------------------------ لوحة المفاتيح
    @staticmethod
    def select_all(w):
        if isinstance(w, tk.Text):
            w.tag_add("sel", "1.0", "end-1c")
            w.mark_set("insert", "end-1c")
        else:
            w.select_range(0, "end")
            w.icursor("end")

    def on_ctrl_key(self, e):
        kc = e.keycode
        # لوحة لاتينية: الاختصارات الافتراضية تعمل، لا حاجة للتدخل
        if 65 <= kc <= 90 and e.keysym.lower() == chr(kc).lower():
            return None
        w = e.widget
        editable = isinstance(w, (tk.Text, tk.Entry, ttk.Entry))
        if kc == 86 and editable:
            w.event_generate("<<Paste>>")
        elif kc == 67 and editable:
            w.event_generate("<<Copy>>")
        elif kc == 88 and editable:
            w.event_generate("<<Cut>>")
        elif kc == 65 and editable:
            self.select_all(w)
        elif kc == 90 and isinstance(w, tk.Text):
            try:
                w.edit_undo()
            except tk.TclError:
                pass
        elif kc == 89 and isinstance(w, tk.Text):
            try:
                w.edit_redo()
            except tk.TclError:
                pass
        elif kc == 83:
            self.save_note()
        elif kc == 78:
            self.new_note()
        elif kc == 70:
            self.search_entry.focus_set()
        else:
            return None
        return "break"

    def show_menu(self, e):
        w = e.widget
        w.focus_set()
        m = tk.Menu(self.root, tearoff=0, font=FONT)
        m.add_command(label="قص", command=lambda: w.event_generate("<<Cut>>"))
        m.add_command(label="نسخ", command=lambda: w.event_generate("<<Copy>>"))
        m.add_command(label="لصق", command=lambda: w.event_generate("<<Paste>>"))
        m.add_separator()
        m.add_command(label="تحديد الكل", command=lambda: self.select_all(w))
        try:
            m.tk_popup(e.x_root, e.y_root)
        finally:
            m.grab_release()

    # ------------------------------------------------------------ قائمة وبحث
    def on_search_key(self, event=None):
        if event is not None and event.keysym in ("Return", "Tab"):
            return
        if self._after:
            self.root.after_cancel(self._after)
        self._after = self.root.after(180, self.refresh_list)

    def clear_search(self):
        self.search_var.set("")
        self.refresh_list()

    def refresh_list(self, select_id=None):
        q = self.search_var.get().strip()
        results = self.engine.search(q)
        self._loading = True
        try:
            self.tree.delete(*self.tree.get_children())
            for n, _ in results:
                self.tree.insert("", "end", iid=str(n["id"]), values=(n["title"] or "بدون عنوان",))
            sid = select_id if select_id is not None else self.current_id
            if sid is not None and self.tree.exists(str(sid)):
                self.tree.selection_set(str(sid))
                self.tree.see(str(sid))
        finally:
            self._loading = False
        if q:
            self.status_var.set("النتائج: %d من %d ملاحظة" % (len(results), self.engine.N))
        else:
            self.status_var.set("إجمالي الملاحظات: %d" % self.engine.N)

    # ------------------------------------------------------------ المحرر
    def state(self):
        return (self.title_var.get().strip(), self.tags_var.get().strip(),
                self.text.get("1.0", "end-1c").strip())

    def is_dirty(self):
        cur = self.state()
        if self.current_id is None and cur == ("", "", ""):
            return False
        return cur != self.snapshot

    def confirm_discard(self):
        if not self.is_dirty():
            return True
        ans = messagebox.askyesnocancel(APP_TITLE, "توجد تغييرات غير محفوظة. هل تريد حفظها؟")
        if ans is None:
            return False
        if ans:
            return self.save_note()
        return True

    def load_note(self, nid):
        n = self.engine.by_id.get(nid)
        if not n:
            return
        self.current_id = nid
        self.title_var.set(n["title"])
        self.tags_var.set(n["tags"])
        self.text.delete("1.0", "end")
        self.text.insert("1.0", n["content"])
        self.text.tag_add("rtl", "1.0", "end")
        self.snapshot = self.state()
        self.write_ideas([])

    def on_select(self, event=None):
        if self._loading:
            return
        sel = self.tree.selection()
        if not sel:
            return
        nid = int(sel[0])
        if nid == self.current_id:
            return
        if not self.confirm_discard():
            self._loading = True
            try:
                if self.current_id is not None and self.tree.exists(str(self.current_id)):
                    self.tree.selection_set(str(self.current_id))
                else:
                    self.tree.selection_remove(sel)
            finally:
                self._loading = False
            return
        self.load_note(nid)

    def new_note(self):
        if not self.confirm_discard():
            return
        self.current_id = None
        self.title_var.set("")
        self.tags_var.set("")
        self.text.delete("1.0", "end")
        self.snapshot = ("", "", "")
        self._loading = True
        try:
            self.tree.selection_remove(self.tree.selection())
        finally:
            self._loading = False
        self.write_ideas([])
        self.text.focus_set()

    def save_note(self):
        title, tags, content = self.state()
        if not title and not content:
            messagebox.showinfo(APP_TITLE, "الملاحظة فارغة.")
            return False
        if not title:
            first = content.splitlines()[0] if content else ""
            title = (first[:40] or "بدون عنوان").strip()
            self.title_var.set(title)
        if self.current_id is None:
            self.current_id = self.db.add(title, content, tags)
        else:
            self.db.update(self.current_id, title, content, tags)
        self.engine.reload()
        self.snapshot = self.state()
        self.refresh_list(select_id=self.current_id)
        self.status_var.set("تم الحفظ  •  إجمالي الملاحظات: %d" % self.engine.N)
        return True

    def delete_note(self):
        if self.current_id is None:
            return
        if not messagebox.askyesno(APP_TITLE, "حذف هذه الملاحظة نهائياً؟"):
            return
        self.db.delete(self.current_id)
        self.engine.reload()
        self.current_id = None
        self.snapshot = ("", "", "")
        self.title_var.set("")
        self.tags_var.set("")
        self.text.delete("1.0", "end")
        self.write_ideas([])
        self.refresh_list()

    # ------------------------------------------------------------ الأفكار
    def write_ideas(self, blocks):
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        for kind, txt in blocks:
            if kind == "h":
                self.out.insert("end", txt + "\n", ("h",))
            elif kind == "b":
                self.out.insert("end", "•  " + txt + "\n", ("b",))
            elif kind == "k":
                self.out.insert("end", txt + "\n", ("k",))
            else:
                self.out.insert("end", txt + "\n")
        self.out.tag_add("rtl", "1.0", "end")
        self.out.config(state="disabled")

    def show_note_ideas(self):
        title, tags, content = self.state()
        if len(content) < 8:
            self.write_ideas([("n", "اكتب نصاً في الملاحظة أولاً.")])
            return
        ideas = self.engine.key_ideas(content, 5)
        kws = self.engine.keywords(title + " " + content, 8)
        blocks = [("h", "الأفكار الرئيسية")]
        blocks += [("b", s) for s in ideas]
        if kws:
            blocks += [("h", "الكلمات المفتاحية"), ("k", "  ،  ".join(kws))]
        self.write_ideas(blocks)

    def show_search_ideas(self):
        q = self.search_var.get().strip()
        if not q:
            self.write_ideas([("n", "اكتب كلمة أو سؤالاً في خانة البحث.")])
            return
        items = self.engine.ask(q)
        if not items:
            self.write_ideas([("n", "لا توجد نتائج مطابقة.")])
            return
        blocks = []
        for n, sc, picks in items:
            blocks.append(("h", n["title"] or "بدون عنوان"))
            blocks += [("b", s) for s in picks]
        joined = " ".join(n["title"] + " " + n["content"] for n, _, _ in items)
        kws = self.engine.keywords(joined, 8)
        if kws:
            blocks += [("h", "كلمات مرتبطة"), ("k", "  ،  ".join(kws))]
        self.write_ideas(blocks)
        self.refresh_list()

    # ------------------------------------------------------------ أدوات
    def export_all(self):
        if not self.engine.notes:
            messagebox.showinfo(APP_TITLE, "لا توجد ملاحظات للتصدير.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text", "*.txt")],
            initialfile="notes-export.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8-sig") as f:
            for n in self.engine.notes:
                f.write("# %s\n" % (n["title"] or "بدون عنوان"))
                if n["tags"]:
                    f.write("الوسوم: %s\n" % n["tags"])
                f.write("آخر تعديل: %s\n\n%s\n\n%s\n\n" % (n["updated"], n["content"], "-" * 40))
        self.status_var.set("تم التصدير: " + path)

    def change_password(self):
        old = simpledialog.askstring(APP_TITLE, "كلمة السر الحالية:", show="•", parent=self.root)
        if old is None:
            return
        if not verify_password(self.db, old):
            messagebox.showerror(APP_TITLE, "كلمة السر الحالية غير صحيحة.")
            return
        new = simpledialog.askstring(APP_TITLE, "كلمة السر الجديدة:", show="•", parent=self.root)
        if new is None:
            return
        if len(new) < 4:
            messagebox.showerror(APP_TITLE, "كلمة السر قصيرة جداً (4 أحرف على الأقل).")
            return
        again = simpledialog.askstring(APP_TITLE, "أعد كتابة كلمة السر الجديدة:", show="•", parent=self.root)
        if again != new:
            messagebox.showerror(APP_TITLE, "كلمتا السر غير متطابقتين.")
            return
        set_password(self.db, new)
        messagebox.showinfo(APP_TITLE, "تم تغيير كلمة السر.")

    def on_close(self):
        if self.confirm_discard():
            self.root.destroy()


def main():
    db = DB(os.path.join(data_dir(), "kb.db"))
    if not run_login(db):
        return
    root = tk.Tk()
    App(root, db)
    root.mainloop()


if __name__ == "__main__":
    main()
