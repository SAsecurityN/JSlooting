#!/usr/bin/env python3
import base64
import math
import os
import re
from collections import defaultdict
from urllib.parse import urlparse

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font as tkfont

_RAW_SECRET_PATTERNS = [
    ("AWS Access Key ID",        r"\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16})\b"),
    ("AWS Secret Access Key",    r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
    ("Google API Key",           r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    ("Google OAuth Token",       r"\b(ya29\.[0-9A-Za-z\-_]+)\b"),
    ("Firebase Cloud Messaging", r"\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b"),
    ("GCP Service Acct (JSON)",  r"\"type\"\s*:\s*\"service_account\""),
    ("Stripe Live Secret Key",   r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
    ("Stripe Restricted Key",    r"\b(rk_live_[0-9a-zA-Z]{24,})\b"),
    ("Stripe Publishable Key",   r"\b(pk_live_[0-9a-zA-Z]{24,})\b"),
    ("GitHub Token",             r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{36,})\b"),
    ("GitLab PAT",               r"\b(glpat-[0-9A-Za-z\-_]{20,})\b"),
    ("Slack Token",              r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
    ("Slack Webhook",            r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)"),
    ("Discord Webhook",          r"(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+)"),
    ("Discord Bot Token",        r"\b([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,})\b"),
    ("Twilio Account SID",       r"\b(AC[a-z0-9]{32})\b"),
    ("Twilio API Key",           r"\b(SK[a-z0-9]{32})\b"),
    ("SendGrid API Key",         r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
    ("Mailgun API Key",          r"\b(key-[0-9a-zA-Z]{32})\b"),
    ("Mailchimp API Key",        r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"),
    ("Square Access Token",      r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b"),
    ("Square OAuth Secret",      r"\b(sq0csp-[0-9A-Za-z\-_]{43})\b"),
    ("PayPal Braintree Token",   r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b"),
    ("NPM Access Token",         r"\b(npm_[0-9A-Za-z]{36})\b"),
    ("OpenAI API Key",           r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b"),
    ("Anthropic API Key",        r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
    ("Heroku API Key",           r"(?i)heroku.{0,20}?['\"]([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})['\"]"),
    ("Cloudinary URL",           r"(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+)"),
    ("JWT",                      r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})\b"),
    ("Private Key Block",        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"),
    ("Basic Auth in URL",        r"([a-zA-Z][\w+.-]*://[^/\s:@]+:[^/\s:@]+@[^\s/'\"]+)"),
    ("Generic Secret Assign",    r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|auth|access[_-]?key|client[_-]?secret|private[_-]?key)"
                                 r"[\"'\s]*[:=]\s*[\"']([^\"']{8,120})[\"']"),
]
SECRET_PATTERNS = [(label, re.compile(rx)) for label, rx in _RAW_SECRET_PATTERNS]
_ENTROPY_GATED = {"Generic Secret Assign", "AWS Secret Access Key"}

URL_RE = re.compile(r"""(?xi)\b((?:https?|wss?|ftp)://[^\s"'`<>()\[\]{}\\]+)""")

ENDPOINT_RE = re.compile(r"""(?x)
    ["'`](
      /(?:[A-Za-z0-9_\-.~%]+/)*
      (?:api|v\d+|graphql|rest|rpc|internal|admin|auth|oauth|token|user|users|
         account|upload|download|file|files|search|query|callback|webhook|
         config|settings|debug|status|health|metrics|export|import|proxy)
      [A-Za-z0-9_\-./~%]*
    )["'`]
""", re.IGNORECASE)

HOST_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24}))\b")
IPV4_RE = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})\b")
BUCKET_RE = re.compile(r"""(?xi)(
      [a-z0-9.\-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com |
      s3\.amazonaws\.com/[a-z0-9.\-]+                     |
      [a-z0-9.\-]+\.blob\.core\.windows\.net              |
      storage\.googleapis\.com/[a-z0-9.\-_]+              |
      [a-z0-9.\-]+\.storage\.googleapis\.com              |
      [a-z0-9.\-]+\.r2\.cloudflarestorage\.com            |
      [a-z0-9.\-]+\.digitaloceanspaces\.com
)""")

_BORING_HOST_SUFFIXES = (
    "w3.org", "schema.org", "example.com", "example.org", "example.net",
    "jquery.com", "jsdelivr.net", "unpkg.com", "cloudflare.com", "gstatic.com",
    "bootstrapcdn.com", "fontawesome.com", "google-analytics.com",
    "googletagmanager.com", "polyfill.io", "cdnjs.com", "cdnjs.cloudflare.com",
    "googleapis.com", "google.com", "youtube.com", "ytimg.com",
    "facebook.com", "fbcdn.net", "twitter.com", "twimg.com", "github.com",
    "githubusercontent.com", "npmjs.com", "npmjs.org", "nodejs.org",
    "mozilla.org", "wikipedia.org", "wikimedia.org", "apache.org",
    "opensource.org", "creativecommons.org", "ietf.org", "iana.org",
    "localhost", "local", "test", "invalid", "internal",
)
_FILE_SUFFIXES = {
    "js", "css", "png", "jpg", "jpeg", "gif", "svg", "map", "json", "html",
    "htm", "woff", "woff2", "ttf", "ico", "webp", "min", "sql", "xml", "txt",
    "pdf", "zip", "gz", "tar", "csv", "yml", "yaml", "env", "md", "mp4",
    "mp3", "wasm", "bundle", "ts", "tsx", "jsx", "mjs", "cjs",
}
_REAL_TLDS = {
    "com", "net", "org", "io", "co", "ai", "app", "dev", "me", "info", "biz",
    "xyz", "tech", "online", "site", "cloud", "store", "shop", "blog", "news",
    "edu", "gov", "mil", "int", "uk", "us", "ca", "au", "de", "fr", "nl", "ru",
    "cn", "jp", "kr", "in", "br", "es", "it", "se", "no", "fi", "dk", "ch",
    "at", "be", "pl", "cz", "ie", "pt", "gr", "tr", "mx", "ar", "za", "nz",
    "sg", "hk", "tw", "my", "id", "ph", "th", "vn", "ae", "sa", "il", "eg",
    "tv", "cc", "ws", "to", "fm", "ly", "gg", "so", "sh", "ac", "io", "ai",
    "vercel.app", "netlify.app", "herokuapp.com", "pages.dev", "workers.dev",
    "github.io", "gitlab.io", "azurewebsites.net", "cloudapp.azure.com",
    "appspot.com", "firebaseapp.com", "web.app", "run.app", "ondigitalocean.app",
}
_JS_NOISE_LABELS = {
    "useeffect", "uselayouteffect", "usememo", "usecallback", "usestate",
    "usecontext", "useref", "usereducer", "useimperativehandle", "usedebugvalue",
    "prototype", "constructor", "tostring", "valueof", "hasownproperty",
    "isprototypeof", "propertyisenumerable", "tolocalestring", "startswith",
    "endswith", "includes", "indexof", "lastindexof", "substring", "substr",
    "slice", "split", "join", "concat", "replace", "match", "search", "test",
    "exec", "compile", "apply", "call", "bind", "push", "pop", "shift",
    "unshift", "splice", "sort", "reverse", "filter", "map", "reduce",
    "foreach", "some", "every", "find", "findindex", "flat", "flatmap",
    "keys", "values", "entries", "assign", "create", "defineproperty",
    "getprototypeof", "setprototypeof", "isextensible", "preventextensions",
    "freeze", "seal", "isfrozen", "issealed", "from", "of", "isarray",
    "parse", "stringify", "now", "round", "floor", "ceil", "abs", "max",
    "min", "pow", "sqrt", "random", "transform", "translate", "rotate",
    "scale", "matrix", "perspective", "getcontext", "createcontext",
    "webpackchunk", "webpackjsonp", "require", "exports", "module",
    "default", "length", "name", "message", "stack", "type", "target",
    "currenttarget", "src", "href", "pathname", "hostname", "protocol",
    "searchparams", "tostringtag", "iterator", "asynciterator", "species",
    "unscopables", "matchall", "replaceall", "padstart", "padend",
    "trimstart", "trimend", "trimleft", "trimright", "normalize",
    "codepointat", "fromcodepoint", "raw", "repeat", "localecompare",
    "this", "self", "window", "document", "global", "globalthis", "console",
    "process", "buffer", "object", "array", "string", "number", "boolean",
    "function", "symbol", "bigint", "undefined", "null", "true", "false",
    "id", "key", "val", "value", "data", "item", "node", "elem", "el",
    "ctx", "req", "res", "err", "error", "cb", "fn", "opts", "opt",
    "config", "cfg", "params", "args", "arg", "prop", "props", "attr",
    "class", "style", "css", "html", "text", "inner", "outer", "parent",
    "child", "children", "sibling", "next", "prev", "first", "last",
    "get", "set", "add", "remove", "delete", "update", "read", "write",
    "open", "close", "start", "stop", "run", "init", "load", "save",
    "send", "recv", "fetch", "post", "put", "patch", "head", "options",
    "emit", "on", "once", "off", "then", "catch", "finally", "resolve",
    "reject", "promise", "async", "await", "yield", "return", "throw",
    "try", "if", "else", "for", "while", "do", "switch", "case", "break",
    "continue", "var", "let", "const", "new", "typeof", "instanceof",
    "void", "with", "debugger", "eval", "arguments",
}


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(val):
    low = val.lower()
    if len(set(val)) <= 3:
        return True
    placeholders = ("your", "xxxx", "changeme", "example", "placeholder",
                    "insert", "todo", "dummy", "sample", "test", "foo", "bar",
                    "abcdef", "123456", "<", ">", "{{", "}}", "${", "%s",
                    "null", "undefined")
    return any(p in low for p in placeholders)


def _host_has_real_tld(host):
    host = host.lower().strip(".")
    for tld in _REAL_TLDS:
        if host == tld or host.endswith("." + tld):
            return True
    return False


def is_plausible_host(host):
    host = host.lower().strip(".")
    if len(host) < 6 or host.count(".") < 1:
        return False
    if any(host.endswith(b) for b in _BORING_HOST_SUFFIXES):
        return False
    if host.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
        return False
    if re.fullmatch(r"[\d.]+", host):
        return False
    if not _host_has_real_tld(host):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    sld = labels[-2]
    if len(tld) <= 2 and len(sld) < 3:
        return False
    for lab in labels:
        if not lab or len(lab) > 63:
            return False
        if lab in _JS_NOISE_LABELS:
            return False
        if lab.isdigit():
            return False
        if not re.fullmatch(r"[a-z0-9-]+", lab):
            return False
    return True


def is_full_url(u):
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https", "ws", "wss", "ftp"):
            return False
        if not p.netloc or "." not in p.netloc:
            return False
        host = (p.hostname or "").lower()
        if not host or len(host) < 4:
            return False
        if host.startswith(".") or host.endswith("."):
            return False
        if any(host.endswith(b) for b in _BORING_HOST_SUFFIXES):
            return False
        if not _host_has_real_tld(host):
            return False
        return True
    except Exception:
        return False


def line_index(text):
    idx, off = [], 0
    for i, line in enumerate(text.splitlines(keepends=True), start=1):
        idx.append((off, i))
        off += len(line)
    return idx


def offset_to_line(idx, offset):
    lo, hi, ans = 0, len(idx) - 1, 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if idx[mid][0] <= offset:
            ans = idx[mid][1]
            lo = mid + 1
        else:
            hi = mid - 1
    return ans


def scan_text(text, min_entropy=3.2):
    idx = line_index(text)
    lines = text.splitlines()
    findings = defaultdict(list)

    def add(category, value, offset, kind=None):
        ln = offset_to_line(idx, offset)
        snippet = lines[ln - 1].strip() if 0 <= ln - 1 < len(lines) else ""
        if len(snippet) > 240:
            snippet = snippet[:237] + "..."
        findings[category].append(
            {"line": ln, "value": value, "kind": kind, "snippet": snippet})

    seen_secrets = set()
    for label, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            captured = m.group(1) if m.groups() else m.group(0)
            key = (label, captured)
            if key in seen_secrets:
                continue
            if label in _ENTROPY_GATED:
                if looks_like_placeholder(captured):
                    continue
                if shannon_entropy(captured) < min_entropy:
                    continue
            seen_secrets.add(key)
            add("secrets", captured, m.start(), kind=label)

    seen = set()
    for m in URL_RE.finditer(text):
        u = m.group(1).rstrip(".,;)'\"")
        if u in seen:
            continue
        if not is_full_url(u):
            continue
        seen.add(u)
        add("urls", u, m.start())

    seen = set()
    for m in ENDPOINT_RE.finditer(text):
        ep = m.group(1)
        if ep not in seen:
            seen.add(ep)
            add("endpoints", ep, m.start(1))

    seen = set()
    for m in BUCKET_RE.finditer(text):
        b = m.group(1)
        if b not in seen:
            seen.add(b)
            add("buckets", b, m.start(1))

    seen = set()
    for m in HOST_RE.finditer(text):
        host = m.group(1).lower().strip(".")
        if host in seen:
            continue
        if not is_plausible_host(host):
            continue
        seen.add(host)
        kind = "subdomain" if host.count(".") >= 2 else "domain"
        add("hosts", host, m.start(1), kind=kind)

    seen = set()
    for m in IPV4_RE.finditer(text):
        ip = m.group(1)
        if ip in seen or ip == "0.0.0.0" or ip.endswith(".0.0"):
            continue
        seen.add(ip)
        add("ips", ip, m.start(1))

    seen = set()
    for m in EMAIL_RE.finditer(text):
        e = m.group(1)
        if e not in seen:
            seen.add(e)
            add("emails", e, m.start(1))

    seen = set()
    for m in re.finditer(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", text):
        blob = m.group(1)
        if blob in seen:
            continue
        seen.add(blob)
        try:
            dec = base64.b64decode(blob, validate=True)
            printable = sum(32 <= b < 127 for b in dec)
            if dec and printable / len(dec) > 0.85 and len(dec) >= 8:
                preview = dec.decode("latin-1")[:80]
                if any(t in preview.lower() for t in
                       ("http", "key", "secret", "token", "pass", "user", "@", "://")):
                    add("base64", preview, m.start(1), kind="decoded")
        except Exception:
            pass

    return findings


CATEGORY_META = [
    ("secrets",   "SECRETS / API KEYS",           "#FF5C5C"),
    ("buckets",   "CLOUD STORAGE BUCKETS",         "#C084FC"),
    ("urls",      "FULL URLs",                     "#5EC8FF"),
    ("endpoints", "RELATIVE ENDPOINTS",            "#3DDC97"),
    ("hosts",     "HOSTS / SUBDOMAINS",            "#F5C542"),
    ("ips",       "IP ADDRESSES",                  "#6BA3FF"),
    ("emails",    "EMAILS",                        "#6BA3FF"),
    ("base64",    "DECODED BASE64 (of interest)",  "#C084FC"),
]

# Premium dark palette — depth, contrast, restrained accent
BG        = "#0B0D0F"
SURFACE   = "#14181C"
PANEL     = "#161A1F"
ENTRYBG   = "#0E1114"
BORDER    = "#252A31"
BORDER_HI = "#32383F"
FG        = "#F2F4F7"
FG_SOFT   = "#B0B7C3"
DIM       = "#6B7380"
ACCENT    = "#3DDC97"
ACCENT_DIM= "#1F9A68"
SEPARATOR = "#1F242B"


class JSLootingGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("jslooting")
        self.geometry("1200x760")
        self.minsize(900, 560)
        self.configure(bg=BG)

        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jslooting_icon.png")
        if os.path.isfile(icon_path):
            try:
                self._icon = tk.PhotoImage(file=icon_path)
                self.iconphoto(True, self._icon)
            except Exception:
                pass

        self.current_file = None
        self._build_fonts()
        self._build_style()
        self._build_widgets()

    def _build_fonts(self):
        families = set(tkfont.families())
        mono_candidates = ("SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono",
                           "Liberation Mono", "Courier New", "Courier")
        ui_candidates = ("SF Pro Display", "Segoe UI", "Helvetica Neue",
                         "Helvetica", "Arial")

        mono_fam = next((f for f in mono_candidates if f in families), "Courier")
        ui_fam = next((f for f in ui_candidates if f in families), "Helvetica")

        self.mono = tkfont.Font(family=mono_fam, size=12)
        self.mono_sm = tkfont.Font(family=mono_fam, size=11)
        self.ui = tkfont.Font(family=ui_fam, size=11)
        self.ui_sm = tkfont.Font(family=ui_fam, size=10)
        self.ui_bold = tkfont.Font(family=ui_fam, size=11, weight="bold")
        self.ui_med = tkfont.Font(family=ui_fam, size=12)
        self.title_font = tkfont.Font(family=ui_fam, size=20, weight="bold")
        self.section_font = tkfont.Font(family=ui_fam, size=10, weight="bold")
        self.badge_font = tkfont.Font(family=ui_fam, size=10, weight="bold")

    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TButton",
                        background=SURFACE,
                        foreground=FG,
                        borderwidth=0,
                        focusthickness=0,
                        padding=(16, 9),
                        font=self.ui)
        style.map("TButton",
                  background=[("active", BORDER_HI), ("!active", SURFACE)],
                  foreground=[("active", FG), ("!active", FG)])

        style.configure("Accent.TButton",
                        background=ACCENT,
                        foreground="#000000",
                        borderwidth=0,
                        focusthickness=0,
                        padding=(20, 10),
                        font=self.ui_bold)
        style.map("Accent.TButton",
                  background=[("active", "#5DE87A"), ("!active", ACCENT)],
                  foreground=[("active", "#000000"), ("!active", "#000000")])

        style.configure("Ghost.TButton",
                        background=BORDER,
                        foreground=FG,
                        borderwidth=0,
                        focusthickness=0,
                        padding=(16, 9),
                        font=self.ui)
        style.map("Ghost.TButton",
                  background=[("active", BORDER_HI), ("!active", BORDER)],
                  foreground=[("active", FG), ("!active", FG)])

        style.configure("Vertical.TScrollbar",
                        background=BORDER,
                        troughcolor=BG,
                        borderwidth=0,
                        arrowcolor=DIM,
                        relief="flat")
        style.map("Vertical.TScrollbar",
                  background=[("active", BORDER_HI), ("!active", BORDER)])
        style.configure("Horizontal.TScrollbar",
                        background=BORDER,
                        troughcolor=BG,
                        borderwidth=0,
                        arrowcolor=DIM,
                        relief="flat")

    def _card(self, parent, **kwargs):
        outer = tk.Frame(parent, bg=BORDER, **kwargs)
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        return outer, inner

    def _select_all(self, event):
        w = event.widget
        w.tag_add("sel", "1.0", "end-1c")
        w.mark_set("insert", "1.0")
        w.see("insert")
        return "break"

    def _build_widgets(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=28, pady=(22, 0))

        tk.Label(header, text="jslooting", bg=BG, fg=FG,
                 font=self.title_font).pack(side="left")

        note_row = tk.Frame(self, bg=BG)
        note_row.pack(fill="x", padx=28, pady=(10, 0))
        tk.Label(
            note_row,
            text="Note: Some results may be false positives. Always verify findings independently.",
            bg=BG, fg=FG_SOFT, font=self.ui_bold, anchor="w"
        ).pack(side="left")

        div = tk.Frame(self, bg=SEPARATOR, height=1)
        div.pack(fill="x", padx=28, pady=(14, 0))

        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=28, pady=16)
        main.columnconfigure(0, weight=1, uniform="col")
        main.columnconfigure(1, weight=1, uniform="col")
        main.rowconfigure(0, weight=1)

        left_outer, left = self._card(main)
        left_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.rowconfigure(2, weight=1)
        left.columnconfigure(0, weight=1)

        lhead = tk.Frame(left, bg=PANEL)
        lhead.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 0))
        tk.Label(lhead, text="INPUT", bg=PANEL, fg=DIM,
                 font=self.section_font).pack(side="left")
        self.file_label = tk.Label(lhead, text="paste or upload a file",
                                   bg=PANEL, fg=DIM, font=self.ui_sm)
        self.file_label.pack(side="right")

        lbtns = tk.Frame(left, bg=PANEL)
        lbtns.grid(row=1, column=0, sticky="ew", padx=20, pady=(14, 12))

        ttk.Button(lbtns, text="Upload .js", style="Ghost.TButton",
                   command=self.on_upload).pack(side="left")
        ttk.Button(lbtns, text="Clear", style="Ghost.TButton",
                   command=self.on_clear).pack(side="left", padx=(8, 0))
        ttk.Button(lbtns, text="Scan", style="Accent.TButton",
                   command=self.on_scan).pack(side="right")

        in_frame = tk.Frame(left, bg=BORDER)
        in_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        in_inner = tk.Frame(in_frame, bg=ENTRYBG)
        in_inner.pack(fill="both", expand=True, padx=1, pady=1)
        in_inner.rowconfigure(0, weight=1)
        in_inner.columnconfigure(0, weight=1)

        self.input_text = tk.Text(
            in_inner, bg=ENTRYBG, fg=FG, insertbackground=ACCENT,
            font=self.mono, wrap="none", undo=True, relief="flat",
            padx=16, pady=14, selectbackground="#1A2F28",
            selectforeground=FG, highlightthickness=0, borderwidth=0
        )
        self.input_text.grid(row=0, column=0, sticky="nsew")

        in_sy = ttk.Scrollbar(in_inner, orient="vertical", command=self.input_text.yview)
        in_sy.grid(row=0, column=1, sticky="ns")
        in_sx = ttk.Scrollbar(in_inner, orient="horizontal", command=self.input_text.xview)
        in_sx.grid(row=1, column=0, sticky="ew")
        self.input_text.configure(yscrollcommand=in_sy.set, xscrollcommand=in_sx.set)

        self._placeholder_on = True
        self.input_text.insert("1.0", "// paste JavaScript here…")
        self.input_text.configure(fg=DIM)
        self.input_text.bind("<FocusIn>", self._clear_placeholder)
        self.input_text.bind("<Control-a>", self._select_all)
        self.input_text.bind("<Control-A>", self._select_all)
        self.input_text.bind("<Command-a>", self._select_all)
        self.input_text.bind("<Command-A>", self._select_all)

        right_outer, right = self._card(main)
        right_outer.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        rhead = tk.Frame(right, bg=PANEL)
        rhead.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 12))
        tk.Label(rhead, text="FINDINGS", bg=PANEL, fg=DIM,
                 font=self.section_font).pack(side="left")
        self.count_label = tk.Label(rhead, text="", bg=PANEL, fg=ACCENT,
                                    font=self.badge_font)
        self.count_label.pack(side="right")

        out_frame = tk.Frame(right, bg=BORDER)
        out_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        out_inner = tk.Frame(out_frame, bg=ENTRYBG)
        out_inner.pack(fill="both", expand=True, padx=1, pady=1)
        out_inner.rowconfigure(0, weight=1)
        out_inner.columnconfigure(0, weight=1)

        self.output = tk.Text(
            out_inner, bg=ENTRYBG, fg=FG, font=self.mono_sm,
            wrap="word", relief="flat", padx=18, pady=16,
            state="disabled", spacing1=2, spacing3=4,
            highlightthickness=0, borderwidth=0,
            selectbackground="#1A2F28", selectforeground=FG
        )
        self.output.grid(row=0, column=0, sticky="nsew")
        out_sy = ttk.Scrollbar(out_inner, orient="vertical", command=self.output.yview)
        out_sy.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=out_sy.set)
        self.output.bind("<Control-a>", self._select_all)
        self.output.bind("<Control-A>", self._select_all)
        self.output.bind("<Command-a>", self._select_all)
        self.output.bind("<Command-A>", self._select_all)

        self.output.tag_configure("dim", foreground=DIM)
        self.output.tag_configure("val", foreground=FG, font=self.mono)
        self.output.tag_configure("hdr", font=self.ui_bold, spacing1=14, spacing3=6)
        self.output.tag_configure("empty", foreground=DIM, font=self.ui)
        for cat, _title, color in CATEGORY_META:
            self.output.tag_configure(f"cat_{cat}", foreground=color, font=self.ui_bold)
            self.output.tag_configure(f"kind_{cat}", foreground=color)

        status_wrap = tk.Frame(self, bg=BG)
        status_wrap.pack(fill="x", padx=28, pady=(0, 18))
        self.status = tk.Label(status_wrap, text="Ready", bg=BG, fg=DIM,
                               font=self.ui_sm, anchor="w")
        self.status.pack(side="left")

    def _clear_placeholder(self, _evt=None):
        if self._placeholder_on:
            self.input_text.delete("1.0", "end")
            self.input_text.configure(fg=FG)
            self._placeholder_on = False

    def on_upload(self):
        path = filedialog.askopenfilename(
            title="Open JavaScript file",
            filetypes=[("JavaScript / source",
                        "*.js *.mjs *.cjs *.jsx *.ts *.tsx *.map"),
                       ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            text = None
            for enc in ("utf-8", "utf-16", "latin-1"):
                try:
                    text = raw.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if text is None:
                text = raw.decode("utf-8", errors="replace")
        except OSError as e:
            messagebox.showerror("Could not read file", str(e))
            return

        self._placeholder_on = False
        self.input_text.configure(fg=FG)
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", text)
        self.current_file = path
        name = os.path.basename(path)
        size = len(raw)
        self.file_label.configure(text=f"{name}  ·  {size:,} bytes")
        self.status.configure(text=f"Loaded {name}")
        self.on_scan()

    def on_clear(self):
        self.input_text.delete("1.0", "end")
        self.input_text.configure(fg=FG)
        self._placeholder_on = False
        self.current_file = None
        self.file_label.configure(text="paste or upload a file")
        self._set_output_clear()
        self.count_label.configure(text="")
        self.status.configure(text="Cleared")

    def _get_input(self):
        if self._placeholder_on:
            return ""
        return self.input_text.get("1.0", "end-1c")

    def on_scan(self):
        text = self._get_input()
        if not text.strip():
            self.status.configure(text="Nothing to scan — paste or upload JS first")
            self._set_output_clear()
            self.count_label.configure(text="")
            return
        self.status.configure(text="Scanning…")
        self.update_idletasks()
        try:
            findings = scan_text(text)
        except Exception as e:
            messagebox.showerror("Scan error", str(e))
            self.status.configure(text="Scan failed")
            return
        self._render(findings)

    def _set_output_clear(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    def _render(self, findings):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")

        total = 0
        for cat, title, _color in CATEGORY_META:
            items = findings.get(cat, [])
            if not items:
                continue
            total += len(items)
            self.output.insert("end", f"{title}  ({len(items)})\n",
                               ("hdr", f"cat_{cat}"))
            for it in items:
                self.output.insert("end", "  ›  ")
                self.output.insert("end", it["value"], ("val",))
                if it.get("kind"):
                    self.output.insert("end", f"  [{it['kind']}]",
                                       (f"kind_{cat}",))
                self.output.insert("end", "\n")
                self.output.insert("end", f"      L{it['line']}", ("dim",))
                if it.get("snippet"):
                    self.output.insert("end", f"   {it['snippet']}", ("dim",))
                self.output.insert("end", "\n")
            self.output.insert("end", "\n")

        if total == 0:
            self.output.insert("end", "No findings.\n", ("empty",))
            self.count_label.configure(text="0")
            self.status.configure(text="Scan complete — nothing matched")
        else:
            self.count_label.configure(text=f"{total} findings")
            self.status.configure(text="Scan complete")

        self.output.configure(state="disabled")


def main():
    app = JSLootingGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
