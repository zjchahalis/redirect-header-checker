"""Hop map and http/https tracer for the Redirect and Header Response Checker.

Adapted from the port80 viewer. It requests the http:// and https:// versions of a URL (and the www or non-www host),
follows every redirect one hop at a time, keeps every response header, and draws the result as a map: one column per
origin, one row per entry point, one arc per redirect.

Everything here returns plain data or HTML strings, so it can be tested without Streamlit. It reuses the checker's safety
rules: every hop goes through ``botcheck.check_address``, HSTS is never applied, and no cookies are carried.
"""
from __future__ import annotations

import concurrent.futures
import difflib
import hashlib
import html
import math
import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

import botcheck as bc

TEMP_REDIRECTS = {302, 303, 307}
HOT_HEADERS = {"location", "strict-transport-security", "x-robots-tag", "link", "alt-svc"}
MAX_BODY_BYTES = 1_000_000
BODY_PREVIEW_CHARS = 40_000
LIST_DISPLAY_ROWS = 500
SLOT_NAMES = {"http": "http", "https": "https", "http-alt": "http · other host", "https-alt": "https · other host"}
NUMBER_WORDS = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six"}


@dataclass
class Hop:
    url: str
    status: Optional[int]
    reason: str = ""
    http_version: str = ""
    ms: float = 0.0
    headers: List[Tuple[str, str]] = field(default_factory=list)
    location: Optional[str] = None
    error: Optional[str] = None

    def header(self, name: str) -> Optional[str]:
        vals = [v for k, v in self.headers if k.lower() == name.lower()]
        return ", ".join(vals) if vals else None


@dataclass
class Chain:
    label: str
    slot: str
    scheme: str
    start_url: str
    hops: List[Hop]
    final_url: str
    final_status: Optional[int]
    total_ms: float = 0.0
    body_bytes: int = 0
    body: str = ""
    page: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def codes(self) -> str:
        return " > ".join(str(h.status) if h.status else "ERR" for h in self.hops) or "ERR"

    @property
    def redirects(self) -> int:
        return sum(1 for h in self.hops if h.location)

    @property
    def host(self) -> str:
        return urlsplit(self.start_url).hostname or ""

    @property
    def resolved(self) -> bool:
        return bool(self.final_status and self.final_status < 400)


@dataclass
class Finding:
    sev: str                  # error | warn | info | ok
    scope: str
    msg: str
    chain: Optional[int] = None
    hop: Optional[int] = None


@dataclass
class TraceOptions:
    cfg: "bc.Config"
    method: str = "GET"                       # GET, or HEAD for a lighter check (no page signals)
    include_alt_host: bool = True
    verify_tls: bool = True
    extra_headers: Dict[str, str] = field(default_factory=dict)
    read_body: bool = True


# ------------------------------------------------------------------ fetching

def _short_error(e: Exception) -> str:
    msg = re.sub(r"\s+", " ", str(e))
    for marker in ("Caused by ", "Max retries exceeded"):
        if marker in msg:
            msg = msg.split(marker, 1)[-1]
    msg = re.sub(r"<urllib3\.[^>]+>", "", msg).strip(" :()'\"")
    if isinstance(e, requests.exceptions.SSLError):
        return f"TLS/SSL error: {msg[:200]}"
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return "Connection timed out"
    if isinstance(e, requests.exceptions.ReadTimeout):
        return "Read timed out"
    if isinstance(e, requests.exceptions.ConnectionError):
        return f"Connection failed: {msg[:200]}"
    return msg[:200] or e.__class__.__name__


class _Text(HTMLParser):
    """Visible text and the first h1, without needing BeautifulSoup."""
    SKIP = {"script", "style", "noscript", "svg", "head", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.h1, self._skip, self._in_h1 = "", 0, False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag == "h1" and not self.h1:
            self._in_h1 = True

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag == "h1":
            self._in_h1 = False

    def handle_data(self, data):
        if self._skip:
            return
        t = data.strip()
        if t:
            self.parts.append(t)
            if self._in_h1 and len(self.h1) < 200:
                self.h1 += (" " if self.h1 else "") + t


def page_signals(body: str, token: str, base_url: str, x_robots: str = "") -> Dict[str, str]:
    p = bc.parse_page(body, token)
    tp = _Text()
    try:
        tp.feed(body)
    except Exception:                                  # noqa: BLE001
        pass
    text = "\n".join(tp.parts)
    canon = urljoin(base_url, str(p["canonical"])) if p["canonical"] else ""
    return {"title": str(p["title"]), "canonical": canon, "meta_robots": str(p["meta_robots"]), "x_robots_tag": x_robots,
            "h1": tp.h1, "text": text, "text_hash": hashlib.sha1(text.encode()).hexdigest()[:12] if text else ""}


def fetch_chain(label: str, slot: str, url: str, opts: TraceOptions, limiter: "bc.HostLimiter",
                protocols: Optional["bc.ProtocolCache"] = None) -> Chain:
    cfg = opts.cfg
    s = requests.Session()
    s.trust_env = False
    headers = bc._headers(cfg)
    headers.update(opts.extra_headers)
    hops: List[Hop] = []
    seen, cur, err = set(), url, None
    body, body_bytes, page = "", 0, {}
    t_start = time.perf_counter()
    try:
        for _ in range(cfg.max_hops + 1):
            if bc.norm(cur) in seen:
                err = f"Redirect loop back to {cur}"
                break
            seen.add(bc.norm(cur))
            ok, why = bc.check_address(cur, cfg.allow_private, cfg.allowed_hosts)
            if not ok:
                err = "Blocked: " + why
                hops.append(Hop(cur, None, error=err))
                break
            limiter.wait(urlsplit(cur).netloc)
            t0 = time.perf_counter()
            try:
                r = s.request(opts.method, cur, headers=headers, allow_redirects=False, stream=True, verify=opts.verify_tls,
                              timeout=(cfg.connect_timeout, cfg.read_timeout))
            except requests.RequestException as e:
                err = _short_error(e)
                hops.append(Hop(cur, None, ms=(time.perf_counter() - t0) * 1000, error=err))
                break
            raw = r.raw.headers
            hl = [(k, v) for k in raw for v in raw.getlist(k)]
            loc = r.headers.get("Location") if r.status_code in bc.REDIRECT_CODES else None
            version = (protocols.get(cur) if (protocols and cfg.check_http_version) else "") or ""
            hop = Hop(cur, r.status_code, r.reason or "", version, (time.perf_counter() - t0) * 1000, hl,
                      urljoin(cur, loc) if loc else None)
            hops.append(hop)
            if hop.location:
                r.close()
                cur = hop.location
                continue
            if opts.read_body and opts.method != "HEAD":
                buf = b""
                for chunk in r.iter_content(65536):
                    buf += chunk
                    if len(buf) >= MAX_BODY_BYTES:
                        break
                body_bytes = len(buf)
                if "html" in (r.headers.get("Content-Type") or "").lower():
                    body = buf.decode(r.encoding if r.encoding and r.encoding.lower() != "iso-8859-1" else "utf-8", errors="replace")
                    page = page_signals(body, cfg.token, cur, r.headers.get("X-Robots-Tag", ""))
            r.close()
            break
        else:
            err = f"Stopped after {cfg.max_hops} redirects"
    finally:
        s.close()
    last = hops[-1] if hops else None
    return Chain(label, slot, urlsplit(url).scheme, url, hops, last.url if last else url, last.status if last else None,
                 (time.perf_counter() - t_start) * 1000, body_bytes, "", page, err)


def build_variants(raw: str, include_alt_host: bool = True) -> List[Tuple[str, str, str]]:
    """(label, slot, url) for each scheme and host. A URL with an explicit port is traced exactly as typed."""
    raw = (raw or "").strip()
    if not raw:
        return []
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, flags=re.I):
        raw = "http://" + raw
    parts = urlsplit(raw)
    try:
        port = parts.port
    except ValueError:
        return []
    host = (parts.hostname or "").lower()
    if not host or parts.scheme not in ("http", "https"):
        return []
    path = parts.path or "/"
    if port:
        return [(f"{parts.scheme.upper()} · {host}:{port}", parts.scheme, urlunsplit((parts.scheme, f"{host}:{port}", path, parts.query, "")))]
    is_ip = bool(re.fullmatch(r"[\d.]+|[0-9a-f:]+", host)) or "." not in host
    hosts = [(host, "")]
    if include_alt_host and not is_ip:
        hosts.append((host[4:] if host.startswith("www.") else f"www.{host}", "-alt"))
    multi = len(hosts) > 1
    return [(f"{sch.upper()} · {h}" if multi else sch.upper(), sch + suffix, urlunsplit((sch, h, path, parts.query, "")))
            for h, suffix in hosts for sch in ("http", "https")]


def trace_url(raw: str, opts: TraceOptions, limiter: "bc.HostLimiter",
              protocols: Optional["bc.ProtocolCache"] = None) -> List[Chain]:
    return [fetch_chain(lb, sl, u, opts, limiter, protocols) for lb, sl, u in build_variants(raw, opts.include_alt_host)]


def preload_status(domain: str) -> str:
    """Whether the domain is on the HSTS preload list (hstspreload.org). Returns 'unknown' if the lookup fails."""
    try:
        r = requests.get("https://hstspreload.org/api/v2/status", params={"domain": domain}, timeout=6)
        return str(r.json().get("status", "unknown"))
    except Exception:                                  # noqa: BLE001
        return "lookup failed"


# ------------------------------------------------------------------ analysis

def first_https_hop(c: Chain) -> Optional[int]:
    return next((i for i, h in enumerate(c.hops) if h.url.startswith("https://") and h.status), None)


def hsts_summary(c: Chain) -> str:
    i = first_https_hop(c)
    if i is None:
        return "n/a"
    value = c.hops[i].header("Strict-Transport-Security")
    if not value:
        return "missing"
    p = bc.parse_hsts(value)
    flags = [f"max-age={p['max_age']}"] + (["includeSubDomains"] if p["include_subdomains"] else []) + (["preload"] if p["preload"] else [])
    return "; ".join(flags)


def analyze(chains: Sequence[Chain]) -> List[Finding]:
    out: List[Finding] = []
    for ci, c in enumerate(chains):
        last = len(c.hops) - 1
        if c.scheme == "http":
            if not any(h.status for h in c.hops):
                out.append(Finding("info", c.label, f"Not reachable over plain HTTP ({c.error}).", ci, last))
                continue
            first = c.hops[0]
            if first.location:
                if first.status in TEMP_REDIRECTS:
                    out.append(Finding("warn", c.label, f"The first redirect is a {first.status}, which is temporary. Use 301 or 308.", ci, 0))
                fl = urlsplit(first.location)
                if fl.scheme != "https":
                    out.append(Finding("info", c.label, f"The first hop goes to {first.location} instead of straight to HTTPS. "
                                       "HSTS preload requires HTTP to redirect to HTTPS on the same host first.", ci, 0))
                elif (fl.hostname or "") != (urlsplit(first.url).hostname or ""):
                    out.append(Finding("info", c.label, f"The first hop changes the host as well as the scheme ({urlsplit(first.url).hostname} to {fl.hostname}). "
                                       "HSTS preload wants the HTTP to HTTPS redirect to stay on the same host first.", ci, 0))
            if c.final_status and 200 <= c.final_status < 300 and urlsplit(c.final_url).scheme == "http":
                out.append(Finding("warn", c.label, f"Serves {c.final_status} over plain HTTP without redirecting to HTTPS. That is duplicate content, "
                                   "and anyone with an HSTS cache will never see it.", ci, last))
            for hi, h in enumerate(c.hops):
                if h.url.startswith("http://") and h.header("Strict-Transport-Security"):
                    out.append(Finding("info", c.label, "Sends Strict-Transport-Security over plain HTTP, where browsers ignore it.", ci, hi))
                    break
        else:
            if c.error and "TLS/SSL" in c.error:
                out.append(Finding("error", c.label, c.error, ci, last))
            elif not any(h.status for h in c.hops):
                out.append(Finding("error", c.label, f"Not reachable ({c.error}).", ci, last))
                continue
            hi = first_https_hop(c)
            if hi is not None:
                value = c.hops[hi].header("Strict-Transport-Security")
                if not value:
                    out.append(Finding("warn", c.label, "The HTTPS response has no Strict-Transport-Security header.", ci, hi))
                else:
                    p = bc.parse_hsts(value)
                    if p["max_age"] is not None and int(p["max_age"]) < bc.HSTS_YEAR:
                        out.append(Finding("info", c.label, f"HSTS max-age is {p['max_age']}, under the one year that preload needs.", ci, hi))
                    else:
                        out.append(Finding("ok", c.label, f"HSTS {hsts_summary(c)}", ci, hi))
        for hi, (a, b) in enumerate(zip(c.hops, c.hops[1:]), 1):
            if a.url.startswith("https://") and b.url.startswith("http://"):
                out.append(Finding("error", c.label, f"Downgrades from HTTPS to HTTP ({a.url} to {b.url}).", ci, hi))
        if c.redirects > 1:
            out.append(Finding("info", c.label, f"Takes {c.redirects} redirects to settle ({c.codes}).", ci, last))
        if c.error and c.error.startswith(("Redirect loop", "Stopped after")):
            out.append(Finding("error", c.label, c.error, ci, last))
        if c.final_status and c.final_status >= 400:
            out.append(Finding("warn", c.label, f"Ends on a {c.final_status}.", ci, last))
        canon = c.page.get("canonical", "")
        if canon.startswith("http://"):
            out.append(Finding("warn", c.label, f"The canonical points to HTTP ({canon}).", ci, last))
        xr = c.page.get("x_robots_tag", "") + "," + c.page.get("meta_robots", "")
        if "noindex" in xr.lower():
            out.append(Finding("warn", c.label, "The final page says noindex.", ci, last))
    finals = {c.final_url for c in chains if c.resolved}
    if len(finals) > 1:
        out.append(Finding("warn", "All variants", f"The entry points split across {len(finals)} final URLs."))
    return out


def numbered(findings: Sequence[Finding]) -> List[Tuple[int, Finding]]:
    order = {"error": 0, "warn": 1, "info": 2}
    return list(enumerate(sorted((f for f in findings if f.sev != "ok"), key=lambda f: order[f.sev]), 1))


def chain_from_hops(start_url: str, hop_rows: Sequence[Dict[str, object]]) -> Chain:
    """Build a Chain from the checker's own per-hop table, so the map can draw any result without new requests."""
    hops = []
    for h in hop_rows:
        st = h.get("status")
        st = None if st is None or (isinstance(st, float) and math.isnan(st)) else int(st)
        loc = str(h.get("location") or "")
        hops.append(Hop(str(h["url"]), st, "", str(h.get("protocol") or ""), float(h.get("ms") or 0),
                        [("Strict-Transport-Security", str(h["hsts"]))] if h.get("hsts") else [],
                        urljoin(str(h["url"]), loc) if loc and st in bc.REDIRECT_CODES else None, str(h.get("note") or "") or None))
    last = hops[-1]
    return Chain(urlsplit(start_url).scheme.upper(), urlsplit(start_url).scheme, urlsplit(start_url).scheme, start_url, hops,
                 last.url, last.status, sum(h.ms for h in hops), error=last.error)


# ------------------------------------------------------------------ rendering helpers

def esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def letter(i: int) -> str:
    return chr(65 + i)


def code_cls(status: Optional[int]) -> str:
    if status is None:
        return "kx"
    if status in TEMP_REDIRECTS:
        return "k3t"
    return f"k{min(max(status // 100, 2), 5)}"


def fmt_ms(ms: float) -> str:
    return f"{ms / 1000:.2f}s" if ms >= 1000 else f"{ms:.0f}ms"


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc.lower()}"


def clip(t: str, n: int) -> str:
    return t if len(t) <= n else t[: max(n - 1, 1)] + "…"


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter+Tight:wght@400;500;600&family=Newsreader:ital,opsz,wght@1,6..72,400&display=swap');
.hm{--bg:#0E0F10;--ink:#ECE9E3;--mute:#85827C;--faint:#4E4C48;--line:#232322;--line2:#33322F;--hover:#151617;--acc:#FADD23;--warn:#F49713;--bad:#FF5C4D;--info:#8FA3BF;
--mono:'JetBrains Mono',ui-monospace,monospace;--sans:'Inter Tight',system-ui,sans-serif;--serif:'Newsreader',Georgia,serif;
background:var(--bg);color:var(--ink);padding:26px 28px 30px;margin:0 0 14px;font-family:var(--sans);border-radius:4px;}
.hm *{box-sizing:border-box;}
.hm p{margin:0;color:inherit;}
.hm .w-sum{display:flex;justify-content:space-between;align-items:flex-end;gap:32px;margin:0;}
.hm .w-head{font-family:var(--sans);font-size:30px;font-weight:500;letter-spacing:-.025em;line-height:1.1;color:var(--ink);}
.hm .w-head em{font-style:normal;color:var(--acc);} .hm .w-head em.split{color:var(--warn);}
.hm .w-dests{margin-top:14px;display:grid;gap:5px;}
.hm .w-dest{font-family:var(--mono);font-size:13px;color:var(--ink);display:flex;gap:10px;align-items:center;word-break:break-all;}
.hm .w-dest .d{width:8px;height:8px;border-radius:50%;background:var(--acc);flex:none;}
.hm .w-dest .via{color:var(--mute);white-space:nowrap;}
.hm .w-tally{font-family:var(--mono);font-size:12px;color:var(--mute);text-align:right;line-height:1.8;white-space:nowrap;}
.hm .w-tally b{font-weight:500;color:var(--ink);} .hm .w-tally b.bad{color:var(--bad);} .hm .w-tally b.warn{color:var(--warn);}
.hm .w-map{margin:24px 0 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line);}
.hm .w-svg{display:block;width:100%;height:auto;}
.hm .m-hatch{stroke:#1D1D1C;stroke-width:3;} .hm .m-sep{stroke:var(--line);stroke-width:1;} .hm .m-row{stroke:#191919;stroke-width:1;}
.hm .m-host{font:500 12.5px var(--mono);fill:var(--ink);} .hm .m-port{font:400 10.5px var(--mono);fill:var(--mute);letter-spacing:.06em;}
.hm .m-port.ins{fill:var(--warn);} .hm .m-dbar{fill:var(--acc);}
.hm .m-letter{font:600 11px var(--mono);fill:var(--bg);} .hm .m-lbox{fill:var(--ink);} .hm .m-entry{font:400 11px var(--mono);fill:var(--mute);}
.hm .m-edge{fill:none;stroke:#77746E;stroke-width:1.4;} .hm .m-edge.t{stroke:var(--warn);stroke-dasharray:4 3;} .hm .m-edge.d{stroke:var(--bad);}
.hm .m-arrow{fill:#77746E;} .hm .m-arrow.t{fill:var(--warn);} .hm .m-arrow.d{fill:var(--bad);}
.hm .m-ec{font:500 11px var(--mono);fill:var(--mute);} .hm .m-ec.t{fill:var(--warn);} .hm .m-ec.d{fill:var(--bad);}
.hm .m-node{fill:var(--bg);stroke:#8A8780;stroke-width:1.5;} .hm .m-fin{fill:var(--acc);} .hm .m-halo{fill:var(--acc);opacity:.13;}
.hm .m-bad{fill:var(--bad);} .hm .m-x{stroke:var(--bad);stroke-width:2;}
.hm .m-fc{font:600 11px var(--mono);fill:var(--acc);} .hm .m-fc.bad{fill:var(--bad);}
.hm .m-mk{fill:var(--bg);stroke-width:1.2;} .hm .m-mk.error{stroke:var(--bad);} .hm .m-mk.warn{stroke:var(--warn);} .hm .m-mk.info{stroke:var(--info);}
.hm .m-mkt{font:600 9.5px var(--mono);} .hm .m-mkt.error{fill:var(--bad);} .hm .m-mkt.warn{fill:var(--warn);} .hm .m-mkt.info{fill:var(--info);}
.hm .w-legend{display:flex;flex-wrap:wrap;gap:8px 26px;font-family:var(--mono);font-size:11px;color:var(--mute);margin:12px 0 0;}
.hm .w-legend span{display:inline-flex;align-items:center;gap:8px;}
.hm .w-legend .sw{display:inline-block;width:22px;height:0;border-top:1.5px solid #77746E;}
.hm .w-legend .sw.t{border-top:1.5px dashed var(--warn);} .hm .w-legend .sw.d{border-top-color:var(--bad);}
.hm .w-legend .dot{width:9px;height:9px;border-radius:50%;background:var(--acc);}
.hm .w-legend .hatch{width:16px;height:12px;background:repeating-linear-gradient(45deg,#2A2A28 0 2px,transparent 2px 5px);}
.hm .w-notes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px 48px;margin:30px 0 0;}
.hm .w-note{display:grid;grid-template-columns:24px 1fr;gap:12px;}
.hm .w-n{width:20px;height:20px;border:1.2px solid currentColor;border-radius:50%;font:600 10px var(--mono);display:flex;align-items:center;justify-content:center;margin-top:4px;}
.hm .w-note.error .w-n{color:var(--bad);} .hm .w-note.warn .w-n{color:var(--warn);} .hm .w-note.info .w-n{color:var(--info);}
.hm .w-note p{font-family:var(--serif);font-style:italic;font-size:17px;line-height:1.42;color:var(--ink);word-break:break-word;}
.hm .w-note .s{font-family:var(--mono);font-size:11px;color:var(--mute);margin-top:5px;}
.hm .w-passed{margin:22px 0 0;font-family:var(--mono);font-size:11.5px;color:var(--mute);display:flex;flex-wrap:wrap;gap:4px 22px;}
.hm .w-passed span::before{content:"✓ ";color:var(--acc);}
.hm .w-label{display:flex;align-items:center;gap:14px;margin:0 0 6px;font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--mute);}
.hm .w-label::after{content:"";flex:1;height:1px;background:var(--line);}
.hm .w-group{padding:18px 0 6px;} .hm .w-group + .w-group{border-top:1px solid var(--line);}
.hm .w-ghead{display:flex;gap:14px;align-items:baseline;font-family:var(--mono);font-size:13.5px;margin-bottom:8px;}
.hm .w-letter{color:var(--bg);background:var(--ink);font-weight:600;font-size:11px;padding:1px 6px;}
.hm .w-gurl{color:var(--ink);word-break:break-all;} .hm .w-gmeta{color:var(--mute);margin-left:auto;font-size:12px;white-space:nowrap;}
.hm details.w-hop{margin-left:9px;border-left:1px solid var(--line2);}
.hm details.w-hop > summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:42px minmax(0,1fr) auto;gap:14px;align-items:baseline;padding:8px 10px 8px 18px;font-family:var(--mono);font-size:13px;position:relative;}
.hm details.w-hop > summary::-webkit-details-marker{display:none;}
.hm details.w-hop > summary::before{content:"";position:absolute;left:-4px;top:14px;width:7px;height:7px;background:var(--bg);border:1px solid var(--faint);border-radius:50%;}
.hm details.w-hop > summary:hover,.hm details.w-hop[open] > summary{background:var(--hover);}
.hm details.w-hop[open] > summary::before{background:var(--ink);border-color:var(--ink);}
.hm .w-u{color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;} .hm .w-to{color:var(--mute);} .hm .w-ms{color:var(--mute);font-size:12px;}
.hm .k2{color:var(--acc);font-weight:600;} .hm .k3{color:#B9B6AF;font-weight:600;} .hm .k3t{color:var(--warn);font-weight:600;}
.hm .k4,.hm .k5,.hm .kx{color:var(--bad);font-weight:600;}
.hm .w-raw{margin:2px 0 12px 18px;padding:14px 16px;background:#121314;border:1px solid var(--line);font-family:var(--mono);font-size:12.5px;line-height:1.75;color:var(--ink);white-space:pre-wrap;word-break:break-all;}
.hm .w-raw .rq{color:var(--mute);} .hm .w-raw .sl{font-weight:600;} .hm .w-raw .hk{color:var(--mute);} .hm .w-raw .hk.hot{color:var(--acc);}
.hm .w-page{margin:6px 0 8px 28px;display:grid;grid-template-columns:120px minmax(0,1fr);gap:4px 14px;font-family:var(--mono);font-size:12px;color:var(--mute);}
.hm .w-page b{font-weight:400;color:var(--ink);word-break:break-all;}
.hm details.w-body{margin:4px 0 10px 0;} .hm details.w-body > summary{cursor:pointer;font-family:var(--mono);font-size:12px;color:var(--mute);list-style:none;}
.hm details.w-body > summary::-webkit-details-marker{display:none;} .hm details.w-body > summary:hover{color:var(--ink);}
.hm details.w-body pre{margin:8px 0 0;max-height:460px;overflow:auto;padding:14px 16px;background:#121314;border:1px solid var(--line);font-family:var(--mono);font-size:12px;line-height:1.6;color:#B5B2AB;white-space:pre-wrap;word-break:break-all;}
.hm .w-diff .a{color:var(--acc);} .hm .w-diff .r{color:var(--bad);} .hm .w-diff .h{color:var(--mute);}
.hm .w-bsum{font-family:var(--sans);font-size:22px;font-weight:500;letter-spacing:-.02em;line-height:1.3;margin:0 0 18px;max-width:900px;} .hm .w-bsum .m{color:var(--mute);}
.hm .w-tscroll{overflow-x:auto;}
.hm .w-table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12.5px;}
.hm .w-table th{text-align:left;font-weight:500;font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute);padding:9px 12px;border-bottom:1px solid var(--line2);white-space:nowrap;}
.hm .w-table td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;color:var(--ink);}
.hm .w-table tr:hover td{background:var(--hover);}
.hm .w-table td.u{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;} .hm .w-table td.ch{white-space:nowrap;}
.hm .w-table td.ch span + span::before{content:" › ";color:var(--faint);font-weight:400;}
.hm .w-table td.dst{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.hm .w-table .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--acc);margin-right:8px;vertical-align:1px;}
.hm .w-table .split{color:var(--warn);} .hm .w-table td.iss{color:var(--mute);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.hm .w-table td.iss b{color:var(--warn);font-weight:600;margin-right:8px;} .hm .w-table td.iss b.bad{color:var(--bad);}
.hm .w-more{font-family:var(--mono);font-size:11.5px;color:var(--mute);margin:12px 0 0;}
@media (max-width:820px){.hm .w-sum{flex-direction:column;align-items:flex-start;}.hm .w-tally{text-align:left;}.hm .w-notes{grid-template-columns:1fr;}.hm .w-head{font-size:24px;}}
</style>
"""


def panel(inner: str) -> str:
    """Wrap pieces in the dark card. One line, no blank lines: Markdown ends an HTML block at a blank line."""
    return '<div class="hm">' + inner.replace("\n", "") + "</div>"


# ------------------------------------------------------------------ rendering

def summary_html(chains: Sequence[Chain], findings: Sequence[Finding], elapsed: float, preload: Optional[Tuple[str, str]] = None) -> str:
    finals: Dict[str, List[str]] = {}
    for i, c in enumerate(chains):
        if c.resolved:
            finals.setdefault(c.final_url, []).append(letter(i))
    n_in, n_out = len(chains), len(finals)
    w_in = NUMBER_WORDS.get(n_in, str(n_in))
    if n_out == 0:
        head = f"{w_in} entry point{'s' if n_in > 1 else ''}. <em class='split'>None of them resolve.</em>"
    elif n_out == 1:
        head = f"{w_in} entry point{'s' if n_in > 1 else ''}, <em>one final URL.</em>"
    else:
        head = f"{w_in} entry points, <em class='split'>{NUMBER_WORDS.get(n_out, n_out).lower()} final URLs.</em>"
    dests = "".join(f'<div class="w-dest"><span class="d"></span><span>{esc(u)}</span><span class="via">← {" ".join(ls)}</span></div>'
                    for u, ls in finals.items())
    n_err, n_warn, n_info = (sum(f.sev == s for f in findings) for s in ("error", "warn", "info"))
    tally = [f'<b class="{"bad" if n_err else ""}">{n_err}</b> critical',
             f'<b class="{"warn" if n_warn else ""}">{n_warn}</b> issue{"s" if n_warn != 1 else ""} · <b>{n_info}</b> note{"s" if n_info != 1 else ""}',
             f"{sum(len(c.hops) for c in chains)} requests in {elapsed:.1f}s"]
    if preload:
        tally.append(f"preload list · <b>{esc(preload[1])}</b>")
    return (f'<div class="w-sum"><div><div class="w-head">{head}</div><div class="w-dests">{dests}</div></div>'
            f'<div class="w-tally">{"<br>".join(tally)}</div></div>')


def map_svg(chains: Sequence[Chain], findings: Sequence[Finding] = ()) -> str:
    origins: List[str] = []
    for url in [c.start_url for c in chains] + [h.url for c in chains for h in c.hops]:
        if origin_of(url) not in origins:
            origins.append(origin_of(url))
    W, L, R, top, row_h = 1120, 150, 28, 86, 68
    col_w = (W - L - R) / len(origins)
    H = top + row_h * len(chains) + 8
    col_x = lambda i: L + col_w * (i + 0.5)  # noqa: E731
    final_origins = {origin_of(c.final_url) for c in chains if c.resolved}
    split_paths = len({c.final_url for c in chains if c.resolved}) > len(final_origins)
    host_chars = max(int(col_w / 7.8), 8)
    out = [f'<svg class="w-svg" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg">'
           '<defs><pattern id="w-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
           '<line x1="0" y1="0" x2="0" y2="6" class="m-hatch"/></pattern></defs>']
    for i, o in enumerate(origins):
        p = urlsplit(o)
        x0, cx = L + col_w * i, col_x(i)
        if p.scheme == "http":
            out.append(f'<rect x="{x0:.1f}" y="0" width="{col_w:.1f}" height="{H}" fill="url(#w-hatch)"/>')
        out.append(f'<line x1="{x0:.1f}" y1="0" x2="{x0:.1f}" y2="{H}" class="m-sep"/>')
        port = p.port or (80 if p.scheme == "http" else 443)
        out.append(f'<text x="{cx:.1f}" y="34" text-anchor="middle" class="m-host"><title>{esc(o)}</title>{esc(clip(p.hostname or "", host_chars))}</text>')
        out.append(f'<text x="{cx:.1f}" y="52" text-anchor="middle" class="m-port{" ins" if p.scheme == "http" else ""}">{p.scheme} :{port}</text>')
        if o in final_origins:
            out.append(f'<rect x="{cx - 14:.1f}" y="62" width="28" height="2" class="m-dbar"/>')
    out.append(f'<line x1="0" y1="{top - 12}" x2="{W}" y2="{top - 12}" class="m-sep"/>')
    pins: Dict[Tuple[int, int], List[Tuple[int, str]]] = {}
    for n, f in numbered(findings):
        if f.chain is not None:
            pins.setdefault((f.chain, max(f.hop or 0, 0)), []).append((n, f.sev))
    for r, c in enumerate(chains):
        y = top + row_h * r + row_h / 2
        if r:
            out.append(f'<line x1="0" y1="{y - row_h / 2:.1f}" x2="{W}" y2="{y - row_h / 2:.1f}" class="m-row"/>')
        out.append(f'<rect x="20" y="{y - 9:.1f}" width="18" height="17" class="m-lbox"/>')
        out.append(f'<text x="29" y="{y + 4:.1f}" text-anchor="middle" class="m-letter">{letter(r)}</text>')
        entry = c.scheme + (" · www" if c.host.startswith("www.") else "")
        out.append(f'<text x="48" y="{y + 4:.1f}" class="m-entry"><title>{esc(c.start_url)}</title>{esc(entry)}</text>')
        per_col: Dict[int, int] = {}
        pos = []
        for h in c.hops:
            ci = origins.index(origin_of(h.url))
            k = per_col.get(ci, 0)
            per_col[ci] = k + 1
            pos.append(col_x(ci) + k * 22)
        for j in range(len(c.hops) - 1):
            x1, x2 = pos[j], pos[j + 1]
            a, b = c.hops[j], c.hops[j + 1]
            kind = "d" if a.url.startswith("https://") and b.url.startswith("http://") else "t" if a.status in TEMP_REDIRECTS else ""
            d = 1 if x2 >= x1 else -1
            sx, ex = x1 + d * 9, x2 - d * 11
            lift = min(24, 9 + abs(ex - sx) * 0.05)
            mx, cy = (sx + ex) / 2, y - 2 * lift
            out.append(f'<path d="M{sx:.1f},{y:.1f} Q{mx:.1f},{cy:.1f} {ex:.1f},{y:.1f}" class="m-edge {kind}"/>')
            tx, ty = ex - mx, y - cy
            norm_ = math.hypot(tx, ty) or 1
            ux, uy = tx / norm_, ty / norm_
            bx, by = ex - ux * 7, y - uy * 7
            out.append(f'<path d="M{ex:.1f},{y:.1f} L{bx - uy * 3.6:.1f},{by + ux * 3.6:.1f} L{bx + uy * 3.6:.1f},{by - ux * 3.6:.1f} Z" class="m-arrow {kind}"/>')
            out.append(f'<text x="{mx:.1f}" y="{y - lift - 6:.1f}" text-anchor="middle" class="m-ec {kind}">{a.status}</text>')
        for j, (h, x) in enumerate(zip(c.hops, pos)):
            tip = f"{esc(h.url)}&#10;{h.status or 'ERR'} {esc(h.reason or h.error or '')}"
            if j < len(c.hops) - 1:
                out.append(f'<g><title>{tip}</title><circle cx="{x:.1f}" cy="{y:.1f}" r="5" class="m-node"/></g>')
                continue
            if h.status is None:
                out.append(f'<g><title>{tip}</title><line x1="{x - 5:.1f}" y1="{y - 5:.1f}" x2="{x + 5:.1f}" y2="{y + 5:.1f}" class="m-x"/>'
                           f'<line x1="{x - 5:.1f}" y1="{y + 5:.1f}" x2="{x + 5:.1f}" y2="{y - 5:.1f}" class="m-x"/></g>')
                label, bad = "ERR", True
            elif h.status < 300:
                out.append(f'<g><title>{tip}</title><circle cx="{x:.1f}" cy="{y:.1f}" r="13" class="m-halo"/><circle cx="{x:.1f}" cy="{y:.1f}" r="6.5" class="m-fin"/></g>')
                label, bad = str(h.status), False
            elif h.status < 400:
                out.append(f'<g><title>{tip}</title><circle cx="{x:.1f}" cy="{y:.1f}" r="5" class="m-node"/></g>')
                label, bad = str(h.status), False
            else:
                out.append(f'<g><title>{tip}</title><circle cx="{x:.1f}" cy="{y:.1f}" r="6.5" class="m-bad"/></g>')
                label, bad = str(h.status), True
            if split_paths:
                label += f" {clip(urlsplit(h.url).path or '/', 14)}"      # finals can differ only by path (/ vs //)
            out.append(f'<text x="{x:.1f}" y="{y + 24:.1f}" text-anchor="middle" class="m-fc{" bad" if bad else ""}">{esc(label)}</text>')
        for j, x in enumerate(pos):
            for k, (n, sev) in enumerate(pins.get((r, j), [])):
                px, py = x + 13 + k * 17, y - 15
                out.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="7.5" class="m-mk {sev}"/>'
                           f'<text x="{px:.1f}" y="{py + 3.3:.1f}" text-anchor="middle" class="m-mkt {sev}">{n}</text>')
    out.append("</svg>")
    return f'<div class="w-map">{"".join(out)}</div>'


LEGEND = ('<div class="w-legend"><span><i class="hatch"></i>plain http origin</span><span><i class="sw"></i>301 / 308</span>'
          '<span><i class="sw t"></i>temporary redirect</span><span><i class="sw d"></i>downgrade to http</span>'
          '<span><i class="dot"></i>final response</span><span>hover a node for its URL</span></div>')


def notes_html(findings: Sequence[Finding], chains: Sequence[Chain]) -> str:
    notes = "".join(f'<div class="w-note {f.sev}"><span class="w-n">{n}</span><div><p>{esc(f.msg)}</p>'
                    f'<div class="s">{letter(f.chain) + " · " if f.chain is not None else ""}{esc(f.scope)}</div></div></div>'
                    for n, f in numbered(findings))
    passed = "".join((f"<span>{letter(f.chain)} · {esc(f.msg)}</span>" if f.chain is not None else f"<span>{esc(f.msg)}</span>")
                     for f in findings if f.sev == "ok")
    if len({c.final_url for c in chains if c.resolved}) == 1 and len(chains) > 1:
        passed += "<span>every entry point converges</span>"
    return (f'<div class="w-notes">{notes}</div>' if notes else "") + (f'<div class="w-passed">{passed}</div>' if passed else "")


def raw_response_html(h: Hop, method: str) -> str:
    lines = [f'<span class="rq">{esc(method)} {esc(h.url)}</span>', "&nbsp;"]
    if h.error:
        lines.append(f'<span class="sl kx">{esc(h.error)}</span>')
    else:
        lines.append(f'<span class="sl {code_cls(h.status)}">{esc((h.http_version or "HTTP").split(" ")[0])} {h.status} {esc(h.reason)}</span>')
        for k, v in h.headers:
            lines.append(f'<span class="hk{" hot" if k.lower() in HOT_HEADERS else ""}">{esc(k)}:</span> {esc(v)}')
    return f'<div class="w-raw">{"<br>".join(lines)}</div>'


def trace_html(chains: Sequence[Chain], method: str) -> str:
    groups = []
    for i, c in enumerate(chains):
        hops = []
        for h in c.hops:
            to = f' <span class="w-to">→ {esc(h.location)}</span>' if h.location else ""
            err = f' <span class="w-to">{esc(h.error)}</span>' if h.error else ""
            proto = f' <span class="w-to">{esc(h.http_version)}</span>' if h.http_version else ""
            hops.append(f'<details class="w-hop"><summary><span class="{code_cls(h.status)}">{h.status or "ERR"}</span>'
                        f'<span class="w-u">{esc(h.url)}{to}{err}{proto}</span><span class="w-ms">{fmt_ms(h.ms)}</span></summary>'
                        f"{raw_response_html(h, method)}</details>")
        extra = ""
        if c.page:
            rows = [("title", c.page.get("title")), ("canonical", c.page.get("canonical")), ("meta robots", c.page.get("meta_robots")),
                    ("x-robots-tag", c.page.get("x_robots_tag")), ("h1", c.page.get("h1")),
                    ("words · hash", f'{len(c.page.get("text", "").split()):,} · {c.page.get("text_hash")}')]
            extra = '<div class="w-page">' + "".join(f"<span>{k}</span><b>{esc(v) or '—'}</b>" for k, v in rows) + "</div>"
        groups.append(f'<div class="w-group"><div class="w-ghead"><span class="w-letter">{letter(i)}</span><span class="w-gurl">{esc(c.start_url)}</span>'
                      f'<span class="w-gmeta">{len(c.hops)} request{"s" if len(c.hops) != 1 else ""} · {fmt_ms(c.total_ms)}</span></div>{"".join(hops)}{extra}</div>')
    return '<div class="w-label">request log · click a row for the raw response</div>' + "".join(groups)


def diff_html(chains: Sequence[Chain]) -> str:
    distinct: Dict[str, Tuple[str, Chain]] = {}
    for i, c in enumerate(chains):
        if c.page.get("text"):
            distinct.setdefault(c.final_url, (letter(i), c))
    if len(distinct) < 2:
        return ""
    (la, a), (lb, b) = list(distinct.values())[:2]
    diff = list(difflib.unified_diff(a.page["text"].splitlines(), b.page["text"].splitlines(), la, lb, lineterm="", n=2))
    if not diff:
        body = '<span class="h">The extracted text is identical.</span>'
    else:
        cls = lambda ln: "h" if ln.startswith(("@@", "---", "+++")) else "a" if ln.startswith("+") else "r" if ln.startswith("-") else ""  # noqa: E731
        body = "<br>".join(f'<span class="{cls(ln)}">{esc(ln)}</span>' for ln in diff[:400])
    return (f'<details class="w-body w-diff"><summary>+ text diff between final pages {la} and {lb} ({esc(a.final_url)} ↔ {esc(b.final_url)})</summary>'
            f"<pre>{body}</pre></details>")


def single_panel(chains: Sequence[Chain], findings: Sequence[Finding], elapsed: float, preload: Optional[Tuple[str, str]], method: str) -> Tuple[str, str]:
    """(top panel: summary, map, legend, notes; bottom panel: request log and diff)."""
    top = summary_html(chains, findings, elapsed, preload) + map_svg(chains, findings) + LEGEND + notes_html(findings, chains)
    return panel(top), panel(trace_html(chains, method) + diff_html(chains))


def map_only_panel(chain: Chain) -> str:
    return panel(map_svg([chain]) + LEGEND)


# ------------------------------------------------------------------ list mode

def list_row(raw: str, opts: TraceOptions, limiter: "bc.HostLimiter", protocols=None) -> Tuple[Dict[str, str], List[Chain], List[Finding]]:
    chains = trace_url(raw, opts, limiter, protocols)
    findings = analyze(chains)
    row: Dict[str, str] = {"input": raw}
    for c in chains:
        row[f"{c.slot} chain"] = c.codes
        row[f"{c.slot} final"] = c.final_url
    https = next((c for c in chains if c.scheme == "https"), None)
    row["HSTS"] = hsts_summary(https) if https else "n/a"
    row["final URLs"] = str(len({c.final_url for c in chains if c.resolved}))
    row["issues"] = " | ".join(f"{f.scope}: {f.msg}" for f in findings if f.sev in ("error", "warn"))
    row["notes"] = " | ".join(f"{f.scope}: {f.msg}" for f in findings if f.sev == "info")
    return row, chains, findings


def run_list(urls: Sequence[str], opts: TraceOptions, limiter: "bc.HostLimiter", protocols=None, workers: int = 6,
             progress=None) -> List[Tuple[Dict[str, str], List[Chain], List[Finding]]]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(list_row, u, opts, limiter, protocols): u for u in urls}
        for done, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            try:
                results.append(fut.result())
            except Exception as e:                      # noqa: BLE001
                u = futs[fut]
                results.append(({"input": u, "issues": f"crashed: {type(e).__name__}"}, [], [Finding("error", u, f"Crashed: {type(e).__name__}")]))
            if progress:
                progress(done, len(urls))
    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: order.get(r[0]["input"], 0))
    return results


def matrix_html(results, elapsed: float) -> str:
    n = len(results)
    single = sum(1 for _, ch, _ in results if len({c.final_url for c in ch if c.resolved}) == 1)
    dead = sum(1 for _, ch, _ in results if not any(c.resolved for c in ch))
    split = n - single - dead
    flagged = sum(1 for _, _, f in results if any(x.sev in ("error", "warn") for x in f))
    head = (f'<div class="w-bsum">{n} URL{"s" if n != 1 else ""} traced in {elapsed:.1f}s. <span class="m">{single} '
            f'{"settles" if single == 1 else "settle"} on a single final URL, {split} split, {dead} never {"resolves" if dead == 1 else "resolve"}. '
            f'{flagged} {"has" if flagged == 1 else "have"} something worth fixing.</span></div>')
    slots = [s for s in SLOT_NAMES if any(c.slot == s for _, ch, _ in results for c in ch)]
    th = "<tr><th>url</th>" + "".join(f"<th>{SLOT_NAMES[s]}</th>" for s in slots) + "<th>ends at</th><th>issues</th></tr>"
    body = []
    for row, chains, findings in results[:LIST_DISPLAY_ROWS]:
        by = {c.slot: c for c in chains}
        cells = [f'<td class="u" title="{esc(row["input"])}">{esc(row["input"])}</td>']
        for s in slots:
            c = by.get(s)
            if not c:
                cells.append("<td></td>")
                continue
            chips = "".join(f'<span class="{code_cls(h.status)}">{h.status or "ERR"}</span>' for h in c.hops) or '<span class="kx">ERR</span>'
            cells.append(f'<td class="ch" title="{esc(c.final_url)}">{chips}</td>')
        finals = sorted({c.final_url for c in chains if c.resolved})
        if len(finals) == 1:
            cells.append(f'<td class="dst" title="{esc(finals[0])}"><span class="dot"></span>{esc(finals[0])}</td>')
        elif finals:
            cells.append(f'<td class="dst split" title="{esc(chr(10).join(finals))}">{len(finals)} different URLs</td>')
        else:
            cells.append('<td class="dst kx">nothing resolves</td>')
        bad = [f for f in findings if f.sev in ("error", "warn")]
        if bad:
            tip = esc("\n".join(f"{f.scope}: {f.msg}" for f in bad))
            cells.append(f'<td class="iss" title="{tip}"><b class="{"bad" if any(f.sev == "error" for f in bad) else ""}">{len(bad)}</b>{esc(bad[0].msg)}</td>')
        else:
            cells.append('<td class="iss">—</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    more = f'<div class="w-more">Showing the first {LIST_DISPLAY_ROWS} of {n}. The CSV has all of them.</div>' if n > LIST_DISPLAY_ROWS else ""
    return panel(head + f'<div class="w-tscroll"><table class="w-table"><thead>{th}</thead><tbody>{"".join(body)}</tbody></table></div>' + more)
