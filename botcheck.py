"""Engine for the Redirect and Header Response Checker.

Requests every URL the way a search engine crawler does and reports what the crawler would actually see:

  * Each redirect hop is requested separately, exactly as the server answers. HSTS is never applied, so an
    http to https upgrade shows up as the server's real 301, not a browser's internal 307.
  * A crawler user agent is sent, with no cookies, no referrer and no JavaScript.
  * robots.txt is read with Google's matching rules (wildcards, longest match wins) and every URL in the
    chain is checked against it.
  * The final page is checked for noindex (X-Robots-Tag header and meta robots), canonical, meta refresh.
  * With a redirect map, the final URL is compared with the mapped target.

A public deployment fetches URLs that strangers type in, so every request passes through ``check_address``:
only http(s), ports 80 and 443, credentials refused, and any host that resolves to a private, loopback,
link-local or otherwise non-public address is refused, including on every redirect hop.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

import pandas as pd
import requests
try:                                          # optional: only needed to report HTTP/2
    import httpx
except ImportError:                           # pragma: no cover
    httpx = None

# --------------------------------------------------------------------------------------
# Bots
# --------------------------------------------------------------------------------------

def _bot(group, token, ua, note, robots="yes", frm=""):
    return dict(group=group, token=token, ua=ua, note=note, robots=robots, frm=frm)


_CH = "Chrome/130.0.0.0"
BOTS: Dict[str, Dict[str, str]] = {
    # ---- search engines (user agent strings from each vendor's documentation)
    "Googlebot smartphone": _bot("Search", "googlebot",
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"{_CH} Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Google's main crawler for indexing (mobile-first).", frm="googlebot(at)googlebot.com"),
    "Googlebot desktop": _bot("Search", "googlebot",
        f"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) {_CH} Safari/537.36",
        "Google's desktop crawler.", frm="googlebot(at)googlebot.com"),
    "Google-InspectionTool": _bot("Search", "google-inspectiontool",
        "Mozilla/5.0 (compatible; Google-InspectionTool/1.0)", "Used by Search Console's URL Inspection and Rich Results Test."),
    "GoogleOther": _bot("Search", "googleother",
        f"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GoogleOther) {_CH} Safari/537.36",
        "Google's generic crawler for research and product teams."),
    "Bingbot": _bot("Search", "bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "Microsoft Bing's crawler."),
    "Applebot": _bot("Search", "applebot",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 "
        "(Applebot/0.1; +http://www.apple.com/go/applebot)", "Apple's crawler for Spotlight, Siri and Safari suggestions."),
    "DuckAssistBot": _bot("Search", "duckassistbot", "DuckAssistBot/1.2; (+http://duckduckgo.com/duckassistbot.html)",
        "DuckDuckGo's AI answers crawler."),
    # ---- AI crawlers and agents
    "GPTBot (OpenAI training)": _bot("AI", "gptbot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot",
        "OpenAI's crawler for content that may be used to train its models."),
    "OAI-SearchBot (ChatGPT search)": _bot("AI", "oai-searchbot",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; "
        "compatible; OAI-SearchBot/1.4; +https://openai.com/searchbot", "Surfaces sites in ChatGPT's search results."),
    "ChatGPT-User (ChatGPT browsing)": _bot("AI", "chatgpt-user",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
        "Fetches a page when a person asks ChatGPT about it. OpenAI says robots.txt rules may not apply.", robots="no"),
    "ClaudeBot (Anthropic training)": _bot("AI", "claudebot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
        "Anthropic's crawler for content that may be used to train its models. Anthropic's docs name the token; the full string is as published by third parties."),
    "Claude-SearchBot": _bot("AI", "claude-searchbot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +Claude-SearchBot@anthropic.com)",
        "Anthropic's crawler for improving Claude's search results."),
    "Claude-User": _bot("AI", "claude-user",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
        "Fetches a page when a person asks Claude about it."),
    "PerplexityBot": _bot("AI", "perplexitybot", "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://www.perplexity.ai/bot)",
        "Perplexity's search crawler."),
    "Perplexity-User": _bot("AI", "perplexity-user",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://www.perplexity.ai)",
        "Fetches a page when a person asks Perplexity about it. Generally does not follow robots.txt.", robots="no"),
    "Amazonbot": _bot("AI", "amazonbot",
        f"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1) {_CH} Safari/537.36", "Amazon's crawler (Alexa and AI services)."),
    "Meta-ExternalAgent": _bot("AI", "meta-externalagent",
        "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "Meta's crawler for AI training and indexing."),
    "Meta-WebIndexer": _bot("AI", "meta-webindexer",
        "meta-webindexer/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "Meta's crawler for its AI search features."),
    "meta-externalfetcher": _bot("AI", "meta-externalfetcher",
        "meta-externalfetcher/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "Fetches a page when a person shares or asks Meta AI about it.", robots="no"),
    "CCBot (Common Crawl)": _bot("AI", "ccbot", "CCBot/2.0 (https://commoncrawl.org/faq/)",
        "Common Crawl's open web archive, widely used to train models. String from Common Crawl's FAQ."),
    "Bytespider (ByteDance)": _bot("AI", "bytespider",
        "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)",
        "ByteDance's crawler. String as commonly published; confirm against your logs."),
    "Facebook link preview": _bot("Social", "facebookexternalhit",
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "Fetches a page to build a link preview when it is shared on Facebook.", robots="no"),
    # ---- browsers and tools (example version numbers: edit them with Custom if a site sniffs versions)
    "Chrome (desktop browser)": _bot("Browser", "*",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "A normal Chrome browser on Windows. Browsers ignore robots.txt.", robots="no"),
    "Chrome (Android)": _bot("Browser", "*",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
        "A normal Chrome browser on Android.", robots="no"),
    "Firefox (Mozilla desktop browser)": _bot("Browser", "*",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0", "A normal Firefox browser on Windows.", robots="no"),
    "Mozilla/5.0 only (generic, no bot name)": _bot("Browser", "*", "Mozilla/5.0",
        "Just the Mozilla/5.0 prefix with no product name, as many simple scripts send. Useful for seeing how a site treats an unidentified client.", robots="no"),
    "curl": _bot("Browser", "*", "curl/8.5.0", "curl's default user agent: what a quick command-line check sends.", robots="no"),
    "Custom": _bot("Custom", "*", "", "Your own user agent string."),
}
REDIRECT_CODES = (301, 302, 303, 307, 308)
PERMANENT = (301, 308)
TEMPORARY = (302, 303, 307)

# --------------------------------------------------------------------------------------
# Issues (code -> severity, short label, explanation and fix)
# --------------------------------------------------------------------------------------

ISSUES: Dict[str, Tuple[str, str, str]] = {
    "BLOCKED_ADDRESS": ("error", "Address not allowed", "The URL, or a redirect it follows, points to a private or internal address. The checker only requests public sites, so it stopped."),
    "CONNECTION_ERROR": ("error", "Could not connect", "The request failed (DNS, TLS, refused connection). A crawler would fail too. Check the hostname and certificate."),
    "TIMEOUT": ("error", "Timed out", "The server did not answer in time. Crawlers back off from slow servers and may drop the URL."),
    "LOOP": ("error", "Redirect loop", "The chain sends the crawler back to a URL it already visited. It never reaches a page. Fix the rule that creates the loop."),
    "TOO_MANY_HOPS": ("error", "Too many redirects", "The chain is longer than this tool follows (6 redirects, to keep runs safe). Googlebot gives up after 10. Collapse the chain to a single 301."),
    "ROBOTS_BLOCKED_START": ("error", "Old URL blocked by robots.txt", "robots.txt forbids fetching this URL, so a crawler never sees the redirect and the old page's signals are not passed on. Allow it, at least until the redirect is processed."),
    "ROBOTS_BLOCKED_DEST": ("error", "Destination blocked by robots.txt", "A URL in the chain, usually the destination, is disallowed in robots.txt. The crawler cannot fetch the page it is sent to."),
    "ROBOTS_UNAVAILABLE": ("warn", "robots.txt unreachable", "robots.txt returned a server error or timed out. Google treats that as 'do not crawl' for a while, so crawling can stall."),
    "BOT_REFUSED": ("error", "Refuses the crawler (401/403/429)", "The server answers the crawler with an access or rate-limit error. Often a firewall or bot rule. Real crawlers verify by IP, so also check your logs."),
    "BOT_CHALLENGE": ("error", "Host served a bot challenge, not the real page", "The hosting or security layer answered the crawler with a CAPTCHA or JavaScript challenge (often with a 202, 403 or 503) instead of the site's real response, so this result says nothing about your redirects. Options: pass the challenge in your own browser and paste the resulting cookie into the sidebar (Cookie and headers), allowlist the checker's IP in the host's bot protection, or test with a different user agent. These cookies are often tied to the IP and user agent that earned them, so a copy of the tool running on your own computer is the most reliable. Real Googlebot is usually verified by IP and may be treated differently, so confirm in your server logs."),
    "NOT_FOUND": ("error", "Ends on 404 or 410", "The redirect leads to a missing page, or the old URL simply returns 404 and has no redirect."),
    "SERVER_ERROR": ("error", "Ends on a server error (5xx)", "The crawler gets a 5xx. Repeated errors reduce crawling and can drop pages from the index."),
    "OTHER_STATUS": ("error", "Ends on an unexpected status", "The final response is not a 200 page and not a normal error. Check what the server is doing."),
    "NOT_REDIRECTED": ("error", "Old URL does not redirect", "Your map sends this URL somewhere, but it answers 200 itself. The old page is still live (duplicate content) or the rule is missing."),
    "HOP_TYPE_MISMATCH": ("error", "Wrong redirect type", "The first response is not the type your map expects (for example the map says 301 but the server sends 302, or the map says 410 and the server sends 404). Fix the rule or the map."),
    "TARGET_MISMATCH": ("error", "Lands on the wrong page", "The redirect ends on a different URL from the one in your map. Fix the rule or the map."),
    "TARGET_SLASH_DIFF": ("warn", "Target differs only by trailing slash", "The redirect lands on the same page as your map but with or without a trailing slash. Those are different URLs to a crawler. Make them match."),
    "TEMP_REDIRECT": ("warn", "Temporary redirect (302/303/307)", "A temporary redirect was used. For a migration you normally want a permanent 301 or 308 so signals move to the new URL."),
    "CHAIN": ("warn", "Redirect chain (2 or more hops)", "More than one hop. Each extra hop slows crawling and can lose signal. Point the old URL straight at the final page."),
    "NOINDEX_HEADER": ("error", "noindex in HTTP header", "The final page sends X-Robots-Tag: noindex for this crawler. Often staging settings that shipped to production."),
    "NOINDEX_META": ("error", "noindex in meta robots", "The final page has a meta robots noindex for this crawler. It will drop out of the index."),
    "CANONICAL_ELSEWHERE": ("warn", "Canonical points to another URL", "The page's canonical is not itself. If that is not intended, search engines may index a different URL than the one you redirect to."),
    "CANONICAL_MISSING": ("info", "No canonical tag", "The final page has no canonical. Not an error, but a self-referencing canonical is good practice on a migration."),
    "META_REFRESH": ("warn", "Meta refresh redirect", "The page redirects with a meta refresh. Crawlers treat it as a weak redirect. Use a server-side 301 instead."),
    "JS_REDIRECT_SUSPECT": ("info", "Possible JavaScript redirect", "A short page that sets window.location. A crawler without rendering will not follow it, and rendering is slower. Use a server-side 301."),
    "TO_HOME": ("warn", "Redirects to the home page", "A deep URL redirecting to the home page is usually treated as a soft 404. Send it to the closest equivalent page."),
    "INSECURE_FINAL": ("warn", "Ends on http, not https", "The chain finishes on an insecure URL."),
    "CRAWL_STATUS_CHANGED": ("info", "Differs from your crawl", "The live status is different from the status in your Screaming Frog export."),
    "CHAIN_NOT_FOLLOWED": ("info", "Redirect not followed", "Only the first response was requested, so the final URL is not known. Turn on 'Follow the full redirect chain', or use the button under 'Look at one URL step by step'."),
    "HSTS_MISSING": ("warn", "No HSTS header", "The final HTTPS page does not send Strict-Transport-Security. Browsers will keep trying http first. On a migration, set it on the new site once https works everywhere, with a short max-age first."),
    "HSTS_WEAK": ("warn", "HSTS max-age is short or zero", "max-age is under one year (31536000 seconds), or 0, which switches HSTS off. A year or more is needed for preload."),
    "HSTS_ON_HTTP": ("info", "HSTS header sent over http", "Browsers ignore Strict-Transport-Security on plain http, so it does nothing here. Send it only on https responses."),
    "SLOW": ("info", "Slow response", "The chain took a long time end to end."),
}
SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2, "": 3}


# --------------------------------------------------------------------------------------
# Safety: only public addresses
# --------------------------------------------------------------------------------------

def check_address(url: str, allow_private: bool = False, allowed_hosts: Iterable[str] = ()) -> Tuple[bool, str]:
    """Is it safe to request this URL? ``allowed_hosts`` holds exact host:port pairs (used by the built-in demo)."""
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return False, "not a valid URL"
    if p.scheme not in ("http", "https"):
        return False, "only http and https URLs are allowed"
    if not p.hostname:
        return False, "URL has no host"
    if p.username or p.password:
        return False, "URLs with credentials are not allowed"
    port = port or (443 if p.scheme == "https" else 80)
    if f"{p.hostname.lower()}:{port}" in {h.lower() for h in allowed_hosts} or allow_private:
        return True, ""
    if port not in (80, 443):
        return False, "only ports 80 and 443 are allowed"
    try:
        infos = socket.getaddrinfo(p.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return True, ""                              # the request itself will report a clear DNS error
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return False, f"{p.hostname} resolves to a non-public address ({ip})"
    return True, ""


# --------------------------------------------------------------------------------------
# URL helpers
# --------------------------------------------------------------------------------------

def norm(u: str) -> str:
    """Lower-case scheme and host, drop default port and fragment. Path, query and trailing slash are kept."""
    p = urlsplit((u or "").strip())
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    return urlunsplit((p.scheme.lower(), host + port, p.path or "/", p.query, ""))


def _strip_slash(u: str) -> str:
    p = urlsplit(u)
    return urlunsplit((p.scheme, p.netloc, p.path.rstrip("/") or "/", p.query, ""))


def match_kind(final_url: str, expected: str) -> str:
    """exact, slash (differs only by trailing slash), different, or n/a when there is no expected target."""
    if not expected:
        return "n/a"
    a, b = norm(final_url), norm(expected)
    if a == b:
        return "exact"
    return "slash" if _strip_slash(a) == _strip_slash(b) else "different"


# --------------------------------------------------------------------------------------
# robots.txt with Google's matching rules
# --------------------------------------------------------------------------------------

class RobotsRules:
    """Parsed robots.txt. Rules from every group that names the crawler (else the * group) are merged; the longest
    matching pattern wins and Allow beats Disallow on a tie. ``*`` matches any characters and a trailing ``$`` anchors."""

    def __init__(self, text: str = ""):
        self.groups: List[Tuple[List[str], List[Tuple[str, str]]]] = []
        agents: List[str] = []
        rules: List[Tuple[str, str]] = []
        collecting = True
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "user-agent":
                if not collecting:
                    self.groups.append((agents, rules))
                    agents, rules, collecting = [], [], True
                agents.append(v.lower())
            elif k in ("allow", "disallow") and agents:
                collecting = False
                rules.append((k, v))
        if agents:
            self.groups.append((agents, rules))

    def _rules_for(self, token: str) -> List[Tuple[str, str]]:
        token = token.lower()
        named = [r for a, r in self.groups if token in a]
        use = named or [r for a, r in self.groups if "*" in a]
        return [x for r in use for x in r]

    def allowed(self, path: str, token: str = "googlebot") -> bool:
        best_len, verdict = -1, True
        for kind, pat in self._rules_for(token):
            if not pat:
                continue
            rx = "^" + re.escape(pat).replace(r"\*", ".*")
            if rx.endswith(r"\$"):
                rx = rx[:-2] + "$"
            if re.match(rx, path):
                is_allow = kind == "allow"
                if len(pat) > best_len or (len(pat) == best_len and is_allow):
                    best_len, verdict = len(pat), is_allow
        return verdict


MAX_HOPS_CAP = 6


@dataclass
class Config:
    ua: str = BOTS["Googlebot smartphone"]["ua"]
    token: str = "googlebot"
    frm: str = ""
    max_hops: int = 6                      # hard cap on redirects followed, so loops and runaway chains cannot stall a run
    follow_chain: bool = True              # False: request each URL once and report only its first response
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    interval: float = 0.15                 # minimum seconds between requests to the same host
    allow_private: bool = False
    allowed_hosts: Tuple[str, ...] = ()
    body_limit: int = 262144
    slow_ms: int = 3000
    check_robots: bool = True              # robots.txt checks are optional
    honors_robots: bool = True             # False for agents that act on a person's request and ignore robots.txt
    check_http_version: bool = True        # report HTTP/1.1, HTTP/2 and whether HTTP/3 is advertised
    check_hsts: bool = True                # report the Strict-Transport-Security header (optional)
    cookie: str = ""                       # Cookie header value copied from a browser that passed the host's bot challenge
    extra_headers: Dict[str, str] = field(default_factory=dict)
    header_domain: str = ""                # cookie and extra headers go only to this domain and its subdomains, never to other hosts

    def __post_init__(self):
        self.max_hops = max(1, min(MAX_HOPS_CAP, int(self.max_hops)))


def find_bot(name: str) -> str:
    """Resolve a bot name typed on the command line: exact (any case), or a unique prefix or substring."""
    low = {k.lower(): k for k in BOTS}
    n = name.strip().lower()
    if n in low:
        return low[n]
    hits = [k for k in BOTS if k.lower().startswith(n)] or [k for k in BOTS if n in k.lower()]
    if len(hits) == 1:
        return hits[0]
    raise ValueError(f"Unknown or ambiguous bot '{name}'. Options: " + ", ".join(BOTS))


class HostLimiter:
    """Polite crawling: at most one request per ``interval`` seconds to each host."""

    def __init__(self, interval: float):
        self.interval, self._next, self._lock = interval, {}, threading.Lock()

    def wait(self, host: str) -> None:
        with self._lock:
            t = max(time.monotonic(), self._next.get(host, 0.0))
            self._next[host] = t + self.interval
        delay = t - time.monotonic()
        if delay > 0:
            time.sleep(delay)


_tls = threading.local()


def _session() -> requests.Session:
    s = getattr(_tls, "s", None)
    if s is None:
        s = requests.Session()
        s.trust_env = False                          # no proxies or netrc: keeps the address check meaningful
        _tls.s = s
    return s


def _domain_match(host: str, domain: str) -> bool:
    host, domain = host.split(":")[0].lower().strip("."), domain.lower().strip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


def _headers(cfg: Config, url: str = "") -> Dict[str, str]:
    h = {"User-Agent": cfg.ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Encoding": "gzip, deflate"}
    if cfg.frm:
        h["From"] = cfg.frm
    # a pasted cookie or header is only sent to the domain it was meant for, so a redirect to a third party never receives it
    if url and (cfg.cookie or cfg.extra_headers) and _domain_match(urlsplit(url).netloc, cfg.header_domain):
        h.update(cfg.extra_headers)
        if cfg.cookie:
            h["Cookie"] = cfg.cookie
    return h


def _get(url: str, cfg: Config, limiter: HostLimiter, read_body: bool = False):
    """One GET with no redirect following and no cookies. Returns (response or None, error text, body, ms)."""
    host = urlsplit(url).netloc
    last_err = ""
    for attempt in range(2):
        limiter.wait(host)
        t0 = time.monotonic()
        try:
            r = _session().get(url, headers=_headers(cfg, url), allow_redirects=False, stream=True,
                               timeout=(cfg.connect_timeout, cfg.read_timeout))
            body = ""
            if read_body and r.status_code not in REDIRECT_CODES:
                buf = b""
                for chunk in r.iter_content(8192):
                    buf += chunk
                    if len(buf) >= cfg.body_limit:
                        break
                body = buf.decode(r.encoding or "utf-8", errors="replace")
            ms = int((time.monotonic() - t0) * 1000)
            r.close()
            _session().cookies.clear()               # crawlers do not carry cookies between requests
            return r, "", body, ms
        except requests.exceptions.Timeout:
            last_err = "timeout"
        except requests.exceptions.RequestException as e:
            last_err = "connection: " + re.sub(r"\s+", " ", str(e))[:160]
            break
    return None, last_err, "", int((time.monotonic() - t0) * 1000)


class ProtocolCache:
    """Which HTTP version each origin negotiates, probed once per origin as the chosen crawler.

    Redirect and content checks use requests, which speaks HTTP/1.1 only, so a separate probe with an HTTP/2 capable client
    asks the server what it would negotiate. HTTP/3 runs over QUIC and cannot be tested here: it is reported as
    "advertised" when the server's Alt-Svc header offers it. Plain http is always HTTP/1.1 (browsers and crawlers do not use h2c)."""

    def __init__(self, cfg: Config, limiter: HostLimiter):
        self.cfg, self.limiter, self._d, self._lock, self._locks = cfg, limiter, {}, threading.Lock(), {}

    def get(self, url: str) -> str:
        sp = urlsplit(url)
        if sp.scheme == "http":
            return "HTTP/1.1"
        if httpx is None:
            return "unknown (httpx not installed)"
        origin = f"{sp.scheme}://{sp.netloc.lower()}"
        with self._lock:
            lock = self._locks.setdefault(origin, threading.Lock())
        with lock:
            if origin not in self._d:
                self._d[origin] = self._probe(url)
            return self._d[origin]

    def _probe(self, url: str) -> str:
        ok, _why = check_address(url, self.cfg.allow_private, self.cfg.allowed_hosts)
        if not ok:
            return "unknown"
        reason = ""
        for _attempt in range(2):                            # one retry: a first failure is often a dropped connection
            self.limiter.wait(urlsplit(url).netloc)
            try:
                client = httpx.Client(http2=True, trust_env=False, follow_redirects=False, headers=_headers(self.cfg, url),
                                      timeout=httpx.Timeout(self.cfg.read_timeout, connect=self.cfg.connect_timeout))
            except ImportError:
                return "unknown (HTTP/2 support missing: pip install \"httpx[http2]\")"
            try:
                with client:
                    with client.stream("GET", url) as r:
                        version = r.http_version or "HTTP/1.1"
                        alt = r.headers.get("Alt-Svc", "")
                h3 = re.search(r'\bh3(-\d+)?\s*=', alt) is not None
                return version + (" (HTTP/3 advertised)" if h3 else "")
            except Exception as e:                           # noqa: BLE001
                reason = type(e).__name__
        return f"unknown ({reason})"


class RobotsCache:
    """robots.txt per scheme and host, fetched once, as the chosen crawler."""

    def __init__(self, cfg: Config, limiter: HostLimiter):
        self.cfg, self.limiter, self._d, self._lock, self._locks = cfg, limiter, {}, threading.Lock(), {}

    def _fetch(self, origin: str) -> Tuple[str, RobotsRules]:
        url = origin + "/robots.txt"
        for _ in range(6):
            ok, _why = check_address(url, self.cfg.allow_private, self.cfg.allowed_hosts)
            if not ok:
                return "unavailable", RobotsRules()
            r, err, body, _ms = _get(url, self.cfg, self.limiter, read_body=True)
            if r is None:
                return "unavailable", RobotsRules()
            if r.status_code in REDIRECT_CODES and r.headers.get("Location"):
                url = urljoin(url, r.headers["Location"])
                continue
            if r.status_code == 200:
                return "ok", RobotsRules(body[:512000])
            if r.status_code == 429 or r.status_code >= 500:
                return "unavailable", RobotsRules()
            return "none", RobotsRules()               # 404 and other 4xx: no restrictions
        return "unavailable", RobotsRules()

    def check(self, url: str) -> str:
        """allowed, blocked or unknown"""
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}".lower()
        with self._lock:
            lock = self._locks.setdefault(origin, threading.Lock())
        with lock:
            if origin not in self._d:
                self._d[origin] = self._fetch(origin)
        state, rules = self._d[origin]
        if state == "unavailable":
            return "unknown"
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        return "allowed" if rules.allowed(path, self.cfg.token) else "blocked"

    def state(self, url: str) -> str:
        p = urlsplit(url)
        return self._d.get(f"{p.scheme}://{p.netloc}".lower(), ("", None))[0]


# --------------------------------------------------------------------------------------
# What the page says to a crawler
# --------------------------------------------------------------------------------------

_KNOWN_DIRECTIVES = {"all", "noindex", "nofollow", "none", "noarchive", "nosnippet", "notranslate", "noimageindex",
                     "unavailable_after", "max-snippet", "max-image-preview", "max-video-preview", "indexifembedded",
                     "nositelinkssearchbox"}


def directives_for(value: str, token: str) -> set:
    """Directives in an X-Robots-Tag or meta robots value that apply to this crawler. 'googlebot: noindex' only applies
    to Googlebot; a bare 'noindex' applies to every crawler. 'none' means noindex and nofollow."""
    out: set = set()
    scope: Optional[str] = None
    for part in (value or "").split(","):
        part = part.strip().lower()
        if not part:
            continue
        head, sep, rest = part.partition(":")
        if sep and head.strip() not in _KNOWN_DIRECTIVES:
            scope, part = head.strip(), rest.strip()
        d = part.split(":")[0].strip()
        if scope is None or scope == token.lower() or scope == "*":
            out.add(d)
            if d == "none":
                out |= {"noindex", "nofollow"}
    return out


class _Head(HTMLParser):
    def __init__(self, token: str):
        super().__init__(convert_charrefs=True)
        self.token, self.robots, self.canonical, self.refresh = token.lower(), [], "", ""
        self.title, self._in_title, self.script = "", False, []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            name = a.get("name", "").lower()
            if name in ("robots", self.token, "googlebot") and (name != "googlebot" or self.token == "googlebot"):
                self.robots.append(a.get("content", ""))
            if a.get("http-equiv", "").lower() == "refresh":
                self.refresh = a.get("content", "")
        elif tag == "link" and "canonical" in a.get("rel", "").lower().split() and not self.canonical:
            self.canonical = a.get("href", "").strip()
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data


def parse_page(body: str, token: str) -> Dict[str, object]:
    p = _Head(token)
    try:
        p.feed(body)
    except Exception:                                  # noqa: BLE001  malformed HTML must never break a run
        pass
    d: set = set()
    for v in p.robots:
        d |= directives_for(v, token)
    m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", p.refresh, flags=re.I)
    js = bool(re.search(r"(window\.|document\.)?location(\.href|\.replace\(|\.assign\()?\s*=?\s*[\(\"']?https?://|"
                        r"location\.(replace|assign)\(", body)) and len(body) < 4000
    return dict(meta_directives=d, meta_robots=", ".join(p.robots), canonical=p.canonical, title=" ".join(p.title.split()),
                meta_refresh=(m.group(1).strip() if m else ("yes" if p.refresh else "")), js_redirect=js)


def header_canonical(link_header: str) -> str:
    m = re.search(r"<([^>]+)>\s*;[^,]*rel\s*=\s*\"?canonical\"?", link_header or "", flags=re.I)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------------------
# One URL
# --------------------------------------------------------------------------------------

def parse_hsts(value: str) -> Dict[str, object]:
    d: Dict[str, object] = dict(max_age=None, include_subdomains=False, preload=False)
    for part in (value or "").split(";"):
        p = part.strip().lower()
        m = re.match(r"max-age\s*=\s*\"?(\d+)", p)
        if m:
            d["max_age"] = int(m.group(1))
        elif p == "includesubdomains":
            d["include_subdomains"] = True
        elif p == "preload":
            d["preload"] = True
    return d


HSTS_YEAR = 31536000


def hsts_assess(scheme: str, header: str, status: Optional[int]) -> Tuple[str, str]:
    """(summary text, issue code or ''). Browsers only honour HSTS on https, so http responses are n/a."""
    if scheme != "https":
        return ("n/a (http)", "HSTS_ON_HTTP" if header else "")
    if not header:
        return ("missing", "HSTS_MISSING" if status == 200 else "")
    d = parse_hsts(header)
    ma = d["max_age"]
    if ma is None:
        return ("invalid: no max-age", "HSTS_WEAK")
    flags = ", includeSubDomains" * bool(d["include_subdomains"]) + ", preload" * bool(d["preload"])
    if ma == 0:
        return ("disabled (max-age=0)", "HSTS_WEAK")
    if ma < HSTS_YEAR:
        return (f"short: max-age {ma}{flags}", "HSTS_WEAK")
    ready = " (meets preload requirements)" if d["include_subdomains"] and d["preload"] else ""
    return (f"ok: max-age {ma}{flags}{ready}", "")


def challenge_vendor(headers, status) -> str:
    """Name the bot-protection layer if the response is a CAPTCHA or JavaScript challenge rather than the site's own page."""
    h = {k.lower(): str(v) for k, v in headers.items()}
    if h.get("sg-captcha"):
        return "SiteGround"
    if h.get("cf-mitigated", "").lower() == "challenge":
        return "Cloudflare"
    if "x-datadome" in h or "x-datadome-response" in h:
        return "DataDome"
    if any(k.startswith("x-sucuri") for k in h) and status in (202, 403, 503):
        return "Sucuri"
    if "x-iinfo" in h and status in (403, 503):
        return "Imperva"
    if status in (202, 403, 429, 503) and "captcha" in " ".join(h.get(k, "") for k in ("x-robots-tag", "server", "via", "x-cdn")).lower():
        return "a bot-protection service"
    return ""


def curl_command(url: str, cfg: Config) -> str:
    """The curl command that shows the same hop-by-hop headers (use curl.exe in PowerShell, NUL for /dev/null on Windows)."""
    ua = cfg.ua.replace('"', "'")
    return f'curl -s -o /dev/null -D - -L --max-redirs {cfg.max_hops} -A "{ua}" "{url}"'


def check_url(url: str, cfg: Config, limiter: HostLimiter, robots: RobotsCache, expected: str = "",
              crawl_status: str = "", expected_type: str = "", protocols: Optional[ProtocolCache] = None) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    hops: List[Dict[str, object]] = []
    seen, cur = {norm(url)}, url
    loop = too_many = not_followed = False
    err_code, final, body, final_ms = "", None, "", 0
    challenged = ""
    for i in range(cfg.max_hops + 1):
        ok, why = check_address(cur, cfg.allow_private, cfg.allowed_hosts)
        if not ok:
            hops.append(dict(hop=i + 1, url=cur, status=None, location="", ms=0, note="blocked: " + why))
            err_code = "BLOCKED_ADDRESS"
            break
        r, err, text, ms = _get(cur, cfg, limiter, read_body=True)
        if r is None:
            hops.append(dict(hop=i + 1, url=cur, status=None, location="", ms=ms, note=err))
            err_code = "TIMEOUT" if err == "timeout" else "CONNECTION_ERROR"
            break
        loc = r.headers.get("Location", "")
        chal = challenge_vendor(r.headers, r.status_code)
        hops.append(dict(hop=i + 1, url=cur, status=r.status_code, location=loc, ms=ms,
                         note=(f"bot challenge ({chal}), not the site's real response" if chal else ""),
                         hsts=r.headers.get("Strict-Transport-Security", ""),
                        protocol=(protocols.get(cur) if (protocols and cfg.check_http_version) else "")))
        if r.status_code in REDIRECT_CODES and loc:
            nxt = urljoin(cur, loc)
            if not cfg.follow_chain:
                not_followed = True
                break
            if norm(nxt) in seen:
                loop = True
                break
            if i == cfg.max_hops:
                too_many = True
                break
            seen.add(norm(nxt))
            cur = nxt
            continue
        final, body, final_ms = r, text, ms
        challenged = chal
        break

    n_redirects = sum(1 for h in hops if h["status"] in REDIRECT_CODES and h["location"])
    last = hops[-1]
    final_url = last["url"] if final is not None else ""
    chain_status = ("complete" if final is not None else "loop" if loop else f"stopped at {cfg.max_hops} redirects" if too_many
                    else "not followed" if not_followed else "error")
    first_status = hops[0]["status"]
    final_status = final.status_code if final is not None else None
    chain = " > ".join(str(h["status"] if h["status"] is not None else "ERR") for h in hops)
    total_ms = sum(int(h["ms"]) for h in hops)

    # does the expected first hop happen? (type and, if given, where it points)
    etype = int(expected_type) if str(expected_type).strip().isdigit() else None
    hop_check = "n/a"
    if etype is not None:
        if first_status is None:
            hop_check = "no response"
        elif etype in REDIRECT_CODES:
            if first_status == etype:
                first_loc = urljoin(hops[0]["url"], hops[0]["location"]) if hops[0]["location"] else ""
                hop_check = ("confirmed" if not expected or match_kind(first_loc, expected) in ("exact", "slash")
                             else "right type, goes via another URL" if n_redirects > 1 else "right type, different target")
            elif first_status in REDIRECT_CODES:
                hop_check = f"wrong type (got {first_status})"
            else:
                hop_check = f"no redirect (got {first_status})"
        else:
            hop_check = "confirmed" if first_status == etype else f"wrong response (got {first_status})"

    # robots.txt for every URL the crawler would fetch (optional)
    if cfg.check_robots and cfg.honors_robots:
        blocked = {h["url"]: robots.check(h["url"]) for h in hops if h["status"] is not None or h["note"] == ""}
        robots_start = blocked.get(url, "unknown")
        others = [v for u, v in blocked.items() if u != url]
        robots_dest = "n/a" if not others else "blocked" if "blocked" in others else (
            "allowed" if all(v == "allowed" for v in others) else "unknown")
        robots_unavailable = robots.state(url) == "unavailable"
    else:
        robots_start = robots_dest = "not checked" if not cfg.check_robots else "not applicable (agent ignores robots.txt)"
        robots_unavailable = False

    x_robots = canonical = title = meta_robots = meta_refresh = ctype = ""
    noindex_h = noindex_m = js_redirect = False
    if final is not None:
        x_robots = final.headers.get("X-Robots-Tag", "")
        ctype = final.headers.get("Content-Type", "")
        noindex_h = "noindex" in directives_for(x_robots, cfg.token)
        canonical = header_canonical(final.headers.get("Link", ""))
        if final_status == 200 and ("html" in ctype.lower() or not ctype):
            pg = parse_page(body, cfg.token)
            noindex_m = "noindex" in pg["meta_directives"]
            canonical = pg["canonical"] or canonical
            title, meta_robots, meta_refresh, js_redirect = pg["title"], pg["meta_robots"], pg["meta_refresh"], pg["js_redirect"]
        if canonical:
            canonical = urljoin(final_url, canonical)

    http_version = "not checked"
    if cfg.check_http_version and protocols is not None:
        http_version = protocols.get(final_url) if final is not None else "n/a (no final page)"
    hsts_text, hsts_value, hsts_code = "not checked", "", ""
    if cfg.check_hsts:
        if final is not None:
            hsts_value = final.headers.get("Strict-Transport-Security", "")
            hsts_text, hsts_code = hsts_assess(urlsplit(final_url).scheme, hsts_value, final_status)
        else:
            hsts_text = "n/a (no final page)"

    # ---- issues
    codes: List[str] = []
    add = codes.append
    if err_code:
        add(err_code)
    if loop:
        add("LOOP")
    if too_many:
        add("TOO_MANY_HOPS")
    if not_followed:
        add("CHAIN_NOT_FOLLOWED")
    if robots_start == "blocked":
        add("ROBOTS_BLOCKED_START")
    if robots_dest == "blocked":
        add("ROBOTS_BLOCKED_DEST")
    if robots_unavailable:
        add("ROBOTS_UNAVAILABLE")
    intended_error = etype is not None and etype >= 400 and first_status == etype and n_redirects == 0
    if hop_check.startswith("wrong type") or hop_check.startswith("wrong response"):
        add("HOP_TYPE_MISMATCH")
    if challenged and final_status != 200:
        add("BOT_CHALLENGE")
    elif final is not None and final_status != 200 and not intended_error and not hop_check.startswith("wrong response"):
        if final_status in (401, 403, 429):
            add("BOT_REFUSED")
        elif final_status in (404, 410):
            add("NOT_FOUND")
        elif final_status >= 500:
            add("SERVER_ERROR")
        else:
            add("OTHER_STATUS")
    kind = match_kind(final_url, expected) if final_status == 200 else "n/a"
    if expected and final_status == 200:
        if n_redirects == 0 and kind != "exact":
            add("NOT_REDIRECTED")
        elif kind == "different":
            add("TARGET_MISMATCH")
        elif kind == "slash":
            add("TARGET_SLASH_DIFF")
    if any(h["status"] in TEMPORARY for h in hops) and etype not in TEMPORARY and "HOP_TYPE_MISMATCH" not in codes:
        add("TEMP_REDIRECT")
    if n_redirects >= 2 and not (loop or too_many):
        add("CHAIN")
    if final_status == 200:
        if noindex_h:
            add("NOINDEX_HEADER")
        if noindex_m:
            add("NOINDEX_META")
        if canonical and norm(canonical) != norm(final_url):
            add("CANONICAL_ELSEWHERE")
        elif not canonical and ("html" in ctype.lower() or not ctype):
            add("CANONICAL_MISSING")
        if meta_refresh:
            add("META_REFRESH")
        if js_redirect:
            add("JS_REDIRECT_SUSPECT")
        fp, sp = urlsplit(final_url), urlsplit(url)
        if n_redirects and fp.path in ("", "/") and sp.path not in ("", "/") and (not expected or urlsplit(expected).path not in ("", "/")):
            add("TO_HOME")
        if fp.scheme == "http" and fp.netloc.lower() not in {h.lower() for h in cfg.allowed_hosts}:
            add("INSECURE_FINAL")
    if hsts_code:
        add(hsts_code)
    if crawl_status and first_status is not None and str(crawl_status).strip() not in ("", str(first_status)):
        add("CRAWL_STATUS_CHANGED")
    if total_ms > cfg.slow_ms:
        add("SLOW")
    codes = list(dict.fromkeys(codes))
    sev = min((ISSUES[c][0] for c in codes), key=lambda s: SEVERITY_ORDER[s], default="")

    row = dict(url=url, expected=expected, expected_type=(etype if etype is not None else ""), hop_check=hop_check, severity=sev or "ok", issues="; ".join(ISSUES[c][1] for c in codes),
               issue_codes=",".join(codes), first_status=first_status, final_status=final_status, hops=n_redirects,
               chain=chain, chain_status=chain_status, final_url=final_url, target_match=kind, robots_start=robots_start, robots_dest=robots_dest,
               http_version=http_version, hsts=hsts_value, hsts_status=hsts_text, x_robots_tag=x_robots, meta_robots=meta_robots, canonical=canonical, title=title, content_type=ctype.split(";")[0],
               total_ms=total_ms, crawl_status=crawl_status, curl=curl_command(url, cfg))
    return row, hops


# --------------------------------------------------------------------------------------
# Many URLs
# --------------------------------------------------------------------------------------

def sort_results(df: pd.DataFrame) -> pd.DataFrame:
    """Errors first, then warnings, info and clean URLs; otherwise the original order."""
    key = df.severity.map(lambda v: SEVERITY_ORDER.get(v if v != "ok" else "", 3))
    return df.assign(_s=key).sort_values("_s", kind="stable").drop(columns="_s").reset_index(drop=True)


def run_checks(items: Sequence[Dict[str, str]], cfg: Config, workers: int = 6,
               progress: Optional[Callable[[int, int], None]] = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """items: dicts with url and optionally expected and crawl_status. Returns (results, hops)."""
    limiter = HostLimiter(cfg.interval)
    robots = RobotsCache(cfg, limiter)
    protocols = ProtocolCache(cfg, limiter)
    rows: Dict[int, Dict[str, object]] = {}
    hop_rows: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(check_url, it["url"], cfg, limiter, robots, it.get("expected", ""), it.get("crawl_status", ""), it.get("expected_type", ""), protocols): i
                for i, it in enumerate(items)}
        for n, f in enumerate(as_completed(futs), 1):
            i = futs[f]
            try:
                row, hops = f.result()
            except Exception as e:                   # noqa: BLE001
                row = dict(url=items[i]["url"], expected=items[i].get("expected", ""), severity="error",
                           issues="Could not check this URL", issue_codes="CONNECTION_ERROR",
                           chain="ERR", curl=curl_command(items[i]["url"], cfg))
                hops = [dict(hop=1, url=items[i]["url"], status=None, location="", ms=0, note=str(e)[:160])]
            rows[i] = row
            hop_rows += [dict(h, start_url=row["url"]) for h in hops]
            if progress:
                progress(n, len(items))
    df = pd.DataFrame([rows[i] for i in sorted(rows)])
    for c in ("first_status", "final_status"):
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")
    df = sort_results(df)
    hop_df = pd.DataFrame(hop_rows, columns=["start_url", "hop", "url", "status", "location", "ms", "note", "hsts", "protocol"])
    hop_df["hsts"] = hop_df["hsts"].fillna("")
    hop_df["protocol"] = hop_df["protocol"].fillna("")
    return df, hop_df


def issue_summary(df: pd.DataFrame) -> pd.DataFrame:
    c: Counter = Counter()
    for codes in df.get("issue_codes", []):
        c.update([x for x in str(codes).split(",") if x])
    rows = [dict(code=k, severity=ISSUES[k][0], issue=ISSUES[k][1], urls=n, what_it_means=ISSUES[k][2]) for k, n in c.items()]
    out = pd.DataFrame(rows, columns=["code", "severity", "issue", "urls", "what_it_means"])
    out["_s"] = out.severity.map(SEVERITY_ORDER)
    return out.sort_values(["_s", "urls"], ascending=[True, False]).drop(columns="_s").reset_index(drop=True)


# --------------------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------------------

def _col(df: pd.DataFrame, *names: str) -> Optional[str]:
    low = {str(c).lower().strip(): c for c in df.columns}
    for n in names:
        if n in low:
            return low[n]
    return None


def absolute(u: str, base: str = "") -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if re.match(r"^https?://", u, flags=re.I):
        return u
    return urljoin(base.rstrip("/") + "/", u.lstrip("/")) if base else ""


def parse_type(v) -> str:
    """'301', '301 Moved Permanently', 'permanent', 'temporary' to a status code string ('' if none)."""
    t = str(v or "").strip().lower()
    m = re.search(r"\b([1-5]\d\d)\b", t)
    if m:
        return m.group(1)
    return {"permanent": "301", "temporary": "302", "gone": "410"}.get(t, "")


def load_map(df: pd.DataFrame, base_url: str = "", default_type: str = "") -> List[Dict[str, str]]:
    """Redirect map: Source, expected redirect type (optional) and Target. Also accepts Old/New and From/To; the type
    column can be called Type, Redirect type, Expected type, Status or Code. Paths are joined to base_url.
    A 404 or 410 row may leave Target empty. default_type fills rows that have a target but no type."""
    sc = _col(df, "source", "old", "old url", "from", "address", "url")
    tc = _col(df, "target", "new", "new url", "to", "destination")
    yc = _col(df, "expected redirect type", "redirect type", "expected type", "type", "expected status", "status code", "status", "code")
    if not (sc and tc):
        raise ValueError("The redirect map needs a Source column and a Target column (old URL and new URL). "
                         "An optional Type column holds the expected redirect type, for example 301.")
    out, seen = [], set()
    for i in range(len(df)):
        s_ = absolute(str(df[sc].iloc[i]), base_url)
        t_ = absolute(str(df[tc].iloc[i]), base_url)
        ty = parse_type(df[yc].iloc[i]) if yc else ""
        if not ty and t_ and default_type:
            ty = str(default_type)
        if s_ and s_ not in seen and (t_ or ty):
            seen.add(s_)
            out.append(dict(url=s_, expected=t_, expected_type=ty))
    return out


def load_sf(df: pd.DataFrame, statuses: Sequence[str] = ("2xx", "3xx", "4xx", "5xx"), html_only: bool = True,
            indexable_only: bool = False) -> pd.DataFrame:
    """Screaming Frog Internal: All export, filtered. Returns url, crawl_status, redirect_url."""
    ac = _col(df, "address", "url")
    if not ac:
        raise ValueError("The Screaming Frog export needs an Address column.")
    sc, ct, ix, rc = _col(df, "status code"), _col(df, "content type"), _col(df, "indexability"), _col(df, "redirect url")
    d = pd.DataFrame({"url": df[ac].astype(str).str.strip(),
                      "crawl_status": df[sc].astype(str).str.strip() if sc else "",
                      "redirect_url": df[rc].astype(str).str.strip() if rc else ""})
    mask = d.url.str.match(r"^https?://", case=False)
    if sc:
        cls = d.crawl_status.str[:1] + "xx"
        mask &= cls.isin(list(statuses)) | (d.crawl_status == "")
    if ct and html_only:
        mask &= df[ct].astype(str).str.contains("html", case=False) | (df[ct].astype(str).str.strip() == "")
    if ix and indexable_only:
        mask &= df[ix].astype(str).str.lower().eq("indexable")
    return d[mask].drop_duplicates("url").reset_index(drop=True)


def build_items(map_items: Sequence[Dict[str, str]] = (), pasted: str = "", sf: Optional[pd.DataFrame] = None,
                base_url: str = "", use_sf_urls: bool = True) -> List[Dict[str, str]]:
    """Combine a redirect map, pasted URLs and a Screaming Frog export into one de-duplicated list."""
    items: Dict[str, Dict[str, str]] = {}
    for m in map_items:
        items[m["url"]] = dict(m)
    for line in pasted.splitlines():
        u = absolute(line.split(",")[0], base_url)
        if u and u not in items:
            items[u] = dict(url=u, expected="")
    sfmap = {}
    if sf is not None:
        sfmap = dict(zip(sf.url, sf.crawl_status))
        if use_sf_urls:
            for u in sf.url:
                if u not in items:
                    items[u] = dict(url=u, expected="")
    for u, it in items.items():
        if u in sfmap:
            it["crawl_status"] = sfmap[u]
    return list(items.values())
