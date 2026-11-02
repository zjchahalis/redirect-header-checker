"""A tiny local web server with deliberately broken redirects, so the app can be tried without touching a real site.

Every behaviour the checker reports is represented: a clean 301, a chain, a temporary redirect, a loop, the wrong
destination, a 404, a five-hop chain, a chain that never ends, a page that redirects to itself, a redirect to the home page, a noindex header, a noindex meta tag, a canonical pointing elsewhere,
a robots.txt block (with a wildcard), a meta refresh, a 500, and a page that refuses Googlebot user agents, a page that refuses AI crawlers, and an HSTS header sent over http.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Tuple

AI_TOKENS = ("gptbot", "oai-searchbot", "chatgpt-user", "claudebot", "claude-user", "claude-searchbot", "perplexity", "ccbot",
             "bytespider", "amazonbot", "meta-external", "meta-webindexer")

PAGE = "<html><head><title>{t}</title>{h}</head><body><h1>{t}</h1></body></html>"

ROBOTS = """User-agent: *
Disallow: /private/
Disallow: /old/blocked/
Disallow: /*?sessionid=
Allow: /old/blocked/ok$
"""

# path -> (status, location or None, extra headers, head html)
ROUTES: Dict[str, Tuple[int, str, Dict[str, str], str]] = {
    "/old/clean": (301, "/new/clean", {}, ""),
    "/new/clean": (200, "", {}, '<link rel="canonical" href="{base}/new/clean">'),
    "/old/chain": (301, "/old/chain-step", {}, ""),
    "/old/chain-step": (301, "/new/chain", {}, ""),
    "/new/chain": (200, "", {}, '<link rel="canonical" href="{base}/new/chain">'),
    "/old/temporary": (302, "/new/temporary", {}, ""),
    "/new/temporary": (200, "", {}, '<link rel="canonical" href="{base}/new/temporary">'),
    "/old/loop-a": (301, "/old/loop-b", {}, ""),
    "/old/loop-b": (301, "/old/loop-a", {}, ""),
    "/old/wrong": (301, "/new/other-page", {}, ""),
    "/new/other-page": (200, "", {}, '<link rel="canonical" href="{base}/new/other-page">'),
    "/new/intended": (200, "", {}, '<link rel="canonical" href="{base}/new/intended">'),
    "/old/gone": (404, "", {}, ""),
    "/old/to-home": (301, "/", {}, ""),
    "/": (200, "", {}, '<link rel="canonical" href="{base}/">'),
    "/old/staging-leak": (301, "/new/noindex-header", {}, ""),
    "/new/noindex-header": (200, "", {"X-Robots-Tag": "noindex, nofollow"}, '<link rel="canonical" href="{base}/new/noindex-header">'),
    "/old/meta-noindex": (301, "/new/noindex-meta", {}, ""),
    "/new/noindex-meta": (200, "", {}, '<meta name="robots" content="noindex"><link rel="canonical" href="{base}/new/noindex-meta">'),
    "/old/canonical": (301, "/new/canonical-elsewhere", {}, ""),
    "/new/canonical-elsewhere": (200, "", {}, '<link rel="canonical" href="{base}/new/clean">'),
    "/old/blocked/page": (301, "/new/blocked-target", {}, ""),
    "/new/blocked-target": (200, "", {}, '<link rel="canonical" href="{base}/new/blocked-target">'),
    "/old/meta-refresh": (200, "", {}, '<meta http-equiv="refresh" content="0; url={base}/new/clean"><link rel="canonical" href="{base}/old/meta-refresh">'),
    "/old/promo": (302, "/new/promo", {}, ""),
    "/new/promo": (200, "", {}, '<link rel="canonical" href="{base}/new/promo">'),
    "/old/retired": (410, "", {}, ""),
    "/old/long-1": (301, "/old/long-2", {}, ""),
    "/old/long-2": (301, "/old/long-3", {}, ""),
    "/old/long-3": (301, "/old/long-4", {}, ""),
    "/old/long-4": (301, "/new/long", {}, ""),
    "/new/long": (200, "", {}, '<link rel="canonical" href="{base}/new/long">'),
    "/old/self": (301, "/old/self", {}, ""),
    "/old/hsts-http": (301, "/new/hsts-http", {}, ""),
    "/new/hsts-http": (200, "", {"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}, '<link rel="canonical" href="{base}/new/hsts-http">'),
    "/old/ai-blocked": (301, "/new/ai-blocked", {}, ""),
    "/new/ai-blocked": (200, "", {}, '<link rel="canonical" href="{base}/new/ai-blocked">'),
    "/old/error": (500, "", {}, ""),
    "/old/waf": (301, "/new/waf", {}, ""),
    "/new/waf": (200, "", {}, '<link rel="canonical" href="{base}/new/waf">'),
}


def make_handler(base_holder: List[str]):
    class H(BaseHTTPRequestHandler):
        def _send(self, status, body=b"", headers=None):
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            base = base_holder[0]
            path = self.path
            bare = path.split("?")[0]
            if bare == "/robots.txt":
                return self._send(200, ROBOTS.encode(), {"Content-Type": "text/plain"})
            ua = self.headers.get("User-Agent", "").lower()
            if bare == "/new/ai-blocked" and any(t in ua for t in AI_TOKENS):
                return self._send(403, b"AI crawlers are not allowed", {"Content-Type": "text/plain"})
            if bare == "/new/waf" and "googlebot" in self.headers.get("User-Agent", "").lower():
                return self._send(403, b"Forbidden", {"Content-Type": "text/plain"})
            if bare.startswith("/old/blocked/") and bare != "/old/blocked/page":
                bare = "/old/blocked/page"
            if bare == "/old/clean" and "sessionid" in path:
                bare = "/old/clean"
            if bare.startswith("/old/endless/"):                       # every URL redirects to the next, forever
                n = int(bare.rsplit("/", 1)[1]) if bare.rsplit("/", 1)[1].isdigit() else 0
                return self._send(301, b"", {"Location": f"/old/endless/{n + 1}"})
            route = ROUTES.get(bare)
            if route is None:
                return self._send(404, b"Not found", {"Content-Type": "text/plain"})
            status, loc, hdrs, head = route
            h = {"Content-Type": "text/html; charset=utf-8", **hdrs}
            if loc:
                h["Location"] = loc
            body = PAGE.format(t=bare.strip("/") or "Home", h=head.format(base=base)).encode()
            self._send(status, b"" if status in (301, 302) else body, h)

        do_HEAD = do_GET  # noqa: N815

        def log_message(self, *a):
            pass

    return H


def start() -> Tuple[HTTPServer, str]:
    """Start the demo server on a free local port. Returns (server, base_url)."""
    holder: List[str] = [""]
    srv = HTTPServer(("127.0.0.1", 0), make_handler(holder))
    holder[0] = f"http://127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, holder[0]


def demo_items(base: str) -> List[Dict[str, str]]:
    """Old URLs to test: (old path, expected target path or '', expected redirect type)."""
    m = [("/old/clean", "/new/clean", "301"), ("/old/chain", "/new/chain", "301"), ("/old/temporary", "/new/temporary", "301"),
         ("/old/loop-a", "/new/loop", "301"), ("/old/wrong", "/new/intended", "301"), ("/old/gone", "", "410"),
         ("/old/to-home", "/new/to-home", "301"), ("/old/staging-leak", "/new/noindex-header", "301"),
         ("/old/meta-noindex", "/new/noindex-meta", "301"), ("/old/canonical", "/new/canonical-elsewhere", "301"),
         ("/old/blocked/page", "/new/blocked-target", "301"), ("/old/clean?sessionid=7", "/new/clean", "301"),
         ("/old/meta-refresh", "/new/clean", "301"), ("/old/error", "/new/error", "301"), ("/old/waf", "/new/waf", "301"),
         ("/old/long-1", "/new/long", "301"), ("/old/endless/1", "/new/endless", "301"), ("/old/self", "/new/self", "301"),
         ("/old/promo", "/new/promo", "302"), ("/old/retired", "", "410"),
         ("/old/hsts-http", "/new/hsts-http", "301"), ("/old/ai-blocked", "/new/ai-blocked", "301")]
    return [dict(url=base + a, expected=(base + b) if b else "", expected_type=t,
                 crawl_status="200" if a.endswith("clean") else "") for a, b, t in m]
