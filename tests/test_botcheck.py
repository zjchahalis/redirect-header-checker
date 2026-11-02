import os
import subprocess
import sys

import pandas as pd
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import botcheck as bc  # noqa: E402
import demo_server  # noqa: E402


@pytest.fixture(scope="module")
def srv():
    server, base = demo_server.start()
    yield base
    server.shutdown()


def run(base, items=None, **kw):
    cfg = bc.Config(allowed_hosts=(base.split("//")[1],), interval=0.0, **kw)
    return bc.run_checks(items or demo_server.demo_items(base), cfg, workers=4)


def codes(df, path):
    r = df[df.url.str.endswith(path)].iloc[0]
    return set(filter(None, r.issue_codes.split(",")))


def test_demo_findings(srv):
    df, hops = run(srv)
    assert codes(df, "/old/loop-a") == {"LOOP"}
    assert codes(df, "/old/wrong") == {"TARGET_MISMATCH"}
    assert codes(df, "/old/to-home") == {"TARGET_MISMATCH", "TO_HOME"}
    assert codes(df, "/old/staging-leak") == {"NOINDEX_HEADER"}
    assert codes(df, "/old/meta-noindex") == {"NOINDEX_META"}
    assert codes(df, "/old/blocked/page") == {"ROBOTS_BLOCKED_START"}
    assert codes(df, "sessionid=7") == {"ROBOTS_BLOCKED_START"}                  # wildcard rule
    assert codes(df, "/old/meta-refresh") == {"NOT_REDIRECTED", "META_REFRESH"}
    assert codes(df, "/old/error") == {"SERVER_ERROR"}
    assert codes(df, "/old/waf") == {"BOT_REFUSED"}                              # 403 only for Googlebot UAs
    assert codes(df, "/old/chain") == {"CHAIN"}
    assert codes(df, "/old/temporary") == {"HOP_TYPE_MISMATCH"}                  # map says 301, server sends 302
    assert codes(df, "/old/gone") == {"HOP_TYPE_MISMATCH"}                       # map says 410, server sends 404
    assert codes(df, "/old/promo") == set() and codes(df, "/old/retired") == set()   # expected 302 and 410 happen
    assert codes(df, "/old/long-1") == {"CHAIN"} and codes(df, "/old/endless/1") == {"TOO_MANY_HOPS"}
    assert codes(df, "/old/self") == {"LOOP"}
    assert codes(df, "/old/canonical") == {"CANONICAL_ELSEWHERE"}
    assert codes(df, "/old/clean") == {"CRAWL_STATUS_CHANGED"}                  # crawl said 200, live says 301
    assert df.severity.iloc[0] == "error" and df.severity.iloc[-1] == "ok"     # errors first, clean URLs last
    r = df[df.url.str.endswith("/old/chain")].iloc[0]
    assert r.hops == 2 and r.chain == "301 > 301 > 200" and r.final_url.endswith("/new/chain")
    assert len(hops[hops.start_url == r.url]) == 3
    assert r.curl.startswith("curl ") and "Googlebot" in r.curl and "--max-redirs 6" in r.curl


def test_robots_checks_are_optional(srv):
    items = [i for i in demo_server.demo_items(srv) if i["url"].endswith("/old/blocked/page") or "sessionid" in i["url"]]
    on, _ = run(srv, items)
    off, _ = run(srv, items, check_robots=False)
    assert set(on.issue_codes) == {"ROBOTS_BLOCKED_START"}
    assert not any("ROBOTS" in c for c in off.issue_codes) and set(off.robots_start) == {"not checked"}
    assert (off.final_status == 200).all()                                       # the redirects themselves are still checked


def test_user_agent_matters(srv):
    waf = [i for i in demo_server.demo_items(srv) if i["url"].endswith("/old/waf")]
    df, _ = run(srv, waf)
    assert df.final_status.iloc[0] == 403 and "BOT_REFUSED" in df.issue_codes.iloc[0]
    bing = bc.BOTS["Bingbot"]
    df, _ = run(srv, waf, ua=bing["ua"], token=bing["token"])                     # same URL, a different crawler gets the page
    assert df.final_status.iloc[0] == 200 and "BOT_REFUSED" not in df.issue_codes.iloc[0]


def test_too_many_hops_and_no_map(srv):
    df, _ = run(srv, [dict(url=srv + "/old/chain")], max_hops=1)
    assert "TOO_MANY_HOPS" in df.issue_codes.iloc[0] and pd.isna(df.final_status.iloc[0])
    df, _ = run(srv, [dict(url=srv + "/old/clean")])
    assert df.target_match.iloc[0] == "n/a" and df.severity.iloc[0] == "ok"


def test_target_slash_difference(srv):
    df, _ = run(srv, [dict(url=srv + "/old/clean", expected=srv + "/new/clean/")])
    assert "TARGET_SLASH_DIFF" in df.issue_codes.iloc[0]


def test_connection_error_is_reported():
    cfg = bc.Config(allow_private=True, interval=0.0, connect_timeout=1.0)
    df, _ = bc.run_checks([dict(url="http://127.0.0.1:1/nothing")], cfg)
    assert df.issue_codes.iloc[0] == "CONNECTION_ERROR" and pd.isna(df.final_status.iloc[0])


# ---------------------------------------------------------------- the address guard
@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://localhost/", "http://10.0.0.5/admin", "http://192.168.1.1/",
                                 "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://0.0.0.0/",
                                 "http://100.64.0.1/", "file:///etc/passwd", "ftp://example.com/", "http://user:pw@example.com/",
                                 "https://example.com:8443/", "http://[::ffff:127.0.0.1]/"])
def test_guard_refuses_private_and_odd_urls(url):
    ok, why = bc.check_address(url)
    assert not ok and why


def test_guard_allows_public_and_explicit_exceptions():
    assert bc.check_address("http://93.184.216.34/")[0] and bc.check_address("https://93.184.216.34:443/x")[0]
    assert bc.check_address("http://127.0.0.1:8000/", allowed_hosts=["127.0.0.1:8000"])[0]
    assert not bc.check_address("http://127.0.0.1:8001/", allowed_hosts=["127.0.0.1:8000"])[0]
    assert bc.check_address("http://127.0.0.1:8000/", allow_private=True)[0]


def test_private_target_is_not_requested_by_default(srv):
    df, hops = bc.run_checks([dict(url=srv + "/old/clean")], bc.Config(interval=0.0))      # no exception for the demo host
    assert df.issue_codes.iloc[0] == "BLOCKED_ADDRESS" and hops.status.isna().all()


def test_redirect_to_private_address_is_refused(monkeypatch):
    """A public-looking host that redirects to the cloud metadata address must not be followed."""
    class R:
        status_code, headers, encoding = 302, {"Location": "http://169.254.169.254/latest/"}, "utf-8"

        def iter_content(self, n):
            return iter(())

        def close(self):
            pass

    real_guard, requested = bc.check_address, []
    monkeypatch.setattr(bc, "check_address", lambda u, p=False, a=(): (True, "") if "public.test" in u else real_guard(u, p, a))

    def fake_get(url, cfg, limiter, read_body=False):
        requested.append(url)
        return (R(), "", "", 1)

    monkeypatch.setattr(bc, "_get", fake_get)
    cfg = bc.Config()
    row, hops = bc.check_url("http://public.test/", cfg, bc.HostLimiter(0), bc.RobotsCache(cfg, bc.HostLimiter(0)))
    assert "BLOCKED_ADDRESS" in row["issue_codes"] and hops[-1]["status"] is None
    assert not any("169.254" in u for u in requested)


# ---------------------------------------------------------------- robots.txt and directives
def test_robots_matching_follows_google_rules():
    r = bc.RobotsRules("User-agent: *\nDisallow: /private/\nDisallow: /*?sessionid=\nDisallow: /exact$\nAllow: /private/ok\n"
                       "\nUser-agent: googlebot\nDisallow: /g-only/\n")
    assert r.allowed("/private/x", "bingbot") is False and r.allowed("/private/ok", "bingbot") is True      # longest match wins
    assert r.allowed("/a?sessionid=1", "bingbot") is False                                                    # wildcard
    assert r.allowed("/exact", "bingbot") is False and r.allowed("/exact/more", "bingbot") is True            # $ anchor
    assert r.allowed("/g-only/x", "googlebot") is False and r.allowed("/private/x", "googlebot") is True     # own group replaces *
    assert bc.RobotsRules("User-agent: *\nDisallow:\n").allowed("/anything", "googlebot")                     # empty = allow all
    assert bc.RobotsRules("User-agent: *\nDisallow: /\nAllow: /x\n").allowed("/x", "googlebot")               # longer Allow beats shorter Disallow
    assert bc.RobotsRules("").allowed("/x")


def test_robots_directive_parsing():
    assert "noindex" in bc.directives_for("noindex, nofollow", "googlebot")
    assert "noindex" in bc.directives_for("googlebot: noindex", "googlebot")
    assert "noindex" not in bc.directives_for("bingbot: noindex", "googlebot")
    assert "noindex" not in bc.directives_for("googlebot: nofollow, bingbot: noindex", "googlebot")
    assert {"noindex", "nofollow"} <= bc.directives_for("none", "googlebot")
    assert "noindex" not in bc.directives_for("unavailable_after: 25 Jun 2030 15:00:00 PST", "googlebot")
    p = bc.parse_page('<html><head><meta name="robots" content="noindex"><link rel="canonical" href="/a"><title> Hi  there </title></head>', "googlebot")
    assert "noindex" in p["meta_directives"] and p["canonical"] == "/a" and p["title"] == "Hi there"
    assert "noindex" not in bc.parse_page('<meta name="bingbot" content="noindex">', "googlebot")["meta_directives"]
    assert bc.header_canonical('<https://x.com/a>; rel="canonical"') == "https://x.com/a"


# ---------------------------------------------------------------- inputs
def test_inputs_and_url_building():
    m = bc.load_map(pd.DataFrame({"Old": ["/a", "/b", "/a"], "New": ["/x", "/y", "/z"]}), "https://s.com")
    assert m == [dict(url="https://s.com/a", expected="https://s.com/x", expected_type=""),
                 dict(url="https://s.com/b", expected="https://s.com/y", expected_type="")]
    sf = bc.load_sf(pd.DataFrame({"Address": ["https://s.com/a", "https://s.com/img.png", "https://s.com/err", "https://s.com/c"],
                                  "Content Type": ["text/html", "image/png", "text/html", "text/html"],
                                  "Status Code": ["200", "200", "404", "301"], "Indexability": ["Indexable"] * 4}), ["2xx", "3xx"])
    assert list(sf.url) == ["https://s.com/a", "https://s.com/c"]
    items = bc.build_items(m, "/p\nhttps://s.com/a", sf, "https://s.com", use_sf_urls=True)
    assert [i["url"] for i in items] == ["https://s.com/a", "https://s.com/b", "https://s.com/p", "https://s.com/c"]
    assert items[0]["crawl_status"] == "200" and items[0]["expected"] == "https://s.com/x"
    with pytest.raises(ValueError):
        bc.load_map(pd.DataFrame({"Address": ["x"]}))
    typed = bc.load_map(pd.DataFrame({"Source": ["/a", "/b", "/c", "/d"], "Type": ["301", "302 Found", "", "410"],
                                      "Target": ["/x", "/y", "/z", ""]}), "https://s.com", default_type="308")
    assert [(t["expected_type"], t["expected"].replace("https://s.com", "")) for t in typed] == [
        ("301", "/x"), ("302", "/y"), ("308", "/z"), ("410", "")]               # default fills the blank, gone pages need no target
    assert bc.parse_type("Permanent") == "301" and bc.parse_type("temporary") == "302" and bc.parse_type("n/a") == ""


def test_cli_end_to_end(srv, tmp_path):
    mp = tmp_path / "m.csv"
    mp.write_text("Source,Target\n" + "\n".join(f"{i['url']},{i['expected']}" for i in demo_server.demo_items(srv)[3:6]))
    out = tmp_path / "o"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "bot_cli.py"), "--map", str(mp), "--allow-private", "--rps", "50",
                        "--out", str(out)], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 1, r.stderr                                           # errors present, so non-zero exit
    assert (out / "results.csv").exists() and (out / "hops.csv").exists() and (out / "issues.csv").exists()


def test_streamlit_app_runs_demo():
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(os.path.join(ROOT, "app.py"), default_timeout=120)
    at.run()
    assert not at.exception
    assert [t.label for t in at.tabs][:4] == ["1. How it works", "2. Check URLs", "3. Check a redirect map", "Glossary"]
    at.sidebar.checkbox(key="use_demo").check()
    at.run()
    # one-off URL tab: no map columns, no map metric
    [b for b in at.button if b.label == "Run checks"][0].click()
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    vals = {m.label: m.value for m in at.metric}
    assert vals["URLs checked"] == "22" and vals["Longest chain"] == "7 hops" and "Expected hop happened" not in vals
    shown = at.multiselect(key=[k for k in [m.key for m in at.multiselect] if k and k.startswith("bc_urls_cols_")][0]).value
    assert "http_version" in shown and "hsts_status" in shown and "robots_start" in shown and "hop_check" not in shown and "curl" not in shown
    # redirect map tab: map columns and the expected-hop metric
    [b for b in at.button if b.label == "Check the redirect map"][0].click()
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert any(m.label == "Expected hop happened" for m in at.metric)
    shown = at.multiselect(key=[k for k in [m.key for m in at.multiselect] if k and k.startswith("bc_map_cols_")][0]).value
    assert {"expected_type", "expected", "hop_check", "target_match", "http_version"} <= set(shown) and "curl" not in shown


def test_protocol_probe_failure_is_explained(monkeypatch):
    import types
    cfg = bc.Config(interval=0.0, allowed_hosts=("203.0.113.9",))
    monkeypatch.setattr(bc, "check_address", lambda *a, **k: (True, ""))
    fake = types.SimpleNamespace(Timeout=lambda *a, **k: None,
                                 Client=lambda **k: (_ for _ in ()).throw(ImportError("h2")))
    monkeypatch.setattr(bc, "httpx", fake)
    assert "pip install" in bc.ProtocolCache(cfg, bc.HostLimiter(0))._probe("https://203.0.113.9/")


# ---------------------------------------------------------------- hop cap, chain option, expected hop
def test_hop_cap_is_six_and_loops_cannot_stall(srv):
    assert bc.Config(max_hops=50).max_hops == 6 and bc.Config(max_hops=0).max_hops == 1
    cfg = bc.Config(allowed_hosts=(srv.split("//")[1],), interval=0.0, max_hops=50)
    df, hops = bc.run_checks([dict(url=srv + "/old/endless/1"), dict(url=srv + "/old/self"), dict(url=srv + "/old/loop-a")], cfg)
    by = {u.rsplit("/old/", 1)[1]: r for u, r in zip(df.url, df.itertuples())}
    assert by["endless/1"].chain_status == "stopped at 6 redirects" and by["endless/1"].hops == 7
    assert len(hops[hops.start_url.str.endswith("endless/1")]) == 7             # the seventh response is seen, never an eighth
    assert by["self"].chain_status == "loop" and by["loop-a"].chain_status == "loop"
    assert all(pd.isna(r.final_status) and r.final_url == "" for r in by.values())
    assert "--max-redirs 6" in df.curl.iloc[0]


def test_five_hop_chain_within_cap_reaches_final_url(srv):
    df, _ = run(srv, [dict(url=srv + "/old/long-1", expected=srv + "/new/long", expected_type="301")])
    r = df.iloc[0]
    assert r.hops == 4 and r.chain == "301 > 301 > 301 > 301 > 200" and r.chain_status == "complete"
    assert r.final_url.endswith("/new/long") and r.target_match == "exact" and r.hop_check == "right type, goes via another URL"


def test_follow_chain_can_be_turned_off(srv):
    cfg = bc.Config(allowed_hosts=(srv.split("//")[1],), interval=0.0, follow_chain=False)
    df, hops = bc.run_checks([dict(url=srv + "/old/chain", expected=srv + "/new/chain", expected_type="301")], cfg)
    r = df.iloc[0]
    assert r.chain == "301" and r.chain_status == "not followed" and r.final_url == "" and len(hops) == 1
    assert "CHAIN_NOT_FOLLOWED" in r.issue_codes and "TARGET_MISMATCH" not in r.issue_codes


def test_expected_hop_checks(srv):
    def one(path, target, typ):
        df, _ = run(srv, [dict(url=srv + path, expected=(srv + target) if target else "", expected_type=typ)])
        return df.iloc[0]
    assert one("/old/clean", "/new/clean", "301").hop_check == "confirmed"
    assert one("/old/clean", "", "301").hop_check == "confirmed"                  # type only, no target
    assert one("/old/clean", "/new/clean", "").hop_check == "n/a"                 # no type in the map: not checked
    assert one("/old/temporary", "/new/temporary", "301").hop_check == "wrong type (got 302)"
    assert one("/old/promo", "/new/promo", "302").hop_check == "confirmed"
    assert one("/old/wrong", "/new/intended", "301").hop_check == "right type, different target"
    assert one("/old/meta-refresh", "/new/clean", "301").hop_check == "no redirect (got 200)"
    assert one("/old/retired", "", "410").issue_codes == "" and one("/old/gone", "", "410").hop_check == "wrong response (got 404)"
    assert one("/old/promo", "/new/promo", "302").issue_codes == ""               # an intended temporary redirect is not flagged


def test_cli_options(srv, tmp_path):
    mp = tmp_path / "m.csv"
    mp.write_text(f"Source,Type,Target\n{srv}/old/chain,301,{srv}/new/chain\n")
    out = tmp_path / "o"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "bot_cli.py"), "--map", str(mp), "--allow-private", "--rps", "50",
                        "--no-follow", "--max-hops", "99", "--out", str(out)], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    assert pd.read_csv(out / "results.csv").chain_status.iloc[0] == "not followed"


def test_bot_list_and_lookup():
    groups = {b["group"] for b in bc.BOTS.values()}
    assert {"Search", "AI", "Browser", "Custom"} <= groups
    for name, b in bc.BOTS.items():
        assert {"group", "token", "ua", "note", "robots"} <= set(b), name
    for key in ("GPTBot (OpenAI training)", "ClaudeBot (Anthropic training)", "PerplexityBot", "Chrome (desktop browser)", "Firefox (Mozilla desktop browser)"):
        assert key in bc.BOTS
    assert bc.find_bot("gptbot") == "GPTBot (OpenAI training)" and bc.find_bot("claudebot") == "ClaudeBot (Anthropic training)"
    assert bc.find_bot("firefox") == "Firefox (Mozilla desktop browser)"
    assert bc.BOTS["Chrome (desktop browser)"]["robots"] == "no"
    with pytest.raises(ValueError):
        bc.find_bot("nope-not-a-bot")


def test_hsts_parse_and_assess():
    d = bc.parse_hsts('max-age=31536000; includeSubDomains; preload')
    assert d == dict(max_age=31536000, include_subdomains=True, preload=True)
    assert bc.hsts_assess("https", "", 200) == ("missing", "HSTS_MISSING")
    assert bc.hsts_assess("https", "max-age=300", 200)[1] == "HSTS_WEAK"
    assert bc.hsts_assess("https", "max-age=0", 200)[1] == "HSTS_WEAK"
    assert bc.hsts_assess("https", "max-age=31536000", 200)[1] == ""
    assert "preload" in bc.hsts_assess("https", "max-age=63072000; includeSubDomains; preload", 200)[0]
    assert bc.hsts_assess("http", "max-age=31536000", 200)[1] == "HSTS_ON_HTTP"
    assert bc.hsts_assess("http", "", 200)[1] == ""


def test_hsts_over_http_and_toggle(srv):
    items = [i for i in demo_server.demo_items(srv) if i["url"].endswith("/old/hsts-http")]
    df, _ = run(srv, items)
    assert "HSTS_ON_HTTP" in df.issue_codes.iloc[0]
    off, _ = run(srv, items, check_hsts=False)
    assert "HSTS" not in off.issue_codes.iloc[0] and off.hsts_status.iloc[0] == "not checked"


def test_ai_bot_blocked_and_robots_skipped(srv):
    items = [i for i in demo_server.demo_items(srv) if i["url"].endswith("/old/ai-blocked")]
    gpt = bc.BOTS["GPTBot (OpenAI training)"]
    df, _ = run(srv, items, ua=gpt["ua"], token=gpt["token"])
    assert df.final_status.iloc[0] == 403 and "BOT_REFUSED" in df.issue_codes.iloc[0]
    chrome = bc.BOTS["Chrome (desktop browser)"]
    df, _ = run(srv, items, ua=chrome["ua"], token=chrome["token"], honors_robots=False)
    assert df.final_status.iloc[0] == 200 and set(df.robots_start) == {"not applicable (agent ignores robots.txt)"}


def test_http_version_reported(srv, monkeypatch):
    items = [i for i in demo_server.demo_items(srv) if i["url"].endswith("/old/clean")][:1] or demo_server.demo_items(srv)[:1]
    df, hops = run(srv, items)
    assert df.http_version.iloc[0] == "HTTP/1.1" and set(hops.protocol) == {"HTTP/1.1"}     # plain http is always 1.1
    off, _ = run(srv, items, check_http_version=False)
    assert off.http_version.iloc[0] == "not checked"
    monkeypatch.setattr(bc.ProtocolCache, "_probe", lambda self, url: "HTTP/2 (HTTP/3 advertised)")
    cfg = bc.Config(interval=0.0)
    pc = bc.ProtocolCache(cfg, bc.HostLimiter(0))
    assert pc.get("https://example.com/a") == "HTTP/2 (HTTP/3 advertised)" and pc.get("http://example.com/") == "HTTP/1.1"


def test_alt_svc_h3_detection_and_probe_guard():
    cfg = bc.Config(interval=0.0)
    pc = bc.ProtocolCache(cfg, bc.HostLimiter(0))
    assert pc._probe("https://127.0.0.1/") == "unknown"                                      # private address is never probed
