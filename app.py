"""Redirect and Header Response Checker (Streamlit).

Run locally:   streamlit run app.py
Deploy free:   push this folder to GitHub, then create an app on Streamlit Community Cloud.
"""
from __future__ import annotations

import io
import os
import zipfile

import pandas as pd
import streamlit as st

import botcheck as bc
import demo_server
import glossary as gl

HARD_CAP = int(os.environ.get("MAX_URLS", "500"))
LOCAL_OK = os.environ.get("ALLOW_PRIVATE_HOSTS") == "1"

st.set_page_config(page_title="Redirect and Header Response Checker", layout="wide")


# ----------------------------------------------------------------------------- helpers
def show(df: pd.DataFrame, pin_url: bool = False, **kw) -> None:
    f = gl.friendly(df)
    cfg = gl.column_config(f, st)
    if pin_url and gl.label_for("url") in f.columns:
        try:
            cfg[gl.label_for("url")] = st.column_config.Column(label=gl.label_for("url"), help=gl.COLUMNS["url"][1], pinned=True)
        except TypeError:
            pass
    try:
        st.dataframe(f, width="stretch", hide_index=True, column_config=cfg, **kw)
    except TypeError:
        st.dataframe(f, use_container_width=True, hide_index=True, column_config=cfg, **kw)


@st.cache_resource(show_spinner=False)
def demo():
    srv, base = demo_server.start()
    return base


@st.cache_data(show_spinner=False, max_entries=6)
def read_csv_bytes(data: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False, encoding="utf-8-sig", low_memory=False)


def zip_reports(frames: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in frames.items():
            z.writestr(f"{k}.csv", gl.friendly(v).to_csv(index=False))
    return buf.getvalue()


# ----------------------------------------------------------------------------- sidebar
st.sidebar.header("Crawler settings")
_groups = {"Search": "Search engines", "AI": "AI crawlers and agents", "Social": "Social", "Browser": "Browsers and tools", "Custom": "Custom"}
bot_name = st.sidebar.selectbox("Check as", list(bc.BOTS), index=0,
                                format_func=lambda n: f"{_groups.get(bc.BOTS[n]['group'], bc.BOTS[n]['group'])}: {n}",
                                help="The user agent sent with every request. No cookies, no referrer and no JavaScript are used. "
                                     "Real crawlers are also verified by IP address, so a pass here does not prove the real bot gets through a firewall: confirm with your server logs.")
bot = dict(bc.BOTS[bot_name])
if bot_name == "Custom":
    bot["ua"] = st.sidebar.text_input("User agent string", "Mozilla/5.0 (compatible; MyCrawler/1.0)")
else:
    st.sidebar.caption(bot["note"])
    with st.sidebar.expander("User agent string sent"):
        st.code(bot["ua"], language=None)
if bot["robots"] == "no":
    st.sidebar.caption("This agent normally ignores robots.txt, so the robots.txt checks are skipped for it.")
rps = st.sidebar.slider("Requests per second to each site", 1, 10, 4, help="Keeps the check polite. Lower it for fragile or staging servers.")
timeout = st.sidebar.slider("Timeout (seconds)", 3, 30, 10)
slow_ms = st.sidebar.number_input("Flag a chain slower than (ms)", 500, 30000, 3000, step=500)
follow_chain = st.sidebar.checkbox("Follow the full redirect chain", value=True,
                                   help="Follows every redirect to the final URL (at most 6, loops are detected and stopped) and counts the hops. "
                                        "Untick to request each URL once and only see its first response, which is lighter and faster.")
check_http = st.sidebar.checkbox("Check HTTP version", value=True,
                                 help="Reports whether the site answers over HTTP/1.1 or HTTP/2, and whether HTTP/3 is advertised in its Alt-Svc header. "
                                      "HTTP/3 itself cannot be tested from here. Adds one small request per site.")
try:
    import h2  # noqa: F401
except ImportError:
    st.sidebar.warning("HTTP/2 detection needs one more package: run  pip install \"httpx[http2]\"  (or  pip install -r requirements.txt)  and restart.")
check_hsts = st.sidebar.checkbox("Check HSTS", value=True,
                                 help="Reports whether the final HTTPS page sends a Strict-Transport-Security header and whether max-age is a year or more. "
                                      "The tool never applies HSTS to its own requests: each redirect is requested exactly as the server answers it.")
check_robots = st.sidebar.checkbox("Check robots.txt", value=True,
                                   help="Reads each site's robots.txt with Google's matching rules and flags old URLs the crawler is not allowed to fetch "
                                        "(so it never sees the redirect), blocked destinations, and a robots.txt that errors. Turn off to skip these checks and the extra requests.")
max_urls = st.sidebar.slider("Maximum URLs per run", 10, HARD_CAP, min(200, HARD_CAP), help=f"A hosted copy is capped at {HARD_CAP} URLs per run.")
allow_private = False
if LOCAL_OK:
    allow_private = st.sidebar.checkbox("Allow private and internal addresses (local use)", help="Lets you test staging servers on a VPN or localhost.")
st.sidebar.checkbox("Try the built-in demo", key="use_demo",
                    help="Starts a tiny test server with deliberately broken redirects so you can see every kind of finding.")
st.sidebar.info("Only test sites you own or have permission to test. HSTS is never applied to the checker's own requests: each redirect is requested exactly as the server answers it, "
                "so an http to https upgrade shows as the server's real 301, not a browser's internal 307.")

# ----------------------------------------------------------------------------- page
st.title("Redirect and Header Response Checker")
st.write("Request every old URL the way a search engine crawler does, follow each redirect hop, and see what it would really get: "
         "the final status, where it lands compared with your redirect map, whether robots.txt lets it through, and whether the "
         "destination says noindex.")


# ----------------------------------------------------------------------------- shared run + results
URL_COLS = ["url", "severity", "issues", "hops", "chain", "chain_status", "final_status", "final_url", "http_version", "hsts_status",
            "robots_start", "robots_dest", "x_robots_tag", "meta_robots", "canonical", "title", "content_type", "total_ms", "crawl_status"]
MAP_COLS = ["url", "expected_type", "expected", "hop_check", "target_match", "severity", "issues", "hops", "chain", "chain_status", "final_status",
            "final_url", "http_version", "hsts_status", "robots_start", "robots_dest", "x_robots_tag", "meta_robots", "canonical", "title",
            "content_type", "total_ms", "crawl_status"]
ALL_COLS = list(dict.fromkeys(MAP_COLS + URL_COLS + ["curl"]))


def make_cfg(demo_on: bool, base_demo: str = ""):
    return bc.Config(ua=bot["ua"], token=bot["token"], frm=bot["frm"], connect_timeout=min(5.0, float(timeout)),
                     read_timeout=float(timeout), interval=1.0 / rps, allow_private=allow_private, slow_ms=int(slow_ms),
                     check_robots=check_robots, follow_chain=follow_chain, check_hsts=check_hsts, check_http_version=check_http,
                     honors_robots=bot["robots"] == "yes", allowed_hosts=((base_demo.split("//")[1],) if demo_on else ()))


def run_block(key: str, items: list, demo_on: bool, base_demo: str, label: str) -> None:
    """Item count, the Run button, and storing the results under st.session_state[key]."""
    n_all = len(items)
    if n_all > max_urls:
        st.warning(f"{n_all:,} URLs found. Only the first {max_urls:,} will be checked (change the limit in the sidebar, up to {HARD_CAP:,}).")
        items = items[:max_urls]
    if items:
        st.caption(f"{len(items):,} URLs ready to check" + (f", {sum(1 for i in items if i['expected']):,} with an expected target." if any(i['expected'] for i in items) else "."))
    if st.button(label, type="primary", disabled=not items, key=key + "_run") and items:
        cfg = make_cfg(demo_on, base_demo)
        bar = st.progress(0.0, text="Starting...")
        res, hops = bc.run_checks(items, cfg, workers=min(8, max(2, rps)),
                                  progress=lambda i, n: bar.progress(i / n, text=f"Checked {i} of {n}"))
        bar.empty()
        prev = st.session_state.get(key)
        st.session_state[key] = dict(res=res, hops=hops, bot=bot_name, robots=check_robots and bot["robots"] == "yes", hsts=check_hsts,
                                     http=check_http, cfg=cfg, items=items, run=(prev["run"] + 1 if prev else 1))


def default_columns(out: dict, map_mode: bool) -> list:
    res = out["res"]
    cols = list(MAP_COLS if map_mode else URL_COLS)
    if not out.get("robots", True):
        cols = [c for c in cols if not c.startswith("robots_")]
    if not out.get("hsts", True):
        cols = [c for c in cols if c != "hsts_status"]
    if not out.get("http", True):
        cols = [c for c in cols if c != "http_version"]
    if "crawl_status" in res and not res.crawl_status.astype(str).str.strip().replace("nan", "").any():
        cols = [c for c in cols if c != "crawl_status"]
    return cols


def render_results(key: str, map_mode: bool) -> None:
    out = st.session_state.get(key)
    if out is None:
        return
    res, hops = out["res"], out["hops"]
    st.caption(f"Checked as {out['bot']}." + ("" if out.get("robots", True) else " robots.txt was not checked."))
    m = st.columns(6 if map_mode else 5)
    m[0].metric("URLs checked", f"{len(res):,}")
    m[1].metric("With errors", f"{(res.severity == 'error').sum():,}", help="Fix these before launch.")
    m[2].metric("With warnings", f"{(res.severity == 'warn').sum():,}", help="Worth fixing: temporary redirects, chains, canonical differences.")
    m[3].metric("Clean", f"{res.severity.isin(['ok', 'info']).sum():,}", help="No errors or warnings. Info notes do not count against a URL.")
    m[4].metric("Longest chain", f"{int(res.hops.fillna(0).max())} hops", help="The most redirect hops any URL went through. 1 is ideal. The tool stops at 6.")
    if map_mode:
        typed = res[res.expected_type.astype(str) != ""]
        m[5].metric("Expected hop happened", f"{(typed.hop_check == 'confirmed').sum():,} of {len(typed):,}" if len(typed) else "No types given",
                    help="Of the URLs whose map says what redirect type to expect, how many answered with exactly that type (and, when a target is given, pointing straight at it).")

    st.subheader("What was found")
    summ = bc.issue_summary(res).rename(columns={"severity": "severity_"})
    if len(summ):
        show(summ.drop(columns=["code"]))
    else:
        st.success("No issues found.")

    st.subheader("Results by URL")
    f1, f2, f3 = st.columns([1, 2, 2])
    sev = f1.multiselect("Result", ["error", "warn", "info", "ok"], default=["error", "warn", "info", "ok"], key=key + "_sev")
    codes = f2.multiselect("Issue", [c for c in sorted(bc.ISSUES) if (out.get("robots", True) or not c.startswith("ROBOTS_")) and (out.get("hsts", True) or not c.startswith("HSTS_"))
                                     and (map_mode or c not in ("NOT_REDIRECTED", "HOP_TYPE_MISMATCH", "TARGET_MISMATCH", "TARGET_SLASH_DIFF"))],
                           format_func=lambda c: bc.ISSUES[c][1], key=key + "_codes")
    q = f3.text_input("Search the URL", key=key + "_q")
    view = res[res.severity.isin(sev)]
    if codes:
        view = view[view.issue_codes.map(lambda s: any(c in str(s).split(",") for c in codes))]
    if q:
        view = view[view.url.str.contains(q, case=False, regex=False)]
    with st.expander("Choose the columns shown in the table"):
        shown = st.multiselect("Columns in the table", ALL_COLS, default=default_columns(out, map_mode), key=f"{key}_cols_{out['run']}_{map_mode}",
                               format_func=gl.label_for,
                               help="Everything that applies is shown by default. Remove columns to make the table narrower, or add the curl command. The CSV download always has every column.")
    show(view[[c for c in ALL_COLS if c in shown and c in view]], pin_url=True)

    st.subheader("Look at one URL step by step")
    pick = st.selectbox("URL", list(res.url), key=key + "_pick")
    if pick:
        row = res[res.url == pick].iloc[0]
        st.markdown(f"**{int(row.hops)} redirect hop{'s' if int(row.hops) != 1 else ''}** · chain: {row.chain} · {row.chain_status}"
                    + (f" · expected hop: {row.hop_check}" if str(row.expected_type) != "" else ""))
        hop_view = hops[hops.start_url == pick].drop(columns=["start_url"])
        if not out.get("http", True) and "protocol" in hop_view:
            hop_view = hop_view.drop(columns=["protocol"])
        show(hop_view)
        if row.chain_status == "not followed" and st.button("Follow the full chain for this URL", key=key + "_follow"):
            import dataclasses
            item = next(i for i in out["items"] if i["url"] == pick)
            r2, h2 = bc.run_checks([item], dataclasses.replace(out["cfg"], follow_chain=True), workers=1)
            out["res"] = bc.sort_results(pd.concat([res[res.url != pick], r2], ignore_index=True))
            out["hops"] = pd.concat([hops[hops.start_url != pick], h2], ignore_index=True)
            st.rerun()
        for c in [x for x in str(row.issue_codes).split(",") if x]:
            sev_c, lab, why = bc.ISSUES[c]
            (st.error if sev_c == "error" else st.warning if sev_c == "warn" else st.info)(f"**{lab}.** {why}")
        st.caption("Reproduce it yourself. In PowerShell use curl.exe and NUL instead of /dev/null.")
        st.code(row.curl, language="bash")

    st.subheader("Where the redirects end")
    dist = res.final_status.astype("object").fillna("No response").astype(str).value_counts().rename_axis("Final response").rename("URLs")
    st.bar_chart(dist)

    st.download_button("Download all results (zip)", zip_reports({"results": res, "issues": summ.rename(columns={"severity_": "severity"}),
                                                                   "hops": hops}), "redirect_bot_check.zip", mime="application/zip", key=key + "_dl")


def demo_banner(demo_on: bool, base_demo: str) -> None:
    if demo_on:
        st.info(f"Demo mode: testing a local server at {base_demo} with {len(demo_server.demo_items(base_demo))} deliberately broken URLs. Untick the demo box in the sidebar to test your own site.")


t_how, t_urls, t_map, t_gloss = st.tabs(["1. How it works", "2. Check URLs", "3. Check a redirect map", "Glossary"])

with t_how:
    st.markdown("""
**Use it after Screaming Frog.** A crawl tells you what the site links to. This tool tells you what a crawler gets when it *requests* the old URLs, which is what a redirect map has to survive.

**Two ways to use it, one tab each**

- **2. Check URLs** is for spot checks and audits. Paste URLs, or upload a **Screaming Frog Internal: All export** (Internal tab, filter All, Export) to test its URLs and compare its status codes with what the live site says now. You get every check that applies: chain, status, HTTP version, HSTS, robots.txt, noindex, canonical and more.
- **3. Check a redirect map** is for migrations. Upload a CSV with `Source`, `Type` and `Target` columns: the old URL, the redirect type you expect (301, 302, 307, 308, or 404/410 for pages that should be gone) and the new URL. `Type` is optional. You get all of the above plus whether the expected redirect hop actually happens and where it lands compared with your map. The embeddings mapping and the PageRank tool both produce this file.

If your files hold paths only, enter the site's base URL.

**What it checks for each URL**

- In the redirect map tab, the **expected hop**: does the first response have the type your map expects, and does the chain end on the page your map expects? Every redirect is followed to the final URL (at most 6 hops; loops are detected and stopped) and the hops are counted.
- **HTTP version** (optional, on by default): HTTP/1.1 or HTTP/2 as the server negotiates it (probed once per site), plus whether it advertises HTTP/3. HTTP/3 uses QUIC and cannot be tested directly from here.
- **HSTS** (optional, on by default): whether the final HTTPS page sends a Strict-Transport-Security header and whether `max-age` is at least a year. It is only reported, never applied to the checker's own requests.
- **robots.txt** (optional, on by default; untick *Check robots.txt* in the sidebar to skip it), read with Google's matching rules (wildcards, longest rule wins): is the old URL blocked (the crawler never sees the redirect) and is the destination allowed.
- The destination's **noindex** (HTTP header and meta tag, for the chosen crawler), **canonical**, meta refresh and a possible JavaScript redirect.
- Responses that **refuse the crawler** (401, 403, 429), a common firewall mistake.
- A reproducible **curl command** for every URL (in the step-by-step view and in the CSV), so you can show a developer exactly what you saw.

**What it cannot tell you.** Real Googlebot is [verified by IP address](https://developers.google.com/static/search/apis/ipranges/googlebot.json), so a firewall can treat this tool differently. A pass here is a good sign, not proof: confirm with server logs filtered to verified Googlebot. It also does not render JavaScript.

**Privacy.** On a hosted copy the URLs you enter and the files you upload are processed on the host's servers. Run it locally for confidential client lists.
""")


with t_urls:
    demo_on = bool(st.session_state.get("use_demo"))
    base_demo = demo() if demo_on else ""
    demo_banner(demo_on, base_demo)
    st.write("Spot-check any URLs, or a whole Screaming Frog crawl. Every check that applies is run and shown. To test a migration against a redirect map, use the next tab.")
    c1, c2 = st.columns(2)
    with c1:
        base_url = st.text_input("Site base URL (only needed if your files hold paths, not full URLs)", "", placeholder="https://www.example.com", key="u_base")
        pasted = st.text_area("Paste URLs to test, one per line", "", height=140, key="u_paste")
    with c2:
        sf_f = st.file_uploader("Or a Screaming Frog Internal: All CSV", type=["csv"], key="u_sf")
        use_sf = st.checkbox("Test the URLs from the Screaming Frog export", value=not pasted.strip(), key="u_usesf",
                             help="Off means the export is only used to compare its status codes with the live site.")
        with st.expander("Screaming Frog filters"):
            sts = st.multiselect("Status codes in the crawl", ["2xx", "3xx", "4xx", "5xx"], default=["2xx", "3xx", "4xx", "5xx"], key="u_sts")
            html_only = st.checkbox("HTML pages only", True, key="u_html")
            idx_only = st.checkbox("Indexable pages only", False, key="u_idx")
    items = []
    try:
        if demo_on:
            items = [dict(i, expected="", expected_type="") for i in demo_server.demo_items(base_demo)]
        else:
            sf = bc.load_sf(read_csv_bytes(sf_f.getvalue()), sts, html_only, idx_only) if sf_f else None
            items = bc.build_items([], pasted, sf, base_url, use_sf_urls=use_sf)
    except Exception as e:  # noqa: BLE001
        st.error(f"Could not read the inputs: {e}")
    run_block("bc_urls", items, demo_on, base_demo, "Run checks")
    if st.session_state.get("bc_urls") is None:
        st.info("Paste some URLs or upload a Screaming Frog export (or tick the demo in the sidebar), then press Run checks.")
    render_results("bc_urls", map_mode=False)

with t_map:
    demo_on = bool(st.session_state.get("use_demo"))
    base_demo = demo() if demo_on else ""
    demo_banner(demo_on, base_demo)
    st.write("Check a migration's redirect map: does each old URL answer with the redirect type you planned, and does the chain end on the page you mapped it to? "
             "Everything from the URL checks is included as well.")
    c1, c2 = st.columns(2)
    with c1:
        m_base = st.text_input("Site base URL (only needed if the map holds paths, not full URLs)", "", placeholder="https://www.example.com", key="m_base")
        map_f = st.file_uploader("Redirect map CSV: Source, Type, Target", type=["csv"], key="m_map",
                                 help="Columns: Source (old URL), Type (expected redirect type such as 301, optional) and Target (new URL). "
                                      "Use 410 or 404 as the type, with no target, for pages that should be gone.")
    with c2:
        def_type = st.selectbox("Expected redirect type when the map has none", ["Do not check", "301", "302", "307", "308"], key="m_deftype",
                                help="Applied to map rows that have a target but no Type column value.")
        m_sf = st.file_uploader("Screaming Frog Internal: All CSV (optional)", type=["csv"], key="m_sf",
                                help="Only used to compare the crawl's status codes with the live site. The map decides which URLs are tested.")
    items = []
    try:
        if demo_on:
            items = demo_server.demo_items(base_demo)
        elif map_f:
            mp = bc.load_map(read_csv_bytes(map_f.getvalue()), m_base, "" if def_type.startswith("Do not") else def_type)
            sf = bc.load_sf(read_csv_bytes(m_sf.getvalue()), ["2xx", "3xx", "4xx", "5xx"], False, False) if m_sf else None
            items = bc.build_items(mp, "", sf, m_base, use_sf_urls=False)
    except Exception as e:  # noqa: BLE001
        st.error(f"Could not read the inputs: {e}")
    run_block("bc_map", items, demo_on, base_demo, "Check the redirect map")
    if st.session_state.get("bc_map") is None:
        st.info("Upload a redirect map (or tick the demo in the sidebar), then press Check the redirect map.")
    render_results("bc_map", map_mode=True)

with t_gloss:
    st.write("Every finding in plain English, with the usual fix. The results tables also have a hover tooltip on every column heading.")
    show_df = gl.glossary_table()
    try:
        st.dataframe(show_df, width="stretch", hide_index=True)
    except TypeError:
        st.dataframe(show_df, use_container_width=True, hide_index=True)
