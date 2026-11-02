"""Plain-English column names and hover tooltips for the results tables."""
from __future__ import annotations

import pandas as pd

import botcheck as bc

COLUMNS = {
    "url": ("URL", "The URL that was requested."),
    "expected": ("Should land on", "Where your redirect map says this URL should end up. Blank if you did not supply a map."),
    "severity": ("Result", "error = fix before launch, warn = worth fixing, info = good to know, ok = no problems found."),
    "issues": ("What was found", "Every problem found for this URL. Hover over a row in the Issues tab for what each one means."),
    "issue_codes": ("Issue codes", "Short codes for the issues, for filtering and for scripts."),
    "first_status": ("First response", "The status code the server gave for the URL itself. 301 is a permanent redirect, 302 a temporary one, 200 a normal page."),
    "final_status": ("Final response", "The status code of the page the redirects end on. Blank if the chain never finished (loop, error, timeout)."),
    "hops": ("Redirect hops", "How many redirects the URL goes through before reaching a page. 1 is ideal; 0 means no redirect. This tool follows at most 6 and stops there, so a loop or a runaway chain cannot stall a run."),
    "chain_status": ("Chain finished?", "complete = reached a final page, loop = the chain returns to a URL it already visited, stopped at 6 redirects = still redirecting after the cap, not followed = only the first response was requested, error = it failed before finishing."),
    "expected_type": ("Expected type", "The redirect type your map expects, for example 301 permanent or 302 temporary. 404 or 410 means the URL should be gone."),
    "hop_check": ("Expected hop happened?", "confirmed = the first response is the type your map expects and (if you gave a target) it points straight at it. Otherwise it says what happened: wrong type, no redirect, right type but different target, or goes via another URL."),
    "chain": ("Response chain", "Status codes in order, for example 301 > 301 > 200."),
    "final_url": ("Ends on", "The URL the chain ends on."),
    "target_match": ("Lands on target?", "exact = same as your map, slash = same except for a trailing slash, different = wrong page, n/a = no map or the chain did not end on a 200 page."),
    "robots_start": ("Old URL allowed by robots.txt", "Whether robots.txt lets the crawler fetch the old URL. If blocked, the crawler never sees the redirect."),
    "robots_dest": ("Destination allowed by robots.txt", "Whether robots.txt lets the crawler fetch every later URL in the chain."),
    "http_version": ("HTTP version", "The protocol the final page's site negotiates: HTTP/1.1 or HTTP/2. '(HTTP/3 advertised)' means its Alt-Svc header offers HTTP/3, which browsers may use but this tool cannot test. Plain http is always 1.1. Probed once per site."),
    "protocol": ("HTTP version", "The protocol this site negotiates (HTTP/1.1 or HTTP/2), probed once per site."),
    "hsts_status": ("HSTS", "What the final HTTPS page says about Strict-Transport-Security: missing, ok (with max-age and flags), short or disabled, or n/a for http. This tool never applies HSTS to its own requests, it only reports the header."),
    "hsts": ("HSTS header", "The raw Strict-Transport-Security header of the final page."),
    "x_robots_tag": ("X-Robots-Tag header", "The robots instruction sent in the HTTP headers of the final page."),
    "meta_robots": ("Meta robots tag", "The robots meta tag in the final page's HTML."),
    "canonical": ("Canonical", "The canonical URL declared by the final page (HTML tag or Link header)."),
    "title": ("Page title", "The title of the final page."),
    "content_type": ("Content type", "What kind of file the final URL returned."),
    "total_ms": ("Time (ms)", "Total time for the whole chain in milliseconds."),
    "crawl_status": ("Status in your crawl", "The status code from your Screaming Frog export, for comparison."),
    "curl": ("curl command", "Run this to see the same hop-by-hop headers yourself. In PowerShell use curl.exe, and NUL instead of /dev/null."),
    "hop": ("Step", "Position in the chain."),
    "status": ("Status", "The server's response code for this step."),
    "location": ("Redirects to", "The Location header the server sent."),
    "ms": ("Time (ms)", "How long this step took."),
    "note": ("Note", "Errors or why a step was not made."),
    "start_url": ("Old URL", "The URL the chain started from."),
    "code": ("Code", "Short issue code."),
    "severity_": ("Level", "error = fix before launch, warn = worth fixing, info = good to know."),
    "issue": ("Issue", "What was found."),
    "urls": ("URLs", "How many tested URLs have this issue."),
    "what_it_means": ("What it means and what to do", "Explanation and the usual fix."),
}


def label_for(c: str) -> str:
    return COLUMNS.get(c, (c.replace("_", " ").capitalize(), ""))[0]


def friendly(df: pd.DataFrame) -> pd.DataFrame:
    d = df.copy()
    return d.rename(columns={c: label_for(c) for c in d.columns})


def column_config(df: pd.DataFrame, st) -> dict:
    inv = {label_for(c): c for c in COLUMNS}
    cfg = {}
    for lab in df.columns:
        src = inv.get(lab)
        if src and COLUMNS[src][1]:
            if lab == "curl command":
                cfg[lab] = st.column_config.TextColumn(label=lab, help=COLUMNS[src][1], width="small")
            else:
                cfg[lab] = st.column_config.Column(label=lab, help=COLUMNS[src][1])
    return cfg


def glossary_table() -> pd.DataFrame:
    rows = [(bc.ISSUES[k][1], bc.ISSUES[k][0], bc.ISSUES[k][2]) for k in bc.ISSUES]
    return pd.DataFrame(rows, columns=["Issue", "Level", "What it means and what to do"])
