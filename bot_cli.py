#!/usr/bin/env python3
"""Command line version of the Redirect and Header Response Checker.

    python bot_cli.py --map redirect_map.csv --out results/
    python bot_cli.py --sf internal_all.csv --status 2xx 3xx --out results/
    python bot_cli.py --urls urls.txt --base-url https://www.example.com --bot "Googlebot desktop"
    python bot_cli.py --map staging_map.csv --allow-private          # staging on a VPN or localhost

Writes results.csv, issues.csv and hops.csv. Exit code 1 if any URL has an error, so it can gate a deploy.
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

import botcheck as bc


def _read(path: str) -> pd.DataFrame:
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig", low_memory=False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--map", help="redirect map CSV with Source and Target columns")
    ap.add_argument("--sf", help="Screaming Frog Internal: All CSV")
    ap.add_argument("--urls", help="text file of URLs, one per line")
    ap.add_argument("--base-url", default="", help="join paths in the files to this site")
    ap.add_argument("--status", nargs="*", default=["2xx", "3xx", "4xx", "5xx"], help="Screaming Frog status classes to test (2xx 3xx 4xx 5xx)")
    ap.add_argument("--sf-baseline-only", action="store_true", help="use the SF export only to compare status codes, not as the URL list")
    ap.add_argument("--bot", default="Googlebot smartphone", help="user agent: a name or a unique part of one (gptbot, claudebot, chrome, firefox). See --list-bots")
    ap.add_argument("--list-bots", action="store_true", help="show the available user agents and exit")
    ap.add_argument("--no-http-version", action="store_true", help="skip the HTTP version probe (on by default)")
    ap.add_argument("--no-hsts", action="store_true", help="skip the HSTS header check (on by default)")
    ap.add_argument("--user-agent", help="custom user agent string (with --bot Custom)")
    ap.add_argument("--rps", type=float, default=4.0, help="requests per second to each host")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-urls", type=int, default=5000)
    ap.add_argument("--default-type", default="", help="expected redirect type (301, 302, 307, 308) for map rows with no Type value")
    ap.add_argument("--no-follow", action="store_true", help="request each URL once and report only its first response")
    ap.add_argument("--max-hops", type=int, default=6, help="redirects to follow before stopping (capped at 6)")
    ap.add_argument("--no-robots", action="store_true", help="skip the robots.txt checks (they are on by default)")
    ap.add_argument("--allow-private", action="store_true", help="allow private/internal addresses (local use only)")
    ap.add_argument("--out", default="botcheck_out")
    a = ap.parse_args()
    if a.list_bots:
        for k, v in bc.BOTS.items():
            print(f"{v['group']:8} {k}")
        return
    if not (a.map or a.sf or a.urls):
        sys.exit("Give --map, --sf or --urls")
    mp = bc.load_map(_read(a.map), a.base_url, a.default_type) if a.map else []
    sf = bc.load_sf(_read(a.sf), a.status) if a.sf else None
    pasted = open(a.urls, encoding="utf-8").read() if a.urls else ""
    items = bc.build_items(mp, pasted, sf, a.base_url, use_sf_urls=not (a.sf_baseline_only or a.map or a.urls))[:a.max_urls]
    if not items:
        sys.exit("No URLs to check")
    try:
        a.bot = bc.find_bot(a.bot)
    except ValueError as e:
        sys.exit(str(e))
    bot = dict(bc.BOTS[a.bot])
    if a.user_agent:
        bot["ua"] = a.user_agent
    cfg = bc.Config(ua=bot["ua"], token=bot["token"], frm=bot["frm"], read_timeout=a.timeout, interval=1.0 / a.rps,
                    allow_private=a.allow_private, check_robots=not a.no_robots,
                    follow_chain=not a.no_follow, max_hops=a.max_hops,
                    honors_robots=bot["robots"] == "yes", check_hsts=not a.no_hsts, check_http_version=not a.no_http_version)
    print(f"Checking {len(items)} URLs as {a.bot}")
    res, hops = bc.run_checks(items, cfg, workers=a.workers,
                              progress=lambda i, n: print(f"  {i}/{n}", end="\r", flush=True))
    os.makedirs(a.out, exist_ok=True)
    res.to_csv(os.path.join(a.out, "results.csv"), index=False)
    hops.to_csv(os.path.join(a.out, "hops.csv"), index=False)
    summ = bc.issue_summary(res)
    summ.to_csv(os.path.join(a.out, "issues.csv"), index=False)
    print("\n" + res.severity.value_counts().to_string())
    if len(summ):
        print("\n" + summ[["severity", "issue", "urls"]].to_string(index=False))
    print(f"\nWrote results.csv, issues.csv and hops.csv to {a.out}/")
    sys.exit(1 if (res.severity == "error").any() else 0)


if __name__ == "__main__":
    main()
