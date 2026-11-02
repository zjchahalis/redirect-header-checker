# Redirect and Header Response Checker

Requests every old URL **the way a search engine crawler does** and reports what it would actually get. It is the "curl" half of a migration check: Screaming Frog tells you what the site links to, this tells you what a crawler receives when it asks for the old URLs.

Streamlit app, command line and Python library. Companion to the Internal PageRank Comparison Tool.

## What it checks

For every URL, with a crawler user agent, no cookies, no referrer and no JavaScript:

- **The expected hop.** Your map can say which redirect type to expect (301, 302, 307, 308, or 404/410 for pages that should be gone). The tool confirms the first response is that type, and, if a target is given, that it points straight at it. Otherwise it says what happened: wrong type (got 302), no redirect (got 200), right type but a different target, or goes via another URL.
- **Each redirect hop** is requested separately: status, a **count of hops**, loops, 301/308 versus temporary 302/303/307, chains, and the final URL compared with your redirect map (exact, differs only by trailing slash, wrong page, or not redirected at all). Following the full chain to the final URL is an option (on by default); turn it off to request each URL once and see only its first response, then follow a single URL's chain on demand.
- **Loops and runaway chains cannot stall a run.** At most **6 redirects** are followed. A URL that returns to a URL it already visited is reported as a loop, and a chain that is still redirecting after six is reported as stopped at 6. Googlebot itself gives up after 10.
- **HSTS is reported but never applied.** A browser that has seen HSTS rewrites http to https internally and shows a 307. This tool never applies it, so you see the server's real 301. Separately, an optional check (on by default, `--no-hsts` in the CLI) reads the final HTTPS page's `Strict-Transport-Security` header and flags missing, disabled, or under-a-year max-age values, or the header sent over http where browsers ignore it. The browser preload list is not checked.
- **Two tabs.** *Check URLs* runs every applicable check on pasted URLs or a Screaming Frog export. *Check a redirect map* takes Source, Type and Target and adds the expected-hop and target comparison. The results table shows every column that applies by default (the curl command is in the step-by-step view and the CSV).
- **HTTP version.** Each site is probed once with an HTTP/2 capable client and reported as HTTP/1.1 or HTTP/2, with "(HTTP/3 advertised)" when its Alt-Svc header offers h3. The redirect checks themselves run over HTTP/1.1, and HTTP/3 (QUIC) cannot be tested from here. Turn it off with `--no-http-version`. If the column says "unknown (HTTP/2 support missing)", run `pip install -r requirements.txt` again: HTTP/2 detection needs `httpx[http2]`.
- **Many user agents.** Search engines (Googlebot smartphone and desktop, Google-InspectionTool, GoogleOther, Bingbot, Applebot, DuckAssistBot), AI crawlers and agents (GPTBot, OAI-SearchBot, ChatGPT-User, ClaudeBot, Claude-SearchBot, Claude-User, PerplexityBot, Perplexity-User, Amazonbot, Meta-ExternalAgent, Meta-WebIndexer, meta-externalfetcher, CCBot, Bytespider), Facebook link preview, browsers (Chrome desktop and Android, Firefox, a bare `Mozilla/5.0`), curl, or a custom string. Agents that act for a person and normally ignore robots.txt skip the robots checks. `python bot_cli.py --list-bots` lists them, and `--bot gptbot` matches by partial name.
- **robots.txt** (optional: on by default, untick *Check robots.txt* in the sidebar or pass `--no-robots` to skip it and its extra requests), with Google's matching rules (wildcards, `$`, longest rule wins, Allow beats Disallow on a tie, rules merged across groups that name the crawler). It reports whether the old URL is blocked (the crawler never sees the redirect) and whether any later URL in the chain is blocked. A robots.txt that answers 5xx is reported, because Google treats it as "do not crawl".
- **The destination page:** `X-Robots-Tag` and meta robots noindex for the chosen crawler (including `googlebot: noindex` scoping), canonical (HTML or Link header), meta refresh, and a possible JavaScript redirect.
- **Crawler refusals:** 401, 403 and 429 for a crawler user agent, usually a firewall rule.
- **Soft-404 patterns:** a deep URL that redirects to the home page.
- **Your crawl:** if you supply a Screaming Frog export, it flags URLs whose live status differs from the crawl.
- A **reproducible curl command** for each URL, to show a developer exactly what you saw.

Every finding has a plain-English explanation and the usual fix (Glossary tab).

## Inputs (any combination)

| Input | Use |
|---|---|
| Redirect map CSV | `Source`, `Type` and `Target`: the old URL, the expected redirect type (optional) and the new URL. Also accepts Old/New and From/To. For a page that should be gone, use type 404 or 410 and leave Target empty. If the map has no Type column you can pick a default type in the app (`--default-type` on the command line). |
| Screaming Frog **Internal: All** export | Its URLs can be the test list (filter by status, HTML only, indexable only), and its status codes are compared with the live site. |
| Pasted list | One URL per line for spot checks. |

If your files hold paths only, enter the site's base URL.

## Run it

```bash
pip install -r requirements.txt
streamlit run app.py                 # tick "Try the built-in demo" to see every finding
python -m pytest tests -q
```

The built-in demo starts a tiny local server with deliberately broken redirects (clean 301, chain, 302, loop, wrong target, 404, redirect to home, noindex header, noindex meta, wrong canonical, robots block with a wildcard, meta refresh, 500, a page that refuses Googlebot user agents, a page that refuses AI crawlers, and an HSTS header sent over http).

Command line:

```bash
python bot_cli.py --map redirect_map.csv --out results/           # Source,Type,Target
python bot_cli.py --map redirect_map.csv --no-follow --out results/   # first response only
python bot_cli.py --sf internal_all.csv --out results/
python bot_cli.py --map staging_map.csv --allow-private     # staging on a VPN or localhost
```

It writes `results.csv`, `issues.csv` and `hops.csv`, and exits with code 1 if any URL has an error, so it can gate a deploy.

## Deploy it free

Put this folder in a GitHub repository and create an app at share.streamlit.io with `app.py` as the entry file. A public copy fetches URLs that anyone types in, so it is locked down:

- only `http` and `https`, ports 80 and 443, no credentials in URLs;
- any host that resolves to a private, loopback, link-local, carrier-grade NAT or otherwise non-public address is refused, **including on every redirect hop** (this blocks attempts to reach cloud metadata addresses or internal services);
- proxies and netrc are ignored, so the address check cannot be bypassed;
- at most `MAX_URLS` URLs per run (default 500, set the environment variable to change it) and a per-site request rate limit.

To test staging servers on a private network, run it on your own machine with `ALLOW_PRIVATE_HOSTS=1 streamlit run app.py` (adds a sidebar switch) or use `--allow-private` on the command line.

## Limits

- User agent strings are vendor-documented for Google, Bing, OpenAI, Perplexity, Apple, Amazon and Meta. The Anthropic, Bing mobile, CCBot and Bytespider strings come from third-party sources and may drift, so confirm against the vendor docs. Google-Extended and Applebot-Extended are robots.txt tokens only and cannot be tested as user agents.
- Real Googlebot is [verified by IP address](https://developers.google.com/static/search/apis/ipranges/googlebot.json), so a firewall can treat this tool differently from Googlebot. A pass is a good sign, not proof. Confirm with server logs filtered to verified Googlebot.
- It does not render JavaScript, so it cannot see client-side redirects or content. The JavaScript check is a heuristic on short pages.
- DNS is checked just before each request. A hostile DNS server that changes its answer between the check and the request (DNS rebinding) is a known limit of this approach.
- Only test sites you own or have permission to test. Keep the request rate low on fragile servers.
- On a hosted copy the URLs and files you provide are processed on the host's servers. Run it locally for confidential lists.
