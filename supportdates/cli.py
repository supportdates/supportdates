"""supportdates: collect sourced end-of-support dates for embedded components and track how they change.

    python -m supportdates collect --data data      (fetch, parse, snapshot, print changes)
    python -m supportdates site --data data --out site
"""

import argparse
import calendar
import gzip
import hashlib
import html
import json
import os
import re
import sys
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

from . import backfill as bf
from . import sources as src
from .store import (collapse_new_sources, diff, document_changes, load_hashes, load_snapshot, previous_snapshot,
                    save_snapshot)


def fetch_bytes(url: str) -> bytes:
    # Honest agent on purpose: a browser-like one triggers bot challenges (OpenWrt's Anubis) and hides the data.
    headers = {"User-Agent": "supportdates/0.1 (+research)"}
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"   # optional: 5,000 instead of 60 calls/h
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return gunzip_if_needed(resp.read())


def gunzip_if_needed(data: bytes) -> bytes:
    """Archive raw captures (id_) are sometimes served still gzip-compressed; decompress by magic bytes."""
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data


def fetch(url: str) -> str:
    return fetch_bytes(url).decode("utf-8", "replace")


def fetch_retry(url: str, tries: int = 4, wait: float = 5.0) -> str:
    """For flaky hosts (Internet Archive returns 503 under load)."""
    for i in range(tries):
        try:
            return fetch(url)
        except Exception:  # noqa: BLE001
            if i == tries - 1:
                raise
            time.sleep(wait * (i + 1))
    return ""


def github_tag_date(repo: str, tag: str) -> str:
    """Commit date (YYYY-MM-DD) a tag points to, via the GitHub API (lightweight and annotated tags), or ''."""
    api = f"https://api.github.com/repos/{repo}"
    obj = json.loads(fetch(f"{api}/git/refs/tags/{tag}"))["object"]
    if obj["type"] == "tag":
        obj = json.loads(fetch(f"{api}/git/tags/{obj['sha']}"))["object"]
    return json.loads(fetch(f"{api}/commits/{obj['sha']}"))["commit"]["committer"]["date"][:10]


def pdf_text(data: bytes, mode: str = "-layout") -> str:
    """PDF -> text via poppler's pdftotext (external tool; the only non-stdlib dependency, used at the edge).
    mode '-layout' keeps columns, '-raw' keeps content-stream order (better for wrapped table cells)."""
    return subprocess.run(["pdftotext", mode, "-", "-"], input=data, capture_output=True, check=True).stdout.decode()


def collect_all(keep=lambda sha, data: None) -> tuple[list[src.Record], dict[str, str], list[str], set[str]]:
    """(records, sha256 per raw document, error messages, source URLs that failed).
    keep(sha, data) receives every hashed raw document, so the evidence behind each hash can be archived."""
    records, hashes, errors, failed = [], {}, [], set()

    def hashed(name, data: bytes):
        sha = hashlib.sha256(data).hexdigest()
        hashes[name] = sha
        keep(sha, data)

    def take(name, url, parse, allow_empty=False):
        try:
            text = fetch(url)
            hashed(name, text.encode())
            got = parse(text)
            if not got and not allow_empty:
                errors.append(f"{name}: parser found no records (format change?)")
                failed.add(url)
            records.extend(got)
        except Exception as exc:  # noqa: BLE001 - one source failing must not stop the others
            errors.append(f"{name}: {exc}")
            failed.add(url)

    take("mbedtls", src.MBEDTLS_URL, src.parse_mbedtls)
    take("zephyr", src.ZEPHYR_URL, src.parse_zephyr)
    take("kernel", src.KERNEL_URL, src.parse_kernel)
    take("yocto", src.YOCTO_URL, src.parse_yocto)
    take("openwrt", src.OPENWRT_URL, src.parse_openwrt)
    take("openssl", src.OPENSSL_URL, src.parse_openssl)
    take("python", src.PYTHON_URL, src.parse_python)
    take("nodejs", src.NODEJS_URL, src.parse_nodejs)
    take("containerd", src.CONTAINERD_URL, src.parse_containerd)
    take("qt", src.QT_URL, src.parse_qt)
    take("mender", src.MENDER_URL, src.parse_mender)
    take("moby", src.MOBY_URL, src.parse_moby)
    try:
        for url in src.rpi_notice_links(fetch(src.RPI_EOL_INDEX)):
            data = fetch_bytes(url)
            hashed(f"rpi-eol:{url.rsplit('/', 1)[-1]}", data)
            records.extend(src.parse_rpi_eol_notice(pdf_text(data), url))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"rpi eol notices: {exc}")
        failed.update({"https://pip-assets.raspberrypi.com/*", "doc:rpi-eol:*"})
        failed.add(src.RPI_EOL_INDEX)
    take("espressif-advisories", src.ESPRESSIF_ADVISORIES_URL, src.parse_espressif_advisories)
    try:
        pages = src.toradex_module_pages(fetch(src.TORADEX_SITEMAP))
        for page in pages:
            # new modules legitimately have no PCNs yet
            take(f"toradex:{page.rsplit('/', 1)[-1]}", page, lambda text, u=page: src.parse_toradex_module(text, u),
                 allow_empty=True)
            time.sleep(2)   # polite: 32 pages, no crawl-delay set in robots.txt
    except Exception as exc:  # noqa: BLE001
        errors.append(f"toradex sitemap: {exc}")
        failed.add("https://docs.toradex.com/*")       # module listing failed: keep all Toradex PCNs
    take("renesas-plp", src.RENESAS_PLP_URL, src.parse_renesas_plp)
    take("jetson", src.JETSON_LIFECYCLE_URL, src.parse_jetson_lifecycle)
    take("toradex-bsp", src.TORADEX_BSP_URL, src.parse_toradex_bsp_lifecycle)
    take("jci-eos", src.JCI_EOS_URL, src.parse_jci_eos)
    take("ignition", src.IGNITION_LTS_URL, src.parse_ignition_lts)
    for component, url in src.BECKHOFF_PAGES.items():
        take(f"beckhoff:{component}", url, lambda text, c=component, u=url: src.parse_beckhoff_service(text, c, u))
    try:
        for version in src.ncs_major_releases(json.loads(fetch(src.NCS_RELEASES_API))):
            url = src.NCS_NOTES_URL.format(version=f"{version}.0")
            text = fetch(url)
            if "long-term support" in text or "are the last" in text:
                records.extend(src.parse_ncs_release_notes(text, version, github_tag_date("nrfconnect/sdk-nrf",
                                                                                          f"v{version}.0"), url))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"ncs: {exc}")
        failed.add(src.NCS_NOTES_URL.split("{")[0] + "*")
    take("variscite", src.VARISCITE_URL, src.parse_variscite)
    take("somlabs", src.SOMLABS_URL, src.parse_somlabs)
    for i, url in enumerate(src.PHYTEC_PAGES):
        take(f"phytec-{i}", url, lambda text, u=url: src.parse_phytec(text, u))
    for i, url in enumerate(src.CRITICALLINK_PAGES):
        take(f"criticallink-{i}", url, lambda text, u=url: src.parse_criticallink(text, u))
    def take_pdf(name, url, parse, mode="-layout"):
        try:
            data = fetch_bytes(url)
            hashed(name, data)
            got = parse(pdf_text(data, mode))
            if not got:
                errors.append(f"{name}: parser found no records (document changed?)")
                failed.add(url)
            records.extend(got)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {exc}")
            failed.update({url, f"doc:{name}"})

    for product, url in src.RPI_BRIEFS.items():
        take_pdf(f"rpi:{product}", url, lambda text, p=product, u=url: src.parse_rpi_brief(text, p, u))
    take_pdf("pdf:sma-support", src.SMA_SUPPORT_URL, src.parse_sma_support, "-raw")
    take_pdf("pdf:apsystems-support", src.APSYSTEMS_SUPPORT_URL, src.parse_apsystems_support, "-raw")
    # SolarEdge: not collected since 2026-10-22. The only fetchable copy was a reseller's stale v1.1 (2024); the official
    # note (v1.3, knowledge-center.solaredge.com) sits behind a bot challenge, which we don't circumvent.
    take_pdf("pdf:tridium-n5-faq", src.TRIDIUM_N5_FAQ_URL, src.parse_tridium_n5_faq, "-raw")
    take_pdf("pdf:nuvoton-plp", src.NUVOTON_PLP_URL, src.parse_nuvoton_plp)
    try:
        for branch in src.freertos_lts_branches(json.loads(fetch(src.FREERTOS_BRANCHES_URL))):
            take(f"freertos-{branch}", src.FREERTOS_README_URL.format(branch=branch),
                 lambda text, b=branch: src.parse_freertos_lts(text, b))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"freertos: {exc}")
        failed.add(src.FREERTOS_README_URL.split("{")[0] + "*")
    try:
        months = src.espidf_policy_months(fetch(src.ESPIDF_POLICY_URL))
        releases = json.loads(fetch(src.ESPIDF_RELEASES_URL))
        hashed("espidf", json.dumps(releases, sort_keys=True).encode())
        if months:
            records.extend(src.parse_espidf(releases, months))
        else:
            errors.append("espidf: support-period sentence not found (policy page changed?)")
            failed.add(src.ESPIDF_POLICY_URL)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"espidf: {exc}")
        failed.add(src.ESPIDF_POLICY_URL)
    return src.prefer_official(records), hashes, errors, failed


def raw_keeper(raw_dir: Path):
    """keep() for collect_all: store each raw source document once, gzip-compressed, named by its sha256.
    A private evidence archive: it proves what a hashed page said. Never published or synced to the site."""
    def keep(sha: str, data: bytes) -> None:
        path = raw_dir / f"{sha}.gz"
        if not path.exists():
            raw_dir.mkdir(parents=True, exist_ok=True)
            path.write_bytes(gzip.compress(data, mtime=0))
    return keep


def carry_over(previous: list[src.Record], failed: set[str]) -> list[src.Record]:
    """Records of sources that failed today, copied from the previous snapshot, so a transient outage does not
    show up as 'removed' (and then 'added' again) in the change log."""
    exact = {f for f in failed if not f.endswith("*")}
    prefixes = tuple(f[:-1] for f in failed if f.endswith("*"))      # 'prefix*': a whole source family failed
    return [r for r in previous if r.source in exact or (prefixes and r.source.startswith(prefixes))]


def carry_over_hashes(previous: dict[str, str], now: dict[str, str], failed: set[str]) -> dict[str, str]:
    """Document hashes of sources that failed today ('doc:<name>' or 'doc:<prefix>*' in failed) are copied from the
    previous snapshot, so an outage is never reported as 'document removed'."""
    names = {f[4:] for f in failed if f.startswith("doc:") and not f.endswith("*")}
    prefixes = tuple(f[4:-1] for f in failed if f.startswith("doc:") and f.endswith("*"))
    kept = {k: v for k, v in previous.items() if k not in now and (k in names or (prefixes and k.startswith(prefixes)))}
    return {**now, **kept}


def cmd_collect(args) -> int:
    day = args.date or date.today().isoformat()
    for attempt in range(args.retries + 1):
        records, hashes, errors, failed = collect_all(raw_keeper(Path(args.data) / "raw"))
        if records:
            break
        print(f"nothing reachable (attempt {attempt + 1}); network down?", file=sys.stderr)
        if attempt < args.retries:
            time.sleep(args.retry_wait)
    if not records:      # an all-carried snapshot would certify a day without any real observation
        print("no source reachable: no snapshot saved for", day, file=sys.stderr)
        return 75
    snaps = Path(args.data) / "snapshots"
    prev = previous_snapshot(snaps, day)
    carried = carry_over(load_snapshot(prev) if prev else [], failed)
    records += carried
    if carried:
        hashes["carried_over_from"] = prev.name
    if prev:
        hashes = carry_over_hashes(load_hashes(prev), hashes, failed)
    path = save_snapshot(snaps, day, records, hashes)
    old_records = load_snapshot(prev) if prev else []
    changes = collapse_new_sources(diff(old_records, records), {r.component for r in old_records}) if prev else []
    if prev:   # PDFs only: raw HTML hashes change with every banner/timestamp; HTML is covered by the record diff
        pdf = lambda h: {k: v for k, v in h.items() if k.startswith(("rpi:", "rpi-eol:", "pdf:"))}  # noqa: E731
        changes += document_changes(pdf(load_hashes(prev)), pdf(hashes))
    if changes:
        log = Path(args.data) / "changes.jsonl"
        with log.open("a") as f:
            for c in changes:
                f.write(json.dumps({"date": day, **c}) + "\n")
    print(f"{len(records)} records -> {path}; {len(changes)} changes vs {prev.name if prev else 'nothing'}"
          + (f"; {len(carried)} carried over from failed sources" if carried else ""))
    for e in errors:
        print("WARN", e, file=sys.stderr)
    return 1 if errors else 0


BACKFILL = {"variscite": (src.VARISCITE_URL, src.parse_variscite),
            "somlabs": (src.SOMLABS_URL, src.parse_somlabs),
            "nxp": (src.NXP_LONGEVITY_URL, src.parse_nxp_longevity),
            "phytec": (src.PHYTEC_PAGES[0], src.parse_phytec),   # archive-only (live page blocks scripts)
            "renesas-plp": (src.RENESAS_PLP_URL, src.parse_renesas_plp),
            "jetson": (src.JETSON_LIFECYCLE_URL, src.parse_jetson_lifecycle),
            "toradex-bsp": (src.TORADEX_BSP_URL, src.parse_toradex_bsp_lifecycle),
            "jci-eos": (src.JCI_EOS_URL, src.parse_jci_eos),
            "ignition": (src.IGNITION_LTS_URL, src.parse_ignition_lts),
            "nuvoton-plp": (src.NUVOTON_PLP_URL, src.parse_nuvoton_plp, "pdf-layout"),
            "sma": (src.SMA_SUPPORT_URL, src.parse_sma_support, "pdf"),
            "apsystems": (src.APSYSTEMS_SUPPORT_URL, src.parse_apsystems_support, "pdf"),
            "solaredge": (src.SOLAREDGE_SUPPORT_URL, src.parse_solaredge_support, "pdf"),
            "kernel": (src.KERNEL_URL, lambda page, _src: src.parse_kernel(page)),
            "yocto": (src.YOCTO_URL, lambda page, _src: src.parse_yocto(page)),
            "openssl": (src.OPENSSL_URL, src.parse_openssl)}


def cmd_backfill(args) -> int:
    url, parse, *kind = BACKFILL[args.source]
    read = ((lambda u: pdf_text(fetch_bytes(u), "-raw")) if kind == ["pdf"] else
            (lambda u: pdf_text(fetch_bytes(u))) if kind == ["pdf-layout"] else fetch)
    stamps = bf.snapshots(fetch_retry(bf.CDX.format(url=urllib.parse.quote(url, safe=""))))
    parsed = []
    for ts in stamps:
        raw = bf.RAW.format(ts=ts, url=url)
        recs = []
        for attempt in range(3):          # the archive sometimes serves a challenge/stub page: retry
            try:
                recs = parse(read(raw), raw)
            except Exception as exc:  # noqa: BLE001
                print("WARN", ts, exc, file=sys.stderr)
            if recs:
                break
            time.sleep(args.delay * (attempt + 2))
        parsed.append((ts, recs))
        time.sleep(args.delay)
    events = bf.history_events(parsed, url)
    out = Path(args.data) / "backfill" / f"{args.source}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(e) + "\n" for e in events))
    last = next(((ts, r) for ts, r in reversed(parsed) if r), None)
    if last:   # last usable archived state, to bridge the gap to our own first snapshot
        (out.parent / f"{args.source}.last.json").write_text(json.dumps(
            {"date": bf.ts_date(last[0]), "snapshot": bf.RAW.format(ts=last[0], url=url),
             "records": [r.__dict__ for r in last[1]]}, indent=1))
    usable = sum(1 for _, r in parsed if r)
    print(f"{len(stamps)} archived captures, {usable} parsable; {len(events)} events -> {out}")
    return 0


# Never on the public site. SMA and APsystems are public since 2026-10-22 (founder decision 2026-10-21: the 2026-10-16
# comparison filter was lifted on 2026-10-19, and public snapshots keep the proof chain verifiable). SolarEdge stays
# private: its records (2026-10-16..21) came from a reseller's stale copy, and it is no longer collected.
PRIVATE_COMPONENTS = {"SolarEdge security updates"}
PRIVATE_DOCUMENTS = {"pdf:solaredge-support"}   # its PDF-hash events


def public_only(items: list) -> list:
    """Drop records (or change/event dicts) of private components before anything is published."""
    def private(x) -> bool:
        if isinstance(x, dict):
            return x.get("component") in PRIVATE_COMPONENTS or x.get("line") in PRIVATE_DOCUMENTS
        return x.component in PRIVATE_COMPONENTS
    return [x for x in items if not private(x)]


# Site settings: placeholders are replaced when the site is configured.
SITE_CONFIG = {"alerts_form_action": "ALERTS_FORM_ACTION", "checkout_pro": "CHECKOUT_PRO_URL",
               "checkout_team": "CHECKOUT_TEAM_URL", "privacy_url": "https://asknau.com/en/privacy-policy/",
               "imprint_url": "https://asknau.com/en/legal-notice/",
               "services_contact": "info@asknau.com", "checkout_fact_sheet": "CHECKOUT_FACT_SHEET_URL",
               "checkout_bms_watch": "CHECKOUT_BMS_WATCH_URL",
               "services_url": "https://asknau.com/en/services/#embedded-linux-lifecycle-and-cra-readiness",
               "sample_report_url": "https://asknau.com/en/services/cra-sample-report/",
               "method_url": "https://asknau.com/en/tech-blog/2026/10/29/published-eol-dates-move/",
               "repo_url": "https://github.com/supportdates/supportdates", "api_contact": "supportdates@asknau.com"}
BMS_COMPONENTS = ("Tridium Niagara", "Johnson Controls EOS", "Ignition")
SITE_URL = "https://supportdates.com/"
FAVICON = Path(__file__).resolve().parent.parent / "brand" / "avatar.svg"
ICON_LINK = "<link rel=icon href=favicon.svg type='image/svg+xml'>"
DATA_LICENCE = ('Data: <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>, attribution "supportdates.com" '
                '(current dates and full history; <a href="LICENSE-DATA.txt">details</a>).')
HEADERS = """/api/*
  Access-Control-Allow-Origin: *
/cle/*
  Access-Control-Allow-Origin: *
/changes.xml
  Access-Control-Allow-Origin: *
"""
HTACCESS = """# Apache (netcup Webhosting/Plesk). If Plesk lets nginx serve static files directly, the headers below are skipped:
# then paste nginx-directives.txt into Plesk > Apache & nginx Settings > Additional nginx directives.
AddDefaultCharset UTF-8
<IfModule mod_headers.c>
  <Files "changes.xml">
    Header set Access-Control-Allow-Origin "*"
  </Files>
</IfModule>
"""
HTACCESS_CORS = """<IfModule mod_headers.c>
  Header set Access-Control-Allow-Origin "*"
</IfModule>
"""
NGINX_DIRECTIVES = """location ~ ^/(api|cle)/ { add_header Access-Control-Allow-Origin "*" always; }
location = /changes.xml { add_header Access-Control-Allow-Origin "*" always; }
"""
LICENSE_DATA = """supportdates data: licensed under Creative Commons Attribution 4.0 International (CC BY 4.0),
https://creativecommons.org/licenses/by/4.0/ . Attribution: "supportdates.com".
Covers the current records, the dated change history, the API files (api/), the ECMA-428 CLE documents (cle/) and
changes.xml. Each record links its original source; quotes are short excerpts of those sources, whose own rights remain
with their owners. Facts as published by the sources, provided as is, without warranty.
"""


def configured(value: str) -> bool:
    """A site setting is live once its ALL_CAPS placeholder has been replaced by a real URL or address."""
    return bool(value) and not re.fullmatch(r"[A-Z_]+", value)


def services_section(cfg: dict) -> str:
    """F1+ offer (bridge to recurring revenue), kept apart from the facts-only data. Prices live only on asknau.com,
    so the two sites can't disagree. Advisory wording only: no conformity, certification or 'compliant' claims.
    Left out until a contact address is configured."""
    if not configured(cfg["services_contact"]):
        return ""
    e = {k: html.escape(v) for k, v in cfg.items()}
    sample = (f' · <a href="{e["sample_report_url"]}">sample report</a>'
              if configured(cfg["sample_report_url"]) else "")
    return f"""<h2>Need this for your own product?</h2>
<p>The dataset stays facts only. Separately, its maintainer offers fixed-price, async, remote services for embedded Linux
makers: a CRA readiness pre-assessment from your firmware image, a BSP end-of-life assessment, and a vulnerability triage
retainer. Advisory, not a conformity assessment. <a href="{e['services_url']}">Details and prices</a>{sample} ·
<a href="mailto:{e['services_contact']}">email</a>.</p>"""


def about_line(cfg: dict) -> str:
    """Who runs the site and how it works: trust for a dataset people are asked to rely on."""
    e = {k: html.escape(v) for k, v in cfg.items()}
    return (f'<p style="color:var(--mut)">Maintained by János Naumann (<a href="https://asknau.com/en/about/">ASK NAU</a>) · '
            f'<a href="{e["repo_url"]}">source code</a> · <a href="{e["method_url"]}">method and findings</a> · '
            f'corrections: <a href="mailto:{e["api_contact"]}">{e["api_contact"]}</a></p>')


def sitemap_xml(names: list[str], base: str) -> str:
    """Sitemap for the HTML pages (the item pages are what people search for)."""
    urls = "".join(f"<url><loc>{html.escape(base + ('' if n == 'index.html' else n))}</loc></url>" for n in sorted(names))
    return f"<?xml version='1.0' encoding='UTF-8'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{urls}</urlset>"


def bms_page(recs: list, cfg: dict) -> str:
    """Second-audience landing page (owners/facility managers first): building-automation and OT software dates."""
    e = {k: html.escape(v) for k, v in cfg.items()}
    rows = "".join(
        f"<tr><td>{html.escape(r.component)}</td><td><a href='{slug(r.component, r.line)}.html'>{html.escape(r.line)}</a>"
        f"</td><td>{r.eol or '—'}</td><td>{r.kind}</td><td><a href='{html.escape(r.source)}'>source</a></td></tr>"
        for r in sorted((r for r in recs if r.component in BMS_COMPONENTS), key=lambda r: (BMS_COMPONENTS.index(
            r.component), r.eol or "9999")))
    offers = ""
    if configured(cfg["checkout_fact_sheet"]):
        offers += f"""<h2>For building owners and facility managers</h2>
<p><strong>Site lifecycle fact sheet, €59 one-time</strong> (founding price, money-back guarantee): send your controller
and software list; get the published dates for each item with sources, before you decide on a replacement quote.
<a href="{e['checkout_fact_sheet']}">Order</a>.</p>"""
    if configured(cfg["checkout_bms_watch"]):
        offers += f"""<h2>For integrators</h2><p><strong>Portfolio watch, €29/month</strong> (founding members; cancel any time): a private
watch list for your customers' sites and a monthly change report with sources; email alerts as they go live.
<a href="{e['checkout_bms_watch']}">Join</a>.</p>"""
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>Building Automation Support Dates</title>{ICON_LINK}
<meta name=description content="Published end-of-support dates for Tridium Niagara, Johnson Controls Metasys and Ignition, with sources and a dated change log."><style>
:root{{--bg:#fff;--fg:#1b1f24;--line:#d9dee4;--acc:#0b6bcb}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#111418;--fg:#e6e9ed;--line:#2b323a;--acc:#5aa9ff}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:0 auto;padding:16px}}
a{{color:var(--acc)}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid var(--line);padding:6px 8px;
text-align:left}}.wrap{{overflow-x:auto}}</style></head><body>
<h1>Building automation &amp; OT software: published support dates</h1>
<p>What vendors published about end of support for Niagara, Metasys and Ignition, with sources and a dated change log.
Facts only: not an assessment of safety, security, compliance or fitness, and not a product recommendation.
Fire, security and life-safety products are not covered.</p>
<p><strong>Niagara 4 → 5:</strong> Tridium's FAQ plans Niagara 4.15 updates through Q3 2028 and Niagara 5.0 general
availability for December 2026; JACE-8000 ordering closed in Europe on 2025-12-31. Distributor bulletins quote different dates,
so every date here links its source.</p>
<div class=wrap><table><tr><th>Source</th><th>Line</th><th>End</th><th>Kind</th><th>Source</th></tr>{rows}</table></div>
{offers}<p style="color:var(--mut)">{DATA_LICENCE}</p></body></html>"""


def alerts_section(cfg: dict) -> str:
    """Fake-door offer: measures whether people want alerts and which components (the free table stays free).
    Until the form backend and checkout links are configured, only a short notice and the API contact are shown."""
    e = {k: html.escape(v) for k, v in cfg.items()}
    api = (f' Data API for BOM, PLM and EMS tools: <a href="mailto:{e["api_contact"]}">ask</a>.'
           if configured(cfg["api_contact"]) else "")
    if not configured(cfg["alerts_form_action"]):
        return f"""<h2>Get notified when a date moves</h2>
<p>Support dates and module longevity change: some get extended, some get cut. Alerts are <strong>in preparation</strong>.
Meanwhile, follow <a href="changes.xml">the change feed (RSS)</a>.{api}</p>"""
    plans = ""
    if configured(cfg["checkout_pro"]) and configured(cfg["checkout_team"]):
        plans = f"""<p><strong>Founding member plans</strong> (annual, for products with long lifecycles; founding price kept on renewal;
30-day money-back guarantee). The dataset itself stays free and open.
Product-line watch, €290/year: a private watch list for the modules, BSP lines and libraries of one product, a monthly
change report for that list with sources, and email alerts for the list as they go live (founding members first)
(<a href="{e['checkout_pro']}">join</a>). Portfolio watch, €990/year: all product lines, BOM/manifest upload, CSV export
of your list's history (<a href="{e['checkout_team']}">join</a>).</p>"""
    return f"""<h2>Get notified when a date moves</h2>
<p>Support dates and module longevity change: some get extended, some get cut. Alerts are <strong>in preparation</strong>;
leave your list and we email you when they start.</p>
<form method=post action="{e['alerts_form_action']}" style="border:1px solid var(--line);padding:12px;border-radius:8px">
<label>Email<br><input type=email name=email required style="width:100%"></label><br>
<label>Components, modules or BSP lines to watch (one per line, e.g. "DART-MX8M-PLUS", "Zephyr 3.7 LTS")<br>
<textarea name=watch rows=4 style="width:100%"></textarea></label><br>
<label><input type=checkbox name=consent required> Email me about this list only; unsubscribe any time
(<a href="{e['privacy_url']}">privacy</a>).</label><br><button type=submit>Join the free weekly digest</button></form>
{plans}<p>{api.strip()}</p>"""


def rss_feed(events: list[dict], site_url: str) -> str:
    """RSS 2.0 of date changes (own snapshots + archive-derived), newest first; item link = the source or archived page."""
    from_items = []
    for e in sorted(events, key=lambda e: e["date"], reverse=True)[:100]:
        title = f"{e.get('component', '')} {e.get('line', '')}: {e['change']} {e.get('old', '')} → {e.get('new', e.get('eol', ''))}"
        link = e.get("snapshot") or e.get("source") or site_url
        from_items.append(f"<item><title>{html.escape(title.strip())}</title><link>{html.escape(link)}</link>"
                          f"<guid isPermaLink='false'>{html.escape(e['date'] + ' ' + title)}</guid>"
                          f"<pubDate>{html.escape(e['date'])}</pubDate></item>")
    return ("<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel><title>Embedded Support Dates: changes</title>"
            f"<link>{html.escape(site_url)}</link><description>Moved, added and removed end-of-support dates with sources"
            f"</description>{''.join(from_items)}</channel></rss>")


def slug(component: str, line: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", f"{component} {line}".lower()).strip("-")


def api_date(value: str, end: bool = True) -> str | None:
    """endoflife.date-style YYYY-MM-DD. Partial dates: end=True -> last day of the month/year (support ends),
    end=False -> first day (released in). None if no date."""
    m = re.fullmatch(r"(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", value or "")
    if not m:
        return None
    y = int(m.group(1))
    mo = int(m.group(2) or (12 if end else 1))
    day = m.group(3) or (calendar.monthrange(y, mo)[1] if end else 1)
    return f"{y:04d}-{mo:02d}-{int(day):02d}"


def eol_api(recs: list) -> dict[str, list[dict]]:
    """Per component, the endoflife.date v0 cycle list ([{cycle, releaseDate, eol, lts, link, ...}]), so tools that
    already read endoflife.date (e.g. Renovate's endoflife-date datasource with a custom registryUrl) can read us.
    Extra fields (eolPrecision, kind) are ignored by those tools. Notices are not cycles and are left out."""
    out: dict[str, list[dict]] = {}
    for r in recs:
        if r.kind == "notice" or not (r.eol or r.released):
            continue      # undated membership facts (e.g. Renesas PLP) would read as "eol: false = no end announced"
        precision = "day" if re.fullmatch(r"\d{4}-\d{2}-\d{2}", r.eol or "") else (
            "month" if re.fullmatch(r"\d{4}-\d{2}", r.eol or "") else "year" if r.eol else None)
        out.setdefault(re.sub(r"[^a-z0-9]+", "-", r.component.lower()).strip("-"), []).append({
            # numeric lines ('3.7 LTS', '6.1 Blacksail') -> cycle '3.7'/'6.1' so version matching works; names stay whole
            "cycle": r.line.split()[0] if re.match(r"\d", r.line) else r.line, "label": r.line,
            "releaseDate": api_date(r.released, end=False), "eol": api_date(r.eol) or False,
            "lts": "LTS" in r.line, "link": r.source, "eolPrecision": precision, "kind": r.kind})
    return out


def item_pages(recs: list, events: list[dict], cfg: dict) -> dict[str, str]:
    """One page per (component, line): current date, dated history with sources, alert form. For search engines:
    people look for 'DART-MX8M-PLUS longevity' or 'Zephyr 3.7 end of life', not for a big table."""
    by_key: dict = {}
    for e in events:
        by_key.setdefault((e.get("component", ""), e.get("line", "")), []).append(e)
    pages = {}
    for r in recs:
        hist = sorted(by_key.get((r.component, r.line), []), key=lambda e: e["date"], reverse=True)
        items = "".join(f"<li>{e['date']}: {html.escape(e['change'])} {html.escape(str(e.get('old', '')))} → "
                        f"{html.escape(str(e.get('new', e.get('eol', ''))))}"
                        + (f" ({html.escape(e['between'])})" if e.get("between") else "")
                        + (f" (<a href='{html.escape(e['snapshot'])}'>archived page</a>)" if e.get("snapshot") else "")
                        + "</li>" for e in hist) or "<li>No change recorded since tracking started.</li>"
        title = f"{r.component} {r.line}: end of support / longevity"
        pages[f"{slug(r.component, r.line)}.html"] = f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>{ICON_LINK}
<meta name=description content="{html.escape(f'{r.component} {r.line}: published end of support {r.eol or "not announced"}, with source and dated change history.')}">
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:16px}}</style></head><body>
<p><a href="index.html">All components</a></p><h1>{html.escape(r.component)} {html.escape(r.line)}</h1>
<p><strong>End of support / longevity:</strong> {html.escape(r.eol or "not announced")} ({html.escape(r.kind)}).
Released: {html.escape(r.released or "—")}. <a href="{html.escape(r.source)}">Source</a>.</p>
<p style="color:#5b6470">{html.escape(r.evidence)}</p><h2>Change history</h2><ul>{items}</ul>
{alerts_section(cfg)}<p style="color:#5b6470">{DATA_LICENCE}</p></body></html>"""
    return pages


def bridge_events(data: Path, snaps: list[Path]) -> list[dict]:
    """Changes between the last usable archived capture of a source and the first own snapshot that contains the
    source's components (sources added later bridge to their own first day; date range in the label)."""
    out = []
    for f in sorted((data / "backfill").glob("*.last.json")):
        last = json.loads(f.read_text())
        recs = [src.Record(**r) for r in last["records"]]
        archived = {r.component for r in recs}
        for snap in snaps:
            first = load_snapshot(snap)
            comps = archived & {r.component for r in first}
            if comps:
                for c in diff(recs, [r for r in first if r.component in comps]):
                    out.append({"date": snap.stem, **c, "snapshot": last["snapshot"],
                                "between": f"after {last['date']} (last archived capture), first seen {snap.stem}"})
                break
    return out


def cmd_site(args) -> int:
    snaps = sorted((Path(args.data) / "snapshots").glob("*.json"))
    if not snaps:
        print("no snapshots yet; run collect first", file=sys.stderr)
        return 1
    recs = public_only(load_snapshot(snaps[-1]))
    log = Path(args.data) / "changes.jsonl"
    changes = public_only([json.loads(l) for l in log.read_text().splitlines()] if log.exists() else [])
    rows = "".join(
        f"<tr><td>{html.escape(r.component)}</td><td><a href='{slug(r.component, r.line)}.html'>{html.escape(r.line)}</a></td><td>{r.released}</td>"
        f"<td>{r.eol or '—'}</td><td>{r.kind}</td><td><a href='{html.escape(r.source)}'>source</a></td></tr>"
        for r in sorted(recs, key=lambda r: (r.component, r.eol or "9999")))
    ch = "".join(f"<li>{c['date']}: {html.escape(c['component'])} {html.escape(c['line'])}: {html.escape(c['change'])} "
                 f"{html.escape(str(c.get('old', '')))} → {html.escape(str(c.get('new', c.get('eol', ''))))}</li>" for c in changes) \
        or "<li>No changes recorded yet (history starts with the first snapshot).</li>"
    back = []
    for f in sorted((Path(args.data) / "backfill").glob("*.jsonl")):
        back += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    back = public_only(back + bridge_events(Path(args.data), snaps))
    moved = [e for e in back if e["change"] in ("eol changed", "removed", "added")]
    bk = "".join(f"<li>{e['date']}: {html.escape(e.get('component', ''))} {html.escape(e.get('line', ''))}: "
                 f"{html.escape(e['change'])} {html.escape(str(e.get('old', '')))} → "
                 f"{html.escape(str(e.get('new', e.get('eol', ''))))} (<a href='{html.escape(e['snapshot'])}'>archived page</a>)</li>"
                 for e in reversed(moved)) or "<li>No archive-derived history.</li>"
    page = f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>Embedded Support Dates</title>{ICON_LINK}
<meta name=description content="Published support and end-of-life dates of embedded platforms (SoMs, SoCs, BSPs, RTOS, SDKs), archived daily with sources, timestamped proofs and a dated change log."><style>
:root{{--bg:#fff;--fg:#1b1f24;--mut:#5b6470;--line:#d9dee4;--acc:#0b6bcb}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#111418;--fg:#e6e9ed;--mut:#9aa4af;--line:#2b323a;--acc:#5aa9ff}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:0 auto;padding:16px}}
a{{color:var(--acc)}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left}}
th{{color:var(--mut)}}.wrap{{overflow-x:auto}}</style></head><body>
<h1>Embedded Support Dates</h1>
<p><a href="changes.xml">RSS feed of changes</a></p>
<p style="color:var(--mut)">Snapshot {snaps[-1].stem}. End-of-support dates as published by each project (official) or computed from its
published support policy (derived), with the source link. Facts only, no assessments. History: {len(snaps)} snapshot(s).</p>
{alerts_section(SITE_CONFIG)}
{services_section(SITE_CONFIG)}
<h2>Current dates</h2>
<div class=wrap><table><tr><th>Component</th><th>Line</th><th>Released</th><th>End of support</th><th>Kind</th><th>Source</th></tr>{rows}</table></div>
<h2>Change log (own snapshots)</h2><ul>{ch}</ul>
<h2>Earlier history from the Internet Archive</h2>
<p style="color:var(--mut)">Reconstructed from Wayback Machine captures of the vendor page; dates are capture dates, not
announcement dates. Gaps where the archive has no usable capture.</p><ul>{bk}</ul>
<p style="color:var(--mut)">Facts with sources only; no recommendations. Vendor and product names are used to identify the
products the dates refer to. <a href="{html.escape(SITE_CONFIG['imprint_url'])}">Imprint</a> ·
<a href="{html.escape(SITE_CONFIG['privacy_url'])}">Privacy</a></p>{about_line(SITE_CONFIG)}<p style="color:var(--mut)">{DATA_LICENCE}</p></body></html>"""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(page)
    events = changes + [e for e in back if e["change"] in ("eol changed", "removed", "added")]
    (out / "changes.xml").write_text(rss_feed(events, SITE_URL))
    (out / "_headers").write_text(HEADERS)              # CORS for tools fetching api/, cle/ and the feed (Cloudflare)
    (out / ".htaccess").write_text(HTACCESS)             # same for Apache (netcup Webhosting), per folder
    for folder in ("api", "cle"):
        (out / folder).mkdir(exist_ok=True)
        (out / folder / ".htaccess").write_text(HTACCESS_CORS)
    (out / "nginx-directives.txt").write_text(NGINX_DIRECTIVES)
    (out / "LICENSE-DATA.txt").write_text(LICENSE_DATA)
    (out / "bms.html").write_text(bms_page(recs, SITE_CONFIG))
    api = out / "api"
    api.mkdir(exist_ok=True)
    for name, cycles in eol_api(recs).items():          # public records only (recs passed through public_only)
        (api / f"{name}.json").write_text(json.dumps(cycles, indent=1))
    pages = item_pages(recs, events, SITE_CONFIG)
    for name, text in pages.items():
        (out / name).write_text(text)
    (out / "sitemap.xml").write_text(sitemap_xml(["index.html", "bms.html", *pages], SITE_URL))
    (out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}sitemap.xml\n")
    if FAVICON.exists():
        (out / "favicon.svg").write_bytes(FAVICON.read_bytes())
    print(f"wrote {len(pages)} item pages")
    print(f"wrote {out / 'index.html'} ({len(recs)} records, {len(changes)} changes)")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="supportdates", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--data", default="data")
    c.add_argument("--date", help="override snapshot date (YYYY-MM-DD)")
    c.add_argument("--retries", type=int, default=3, help="retries when no source is reachable (e.g. after resume)")
    c.add_argument("--retry-wait", type=float, default=600, help="seconds between those retries")
    c.set_defaults(func=cmd_collect)
    b = sub.add_parser("backfill", help="history from Wayback Machine snapshots")
    b.add_argument("source", choices=sorted(BACKFILL))
    b.add_argument("--data", default="data")
    b.add_argument("--delay", type=float, default=1.5, help="seconds between archive requests")
    b.set_defaults(func=cmd_backfill)
    s = sub.add_parser("site")
    s.add_argument("--data", default="data")
    s.add_argument("--out", default="site")
    s.set_defaults(func=cmd_site)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
