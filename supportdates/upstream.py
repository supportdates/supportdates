"""Draft endoflife.date product files for components it lacks (Zephyr, Mbed TLS, ESP-IDF, nRF Connect SDK).

    python -m supportdates.upstream --data data --out upstream/endoflife

Facts come from our latest snapshot (cycles, release/end dates, sources) and `git ls-remote --tags`
(latest patch per cycle). Anything not known exactly is written as TODO, to fill in by hand before a PR.
These are drafts for an upstream contribution (distribution and reputation), not published by this tool.
"""

import argparse
import re
import subprocess
from pathlib import Path

from .sources import Record
from .store import load_snapshot

PRODUCTS = {
    "zephyr": {"title": "Zephyr RTOS", "component": "Zephyr", "category": "os", "repo": "zephyrproject-rtos/zephyr",
               "tag": r"v{cycle}\.(\d+)", "policy": "https://docs.zephyrproject.org/latest/project/release_process.html"},
    "mbed-tls": {"title": "Mbed TLS", "component": "Mbed TLS", "category": "framework", "repo": "Mbed-TLS/mbedtls",
                 "tag": r"v{cycle}\.(\d+)", "policy": "https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md"},
    "nrf-connect-sdk": {"title": "nRF Connect SDK", "component": "nRF Connect SDK", "category": "framework",
                        "repo": "nrfconnect/sdk-nrf", "tag": r"v{cycle}\.(\d+)",
                        "policy": "https://github.com/nrfconnect/sdk-nrf/blob/main/doc/nrf/releases_and_maturity/"
                                  "ncs_release_model/lts_releases.rst"},
    "esp-idf": {"title": "ESP-IDF", "component": "ESP-IDF", "category": "framework", "repo": "espressif/esp-idf",
                "tag": r"v{cycle}(?:\.(\d+))?", "policy": "https://docs.espressif.com/projects/esp-idf/en/stable/esp32/versions.html"},
}


def latest_patch(tags: list[str], pattern: str, cycle: str) -> str | None:
    """Highest final (non rc/beta/dev) tag of one release cycle, e.g. '4.4.2' for cycle '4.4'."""
    rx = re.compile(pattern.format(cycle=re.escape(cycle)) + r"$")
    best = None
    for t in tags:
        m = rx.fullmatch(t)
        if m:
            patch = int(m.group(1) or 0)
            if best is None or patch > best[0]:
                best = (patch, t.lstrip("v"))
    return best[1] if best else None


def tag_date(clone: Path | None, tag: str | None) -> str | None:
    """Commit date (YYYY-MM-DD) of a tag in a local bare clone (`git clone --bare --filter=tree:0`), else None."""
    if clone is None or tag is None or not clone.exists():
        return None
    r = subprocess.run(["git", "-C", str(clone), "log", "-1", "--format=%cs", tag], capture_output=True, text=True)
    return r.stdout.strip() or None


def first_tag(tags: list[str], pattern: str, cycle: str) -> str | None:
    """The cycle's first final release tag (x.y.0 or x.y), e.g. 'v3.7.0'."""
    rx = re.compile(pattern.format(cycle=re.escape(cycle)) + r"$")
    finals = [t for t in tags if rx.fullmatch(t) and int(rx.fullmatch(t).group(1) or 0) == 0]
    return finals[0] if finals else None


def yaml_date(value: str) -> str:
    return value if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) else f"TODO  # source gives only '{value or 'none'}'"


def render(slug: str, meta: dict, records: list[Record], tags: list[str], clone: Path | None = None) -> str:
    lines = ["---", f"title: {meta['title']}", "addedAt: TODO", f"category: {meta['category']}", f"permalink: /{slug}",
             f"releasePolicyLink: {meta['policy']}", "", "releases:"]
    for r in sorted(records, key=lambda r: [int(x) for x in re.findall(r"\d+", r.line)], reverse=True):
        cycle = r.line.split()[0]
        latest = latest_patch(tags, meta["tag"], cycle)
        lines += [f'  - releaseCycle: "{cycle}"'] + (["    lts: true"] if "LTS" in r.line else [])
        released = r.released if re.fullmatch(r"\d{4}-\d{2}-\d{2}", r.released or "") else None
        tagged = None if released else tag_date(clone, first_tag(tags, meta["tag"], cycle))
        rel_line = (f"    releaseDate: {released or tagged}" + ("  # git tag date" if tagged and not released else "")
                    if (released or tagged) else f"    releaseDate: {yaml_date(r.released)}")
        lines += [rel_line, f"    eol: {yaml_date(r.eol) if r.eol else 'false'}",
                  f'    latest: "{latest}"' if latest else "    latest: TODO", f"    # source: {r.source}", ""]
    return "\n".join(lines + ["---", "", f"> [{meta['title']}]({meta['policy']}) TODO: one-sentence description.", ""])


def git_tags(repo: str) -> list[str]:
    out = subprocess.run(["git", "ls-remote", "--tags", "--refs", f"https://github.com/{repo}"],
                         capture_output=True, text=True, check=True).stdout
    return [line.rsplit("/", 1)[-1] for line in out.splitlines()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="upstream/endoflife")
    ap.add_argument("--clones", help="directory with bare clones named after the repo (e.g. mbedtls, zephyr, esp-idf)")
    args = ap.parse_args(argv)
    snap = sorted((Path(args.data) / "snapshots").glob("*.json"))[-1]
    records = load_snapshot(snap)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for slug, meta in PRODUCTS.items():
        recs = [r for r in records if r.component == meta["component"] and r.kind != "notice"]
        clone = Path(args.clones) / meta["repo"].split("/")[1] if args.clones else None
        (out / f"{slug}.md").write_text(render(slug, meta, recs, git_tags(meta["repo"]), clone))
        print(f"{slug}: {len(recs)} cycles -> {out / (slug + '.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
