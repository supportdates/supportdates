"""Self-audit: re-fetch the sources of a random sample of records and check that the record's line (item name)
and its date are present in the source text. A reliability number for the dataset ("verified ground truth").

    python -m supportdates.audit [--data data] [--n 30] [--seed 1]
    python -m supportdates.audit --history renesas-plp [--n 10]     (archive change events vs. both archived pages)
"""

import argparse
import html
import json
import random
import re
from pathlib import Path

from .cli import fetch, fetch_bytes, fetch_retry, pdf_text
from .sources import Record
from .store import load_snapshot

MONTH = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def date_forms(value: str) -> list[str]:
    """Textual forms a date may take in a source: '2027-03' -> ['2027-03', 'Mar 2027', 'March 2027', '03/2027'...]."""
    m = re.fullmatch(r"(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", value or "")
    if not m:
        return []
    y, mo, d = m.group(1), m.group(2), m.group(3)
    forms = [value, y] if not mo else [value]
    if mo:
        name = MONTH[int(mo)]
        forms += [f"{name} {y}", f"{name}. {y}", f"{mo}/{y}", f"{name}, {y}", f"{y}, {name}", f"{y}/{int(mo)}", f"{y}/{mo}"]
        full = ["", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
                "November", "December"][int(mo)]
        forms += [f"{full} {y}", f"{full} of {y}", f"{full}, {y}"]
        if d:
            forms += [f"{mo}/{d}/{y}", f"{int(d)} {name} {y}", f"{int(d)} {full} {y}", f"{d}/{mo}/{y}", y + mo + d]
    return forms


def check(record: Record, text: str) -> tuple[bool, bool]:
    """(item name found, date found) in the normalised source text."""
    flat = re.sub(r"\s+", " ", text)
    low = flat.lower()
    name = record.line.split(" [")[0].split(" (")[0].replace(" LTS", "").lower()
    tokens = [t for t in re.split(r"[^a-z0-9.\-]+", name) if t]
    # table cells split names apart ("6.1 | Blacksail", "coreSNTP | 2.0.0"); ids may live only in the source URL
    # parsers may drop spaces ('STP 50-41' -> 'STP50-41') or join wrapped cells ('3AC-\nEC-10')
    squashed = re.sub(r"\s+", "", low)
    name_ok = all(t in low for t in tokens) or name in record.source.lower() or re.sub(r"\s+", "", name) in squashed
    target = record.eol or record.released
    date_ok = any(f.lower() in low for f in date_forms(target)) if target else True
    return name_ok, date_ok


def cached(cache: dict, key: str, read) -> str:
    """read(key) once per key (dict.setdefault would evaluate read() on every call)."""
    if key not in cache:
        cache[key] = read(key)
    return cache[key]


def fragments(page: str) -> set[str]:
    """Normalised table cells, plus their comma-separated items, of raw HTML or PDF text (lowercase, no spaces or
    parentheses). Cells are kept whole too, so names containing commas ('i.MX 6UltraLite (Industrial, Auto)') match."""
    norm = lambda x: re.sub(r"[\s()]+", "", html.unescape(x).lower())   # noqa: E731
    tables = re.findall(r"(?is)<table.*?</table>", page)
    scope = "\n".join(tables) if tables else page      # names in menus outside the table don't count
    cells = [x for x in re.split(r"<[^>]+>|\n|\s{2,}", scope) if x.strip()]   # 2+ spaces: PDF -layout columns
    return {norm(c) for c in cells} | {norm(i) for c in cells for i in c.split(",") if i.strip()}


def check_event(event: dict, before: str, after: str) -> str:
    """Archive history event vs. the two archived pages it was derived from: 'confirmed', 'contradicted' or
    'unverifiable' (names under 4 characters can't be shown absent, they occur everywhere)."""
    if event.get("kind") == "notice" or ": " in event["line"]:
        return "unverifiable"      # synthetic lines ('BSP 6 state: Maintenance') aren't on the page
    if "derived" in (event.get("kind"), event.get("old_kind")) and event["change"] not in ("added", "removed"):
        return "unverifiable"      # computed dates aren't on the page; whether the item is listed still is
    squash = lambda t: re.sub(r"[\s()]+", "", re.sub(r"<[^>]+>", " ", t).lower())   # noqa: E731
    b, a, name = squash(before), squash(after), squash(event["line"])
    if event["change"] in ("added", "removed"):
        if len(name) < 4:
            return "unverifiable"
        # whole cells / list items, so 'Jetson Xavier NX' is not found inside 'Jetson Xavier NX 16GB'
        found = lambda page: any(f == name or f.endswith("/" + name) for f in fragments(page))   # noqa: E731
        present_before, present_after = found(before), found(after)    # 'Torizon/BSP 7' is the line 'BSP 7' 
        expected = (False, True) if event["change"] == "added" else (True, False)
        return "confirmed" if (present_before, present_after) == expected else "contradicted"
    if event["change"] in ("eol changed", "released changed", "eol refined", "released refined"):
        old_ok = not event["old"] or any(f.lower().replace(" ", "") in b for f in date_forms(event["old"]))
        new_ok = any(f.lower().replace(" ", "") in a for f in date_forms(event["new"]))
        return "confirmed" if name in b and name in a and old_ok and new_ok else "contradicted"
    return "unverifiable"


def audit_history(events: list[dict], n: int, seed: int, read=None) -> tuple[dict, list]:
    """Sample change events that carry both snapshot URLs; re-read both pages and check each event."""
    read = read or raw_text
    usable = [e for e in events if e.get("previous") and e["change"] in
              ("added", "removed", "eol changed", "released changed", "eol refined", "released refined")]
    sample = random.Random(seed).sample(usable, min(n, len(usable)))
    counts, bad, cache = {"confirmed": 0, "contradicted": 0, "unverifiable": 0}, [], {}
    for e in sample:
        try:
            before, after = cached(cache, e["previous"], read), cached(cache, e["snapshot"], read)
        except Exception as exc:  # noqa: BLE001
            bad.append((e, f"fetch error {exc}"))
            continue
        verdict = check_event(e, before, after)
        counts[verdict] += 1
        if verdict == "contradicted":
            bad.append((e, verdict))
    return counts, bad


def raw_text(url: str) -> str:
    """Raw HTML (cell structure kept, for the history audit) or PDF text."""
    if url.lower().endswith(".pdf"):
        data = fetch_bytes(url)
        if not data.startswith(b"%PDF"):   # throttle or error page: not evidence that items are absent
            raise ValueError("not a PDF")
        return pdf_text(data) + "\n" + pdf_text(data, "-raw")
    return fetch_retry(url, tries=5, wait=15)    # the archive throttles bursts


def source_text(url: str) -> str:
    if url.lower().endswith(".pdf"):
        data = fetch_bytes(url)   # both orders: '-layout' keeps columns, '-raw' keeps wrapped cells together
        return pdf_text(data) + "\n" + pdf_text(data, "-raw")
    return re.sub(r"<[^>]+>", " ", fetch(url))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--history", metavar="SOURCE", help="audit archive change events of data/backfill/SOURCE.jsonl")
    args = ap.parse_args(argv)
    if args.history:
        path = Path(args.data) / "backfill" / f"{args.history}.jsonl"
        events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        counts, bad = audit_history(events, args.n, args.seed)
        print(f"history audit {args.history}: {counts}")
        for e, why in bad:
            print(f"  {e['date']} {e['change']} {e['line']}: {why}")
        return 0
    snap = sorted((Path(args.data) / "snapshots").glob("*.json"))[-1]
    recs = [r for r in load_snapshot(snap) if r.kind != "derived"]   # derived dates are computed, not quoted
    sample = random.Random(args.seed).sample(recs, min(args.n, len(recs)))
    cache, ok, fails = {}, 0, []
    for r in sample:
        try:
            text = cached(cache, r.source, source_text)
        except Exception as exc:  # noqa: BLE001
            fails.append((r, f"fetch error {exc}"))
            continue
        n_ok, d_ok = check(r, text)
        if n_ok and d_ok:
            ok += 1
        else:
            fails.append((r, f"name {'ok' if n_ok else 'MISSING'}, date {'ok' if d_ok else 'MISSING'}"))
    print(f"audit of {len(sample)} quoted records from {snap.stem}: {ok} confirmed in their source ({ok / len(sample):.0%})")
    for r, why in fails:
        print(f"  {r.component} | {r.line} | {r.eol or r.released}: {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
