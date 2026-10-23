"""Export software release lines as ECMA-428 Common Lifecycle Enumeration (CLE 1.0.0) documents.

    python -m supportdates.cle [--data data] [--out site/cle]

One document per software component. Each release line yields a 'released' and an 'endOfSupport' event; a
date the source later moved becomes a 'withdrawn' event plus a new 'endOfSupport' event, so the prepend-only
CLE stream mirrors supportdates' observed history. 'published' is the date supportdates first observed the value
(own snapshots or archive captures), not a date asserted by the vendor. Only dates the source states (kind
'official') are exported; derived dates and notices are left out.
"""

import argparse
import json
import re
from pathlib import Path

from .cli import api_date
from .sources import Record
from .store import load_snapshot

SCHEMA = "https://TODO/cle.v1.0.0.json"     # the URI ECMA-428 1st edition (Dec 2025) uses in its own example
PURLS = {"Linux kernel LTS": "pkg:generic/linux", "Zephyr": "pkg:github/zephyrproject-rtos/zephyr",
         "Yocto Project": "pkg:generic/poky", "Mbed TLS": "pkg:github/mbed-tls/mbedtls",
         "OpenSSL": "pkg:generic/openssl", "Python": "pkg:generic/python", "Node.js": "pkg:generic/node",
         "containerd": "pkg:github/containerd/containerd", "Qt": "pkg:generic/qt",
         "Docker Engine": "pkg:github/moby/moby", "ESP-IDF": "pkg:github/espressif/esp-idf",
         "nRF Connect SDK": "pkg:github/nrfconnect/sdk-nrf", "OpenWrt": "pkg:generic/openwrt",
         "Mender Client": "pkg:github/mendersoftware/mender"}


def version_range(line: str) -> str | None:
    """'6.6' -> 'vers:generic/>=6.6|<6.7', '22 LTS' -> 'vers:generic/>=22|<23'; None if not numeric."""
    m = re.match(r"(\d+(?:\.\d+)*)", line)
    if not m:
        return None
    parts = m.group(1).split(".")
    upper = parts[:-1] + [str(int(parts[-1]) + 1)]
    return f"vers:generic/>={m.group(1)}|<{'.'.join(upper)}"


def stamp(day: str, end: bool = False) -> str:
    """'2027-12' -> '2027-12-31T00:00:00Z' (end of period for support ends), '2026-10-19' -> same day."""
    return f"{api_date(day, end=end)}T00:00:00Z"


def first_seen(component: str, line: str, history: list[dict], default: str) -> str:
    """Date supportdates first observed the line: its last 'added' event, else the component's baseline."""
    added = [e["date"] for e in history if e.get("component") == component and e.get("line") == line
             and e["change"] == "added"]
    return max(added) if added else default


def cle_document(component: str, records: list[Record], history: list[dict], baseline: str, updated: str) -> dict:
    """CLE document for one component from its current records and observed change history."""
    timeline = []                                   # (published date, sort key, event without id)
    source = next((r.source for r in records), "")
    for r in sorted(records, key=lambda x: x.line):
        rng = version_range(r.line)
        if r.kind != "official" or not r.eol or not rng:
            continue
        seen = first_seen(component, r.line, history, baseline)
        moves = sorted((e for e in history if e.get("component") == component and e.get("line") == r.line
                        and e["change"] == "eol changed" and e.get("old") and e.get("new")), key=lambda e: e["date"])
        first_eol = moves[0]["old"] if moves else r.eol
        if r.released:
            timeline.append((seen, 0, {"type": "released", "effective": stamp(r.released), "published": stamp(seen),
                                       "version": r.line.split()[0]}))
        timeline.append((seen, 1, {"type": "endOfSupport", "effective": stamp(first_eol, end=True),
                                   "published": stamp(seen), "versions": [{"range": rng}], "supportId": "published",
                                   "_line": r.line}))
        for m in moves:
            timeline.append((m["date"], 2, {"type": "withdrawn", "effective": stamp(m["date"]),
                                            "published": stamp(m["date"]), "_withdraws": r.line,
                                            "reason": f"source changed the published end from {m['old']} to "
                                                      f"{m['new']} (observed {m['date']})", "references": [source]}))
            timeline.append((m["date"], 3, {"type": "endOfSupport", "effective": stamp(m["new"], end=True),
                                            "published": stamp(m["date"]), "versions": [{"range": rng}],
                                            "supportId": "published", "_line": r.line}))
    events, last_eos = [], {}
    for i, (_, _, ev) in enumerate(sorted(timeline, key=lambda t: (t[0], t[1])), start=1):
        ev = dict(ev, id=i)
        line = ev.pop("_line", None)
        withdraws = ev.pop("_withdraws", None)
        if withdraws:
            ev["eventId"] = last_eos[withdraws]
        if line:
            last_eos[line] = i
        events.append(ev)
    return {"$schema": SCHEMA, "identifier": PURLS.get(component, f"pkg:generic/{slug(component)}"),
            "updatedAt": stamp(updated),
            "definitions": {"support": [{"id": "published", "url": source,
                                         "description": f"{component}: support end as published by the source; "
                                                        "observed and recorded by supportdates (third party)"}]},
            "events": sorted(events, key=lambda e: -e["id"])}


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="site/cle")
    args = ap.parse_args(argv)
    data, out = Path(args.data), Path(args.out)
    snaps = sorted((data / "snapshots").glob("*.json"))
    records = load_snapshot(snaps[-1])
    read = lambda f: [json.loads(x) for x in f.read_text().splitlines() if x.strip()] if f.exists() else []   # noqa: E731
    history, baselines = read(data / "changes.jsonl"), {}
    for f in sorted((data / "backfill").glob("*.jsonl")):     # archive baselines carry no component: use the file's
        events = read(f)
        base = min((e["date"] for e in events if e["change"] == "baseline"), default=None)
        for comp in {e["component"] for e in events if "component" in e} if base else ():
            baselines[comp] = min(base, baselines.get(comp, base))
        history += events
    for e in history:
        if e["change"] == "source added":
            baselines.setdefault(e["component"], e["date"])
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for component in sorted(PURLS):
        recs = [r for r in records if r.component == component]
        doc = cle_document(component, recs, history, baselines.get(component, snaps[0].stem), snaps[-1].stem)
        if doc["events"]:
            (out / f"{slug(component)}.json").write_text(json.dumps(doc, indent=1))
            written += 1
    print(f"{written} CLE documents -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
