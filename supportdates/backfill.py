"""Backfill a source's history from the Internet Archive (Wayback Machine) snapshots.

Only for sources the archive has captured. Archive-derived history is kept apart from our own snapshots
(data/backfill/<source>.jsonl) and every event names the snapshot it came from, so provenance stays clear.
Note: anyone can do this backfill, so archived history is no moat; our own daily snapshots of pages the
archive rarely captures are.
"""

import json
from datetime import date

from .sources import Record
from .store import diff

CDX = "https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp,statuscode,digest&collapse=digest"
RAW = "https://web.archive.org/web/{ts}id_/{url}"


def snapshots(cdx_json: str) -> list[str]:
    """Timestamps of distinct (by content digest) HTTP-200 captures, oldest first."""
    rows = json.loads(cdx_json or "[]")[1:]
    return [ts for ts, status, _ in rows if status == "200"]


def ts_date(ts: str) -> str:
    return date(int(ts[:4]), int(ts[4:6]), int(ts[6:8])).isoformat()


def history_events(parsed: list[tuple[str, list[Record]]], url: str) -> list[dict]:
    """Changes between consecutive non-empty parsed snapshots; the first non-empty one is the baseline."""
    events, prev, prev_ts = [], None, None
    for ts, recs in parsed:
        if not recs:
            continue
        if prev is None:
            events.append({"date": ts_date(ts), "change": "baseline", "records": len(recs),
                           "snapshot": RAW.format(ts=ts, url=url)})
        else:
            changes = diff(prev, recs)
            # a page redesign turning derived into stated dates is a method change, not a vendor decision:
            # drop the kind change and the date changes that come with it
            switched = {c["line"] for c in changes if c["change"] == "kind changed"}
            for c in changes:
                if c["change"] == "kind changed" or (c["line"] in switched and c["change"].endswith("changed")):
                    continue
                events.append({"date": ts_date(ts), **c, "snapshot": RAW.format(ts=ts, url=url),
                               "previous": RAW.format(ts=prev_ts, url=url)})
        prev, prev_ts = recs, ts
    return events
