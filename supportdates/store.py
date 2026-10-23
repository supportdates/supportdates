"""Snapshots and change detection (pure diff + thin file I/O).

data/snapshots/<YYYY-MM-DD>.json holds every record collected that day plus a sha256 per raw source document.
The change log is what makes the dataset valuable over time: announced dates move (e.g. LTS extensions), and
only someone who snapshotted before the change can show it.
"""

import fnmatch
import json
from dataclasses import asdict
from pathlib import Path

from .sources import Record


def key(r: Record) -> tuple[str, str]:
    return (r.component, r.line)


def diff(old: list[Record], new: list[Record]) -> list[dict]:
    """Added lines, removed lines, and changed release/EOL dates."""
    a, b = {key(r): r for r in old}, {key(r): r for r in new}
    changes = []
    for k in sorted(b.keys() - a.keys()):
        changes.append({"change": "added", "component": k[0], "line": k[1], "eol": b[k].eol, "kind": b[k].kind})
    # a list that switches from part numbers to a wildcard ('ISL28130' -> 'ISL*') still covers the part
    wildcards = [k for k in b if "*" in k[1]]
    for k in sorted(a.keys() - b.keys()):
        cover = next((w[1] for w in wildcards if w[0] == k[0] and fnmatch.fnmatchcase(k[1], w[1])), None)
        if cover:
            changes.append({"change": "listed under wildcard", "component": k[0], "line": k[1], "new": cover})
            continue
        # 'LX2080A' -> 'LX2080A, LX2082A': the part is still listed, now in a combined cell
        merged = next((n for n in b.keys() - a.keys() if n[0] == k[0] and n[1] != k[1]
                       and k[1] in [x.strip() for x in n[1].split(",")]), None)
        # 'Node.js 27' -> '27 LTS' with the same dates: a suffix (status) added to the same line, not a new line
        suffixed = [n for n in b.keys() - a.keys() if n[0] == k[0] and n[1].startswith(k[1] + " ")
                    and (b[n].released, b[n].eol) == (a[k].released, a[k].eol)]
        merged = merged or (suffixed[0] if len(suffixed) == 1 else None)
        if merged:
            changes = [c for c in changes if not (c["change"] == "added" and (c["component"], c["line"]) == merged)]
            changes.append({"change": "renamed", "component": k[0], "line": merged[1], "old": k[1], "new": merged[1]})
            continue
        changes.append({"change": "removed", "component": k[0], "line": k[1], "eol": a[k].eol, "kind": a[k].kind})
    for k in sorted(a.keys() & b.keys()):
        for field in ("released", "eol", "kind"):
            x, y = getattr(a[k], field), getattr(b[k], field)
            if x != y:
                # '2033' -> '2033-06' only adds precision within the same period: not a moved date
                refined = field != "kind" and x and y and (y.startswith(x + "-") or x.startswith(y + "-"))
                changes.append({"change": f"{field} {'refined' if refined else 'changed'}", "component": k[0], "line": k[1],
                                "old": getattr(a[k], field), "new": getattr(b[k], field), "kind": b[k].kind,
                                "old_kind": a[k].kind})
    return changes


def document_changes(old_hashes: dict[str, str], new_hashes: dict[str, str]) -> list[dict]:
    """Raw source documents whose content hash changed between snapshots (revision watch: a vendor replaced a
    page or PDF, even if no parsed date changed). New and vanished documents are reported too."""
    out = []
    for name in sorted(set(old_hashes) | set(new_hashes)):
        if name == "carried_over_from":
            continue
        a, b = old_hashes.get(name), new_hashes.get(name)
        if a != b:
            kind = "document added" if a is None else "document removed" if b is None else "document changed"
            out.append({"change": kind, "component": "source", "line": name, "old": (a or "")[:12], "new": (b or "")[:12]})
    return out


def load_hashes(path: Path) -> dict[str, str]:
    return json.loads(path.read_text()).get("sources", {})


def save_snapshot(directory: Path, day: str, records: list[Record], hashes: dict[str, str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{day}.json"
    path.write_text(json.dumps({"date": day, "sources": hashes, "records": [asdict(r) for r in records]}, indent=1))
    return path


def load_snapshot(path: Path) -> list[Record]:
    return [Record(**r) for r in json.loads(path.read_text())["records"]]


def previous_snapshot(directory: Path, day: str) -> Path | None:
    older = sorted(p for p in directory.glob("*.json") if p.stem < day)
    return older[-1] if older else None


def collapse_new_sources(changes: list[dict], old_components: set[str]) -> list[dict]:
    """A component that did not exist in the previous snapshot is a newly added source, not hundreds of vendor
    changes: replace its 'added' events by one 'source added' event (keeps the public change log meaningful)."""
    new = {c["component"] for c in changes if c["change"] == "added" and c["component"] not in old_components}
    kept = [c for c in changes if not (c["change"] == "added" and c["component"] in new)]
    counts = {comp: sum(1 for c in changes if c["change"] == "added" and c["component"] == comp) for comp in new}
    return kept + [{"change": "source added", "component": comp, "line": f"{n} records"}
                   for comp, n in sorted(counts.items())]

