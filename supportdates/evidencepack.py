"""evidencepack: the support-period evidence pack for one product (facts with sources, dated history and proofs).

    python -m supportdates.evidencepack PRODUCT.json --sbom SBOM_OR_DIR [--data DATA_DIR] --out DIR

PRODUCT.json: {"product", "placed_on_market": "YYYY-MM", "declared_support_end": "YYYY-MM" (the manufacturer's
candidate), "platform": [{"what", "component", "line"}] (dataset lines named exactly, e.g. "Toradex BSP" / "BSP 7"),
"manual": [{"what", "component", "line", "eol", "scope", "source", "evidence", "checked"}] (checked by hand),
"later_manual": [{"component", "line", "eol", "source", "evidence", "checked"}] (later options checked by hand),
"notes": ["..."] (the engineer's reading of the facts)}.
SBOM_OR_DIR: a CycloneDX/SPDX file, or a directory of SPDX documents. Yocto (create-spdx): one component per recipe
that has a package installed in the image; recipe-* documents alone would also list recipes that are only built.
Writes DIR/evidence-pack.md, DIR/components.csv (every SBOM component, FDA addendum columns) and DIR/proof/
(the dataset snapshot, its proof manifest and the RFC 3161 tokens, so every value can be checked offline).
Facts only: the manufacturer determines the support period (CRA Art. 13(8)); this pack does not.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .eolcheck import addendum_csv, fda_addendum, match, months_until, sbom_entries, sbom_finding
from .sources import Record
from .store import load_snapshot

BUILD_HOST = re.compile(r".*-native|.*-cross(-.*)?|cross-.*|packagegroup-.*|.*-initial")   # not shipped in the image


@dataclass(frozen=True)
class Fact:
    what: str               # what the product contains, e.g. "linux-toradex-ti 6.6.157+git"
    component: str
    line: str
    eol: str
    kind: str               # official | derived | as checked by hand
    scope: str              # what the date covers: software support, hardware availability, ...
    source: str
    evidence: str
    origin: str             # "dataset 2026-10-29" or "checked by hand 2026-10-29"


def shipped_entries(docs: list[str]) -> list[dict]:
    """SBOM components without build-host tools, deduplicated by (name, version)."""
    seen, out = set(), []
    for text in docs:
        for e in sbom_entries(text):
            k = (e["name"], e["version"])
            if k not in seen and not BUILD_HOST.fullmatch(e["name"]):
                seen.add(k)
                out.append(e)
    return out


def installed_recipes(docs: list[str]) -> list[dict]:
    """Yocto per-package SPDX documents -> one entry per recipe that has a package in the image (GENERATED_FROM
    link), with the version of its packages and how many there are. Documents without that link are skipped."""
    recipes: dict[str, dict] = {}
    for text in docs:
        doc = json.loads(text)
        rel = next((r["relatedSpdxElement"] for r in doc.get("relationships", [])
                    if r.get("relationshipType") == "GENERATED_FROM"), "")
        m = re.match(r"DocumentRef-recipe-([^:]+):", rel)
        if not m or not doc.get("packages"):
            continue
        entry = recipes.setdefault(m.group(1), {"name": m.group(1), "version": doc["packages"][0].get("versionInfo", ""),
                                               "purl": "", "packages": 0})
        entry["packages"] += 1
    return sorted(recipes.values(), key=lambda e: e["name"])


def dataset_facts(product: dict, entries: list[dict], records: list[Record], snapshot_day: str) -> list[Fact]:
    """Facts for the named platform lines (exact match) and for SBOM components the dataset covers."""
    found: dict[tuple[str, str], tuple[list[str], Record]] = {}
    for p in product.get("platform", []):
        for r in records:
            if r.component == p["component"] and r.line == p["line"] and r.kind != "notice":
                found.setdefault((r.component, r.line), ([], r))[0].append(p["what"])
    for e in entries:
        finding = sbom_finding(e["name"], e["version"], "sbom")
        if not finding or not finding.line_hint:
            continue
        for r in match(finding, records):
            if r.kind != "notice":
                n = e.get("packages", 0)
                what = f"{e['name']} {e['version']}" + (f" ({n} packages)" if n > 1 else "")
                found.setdefault((r.component, r.line), ([], r))[0].append(what)
    scope = "software support (as published)"
    return [Fact(", ".join(dict.fromkeys(whats)), r.component, r.line, r.eol, r.kind, scope, r.source, r.evidence,
                 f"dataset {snapshot_day}") for whats, r in found.values()]


def manual_facts(product: dict) -> list[Fact]:
    return [Fact(m["what"], m["component"], m["line"], m.get("eol", ""), "as checked by hand", m["scope"],
                 m["source"], m["evidence"], f"checked by hand {m['checked']}") for m in product.get("manual", [])]


def months_to(eol: str, end: str) -> int | None:
    """Months from the declared end (YYYY-MM) to a published end; negative = ends before it."""
    y, m = map(int, end.split("-")[:2])
    return months_until(eol, date(y, m, 1))


def name(fact: Fact) -> str:
    """'Toradex BSP' + 'BSP 7' -> 'Toradex BSP 7' (no repeated word)."""
    first, _, rest = fact.line.partition(" ")
    return f"{fact.component} {rest}" if fact.component.endswith(" " + first) and rest else f"{fact.component} {fact.line}"


def coverage(fact: Fact, end: str) -> str:
    months = months_to(fact.eol, end)
    if months is None:
        return "no end date published"
    return f"**ends {-months} months before**" if months < 0 else f"covers (+{months} months)"


def same_line(event: dict, fact: Fact) -> bool:
    line = event.get("line", "")
    return event.get("component") == fact.component and (line == fact.line or line.startswith(fact.line + " "))


def history(fact: Fact, events: list[dict]) -> list[dict]:
    """Dated changes of this line (and its state notices), oldest first."""
    return sorted((e for e in events if same_line(e, fact) and e.get("change") != "source added"),
                  key=lambda e: e["date"])


def tracked_since(fact: Fact, events: list[dict], first_seen: dict[tuple[str, str], str]) -> str:
    """'archive since 2013-05-07, daily since 2026-10-16' (whichever applies)."""
    base = [e["date"] for e in events if e.get("change") == "baseline" and e.get("snapshot", "").endswith(fact.source)]
    parts = [f"archive from {min(base)}"] if base else []
    if (fact.component, fact.line) in first_seen:
        parts.append(f"own daily snapshots from {first_seen[(fact.component, fact.line)]}")
    return ", ".join(parts) or "checked once (no history kept yet)"


def describe(event: dict) -> str:
    change = event["change"]
    if change.endswith(("changed", "refined")):
        text = f"{change}: {event.get('old') or '—'} → {event.get('new') or '—'}"
    elif change == "renamed":
        text = f"renamed from '{event.get('old')}'"
    else:
        text = change + (f" (end {event['eol']})" if event.get("eol") else "")
    if not event.get("snapshot"):
        return f"{event['date']}: {event['line']}: {text} (own daily snapshot)"
    prev = re.search(r"/web/(\d{8})", event.get("previous", ""))
    window = (f"between {prev.group(1)[:4]}-{prev.group(1)[4:6]}-{prev.group(1)[6:]} ([before]({event['previous']})) "
              f"and {event['date']}" if prev else f"first archive copy {event['date']}")
    return f"{window} ([after]({event['snapshot']})): {event['line']}: {text}"


def later_lines(facts: list[Fact], records: list[Record]) -> list[Record]:
    """Published lines of the same dataset components that end later than the line the product uses."""
    used = {f.component: f.eol for f in facts if f.origin.startswith("dataset")}
    return sorted((r for r in records if r.component in used and r.kind != "notice" and r.eol
                   and (months_until(r.eol, date(2000, 1, 1)) or 0) > (months_until(used[r.component], date(2000, 1, 1)) or 0)),
                  key=lambda r: (r.component, r.eol))


def render(product: dict, facts: list[Fact], events: list[dict], first_seen: dict, csv_rows: list[dict],
           later: list[Record], proof: dict, today: date) -> str:
    end = product["declared_support_end"]
    dated = sorted((f for f in facts if f.eol), key=lambda f: months_to(f.eol, end))
    software = [f for f in dated if f.scope.startswith("software")]
    limit = software[0] if software else None
    out = [f"# Support-period evidence pack: {product['product']}", "",
           f"Prepared {today.isoformat()} · dataset snapshot {proof['day']} (sha256 `{proof['snapshot_sha256'][:16]}…`)", "",
           "> Facts with sources, as published by each vendor or project, with their dated history. The manufacturer "
           "determines the support period (CRA Art. 13(8)) and states its end at purchase (Art. 13(19)); this pack "
           "does not make that determination and is not legal advice.", "",
           "## 1. Result", "",
           f"- **Placed on the market (planned):** {product['placed_on_market']}. **Support end the manufacturer is "
           f"considering:** {end}."]
    if limit:
        months = months_to(limit.eol, end)
        verdict = (f"ends **{-months} months before** {end}" if months < 0 else f"covers {end} (+{months} months)")
        out.append(f"- **Shortest published software support:** {name(limit)}, end {limit.eol}: "
                   f"{verdict}.")
    short = [f for f in software if months_to(f.eol, end) < 0]
    if short:
        out.append(f"- **{len(short)} of {len(software)} dated software lines end before {end}:** "
                   + "; ".join(f"{name(f)} ({f.eol})" for f in short) + ". Declaring " + end +
                   " needs a documented plan for each: a move to a later line (section 4), a paid extended-support "
                   "offer, or own maintenance of that component.")
    undated = sum(1 for r in csv_rows if r["level_of_support"] == "unknown")
    out += [f"- **SBOM:** {len(csv_rows)} shipped components (Yocto: recipes with a package in the image); {len(csv_rows) - undated} with a published date or end, "
            f"{undated} without one (one row each, with the reason, in `components.csv`).", "",
            "## 2. Published support ends, shortest first", "",
            "| In the product | Published line | End | Against " + end + " | What the date covers | Kind | Source |",
            "|---|---|---|---|---|---|---|"]
    for f in dated + [f for f in facts if not f.eol]:
        out.append(f"| {f.what} | {name(f)} | {f.eol or 'not announced'} | {coverage(f, end)} | "
                   f"{f.scope} | {f.kind} | [source]({f.source}) |")
    out += ["", "Evidence as published (quoted from the source on the date shown):", ""]
    out += [f"- **{name(f)}** ({f.origin}): \"{f.evidence}\"" for f in dated + [f for f in facts if not f.eol]]
    out += ["", "## 3. Dated history of each line", "",
            "Changes since tracking started. \"No change\" is itself evidence: the date has been stable over that "
            "window.", ""]
    for f in dated + [f for f in facts if not f.eol]:
        changes = history(f, events)
        out.append(f"- **{name(f)}** (tracked: {tracked_since(f, events, first_seen)})")
        out += [f"  - {describe(e)}" for e in changes] or ["  - no change recorded"]
    out += ["", "## 4. Later published lines of the same components", "",
            "| Component | Line | Published end | Source |", "|---|---|---|---|"]
    out += [f"| {r.component} | {r.line} | {r.eol} | [source]({r.source}) |" for r in later]
    out += [f"| {m['component']} | {m['line']} | {m['eol']} | [source]({m['source']}) (checked by hand {m['checked']}: "
            f"\"{m['evidence']}\") |" for m in product.get("later_manual", [])]
    if product.get("notes"):
        out += ["", "## 5. Reading notes (engineer's notes, not vendor statements)", ""]
        out += [f"- {n}" for n in product["notes"]]
    out += ["", f"## {6 if product.get('notes') else 5}. Proof that these values were published on these dates", "",
            f"- `proof/{proof['snapshot_name']}`: the full dataset snapshot of {proof['day']}, "
            f"sha256 `{proof['snapshot_sha256']}`.",
            f"- `proof/{proof['manifest_name']}`: the proof manifest. It contains that snapshot hash and the hash "
            f"of the previous day's manifest, so the daily chain back to 2026-10-16 can't be rewritten unnoticed.",
            *[f"- `proof/{name}`: RFC 3161 timestamp token from {tsa}, time {when}." for name, tsa, when in proof["tokens"]],
            "", "Check it yourself (OpenSSL, no account, offline):", "", "```bash",
            f"sha256sum proof/{proof['snapshot_name']}",
            f"grep -o '\"snapshot_sha256\":\"[0-9a-f]*\"' proof/{proof['manifest_name']}",
            *[f"openssl ts -verify -in proof/{name} -data proof/{proof['manifest_name']} "
              "-CAfile /etc/ssl/certs/ca-certificates.crt" for name, _, _ in proof["tokens"]],
            "```", "",
            "Values marked \"checked by hand\" are not in the dataset yet; they carry the date and URL of the check.",
            "Archive history links to the Internet Archive's copy of each page, so each change can be seen on both "
            "sides."]
    return "\n".join(out) + "\n"


def sbom_input(path: Path) -> list[dict]:
    """SBOM entries: a single SBOM file, or a Yocto SPDX directory reduced to the recipes installed in the image."""
    if path.is_file():
        return shipped_entries([path.read_text()])
    files = sorted(path.glob("*.json"))
    if any(f.name.startswith("recipe-") for f in files):
        return installed_recipes([f.read_text() for f in files if not f.name.startswith(("recipe-", "runtime-"))])
    return shipped_entries([f.read_text() for f in files])


def load_events(data: Path) -> list[dict]:
    events = []
    for f in [*sorted((data / "backfill").glob("*.jsonl")), data / "changes.jsonl"]:
        if f.exists():
            events += [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
    return events


def first_seen_days(snapshots: list[Path]) -> dict[tuple[str, str], str]:
    seen: dict[tuple[str, str], str] = {}
    for snap in snapshots:
        for r in load_snapshot(snap):
            seen.setdefault((r.component, r.line), snap.stem)
    return seen


def token_time(tsr: Path) -> str:
    out = subprocess.run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"], capture_output=True, text=True).stdout
    m = re.search(r"Time stamp: (.+)", out)
    return m.group(1).strip() if m else "unreadable"


def copy_proof(data: Path, snap: Path, out: Path) -> dict:
    proof_dir = out / "proof"
    proof_dir.mkdir(parents=True, exist_ok=True)
    manifest = data / "proofs" / f"{snap.stem}.json"
    for f in [snap, manifest, *sorted((data / "proofs").glob(f"{snap.stem}.*.tsr"))]:
        shutil.copy2(f, proof_dir / (f"snapshot-{f.name}" if f == snap else f.name))
    tokens = [(t.name, t.name.split(".")[1], token_time(t)) for t in sorted(proof_dir.glob("*.tsr"))]
    return {"day": snap.stem, "snapshot_name": f"snapshot-{snap.name}", "manifest_name": manifest.name, "tokens": tokens,
            "snapshot_sha256": hashlib.sha256(snap.read_bytes()).hexdigest()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("product")
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "data"))
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    data, out = Path(args.data), Path(args.out)
    snaps = sorted((data / "snapshots").glob("*.json"))
    snap = next((s for s in reversed(snaps) if (data / "proofs" / f"{s.stem}.json").exists()), None)
    if snap is None:
        print("no snapshot with a proof manifest found; pass --data", file=sys.stderr)
        return 1
    product = json.loads(Path(args.product).read_text())
    records, entries = load_snapshot(snap), sbom_input(Path(args.sbom))
    out.mkdir(parents=True, exist_ok=True)
    proof = copy_proof(data, snap, out)
    csv_rows = fda_addendum(entries, records, date.today(), f"{snap.stem} sha256:{proof['snapshot_sha256'][:16]}")
    (out / "components.csv").write_text(addendum_csv(csv_rows))
    facts = dataset_facts(product, entries, records, snap.stem) + manual_facts(product)
    text = render(product, facts, load_events(data), first_seen_days(snaps), csv_rows, later_lines(facts, records),
                  proof, date.today())
    (out / "evidence-pack.md").write_text(text)
    print(f"{out / 'evidence-pack.md'}: {len(facts)} dated lines, {len(csv_rows)} SBOM components", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
