"""eolcheck: list the published support dates of what an embedded project builds on (facts with sources only).

    python -m supportdates.eolcheck [--data DATA_DIR] [--fail-within MONTHS] [--format text|md] PATH...

PATH may be a project directory or a file. Recognised:
  west.yml               Zephyr revision of the `zephyr` project (e.g. v3.7.0 -> Zephyr 3.7 LTS) and the
                         nRF Connect SDK revision of the `nrf` project (e.g. v3.4.0 -> nRF Connect SDK 3.4 LTS)
  dependencies.lock      ESP-IDF version (idf: version: 5.2.1 -> ESP-IDF 5.2)
  conf/layer.conf        Yocto series from LAYERSERIES_COMPAT_* (e.g. scarthgap -> Yocto Project 5.0 Scarthgap)
  modules.txt            one module/board name per line (e.g. DART-MX8M-PLUS, Compute Module 4)
  *bom*.json, *.spdx.json, *.cdx.json
                         CycloneDX or SPDX SBOM: Linux kernel, Zephyr, ESP-IDF, Mbed TLS, OpenSSL, Python,
                         nRF Connect SDK, Yocto/poky, OpenWrt and FreeRTOS kernel components
    python -m supportdates.eolcheck --fda-addendum SBOM.json > addendum.csv
                         one CSV row per SBOM component with the two support fields FDA's premarket cybersecurity
                         guidance (2026-02-03) asks for: level of support and end-of-support date, each with the
                         published source and the dataset snapshot. Components the dataset doesn't cover say so.
Output: one line per finding with the published end-of-support date, its kind and source. --fail-within N exits
with code 2 if any listed date is within N months of today (a threshold the user chooses; no assessment).
YAML is read with small regexes on purpose (stdlib only): only the fields above are needed.
"""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .policies import POLICIES, Policy, basis
from .sources import Record
from .store import load_snapshot


@dataclass(frozen=True)
class Finding:
    file: str
    what: str               # human-readable thing found, e.g. "Zephyr v3.7.0"
    component: str
    line_hint: str          # release line or module name to look up


def project_revision(text: str, names: set[str]) -> str | None:
    """Revision of the first west project whose name is in `names` ('v3.7.0', 'main', a sha), or None if absent."""
    for block in re.split(r"\n\s*-\s+name:\s*", "\n" + text)[1:]:
        name = block.split("\n", 1)[0].strip().strip("'\"")
        if name in names:
            m = re.search(r"^\s*revision:\s*['\"]?([\w.\-/]+)", block, re.M)
            return m.group(1) if m else "main"      # west default revision
    return None


def zephyr_from_west(text: str) -> str | None:
    return project_revision(text, {"zephyr"})


def release_line(rev: str) -> str | None:
    """'v3.7.0' -> '3.7'; branches and shas (main, v3.7-branch is a branch -> '3.7') -> line or None."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)(?:[.\-][\w.\-]*)?", rev)
    return f"{m.group(1)}.{m.group(2)}" if m else None


def idf_from_lock(text: str) -> str | None:
    """ESP-IDF version from a component-manager dependencies.lock ('5.2.1')."""
    m = re.search(r"^\s{2}idf:\s*\n((?:\s{4}.*\n?)+)", text, re.M)
    if not m:
        return None
    v = re.search(r"^\s{4}version:\s*['\"]?(\d+\.\d+(?:\.\d+)?)", m.group(1), re.M)
    return v.group(1) if v else None


def yocto_series(text: str) -> list[str]:
    """Release codenames from LAYERSERIES_COMPAT_<layer> = "scarthgap kirkstone"."""
    out = []
    for m in re.finditer(r'^LAYERSERIES_COMPAT_\S+\s*[:+?]*=\s*"([^"]*)"', text, re.M):
        out += [c.lower() for c in m.group(1).split()]
    return out


# SBOM component name (lowercase) -> dataset component; the release line is major.minor of the version
SBOM_NAMES = [(r"linux(-yocto|-imx.*|-kernel)?|kernel", "Linux kernel LTS"), (r"(lib)?mbed-?tls", "Mbed TLS"),
              (r"openssl|libssl\d*|libcrypto\d*|libopenssl\d*", "OpenSSL"), (r"python3?(-core)?|libpython3[\d.]*", "Python"),
              (r"node(js)?", "Node.js"), (r"containerd", "containerd"), (r"docker(-ce|-engine|-moby)?|moby(-engine)?", "Docker Engine"),
              (r"qt[56]?-?base|qt[56]?-?core|qtbase", "Qt"), (r"mender(-client)?", "Mender Client"),
              (r"zephyr", "Zephyr"), (r"esp-idf", "ESP-IDF"), (r"poky|yocto|openembedded-core", "Yocto Project"),
              (r"openwrt", "OpenWrt"), (r"nrf|sdk-nrf|nrf-connect-sdk|ncs", "nRF Connect SDK")]


def sbom_entries(text: str) -> list[dict]:
    """Components ({name, version, purl}) of a CycloneDX or SPDX JSON document; [] if it is neither."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    if doc.get("bomFormat") == "CycloneDX":
        out, stack = [], list(doc.get("components", []))
        while stack:                      # nested components (assemblies) included
            c = stack.pop(0)
            out.append({"name": c.get("name", ""), "version": c.get("version", ""), "purl": c.get("purl", "")})
            stack += c.get("components", [])
        return out
    if "spdxVersion" in doc:
        purl = lambda p: next((r.get("referenceLocator", "") for r in p.get("externalRefs", [])   # noqa: E731
                               if r.get("referenceType") == "purl"), "")
        return [{"name": p.get("name", ""), "version": p.get("versionInfo", ""), "purl": purl(p)}
                for p in doc.get("packages", [])]
    return []


def sbom_components(text: str) -> list[tuple[str, str]]:
    """(name, version) pairs from a CycloneDX or SPDX JSON document; [] if it is neither."""
    return [(e["name"], e["version"]) for e in sbom_entries(text)]


def sbom_finding(name: str, version: str, file: str) -> Finding | None:
    """A Finding for SBOM components the dataset covers; FreeRTOS libraries match their exact LTS line."""
    low, ver = name.lower(), version.lstrip("vV")
    if re.fullmatch(r"freertos[-_ ]?kernel", low) and ver:
        return Finding(file, f"{name} {version}", "", f"FreeRTOS Kernel {ver}")
    for pattern, component in SBOM_NAMES:
        if re.fullmatch(pattern, low):
            m = re.match(r"(\d+)\.(\d+)", ver)      # '6.6.52+git', '3.7.0-rc1' -> major.minor
            hint = f"{m.group(1)}.{m.group(2)}" if m else ""
            if component == "OpenSSL" and ver.startswith(("0.", "1.")):      # old scheme: '1.1.1w' is line 1.1.1
                hint = re.match(r"\d+\.\d+\.\d+", ver).group(0) if re.match(r"\d+\.\d+\.\d+", ver) else hint
            return Finding(file, f"{name} {version}".strip(), component, hint)
    return None


def scan(paths: list[Path]) -> list[Finding]:
    files = []
    for p in paths:
        files += sorted(p.rglob("*")) if p.is_dir() else [p]
    found = []
    for f in files:
        if not f.is_file():
            continue
        name = f.name
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if name == "west.yml":
            rev = zephyr_from_west(text)
            if rev:
                found.append(Finding(str(f), f"Zephyr {rev}", "Zephyr", release_line(rev) or ""))
            ncs = project_revision(text, {"nrf", "sdk-nrf"})    # nRF Connect SDK applications import Zephyr via nrf
            if ncs:
                found.append(Finding(str(f), f"nRF Connect SDK {ncs}", "nRF Connect SDK", release_line(ncs) or ""))
        elif name == "dependencies.lock":
            v = idf_from_lock(text)
            if v:
                found.append(Finding(str(f), f"ESP-IDF {v}", "ESP-IDF", ".".join(v.split(".")[:2])))
        elif name == "layer.conf":
            for code in yocto_series(text):
                found.append(Finding(str(f), f"Yocto series {code}", "Yocto Project", code))
        elif name.endswith(".json") and ("bom" in name.lower() or "spdx" in name.lower() or "cdx" in name.lower()):
            for comp, version in sbom_components(text):
                finding = sbom_finding(comp, version, str(f))
                if finding:
                    found.append(finding)
        elif name == "modules.txt":
            for module in (x.strip() for x in text.splitlines()):
                if module and not module.startswith("#"):
                    found.append(Finding(str(f), module, "", module))
    return found


def match(finding: Finding, records: list[Record]) -> list[Record]:
    """Records the finding refers to: same release line (Zephyr '3.7' also matches '3.7 LTS'), Yocto by codename,
    modules by line name in any component, ignoring case and spaces."""
    hint = finding.line_hint.lower()
    if finding.component == "Yocto Project":
        if hint[:1].isdigit():            # SBOM gives poky's version (5.0.12), layer.conf gives the codename
            return [r for r in records if r.component == "Yocto Project" and r.line.split()[0] == hint]
        return [r for r in records if r.component == "Yocto Project" and r.line.lower().endswith(" " + hint)]
    if finding.component:
        same = [r for r in records if r.component == finding.component]
        hits = [r for r in same if r.line.split()[0] == finding.line_hint]
        major = finding.line_hint.split(".")[0]          # lines named by major only: Node.js '22', Docker '29'
        return hits or [r for r in same if r.line.split()[0] == major]
    squash = lambda x: re.sub(r"\s+", "", x.lower())   # noqa: E731  'STP 50-41' == 'STP50-41'
    return [r for r in records if squash(r.line) == squash(hint) and r.kind != "notice"]


def months_until(eol: str, today: date) -> int | None:
    """Whole months from today to the published date (YYYY, YYYY-MM or YYYY-MM-DD; year-only = end of year)."""
    m = re.fullmatch(r"(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", eol or "")
    if not m:
        return None
    y, mo = int(m.group(1)), int(m.group(2) or 12)
    return (y - today.year) * 12 + (mo - today.month)


@dataclass(frozen=True)
class Row:
    finding: Finding
    record: Record | None
    months: int | None
    note: str               # why there is no record ("not a release", "no published date"), else ""


def resolve(findings: list[Finding], records: list[Record], today: date) -> list[Row]:
    """One row per (finding, matching record); findings without a record keep a note instead."""
    rows = []
    for f in findings:
        if f.component and not f.line_hint:
            rows.append(Row(f, None, None, "not a release (branch or commit): no published support period applies"))
            continue
        hits = match(f, records)
        if not hits:
            rows.append(Row(f, None, None, "no published date in the dataset"))
        rows += [Row(f, r, months_until(r.eol, today), "") for r in hits]
    return rows


def report(findings: list[Finding], records: list[Record], today: date) -> tuple[list[str], list[int]]:
    lines, months = [], []
    for row in resolve(findings, records, today):
        f, r, mu = row.finding, row.record, row.months
        if r is None:
            lines.append(f"{f.what:32s} {row.note}" + (f" ({f.file})" if row.note.startswith("no published") else ""))
            continue
        if mu is not None:
            months.append(mu)
        if r.kind == "notice":
            lines.append(f"{f.what:32s} notice: {r.evidence} {r.source}")
            continue
        when = f"{r.eol} ({mu:+d} months)" if mu is not None else (r.eol or "not announced")
        lines.append(f"{f.what:32s} {r.component} {r.line}: end of support {when} [{r.kind}] {r.source}")
    return lines, months


def newer_lines(rows: list[Row], records: list[Record], today: date) -> list[Record]:
    """Release lines of the same software components (Yocto, Zephyr, ESP-IDF) whose published end date is later
    than the latest one the project uses. Modules are skipped: a newer SoM is a different product, not an upgrade."""
    latest: dict[str, int] = {}
    for row in rows:
        if row.record and row.months is not None and row.finding.component:
            latest[row.record.component] = max(latest.get(row.record.component, row.months), row.months)
    newer = [r for r in records if r.component in latest and r.kind != "notice"
             and (months_until(r.eol, today) or -10**6) > latest[r.component]]
    return sorted(newer, key=lambda r: (r.component, r.eol))


def markdown_report(findings: list[Finding], records: list[Record], today: date, snapshot: str) -> str:
    """Assessment skeleton: sourced facts first, then empty sections for the engineer's notes."""
    out = [f"# Support-date facts for this project ({today.isoformat()})", "",
           f"Dataset snapshot {snapshot}. Dates are as published by each source; this report makes no statement "
           "about security, safety or compliance.", "",
           "| Found | In file | Published line | End of support | Months from today | Kind | Source |",
           "|---|---|---|---|---|---|---|"]
    rows = resolve(findings, records, today)
    root = os.path.commonpath([os.path.dirname(os.path.abspath(f.file)) for f in findings]) if findings else ""
    rel = lambda path: os.path.relpath(os.path.abspath(path), root) if root else path   # noqa: E731
    for row in sorted(rows, key=lambda x: (x.months is None, x.months if x.months is not None else 0)):
        f, r = row.finding, row.record
        if r is None:
            out.append(f"| {f.what} | {rel(f.file)} | — | — | — | — | {row.note} |")
        else:
            mu = f"{row.months:+d}" if row.months is not None else "—"
            end = "notice (no date)" if r.kind == "notice" else (r.eol or "not announced")
            out.append(f"| {f.what} | {rel(f.file)} | {r.component} {r.line} | {end} | {mu} "
                       f"| {r.kind} | [source]({r.source}) |")
    out += ["", "## Newer published lines from the same sources", ""]
    out += [f"- {r.component} {r.line}: end of support {r.eol} ([source]({r.source}))"
            for r in newer_lines(rows, records, today)] or ["- none in the dataset"]
    out += ["", "## Blocking layers and recipes", "", "_Engineer's notes._", "",
            "## Migration steps and known pitfalls", "", "_Engineer's notes._", ""]
    return "\n".join(out)


def enrich_cyclonedx(doc: dict, records: list[Record], snapshot: str) -> dict:
    """Copy of a CycloneDX document with supportdates facts added as component properties
    (supportdates:eol, :kind, :source, :snapshot). Facts only; components we don't cover are left untouched."""
    out = json.loads(json.dumps(doc))
    stack = list(out.get("components", []))
    while stack:
        comp = stack.pop(0)
        stack += comp.get("components", [])
        finding = sbom_finding(comp.get("name", ""), comp.get("version", ""), "sbom")
        hits = [r for r in match(finding, records) if r.kind != "notice"] if finding and finding.line_hint else []
        if hits:
            r = hits[0]
            props = [p for p in comp.get("properties", []) if not p.get("name", "").startswith("supportdates:")]
            comp["properties"] = props + [{"name": "supportdates:eol", "value": r.eol or "not announced"},
                                          {"name": "supportdates:line", "value": f"{r.component} {r.line}"},
                                          {"name": "supportdates:kind", "value": r.kind},
                                          {"name": "supportdates:source", "value": r.source},
                                          {"name": "supportdates:snapshot", "value": snapshot}]
    return out


FDA_COLUMNS = ("component", "version", "purl", "level_of_support", "end_of_support", "basis", "source",
               "dataset_snapshot")


def support_level(record: Record | None, today: date) -> str:
    """FDA's vocabulary ('actively maintained', 'no longer maintained') from the published end date alone;
    'unknown' when there is no record or no announced end. The manufacturer makes the determination."""
    months = months_until(record.eol, today) if record else None
    if months is None:
        return "unknown"
    return "no longer maintained" if months < 0 else "actively maintained"


def fda_addendum(entries: list[dict], records: list[Record], today: date, snapshot: str,
                 policies: list[Policy] = POLICIES) -> list[dict]:
    """One row per SBOM component with the published support facts behind FDA's two fields, or the reason
    there are none (a checked support rule or 'no policy found' entry if we have one). Several matching
    records (e.g. two lines of one release): the latest published end wins."""
    rows = []
    for e in entries:
        row = dict.fromkeys(FDA_COLUMNS, "") | {"component": e["name"], "version": e["version"], "purl": e["purl"],
                                                 "level_of_support": "unknown", "dataset_snapshot": snapshot}
        finding = sbom_finding(e["name"], e["version"], "sbom")
        found = match(finding, records) if finding and finding.line_hint else []
        hits = [r for r in found if r.kind != "notice"]
        ended = next((r for r in found if r.kind == "notice" and "no longer supported" in r.line), None)
        policy = next((p for p in policies if re.fullmatch(p.pattern, e["name"].lower())), None)
        if finding is None and policy:
            row |= {"basis": basis(policy), "source": policy.urls[0]}
        elif finding is None:
            row["basis"] = "not covered by the dataset"
        elif not hits and ended:
            row |= {"level_of_support": "no longer maintained", "end_of_support": ended.eol or "passed (date not stated)",
                    "basis": f"{ended.component}: '{ended.evidence}'", "source": ended.source}
        elif not finding.line_hint:
            row["basis"] = "not a release (branch or commit): no published support period applies"
        elif not hits:
            row["basis"] = "no published date in the dataset"
        else:
            r = max(hits, key=lambda x: x.eol or "")
            rule = "; computed from the source's stated rule" if r.kind == "derived" else ""
            row |= {"level_of_support": support_level(r, today), "end_of_support": r.eol or "not announced",
                    "basis": f"{r.component} {r.line}: end of support {r.eol or 'not announced'} as published{rule}",
                    "source": r.source}
        rows.append(row)
    return rows


def addendum_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FDA_COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "data"))
    ap.add_argument("--fail-within", type=int, default=None, metavar="MONTHS")
    ap.add_argument("--format", choices=("text", "md"), default="text", help="md: assessment skeleton in Markdown")
    ap.add_argument("--enrich", metavar="CYCLONEDX_JSON", help="print the SBOM with supportdates:* properties added")
    ap.add_argument("--fda-addendum", metavar="SBOM_JSON",
                    help="CSV: level of support and end-of-support date per SBOM component, with sources")
    args = ap.parse_args(argv)
    snap = sorted((Path(args.data) / "snapshots").glob("*.json"))
    if not snap:
        print("no dataset snapshot found; run `python -m supportdates collect` or pass --data", file=sys.stderr)
        return 1
    if args.fda_addendum:
        snapshot = f"{snap[-1].stem} sha256:{hashlib.sha256(snap[-1].read_bytes()).hexdigest()[:16]}"
        rows = fda_addendum(sbom_entries(Path(args.fda_addendum).read_text()), load_snapshot(snap[-1]),
                            date.today(), snapshot)
        sys.stdout.write(addendum_csv(rows))
        dated = sum(1 for r in rows if r["level_of_support"] != "unknown")
        explained = sum(1 for r in rows if r["level_of_support"] == "unknown" and r["source"])
        print(f"{dated} of {len(rows)} components with a published date or end, {explained} with a checked support "
              "rule or 'no policy found' note; the manufacturer determines the level of support", file=sys.stderr)
        return 0
    if args.enrich:
        doc = json.loads(Path(args.enrich).read_text())
        print(json.dumps(enrich_cyclonedx(doc, load_snapshot(snap[-1]), snap[-1].stem), indent=1))
        return 0
    findings, records = scan([Path(p) for p in args.paths]), load_snapshot(snap[-1])
    if args.format == "md":
        print(markdown_report(findings, records, date.today(), snap[-1].stem))
        return 0
    lines, months = report(findings, records, date.today())
    print(f"dataset snapshot {snap[-1].stem}")
    print("\n".join(lines) or "nothing recognised (west.yml, dependencies.lock, conf/layer.conf, modules.txt)")
    if args.fail_within is not None and any(m <= args.fail_within for m in months):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
