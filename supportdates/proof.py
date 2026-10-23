"""Tamper-evident history: a daily proof manifest chained by hashes, optionally timestamped (RFC 3161).

    python -m supportdates.proof --data data                 (chain manifests for all snapshots, local only)
    python -m supportdates.proof --data data --tsq            (also write RFC 3161 requests via openssl)
    python -m supportdates.proof --data data --submit URL     (send requests to a timestamp authority: the operator's choice)

Each manifest (data/proofs/<day>.json) holds the snapshot's sha256, the per-source document hashes it recorded and
the sha256 of the previous day's manifest. Editing any past snapshot breaks every later link, so the history can be
shown not to have been rewritten after the fact. A timestamp token (.tsr) from an independent authority proves the
manifest existed on that day. Only hashes ever leave the machine.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(day: str, snapshot_sha: str, sources: dict[str, str], previous_sha: str | None) -> dict:
    """Pure: the proof manifest for one day."""
    return {"date": day, "snapshot_sha256": snapshot_sha, "sources": dict(sorted(sources.items())),
            "previous_manifest_sha256": previous_sha}


def manifest_bytes(m: dict) -> bytes:
    """Canonical encoding, so the same manifest always hashes the same."""
    return (json.dumps(m, sort_keys=True, separators=(",", ":")) + "\n").encode()


def verify_chain(manifests: list[dict], snapshot_shas: dict[str, str]) -> list[str]:
    """Problems found walking the chain in date order (empty list = intact)."""
    problems, previous = [], None
    for m in sorted(manifests, key=lambda x: x["date"]):
        if m["previous_manifest_sha256"] != previous:
            problems.append(f"{m['date']}: link to previous manifest broken")
        if snapshot_shas.get(m["date"]) not in (None, m["snapshot_sha256"]):
            problems.append(f"{m['date']}: snapshot changed after its manifest was written")
        previous = hashlib.sha256(manifest_bytes(m)).hexdigest()
    return problems


def build_chain(data: Path) -> list[Path]:
    """Write missing manifests for all snapshots, in order; existing manifests are never rewritten."""
    proofs = data / "proofs"
    proofs.mkdir(exist_ok=True)
    written, previous = [], None
    for snap in sorted((data / "snapshots").glob("*.json")):
        day = snap.stem
        path = proofs / f"{day}.json"
        if not path.exists():
            sources = json.loads(snap.read_text()).get("sources", {})
            path.write_bytes(manifest_bytes(manifest(day, sha256_file(snap), sources, previous)))
            written.append(path)
        previous = sha256_file(path)
    return written


def write_tsq(manifest_path: Path) -> Path:
    """RFC 3161 timestamp request for a manifest (openssl at the edge, like pdftotext)."""
    tsq = manifest_path.with_suffix(".tsq")
    subprocess.run(["openssl", "ts", "-query", "-data", str(manifest_path), "-sha256", "-cert", "-out", str(tsq)],
                   check=True, capture_output=True)
    return tsq


# two independent public roots, both verified against the system CA store (live test 2026-10-20)
DEFAULT_TSAS = ["http://timestamp.digicert.com", "http://timestamp.sectigo.com"]


def tsa_label(url: str) -> str:
    """'http://timestamp.digicert.com' -> 'digicert' (names the response file per authority)."""
    host = urllib.parse.urlparse(url).hostname or "tsa"
    parts = host.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def tsr_path(tsq: Path, url: str) -> Path:
    """'2026-10-20.tsq' -> '2026-10-20.digicert.tsr'."""
    return tsq.with_name(f"{tsq.stem}.{tsa_label(url)}.tsr")


def submit(tsq: Path, url: str) -> Path:
    """POST the request to a timestamp authority; store the signed response next to it. Only the hash leaves."""
    req = urllib.request.Request(url, data=tsq.read_bytes(), headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        tsr = tsr_path(tsq, url)
        tsr.write_bytes(resp.read())
    return tsr


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data")
    ap.add_argument("--tsq", action="store_true", help="write RFC 3161 requests for manifests without one")
    ap.add_argument("--submit", metavar="TSA_URL", action="append",
                    help="send pending requests to this timestamp authority (repeatable; 'default' = DigiCert + Sectigo)")
    ap.add_argument("--verify", action="store_true", help="check the hash chain against the snapshots")
    args = ap.parse_args(argv)
    data = Path(args.data)
    written = build_chain(data)
    print(f"{len(written)} new manifest(s) in {data / 'proofs'}")
    manifests = sorted((data / "proofs").glob("*.json"))
    if args.tsq or args.submit:
        for m in manifests:
            if not m.with_suffix(".tsq").exists():
                write_tsq(m)
    if args.submit:
        urls = [u for x in args.submit for u in (DEFAULT_TSAS if x == "default" else [x])]
        for url in urls:
            for tsq in sorted((data / "proofs").glob("*.tsq")):
                if not tsr_path(tsq, url).exists():
                    print("timestamped", submit(tsq, url))
                    time.sleep(15)          # be gentle: Sectigo asks for at least 15 s between requests
    if args.verify:
        shas = {p.stem: sha256_file(p) for p in (data / "snapshots").glob("*.json")}
        problems = verify_chain([json.loads(m.read_text()) for m in manifests], shas)
        print("chain intact" if not problems else "\n".join(problems))
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
