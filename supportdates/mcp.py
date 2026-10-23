"""Minimal MCP server (stdio, newline-delimited JSON-RPC 2.0) so coding agents can look up sourced support dates.

    python -m supportdates.mcp [--data DATA_DIR]

Tools:
  support_dates(query)        published support/longevity dates matching a component or line name, with sources
  check_manifest(path)        eolcheck on a project directory or file (west.yml, dependencies.lock, layer.conf,
                              modules.txt, CycloneDX/SPDX SBOM)
Facts with sources only; private components are never served. Stdlib only.
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from .cli import public_only
from .eolcheck import report, scan
from .sources import Record
from .store import load_snapshot

PROTOCOL = "2025-06-18"
TOOLS = [
    {"name": "support_dates",
     "description": "Published end-of-support / longevity dates (with source URLs) for embedded components: SoMs, "
                    "SoC longevity programmes, NVIDIA Jetson, BSPs, Zephyr, nRF Connect SDK, ESP-IDF, Yocto, kernel LTS.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string",
                                                                "description": "e.g. 'Zephyr 3.7', 'Jetson Orin NX'"}},
                     "required": ["query"]}},
    {"name": "check_manifest",
     "description": "List published support dates for what a project builds on (west.yml, ESP-IDF dependencies.lock, "
                    "Yocto layer.conf, modules.txt, CycloneDX/SPDX SBOM).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
]


def lookup(query: str, records: list[Record], limit: int = 20) -> list[str]:
    """Records whose component + line contain every query word (case-insensitive)."""
    words = query.lower().split()
    hits = [r for r in records if all(w in f"{r.component} {r.line}".lower() for w in words)]
    return [f"{r.component} | {r.line} | end: {r.eol or 'not announced'} | {r.kind} | {r.source}" for r in hits[:limit]]


FACTS_ONLY = ("Facts as published by each source (linked); not an assessment of security, safety or compliance, "
              "and not a recommendation.")


def handle(msg: dict, records: list[Record], today: date, snapshot: str = "") -> dict | None:
    """Pure request handler: one JSON-RPC message in, one response out (None for notifications)."""
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None                                   # notifications (e.g. notifications/initialized)
    if method == "initialize":
        result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "supportdates", "version": "0.1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name, args = msg["params"].get("name"), msg["params"].get("arguments", {})
        if name == "support_dates":
            lines = lookup(args.get("query", ""), records) or ["no published date in the dataset for that query"]
        elif name == "check_manifest":
            lines, _ = report(scan([Path(args.get("path", "."))]), records, today)
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
        footer = FACTS_ONLY + (f" Dataset snapshot: {snapshot}." if snapshot else "")
        result = {"content": [{"type": "text", "text": "\n".join(lines or ["nothing recognised"]) + "\n" + footer}]}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "data"))
    args = ap.parse_args(argv)
    snap = sorted((Path(args.data) / "snapshots").glob("*.json"))[-1]
    records = public_only(load_snapshot(snap))
    for line in sys.stdin:
        if line.strip():
            response = handle(json.loads(line), records, date.today(), snap.stem)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
