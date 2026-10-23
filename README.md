# supportdates

Published end-of-support and longevity dates of embedded software and platforms, **with sources and a dated history**.

Vendors publish support periods on web pages and PDFs: RTOS and SDK releases, kernel and Yocto series, crypto libraries, BSPs, SoM and chip longevity programmes. Those dates change, usually without notice. supportdates collects them once a day from the primary sources. For every value it keeps where it came from, when it was seen and how it changed.

- **Facts only:** each record is either **official** (stated by the source) or **derived** (computed from a policy the source publishes, e.g. "supported for 24 months after release"). It carries the source URL, a short evidence quote and the retrieval date.
- **History:** a daily snapshot plus a change log (added, removed, date moved, refined, renamed). Archive captures (Internet Archive) are used to backfill history where they exist.
- **Verifiable:** daily proof manifests chain the snapshot hash, the per-source document hashes and the previous manifest. They can be timestamped by RFC 3161 authorities; only hashes leave the machine.
- **Audited:** `supportdates.audit` re-fetches the sources of a random sample of records, or of history events, and checks that the name and date are really there.
- **Standard outputs:** an endoflife.date-compatible API, ECMA-428 Common Lifecycle Enumeration (CLE) documents, CycloneDX enrichment and an FDA SBOM support addendum (`eolcheck`).

Python 3.11+, **standard library only**. PDF sources need `pdftotext` (poppler) on the PATH.

## Covered sources (selection)
- **RTOS / SDKs:** Zephyr, nRF Connect SDK, ESP-IDF (+ Espressif advisories), FreeRTOS LTS.
- **OS / platform software:** Linux kernel LTS, Yocto Project, OpenWrt, Mender, Docker Engine, containerd, Qt, Python, Node.js.
- **Libraries:** Mbed TLS, OpenSSL.
- **Modules, BSPs and chip programmes:** NXP and Renesas product longevity, Nuvoton PLP, NVIDIA Jetson, Toradex (modules + BSP), Variscite, PHYTEC, SoMLabs, Critical Link, Raspberry Pi, Beckhoff IPCs.
- **Building automation / OT:** Johnson Controls end-of-support list, Ignition LTS, Tridium Niagara.

`supportdates/sources.py` has one small parser per source, each with tests.

## Use
```bash
python -m supportdates collect --data data              # fetch sources, write data/snapshots/<day>.json, log changes
python -m supportdates.proof --data data --verify       # extend and check the hash chain (add --submit default for RFC 3161)
python -m supportdates.audit --data data --n 30         # self-audit a random sample against the live sources
python -m supportdates site --data data --out site      # static site + endoflife-compatible API (site/api/)
python -m supportdates.cle --data data --out site/cle   # ECMA-428 CLE documents
python -m supportdates.eolcheck PATH...                 # dates for what a project builds on (west.yml, dependencies.lock,
                                                        # conf/layer.conf, modules.txt, CycloneDX/SPDX SBOMs)
python -m supportdates.mcp --data data                  # minimal MCP server for coding agents
make test                                               # 112 unit tests
```

## Data
The published dataset (current records, change history, API, CLE documents) is released under **CC BY 4.0** (see `LICENSE-DATA`): https://supportdates.com. Each record links its original source; quoted excerpts remain the sources' property.

Collection rules: public pages and documents only, once a day, an honest user agent, robots.txt respected. Only extracted facts, short quotes, links and hashes are stored; full documents are not redistributed.

## Contributing
New sources and corrections are welcome. See `CONTRIBUTING.md`. A wrong date is corrected visibly: the change log keeps the correction.

## Licences
- Code: **MIT** (`LICENSE`).
- Data: **CC BY 4.0** (`LICENSE-DATA`).
