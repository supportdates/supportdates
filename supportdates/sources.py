"""Primary sources of embedded support periods and their parsers (pure: text in, records out).

Every record is a sourced fact: component, release line, release date, end of support, whether the date is
stated by the project ("official") or computed from its published policy ("derived"), the source URL and a
short evidence quote. No assessments, no rankings.
"""

import calendar
import collections
import html
import json
import re
from dataclasses import dataclass

MONTHS = {m: i for i, m in enumerate(calendar.month_name) if m}


@dataclass(frozen=True)
class Record:
    component: str
    line: str
    released: str          # YYYY-MM-DD or YYYY-MM ("" if unknown)
    eol: str               # YYYY-MM-DD, YYYY-MM or YYYY ("" if not announced)
    kind: str              # official | derived | notice (vendor change/EOL notice; released = notice date)
    source: str
    evidence: str


def _month(text: str) -> str:
    """'March 2027' -> '2027-03'."""
    name, year = text.split()
    return f"{int(year):04d}-{MONTHS[name]:02d}"


MBEDTLS_URL = "https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/BRANCHES.md"


def parse_mbedtls(md: str) -> list[Record]:
    text = re.sub(r"\s+", " ", md)
    out = []
    for m in re.finditer(r"Mbed TLS (\d+\.\d+) LTS \(released in (\w+ \d{4})\) will be supported until (\w+ \d{4})", text):
        out.append(Record("Mbed TLS", m.group(1), _month(m.group(2)), _month(m.group(3)), "official",
                          MBEDTLS_URL, m.group(0)))
    for m in re.finditer(r"version (\d+\.\d+), was released [^,]*, in (\w+ \d{4}), and will be supported until (\w+ \d{4})", text):
        out.append(Record("Mbed TLS", m.group(1), _month(m.group(2)), _month(m.group(3)), "official",
                          MBEDTLS_URL, m.group(0)))
    return out


OPENSSL_URL = "https://openssl-library.org/policies/releasestrat/index.html"


def parse_openssl(page: str, source: str = OPENSSL_URL) -> list[Record]:
    """Release strategy page: 'Version 3.5 will be supported until 2030-04-08 (LTS)'; versions the page lists as
    'no longer supported' become notices (the page gives no end date for them)."""
    text = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))
    out = []
    for m in re.finditer(r"Version (\d+\.\d+(?:\.\d+)?) will be supported until (\d{4}-\d{2}-\d{2})( \(LTS\))?", text):
        out.append(Record("OpenSSL", m.group(1) + (" LTS" if m.group(3) else ""), "", m.group(2), "official", source,
                          m.group(0)))
    for m in re.finditer(r"Versions? ((?:\d+\.\d+(?:\.\d+)?(?:, | and )?)+) (?:is|are) no longer supported", text):
        for v in re.findall(r"\d+\.\d+(?:\.\d+)?", m.group(1)):
            out.append(Record("OpenSSL", f"{v} no longer supported", "", "", "notice", source, m.group(0)))
    return out


PYTHON_URL = "https://peps.python.org/api/release-cycle.json"


def parse_python(text: str, source: str = PYTHON_URL) -> list[Record]:
    """Python release-cycle JSON (the devguide's source): {'3.13': {status, first_release, end_of_life, pep}}.
    Lines still in 'feature' status are unreleased and skipped; end dates are the PEP schedule's."""
    out = []
    for line, v in json.loads(text).items():
        if v.get("status") == "feature" or not v.get("end_of_life"):
            continue
        out.append(Record("Python", line, v.get("first_release", ""), v["end_of_life"], "official", source,
                          f"Python {line}: status {v.get('status')}, end of life {v['end_of_life']} (PEP {v.get('pep')})"))
    return out


NODEJS_URL = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"


def parse_nodejs(text: str, source: str = NODEJS_URL) -> list[Record]:
    """Node.js release schedule JSON: {'v22': {start, lts, maintenance, end, codename}}. Odd lines included."""
    out = []
    for key, v in json.loads(text).items():
        m = re.fullmatch(r"v(\d+)", key)
        if not m or not v.get("end"):
            continue          # 'v0.10'-style keys are pre-io.js history; skipped
        lts = f", LTS from {v['lts']} ({v.get('codename', '')})" if v.get("lts") else ""
        out.append(Record("Node.js", m.group(1) + (" LTS" if v.get("lts") else ""), v.get("start", ""), v["end"],
                          "official", source, f"Node.js {m.group(1)}.x: start {v.get('start')}{lts}, end {v['end']}"))
    return out


CONTAINERD_URL = "https://raw.githubusercontent.com/containerd/containerd/main/RELEASES.md"


def parse_containerd(md: str, source: str = CONTAINERD_URL) -> list[Record]:
    """RELEASES.md table '| [2.3](…) | LTS | April 30, 2026 | April 30, 2028 | owners |'. A trailing '*' on the
    end date (an estimate in the source) is kept in the evidence."""
    out = []
    row = re.compile(r"^\|\s*\[?(\d+\.\d+)\]?(?:\([^)]*\))?\s*\|\s*([^|]+?)\s*\|\s*([A-Z][a-z]+ \d{1,2}, \d{4})\s*\|"
                     r"\s*([A-Z][a-z]+(?: \d{1,2},)? \d{4})(\*?)\s*\|", re.M)
    for line, state, start, end, star in row.findall(md):
        def iso(text: str) -> str:
            parts = text.replace(",", "").split()
            month = f"{MONTHS.get(parts[0]) or list(calendar.month_abbr).index(parts[0][:3]):02d}"
            return f"{parts[-1]}-{month}" + (f"-{int(parts[1]):02d}" if len(parts) == 3 else "")
        out.append(Record("containerd", line + (" LTS" if state == "LTS" else ""), iso(start), iso(end), "official",
                          source, f"containerd {line}: {state}, start {start}, end of life {end}{star}"
                          + (" (marked * in the source)" if star else "")))
    return out


def _html_rows(page: str) -> list[list[str]]:
    """Text cells (th and td) of every table row."""
    return [[re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", c))).strip()
             for c in re.findall(r"(?is)<t[hd][^>]*>(.*?)</t[hd]>", row)] for row in re.findall(r"(?is)<tr.*?</tr>", page)]


QT_URL = "https://doc.qt.io/qt-6/qt-releases.html"


def parse_qt(page: str, source: str = QT_URL) -> list[Record]:
    """'Qt 6.8 LTS | Qt 6.8.8 (LTS, commercial only) | 2029-10-08' rows; 'Ended (ES is available)' -> notice.
    The page has several tables (commercial and open-source views); the first row per version is kept and the
    'latest release' cell goes into the evidence."""
    out, seen = [], set()
    for c in _html_rows(page):
        m = re.fullmatch(r"Qt (\d+\.\d+)( LTS)?", c[0]) if len(c) == 3 else None
        if not m or m.group(1) in seen:
            continue
        seen.add(m.group(1))
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", c[2]):
            out.append(Record("Qt", m.group(1) + (m.group(2) or ""), "", c[2], "official", source,
                              f"{c[0]}: standard support until {c[2]} (latest release {c[1]})"))
        elif c[2].startswith("Ended"):
            out.append(Record("Qt", f"{m.group(1)} no longer supported", "", "", "notice", source,
                              f"{c[0]}: standard support '{c[2]}'"))
    return out


MENDER_URL = "https://docs.mender.io/release-information/supported-releases"


def parse_mender(page: str, source: str = MENDER_URL) -> list[Record]:
    """'Mender Client 6.0 | 2026-03 | Supported until 2027-04' / 'EOL (since 2026-09)' / 'Supported'."""
    out = []
    for c in _html_rows(page):
        m = re.fullmatch(r"(Mender(?: [A-Z]+)?(?: [A-Za-z]+)?) (\d+\.\d+)", c[0]) if len(c) == 3 else None
        if not m or not re.fullmatch(r"\d{4}-\d{2}", c[1]):
            continue
        until = re.search(r"(\d{4}-\d{2})", c[2])
        if c[2].startswith("EOL"):
            out.append(Record(m.group(1), f"{m.group(2)} no longer supported", c[1], until.group(1) if until else "",
                              "notice", source, f"{c[0]}: {c[2]}"))
        else:
            out.append(Record(m.group(1), m.group(2), c[1], until.group(1) if until else "", "official", source,
                              f"{c[0]}: released {c[1]}, {c[2]}"))
    return out


MOBY_URL = "https://raw.githubusercontent.com/moby/moby/master/project/BRANCHES-AND-TAGS.md"


def parse_moby(md: str, source: str = MOBY_URL) -> list[Record]:
    """Branch table '| docker-29.x | … | Maintained | After docker-30.x | … |'. The file defines 'Unmaintained' as
    'out-of-scope for security advisories' (-> notice) and calls the status 'informational and not binding'.
    An end that is an event ('After docker-30.x') stays in the evidence with no date."""
    out = []
    pattern = r"(?m)^\|\s*(?:docker-)?(\d+(?:\.\d+|\.x)?)\s*\|[^|]*\|\s*(Maintained(?: \(security\))?|Unmaintained)\s*\|([^|]*)\|"
    for branch, state, end in re.findall(pattern, md):
        line, end = branch.replace(".x", ""), re.sub(r"\]\[[^\]]*\]|[\[\]]", "", end).strip()   # '[2026-12-04][ref]'
        date = re.search(r"\d{4}-\d{2}-\d{2}", end)
        note = "status 'informational and not binding' per the file"
        if state == "Unmaintained":
            out.append(Record("Docker Engine", f"{line} no longer supported", "", date.group(0) if date else "", "notice",
                              source, f"moby branch {branch}: Unmaintained, 'out-of-scope for security advisories'; {note}"))
        else:
            out.append(Record("Docker Engine", line, "", date.group(0) if date else "", "official", source,
                              f"moby branch {branch}: {state}, expected end of maintenance '{end or 'not given'}'; {note}"))
    return out


ZEPHYR_URL = "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/main/doc/releases/index.rst"


def parse_zephyr(rst: str) -> list[Record]:
    out = []
    row = re.compile(r"\* - `Zephyr ([\d.]+)( \(LTS\d\))?`_\s*\n\s*- (\d{4}-\d{2}-\d{2})\s*\n\s*- (\S+)\s*\n\s*- ([^\n]+)")
    for m in row.finditer(rst):
        version, lts, released, eol, status = m.groups()
        line = ".".join(version.split(".")[:2]) + (" LTS" if lts else "")
        eol = eol if re.fullmatch(r"\d{4}-\d{2}-\d{2}", eol) else ""
        out.append(Record("Zephyr", line, released, eol, "official", ZEPHYR_URL,
                          f"Zephyr {version}{lts or ''}: released {released}, EOL {eol or 'n/a'} ({status.strip()})"))
    for m in re.finditer(r"\| `Zephyr ([\d.]+) \((LTS\d)\)`_\s*\|\s*(\d{4}-\d{2}-\d{2})\s*\|", rst):
        version, lts, eol = m.groups()
        out.append(Record("Zephyr", ".".join(version.split(".")[:2]) + " LTS", "", eol, "official", ZEPHYR_URL,
                          f"Zephyr {version} ({lts}) end of life {eol}"))
    return out


ESPIDF_POLICY_URL = "https://docs.espressif.com/projects/esp-idf/en/stable/esp32/versions.html"
ESPIDF_RELEASES_URL = "https://api.github.com/repos/espressif/esp-idf/releases?per_page=100"


def espidf_policy_months(html_text: str) -> int | None:
    m = re.search(r"supported for (\d+) months after the initial stable release date", re.sub(r"\s+", " ", html_text))
    return int(m.group(1)) if m else None


def _add_months(date: str, months: int) -> str:
    y, mth, d = (int(x) for x in date.split("-"))
    total = y * 12 + (mth - 1) + months
    y2, m2 = divmod(total, 12)
    return f"{y2:04d}-{m2 + 1:02d}-{min(d, calendar.monthrange(y2, m2 + 1)[1]):02d}"


def parse_espidf(releases: list[dict], policy_months: int) -> list[Record]:
    """vX.Y (or vX.Y.0) release dates from GitHub; end of support = release + policy months (derived)."""
    out, seen = [], set()
    for r in releases:
        m = re.fullmatch(r"v(\d+\.\d+)(?:\.0)?", r.get("tag_name", ""))
        if not m or m.group(1) in seen or r.get("prerelease"):
            continue
        seen.add(m.group(1))
        released = r["published_at"][:10]
        out.append(Record("ESP-IDF", m.group(1), released, _add_months(released, policy_months), "derived",
                          ESPIDF_POLICY_URL, f"v{m.group(1)} published {released}; policy: {policy_months} months support"))
    return out


KERNEL_URL = "https://www.kernel.org/category/releases.html"


def parse_kernel(html_text: str) -> list[Record]:
    """Longterm table rows. Older archived pages also say 'End of 2015' (kept as the year) and announce a release
    as '2019-XX-XX' (kept as '2019')."""
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html_text))
    out = []
    for m in re.finditer(r"\b(\d+\.\d+) (?:Greg Kroah-Hartman|Ben Hutchings|Sasha Levin)[^0-9]*?(\d{4}-[\dX]{2}-[\dX]{2}) "
                         r"(?:(\w{3}), (\d{4})|End of (\d{4}))", text):
        line, released, mon, year, end_year = m.groups()
        released = re.sub(r"(-XX)+$", "", released)
        eol = end_year or f"{int(year):04d}-{list(calendar.month_abbr).index(mon):02d}"
        stated = f"End of {end_year}" if end_year else f"{mon}, {year}"
        out.append(Record("Linux kernel LTS", line, released, eol, "official", KERNEL_URL,
                          f"{line}: released {released}, projected EOL {stated}"))
    return out


def _cells(html_text: str) -> list[list[str]]:
    """Table rows as cell texts; tolerant of MediaWiki/DokuWiki markup without closing tags."""
    rows = re.findall(r"<tr[^>]*>(.*?)(?=<tr[^>]*>|</table>)", html_text, re.S)
    cell = re.compile(r"<t[dh][^>]*>(.*?)(?=<t[dh][^>]*>|</tr>|$)", re.S)
    return [[html.unescape(re.sub(r"<[^>]+>", "", c)).strip() for c in cell.findall(r)] for r in rows]


def _month_any(text: str) -> str:
    """'April 2030' or 'Oct 2020' -> '2030-04' / '2020-10'."""
    name, year = text.split()
    idx = MONTHS.get(name) or list(calendar.month_abbr).index(name[:3])
    return f"{int(year):04d}-{idx:02d}"


YOCTO_URL = "https://wiki.yoctoproject.org/wiki/Releases"


def parse_yocto(html_text: str) -> list[Record]:
    """Rows whose support-level cell states a date ('until April 2030', 'EOL since November 2025')."""
    out = []
    for c in _cells(html_text):
        if len(c) < 5 or not re.fullmatch(r"\d+\.\d+", c[1]):
            continue
        m = re.search(r"until (\w+ \d{4})|EOL since (\w+ \d{4})", c[4])
        if not m:
            continue
        codename = c[0].split(" (")[0]
        out.append(Record("Yocto Project", f"{c[1]} {codename}", _month_any(c[2]), _month_any(m.group(1) or m.group(2)),
                          "official", YOCTO_URL, f"{codename} {c[1]}: released {c[2]}; {c[4]}"))
    return out


OPENWRT_URL = "https://openwrt.org/docs/guide-developer/security"


def parse_openwrt(html_text: str) -> list[Record]:
    """Support-status table: version, status, initial release 'YYYY, Month DD', EoL (projected) 'YYYY, Month' or TBD."""
    out = []
    for c in _cells(html_text):
        if len(c) < 4 or not re.fullmatch(r"\d+\.\d+", c[0]):
            continue
        rel = re.fullmatch(r"(\d{4}), (\w+) (\d{1,2})", c[2])
        eol = re.fullmatch(r"(\d{4}), (\w+)", c[3])
        if not rel:
            continue
        released = f"{rel.group(1)}-{MONTHS[rel.group(2)]:02d}-{int(rel.group(3)):02d}"
        out.append(Record("OpenWrt", c[0], released, f"{eol.group(1)}-{MONTHS[eol.group(2)]:02d}" if eol else "",
                          "official", OPENWRT_URL, f"OpenWrt {c[0]}: {c[1]}; initial release {c[2]}; EoL (projected) {c[3]}"))
    return out


FREERTOS_BRANCHES_URL = "https://api.github.com/repos/FreeRTOS/FreeRTOS-LTS/branches?per_page=100"
FREERTOS_README_URL = "https://raw.githubusercontent.com/FreeRTOS/FreeRTOS-LTS/{branch}/README.md"


def freertos_lts_branches(branches: list[dict]) -> list[str]:
    """'YYYYMM-LTS' branch names; the README on main only describes one release and can lag behind."""
    return sorted(b["name"] for b in branches if re.fullmatch(r"\d{6}-LTS", b.get("name", "")))


def parse_freertos_lts(md: str, branch: str) -> list[Record]:
    """'| Library | Version | LTS Until (MM/DD/YYYY) | Repo |' rows of one LTS branch README."""
    name = branch.removesuffix("-LTS")
    url = FREERTOS_README_URL.format(branch=branch)
    out = []
    for m in re.finditer(r"^\|\s*([^|]+?)\s*\|\s*([\d.]+)\s*\|\s*(\d{2})/(\d{2})/(\d{4})\s*\|", md, re.M):
        lib, ver, mm, dd, yyyy = m.groups()
        out.append(Record(f"FreeRTOS {branch}", f"{lib} {ver}", f"{name[:4]}-{name[4:]}", f"{yyyy}-{mm}-{dd}",
                          "official", url, f"{branch}: {lib} {ver} LTS until {mm}/{dd}/{yyyy}"))
    return out


VARISCITE_URL = "https://variscite.com/product-longevity/"


def _tokens(html_text: str) -> list[str]:
    """Visible text split at tags: robust to table vs. div layouts across page redesigns."""
    t = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html_text, flags=re.S)
    parts = (html.unescape(p).strip() for p in re.split(r"<[^>]+>", t))
    return [re.sub(r"\s+", " ", p) for p in parts if p.strip()]


def parse_variscite(html_text: str, source: str = VARISCITE_URL) -> list[Record]:
    """'System on Module | Expected Longevity' table: SoM name followed by a year, until 'Note'."""
    tok = _tokens(html_text)
    try:
        start = next(i for i, t in enumerate(tok) if re.fullmatch(r"(Expected )?Longevity", t, re.I)) + 1
    except StopIteration:
        return []
    out = []
    for name, year in zip(tok[start::2], tok[start + 1::2]):
        if not re.fullmatch(r"20\d\d\+?", year):
            break
        out.append(Record("Variscite SoM", name, "", year.rstrip("+"), "official", source,
                          f"{name}: expected longevity {year} (vendor table; based on chip-vendor longevity)"))
    return out


RPI_BRIEFS = {
    "Raspberry Pi 5": "https://datasheets.raspberrypi.com/rpi5/raspberry-pi-5-product-brief.pdf",
    "Raspberry Pi 4 Model B": "https://datasheets.raspberrypi.com/rpi4/raspberry-pi-4-product-brief.pdf",
    "Compute Module 5": "https://datasheets.raspberrypi.com/cm5/cm5-product-brief.pdf",
    "Compute Module 4": "https://datasheets.raspberrypi.com/cm4/cm4-product-brief.pdf",
}


def parse_rpi_brief(text: str, product: str, source: str) -> list[Record]:
    """'<product> will remain in production until at least January 2034' (product-brief PDF text)."""
    flat = re.sub(r"\s+", " ", text)
    tail = r" will remain in production until at least (\w+ \d{4})"
    m = re.search(r"Raspberry Pi[^.()]{0,60}?" + tail, flat) or re.search(r"[^.()]{0,60}" + tail, flat)
    if not m:
        return []
    return [Record("Raspberry Pi", product, "", _month(m.group(1)), "official", source,
                   m.group(0).strip())]


# AM57x (table without PCN rows yet) and ARM9 (no table) left out: they would fail the "no records" check daily.
CRITICALLINK_PAGES = [
    "https://support.criticallink.com/redmine/projects/mitysom_am62x/wiki/Errata_and_Module_Product_Change_Notifications",
    "https://support.criticallink.com/redmine/projects/mitysom_c10gx/wiki/Errata_and_Module_Product_Change_Notifications",
    "https://support.criticallink.com/redmine/projects/mityarm-5cs/wiki/Errata_and_Module_Product_Change_Notifications",
    "https://support.criticallink.com/redmine/projects/armc8-platforms/wiki/Module_Product_Change_Notifications",
]


def _day(text: str) -> str:
    """'5-June-2023' / '11-Jun-2025' / '2025-06-11' -> '2025-06-11' ('' if unparsable)."""
    text = text.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return text
    m = re.fullmatch(r"(\d{1,2})[- ]([A-Za-z]+)\.?[- ,]+(\d{4})", text)
    if not m:
        return ""
    name = m.group(2)[:3].title()
    if name not in calendar.month_abbr:
        return ""
    return f"{int(m.group(3)):04d}-{list(calendar.month_abbr).index(name):02d}-{int(m.group(1)):02d}"


def parse_criticallink(html_text: str, source: str) -> list[Record]:
    """PCN rows of a Critical Link 'Errata and Module Product Change Notifications' wiki table.

    Notices, not end-of-support dates: line = PCN id, released = notice date, evidence = title."""
    family = re.search(r"/projects/([^/]+)/", source)
    family = family.group(1) if family else "unknown"
    out = []
    for c in _cells(html_text):
        if len(c) >= 5 and c[0].upper() == "PCN" and re.fullmatch(r"PCN\d+", c[2]):      # with Device column
            out.append(Record(f"Critical Link {c[1]}", c[2], _day(c[4]), "", "notice", source, f"PCN: {c[3]}"))
        elif len(c) == 4 and c[0].upper() == "PCN" and re.fullmatch(r"PCN\d+", c[1]):    # device = page family
            out.append(Record(f"Critical Link {family}", c[1], _day(c[3]), "", "notice", source, f"PCN: {c[2]}"))
    return out


ESPRESSIF_ADVISORIES_URL = "https://www.espressif.com/en/node/10673"


def parse_espressif_advisories(html_text: str) -> list[Record]:
    """'ESP-IDF v5.2 Release Branch reaches End-of-Life in August of 2026.' rows of Espressif's advisory index.

    'end of 2023' or a bare year stays year-only ('2023'); month names give 'YYYY-MM'."""
    out = []
    for c in _cells(html_text):
        text = " ".join(c)
        m = re.search(r"ESP-IDF v(\d+\.\d+) [Rr]elease [Bb]ranch reaches End-of-Life in ([^.]*?)(\d{4})", text)
        if not m:
            continue
        month = re.search(r"(January|February|March|April|May|June|July|August|September|October|November|December)",
                          m.group(2))
        eol = f"{m.group(3)}-{MONTHS[month.group(1)]:02d}" if month else m.group(3)
        adv = next((x for x in c if re.fullmatch(r"AR\d{4}-\d{3}", x)), "")
        out.append(Record("ESP-IDF", m.group(1), "", eol, "official", ESPRESSIF_ADVISORIES_URL,
                          f"{adv}: {m.group(0)}".strip(": ")))
    return out


def prefer_official(records: list[Record]) -> list[Record]:
    """Where an official record exists for (component, line), drop derived ones for the same key."""
    official = {(r.component, r.line) for r in records if r.kind == "official"}
    return [r for r in records if r.kind != "derived" or (r.component, r.line) not in official]


RPI_EOL_INDEX = "https://pip.raspberrypi.com/categories/1284-eol-notices"
RPI_ASSETS = "https://pip-assets.raspberrypi.com/categories/1284-eol-notices/"


def rpi_notice_links(index_html: str) -> list[str]:
    """PDF URLs of Raspberry Pi obsolescence notices listed in the EOL-notices category."""
    return [RPI_ASSETS + p for p in sorted(set(re.findall(r'(documents/[^"<> ]+\.pdf)', index_html)))]


def _long_day(text: str) -> str:
    """'16 Oct 2025' / '30 June 2026' -> ISO date ('' if unparsable)."""
    m = re.fullmatch(r"(\d{1,2}) ([A-Za-z]+) (\d{4})", text.strip())
    if not m or m.group(2)[:3].title() not in calendar.month_abbr:
        return ""
    return f"{m.group(3)}-{list(calendar.month_abbr).index(m.group(2)[:3].title()):02d}-{int(m.group(1)):02d}"


def parse_rpi_eol_notice(text: str, source: str) -> list[Record]:
    """One record per obsolescence notice: released = notification date, eol = EOL date; LTB/LTS in evidence."""
    flat = re.sub(r"\s+", " ", text)
    date = r"(\d{1,2} [A-Za-z]+ \d{4})"
    field = {k: re.search(pat + r" " + date, flat) for k, pat in {
        "notified": r"Notification date", "eol": r"End of Life \(EOL\) Date",
        "ltb": r"Last time buy \(LTB\) Date", "lts": r"Last time ship \(LTS\) date"}.items()}
    if not field["eol"]:
        return []
    nid = re.search(r"(RP-\d{6})", source + " " + flat)
    product = re.search(r"Products? Affected (Raspberry Pi .{3,120}?) Reason", flat)
    val = {k: (m.group(1) if m else "") for k, m in field.items()}
    return [Record("Raspberry Pi EOL notice", nid.group(1) if nid else source.rsplit("/", 1)[-1],
                   _long_day(val["notified"]), _long_day(val["eol"]), "notice", source,
                   f"{product.group(1) if product else 'product'}: EOL {val['eol']}, LTB {val['ltb']}, LTS {val['lts']}")]


SOMLABS_URL = "https://somlabs.com/longevity/"


def parse_somlabs(html_text: str, source: str = SOMLABS_URL) -> list[Record]:
    """'Product | Expected Longevity | Comments' table. The product cell runs name and description together
    ('SpaceSOM-8Mplus (SLS35)ARM Cortex-A53 ...'), so the name ends at the '(SLSxx)'/'(SLCx)' code when present.
    'TBD' rows are kept with no end date, so a later stated date shows up as a change, not as 'added'."""
    out = []
    for c in _cells(html_text):
        if len(c) < 2 or not re.fullmatch(r"20\d\d\+?|TBD", c[1]):
            continue
        m = re.match(r"(.+?\([A-Z]{2,4}[\w\-]*\))", c[0])
        name = (m.group(1) if m else c[0]).strip()
        note = c[2] if len(c) > 2 else ""
        out.append(Record("SoMLabs", name, "", "" if c[1] == "TBD" else c[1].rstrip("+"), "official", source,
                          f"{name}: expected longevity {c[1]}" + (f" ({note})" if note else "")))
    return out


TORADEX_SITEMAP = "https://developer.toradex.com/sitemap.xml"


TORADEX_PCN_SECTIONS = ("/modules/", "/carrier-boards/", "/add-ons/", "/legacy-products/", "/accessories/")


def toradex_module_pages(sitemap_xml: str) -> list[str]:
    """Hardware pages that link PCN/EOL PDFs: modules, carrier boards, add-ons, accessories and legacy products
    (scan of all 186 hardware pages on 2026-10-16: PCNs only appear in these sections). Index pages skipped."""
    urls = re.findall(r"<loc>([^<]*/hardware/[^<]+)</loc>", sitemap_xml)
    return sorted({u for u in urls if not u.endswith("/") and any(sec in u for sec in TORADEX_PCN_SECTIONS)})


def _toradex_pdf_date(name: str) -> str:
    """'…-20231127.pdf' (YYYYMMDD), '…-2026-07-07.pdf' or '…-270326-133937.pdf' (DDMMYY-hhmmss) -> ISO, else ''."""
    m = re.search(r"-(20\d{2})-?(\d{2})-?(\d{2})\.pdf$", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = re.search(r"-(\d{2})(\d{2})(\d{2})-\d{6}\.pdf$", name)
    if m and 1 <= int(m.group(2)) <= 12:
        return f"20{m.group(3)}-{m.group(2)}-{m.group(1)}"
    return ""


def parse_toradex_module(html_text: str, page_url: str) -> list[Record]:
    """PCN/EOL PDFs linked from a Toradex module page: one notice per document id."""
    module = page_url.rstrip("/").rsplit("/", 1)[-1]   # module, board or accessory name
    out, seen = [], set()
    for url in sorted(set(re.findall(r'https?://docs\.toradex\.com/[^"<> ]*pcn[^"<> ]*\.pdf', html_text, re.I))):
        name = url.rsplit("/", 1)[-1]
        doc = name.split("-", 1)[0]
        if not doc.isdigit() or doc in seen:
            continue
        seen.add(doc)
        title = re.sub(r"[-_]+", " ", name[len(doc) + 1:-4]).strip()
        kind = "EOL notice" if re.search(r"\beol\b", title, re.I) else "PCN"
        out.append(Record(f"Toradex {module}", doc, _toradex_pdf_date(name), "", "notice", url, f"{kind}: {title}"))
    return out


NXP_LONGEVITY_URL = "https://www.nxp.com/products/product-information/product-longevity:PRDCT_LONGEVITY_HM"


def _td_cells(row: str) -> list[str]:
    """Raw <td> cells of a row, split on opening tags: NXP's archived pages sometimes omit '</td>'."""
    return [c.split("</td>")[0] for c in re.split(r"<td[^>]*>", row)[1:]]


def _nxp_old_layout(html_text: str, source: str) -> list[Record]:
    """2017–2020 layout: 'Category | Family/Series | Products | 10Year | 15Year | LaunchDate'. The tier is a
    checkmark icon in the 10Year or 15Year cell; NXP counts availability from the launch date, so the end
    is derived as launch + 10/15 years (kind 'derived')."""
    out = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html_text, re.S):
        cells = _td_cells(row)
        if len(cells) == 5 and "checkmark" in cells[2] + cells[3]:
            cells = [""] + cells          # category cell placed outside the row in some captures
        if len(cells) != 6:
            continue
        text = [re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", c))).strip() for c in cells]
        m = re.fullmatch(r"([A-Za-z]{3})[a-z]* (\d{4})", text[5])
        if not m or m.group(1).title() not in calendar.month_abbr or not text[2]:
            continue
        years = 15 if "checkmark" in cells[4] else 10 if "checkmark" in cells[3] else None
        if years is None:
            continue
        month = list(calendar.month_abbr).index(m.group(1).title())
        launch = f"{m.group(2)}-{month:02d}"
        out.append(Record("NXP longevity", text[2], launch, f"{int(m.group(2)) + years}-{month:02d}", "derived", source,
                          f"{text[1]} ({text[0]}): launch {text[5]}, {years}-year longevity tier "
                          f"(end derived as launch + {years} years, NXP's stated rule)"))
    return out


def _disambiguate(records: list[Record]) -> list[Record]:
    """NXP lists some part names in several rows (different family or launch date). Keyed by part name only,
    so snapshots stay comparable across page redesigns: keep the row with the latest end date and record how
    many rows the name had in the evidence. Spacing is normalised ('LX2120A , LX2122A' == 'LX2120A, LX2122A'):
    NXP re-spelled names between captures, which is not a vendor change."""
    records = [Record(r.component, re.sub(r"\s+,", ",", re.sub(r"\s+", " ", r.line)).strip(), r.released, r.eol,
                      r.kind, r.source, r.evidence) for r in records]
    best: dict[str, Record] = {}
    count = collections.Counter(r.line for r in records)
    for r in records:
        if r.line not in best or r.eol > best[r.line].eol:
            best[r.line] = r
    out = []
    for line, r in best.items():
        if count[line] > 1:
            r = Record(r.component, r.line, r.released, r.eol, r.kind, r.source,
                       r.evidence + f"; listed in {count[line]} rows, latest end shown")
        out.append(r)
    return out


def parse_nxp_longevity(html_text: str, source: str = NXP_LONGEVITY_URL) -> list[Record]:
    """Rows 'Category | Family/Series | Products | Launch Date | 10 Years | 15 Years | Extended | Remains … until'.

    Archive-only source: the live page blocks scripts. Tier marker cells are kept verbatim in the evidence."""
    def ym(text: str) -> str:
        m = re.fullmatch(r"([A-Za-z]{3})[a-z]* (\d{4})", text.strip())
        return f"{m.group(2)}-{list(calendar.month_abbr).index(m.group(1).title()):02d}" if m and \
            m.group(1).title() in calendar.month_abbr else ""
    out = []
    for c in _cells(html_text):
        if len(c) == 8 and ym(c[3]) and (ym(c[7]) or c[7] in ("", "-")) and c[2]:
            until = f"until {c[7]}" if ym(c[7]) else "with no end date given ('-')"   # e.g. LX2120A in 2021
            out.append(Record("NXP longevity", c[2], ym(c[3]), ym(c[7]), "official", source,
                              f"{c[1]} ({c[0]}): launch {c[3]}, remains in longevity program {until}; "
                              f"tier markers 10y='{c[4]}' 15y='{c[5]}' extended='{c[6]}'"))
    if not out:
        old = _nxp_old_layout(html_text, source)
        listed = {r.line for r in old}
        return _disambiguate(old + [r for r in _nxp_2017_layout(html_text, source) if r.line not in listed])
    # pages in transition (March 2021) carry both layouts: parts only in the old table are still listed
    listed = {r.line for r in out}
    return _disambiguate(out + [r for r in _nxp_old_layout(html_text, source) if r.line not in listed])


def _nxp_2017_layout(html_text: str, source: str) -> list[Record]:
    """2017–2018 layout, 5 cells: Category | Family | 10-Year | 15-Year | Product Launched. The product name is
    written INTO its tier column (the other tier cell is '-'). End derived as launch + tier (kind 'derived')."""
    out = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html_text, re.S):
        cells = _td_cells(row)
        if len(cells) != 5 or "checkmark" in cells[2] + cells[3]:
            continue
        text = [re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", c))).strip() for c in cells]
        m = re.fullmatch(r"([A-Za-z]+) (\d{4})", text[4])
        if not m or m.group(1)[:3].title() not in calendar.month_abbr:
            continue
        month = list(calendar.month_abbr).index(m.group(1)[:3].title())
        # a row may name a part in both tiers ('i.MX 6Dual' 10-year, 'i.MX 6Dual (Industrial, Auto)' 15-year)
        for name, years in ((text[2], 10), (text[3], 15)):
            if name in ("", "-"):
                continue
            out.append(Record("NXP longevity", name, f"{m.group(2)}-{month:02d}",
                              f"{int(m.group(2)) + years}-{month:02d}", "derived", source,
                              f"{text[1]} ({text[0]}): launched {text[4]}, {years}-year longevity tier "
                              f"(end derived as launch + {years} years, NXP's stated rule)"))
    return out


# Only the legacy page states longevity; active module pages carry just "Root Part #" (checked 2026-10-16).
PHYTEC_PAGES = ["https://www.phytec.com/legacy-soms/"]


def parse_phytec(html_text: str, source: str) -> list[Record]:
    """Module cards: 'phyCORE-RK3288', 'Root Part #: PCM-059', 'Launch Date: 2018', 'Expected Longevity: 2021+'.
    Text blocks, not a table: walk the visible tokens and attach each 'Expected Longevity' to the last module name."""
    out, name, part, launch = [], None, "", ""
    for tok in _tokens(html_text):
        if re.fullmatch(r"phy[A-Z]+-[\w.\-+ ]+", tok):
            name, part, launch = tok, "", ""
        elif tok.startswith("Root Part #:"):
            part = tok.split(":", 1)[1].strip()
        elif tok.startswith("Launch Date:"):
            m = re.search(r"(\d{4})", tok)
            launch = m.group(1) if m else ""
        elif tok.startswith("Expected Longevity:") and name:
            m = re.search(r"(\d{4})", tok)
            if m:
                out.append(Record("PHYTEC SoM", f"{name} ({part})" if part else name, launch, m.group(1), "official",
                                  source, f"{name}: launch {launch or 'n/a'}, {tok}"))
            name = None
    return out


# Vendor-declared security-update support periods (EU RED / UK PSTI statements). Facts as published, no verdicts.
SMA_SUPPORT_URL = "https://files.sma.de/assets/295280.pdf"
APSYSTEMS_SUPPORT_URL = "https://emea.apsystems.com/wp-content/uploads/2024/07/Defined-Support-Period_V1.pdf"
SOLAREDGE_SUPPORT_URL = "https://shop.solexis.ch/documents/file/accessoires/solaredge/ft_en_solaredga_security-updates_note.pdf"
SMA_FAMILIES = r"SUNNY [A-Z]+|Communication products|Charging [Ss]tations"


def parse_sma_support(text: str, source: str = SMA_SUPPORT_URL) -> list[Record]:
    """SMA 'Support time … with regard to security updates' (pdftotext -raw): model lists followed by
    'until/by the end of YYYY'. One record per model; version noted in the evidence."""
    version = re.search(r"Version (\d+\.\d+)", text)
    ver = f"v{version.group(1)}" if version else "v?"
    body = text.split("support time", 1)[-1]
    out, buf = [], ""
    for line in body.splitlines():
        line = line.strip()
        m = re.search(r"(?:until|by) the end of (\d{4})", line)
        buf += " " + (line[:m.start()] if m else line)
        if not m:
            if re.match(r"(Product|1\)|Update-Support|ENGLISH|Technical Information|\d+ Support time)", line):
                buf = ""
            continue
        models = re.sub(SMA_FAMILIES, " ", buf)
        for model in (re.sub(r"\s+", "", x) for x in models.split(",")):   # versions differ: 'STPS 30-20'/'STPS30-20'
            if re.search(r"[A-Z]{2,}[\w.\-]*\d", model):
                out.append(Record("SMA security updates", model, "", m.group(1), "official", source,
                                  f"{model}: minimum security-update support until the end of {m.group(1)} (SMA TI {ver})"))
        buf = ""
    return out


def parse_apsystems_support(text: str, source: str = APSYSTEMS_SUPPORT_URL) -> list[Record]:
    """APsystems 'Product Security Update Support' (pdftotext -raw): after 'Product List'/'Software List',
    model lines (category lines without digits are skipped) followed by 'launch end' (YYYY-MM)."""
    out, buf, started = [], [], False
    for line in (x.strip() for x in text.splitlines()):
        if line in ("Product List", "Software List"):
            started, buf = True, []
            continue
        if not started or re.search(r"Launch Date|End date|update support|^\.\.\.|^Note", line):
            buf = []
            continue
        m = re.fullmatch(r"(.*?)\s*(\d{4}-\d{2})\s+(\d{4}-\d{2})", line)
        if not m:
            if re.search(r"\d", line):
                buf.append(line)
            continue
        for model in (x.strip() for x in " ".join(buf + [m.group(1)]).split(",")):
            if model:
                out.append(Record("APsystems security updates", model, m.group(2), m.group(3), "official", source,
                                  f"{model}: launch {m.group(2)}, end of security update support {m.group(3)}"))
        buf = []
    return out


def parse_solaredge_support(text: str, source: str = SOLAREDGE_SUPPORT_URL) -> list[Record]:
    """SolarEdge 'Security Updates for SolarEdge Products' (pdftotext -raw): table rows 'name part End of YYYY',
    wrapped over lines. A row that starts with a part number inherits the previous product name.
    Source is a reseller-hosted copy of the official note (no solaredge.com URL found)."""
    version = re.search(r"Version (\d+\.\d+)", text)
    ver = f"v{version.group(1)}" if version else "v?"
    out, buf, started, last_name = [], [], False, ""
    for line in (x.strip() for x in text.splitlines()):
        if line == "Support Period":
            started, buf = True, []
            continue
        if not started or re.match(r"(Version \d|SolarEdge’s Security Updates for)", line):
            continue
        m = re.fullmatch(r"(.*?)\s*End of (\d{4})", line)
        if not m:
            buf.append(line)
            continue
        row = re.sub(r"(\w)- (\w)", r"\1-\2", " ".join(buf + [m.group(1)]).strip())
        buf = []
        if re.match(r"(SE|BAT|SEM|ONE)[\w.]*-", row) and last_name:
            row = f"{last_name} {row}"
        else:
            last_name = re.split(r" (?:SE|BAT|SEM|SMRT|ONE)[\w.]*-", row)[0]
        out.append(Record("SolarEdge security updates", row, "", m.group(2), "official", source,
                          f"{row}: security updates support period end of {m.group(2)} (note {ver}, reseller-hosted copy)"))
    return out


RENESAS_PLP_URL = "https://www.renesas.com/en/support/product-longevity-program-plp"


def parse_renesas_plp(page: str, source: str = RENESAS_PLP_URL) -> list[Record]:
    """Renesas Product Longevity Program: which products/families are listed (no per-part dates on the page).
    Membership itself is the fact; additions and removals become dated changes. Renesas states replacements are
    shown 'for about three months following the change', so only daily snapshots keep that history."""
    out, seen = [], set()
    for row in re.findall(r"(?s)<tr.*?</tr>", page):
        cells = re.findall(r"(?s)<td.*?>(.*?)</td>", row)
        if len(cells) < 2:
            continue
        category = re.sub(r"(?<=[a-z])TM\b|™", "", html.unescape(re.sub(r"<[^>]+>|\s+", " ", cells[0]))).strip()
        if category == "Product":         # header row written with <td>
            continue
        text = re.sub(r"(?i)<br\s*/?>|</p>", "\n", cells[1])
        label = ""
        lines = [x for x in html.unescape(re.sub(r"<[^>]+>", "", text)).replace("\xa0", " ").splitlines() if x.strip()]
        for i, line in enumerate(lines):
            items = [x.strip() for x in line.split(",") if x.strip()]
            heading = len(items) == 1 and " " in items[0] and not re.search(r"\d", items[0].split()[-1])
            if heading and i < len(lines) - 1:
                label = items[0]          # sub-family heading such as 'SuperH RISC engine Family' (more lines follow)
                continue
            for item in items:
                item = re.sub(r"\s*,?\s*etc\.?$", "", item).strip()
                item = re.sub(r"(?<=[a-z])TM\b|™", "", item)      # 'SynergyTM' in old captures, 'Synergy™' now
                if (not item or item.lower() == "etc." or len(item) > 60 or item.upper() in ("PDF", "XLSX", "XLS")
                        or re.fullmatch(r"[\d.]+\s*[KMG]B", item) or (category, item) in seen):   # '612 KB' link sizes
                    continue
                seen.add((category, item))
                group = f"{category} / {label}" if label else category
                out.append(Record("Renesas PLP", item, "", "", "official", source,
                                  f"{item}: listed in the Renesas Product Longevity Program ({group})"))
    return out


NUMBER_WORDS = {"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "ten": 10}
NCS_RELEASES_API = "https://api.github.com/repos/nrfconnect/sdk-nrf/contents/doc/nrf/releases_and_maturity/releases"
NCS_NOTES_URL = ("https://raw.githubusercontent.com/nrfconnect/sdk-nrf/main/doc/nrf/releases_and_maturity/releases/"
                 "release-notes-{version}.rst")


def ncs_major_releases(listing: list[dict], last: int = 6) -> list[str]:
    """Newest x.y.0 versions from the GitHub contents listing of the release-notes directory."""
    versions = [m.group(1) for x in listing if (m := re.fullmatch(r"release-notes-(\d+\.\d+)\.0\.rst", x["name"]))]
    return sorted(versions, key=lambda v: [int(n) for n in v.split(".")])[-last:]


def parse_ncs_release_notes(text: str, version: str, released: str, source: str) -> list[Record]:
    """nRF Connect SDK x.y.0 release notes: 'long-term support (LTS) for a period of N years' gives an LTS line
    (end = release + N years, kind derived); 'the last ... releases that include support for <series>' is kept
    as a notice. `released` is the tag's commit date (YYYY-MM-DD) or ''."""
    out = []
    flat = re.sub(r"\s+", " ", text)
    lts = re.search(r"long-term support \(LTS\) for a period of (\w+) years", flat)
    if lts:
        word = lts.group(1).lower()
        years = int(word) if word.isdigit() else NUMBER_WORDS.get(word, 0)
        eol = f"{int(released[:4]) + years}{released[4:7]}" if released and years else ""
        out.append(Record("nRF Connect SDK", f"{version} LTS", released, eol, "derived", source,
                          f"v{version}.0 'has long-term support (LTS) for a period of {lts.group(1)} years'; "
                          f"end computed from the release date"))
    for m in re.finditer(r"are the last \|NCS\| releases that include support for ([^.]+?)\.", flat):
        out.append(Record("nRF Connect SDK", f"{version} last release with {m.group(1)}", released, "", "notice", source,
                          f"v{version}.0 and its patch releases are the last releases that include support for "
                          f"{m.group(1)}"))
    return out


JETSON_LIFECYCLE_URL = "https://developer.nvidia.com/embedded/lifecycle"


def parse_jetson_lifecycle(page: str, source: str = JETSON_LIFECYCLE_URL) -> list[Record]:
    """NVIDIA Jetson Product Lifecycle tables: header rows ('Commercial Module | Available through', 'Module | Date of
    EOL', 'Processor | ...') set the section; data rows give 'Month YYYY'. Developer kits listed without a date are
    kept as notices (NVIDIA publishes no devkit lifecycle)."""
    out, section = [], ""
    for row in re.findall(r"(?s)<tr.*?</tr>", page):
        cells = [html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c))).strip()
                 for c in re.findall(r"(?s)<t[dh][^>]*>(.*?)</t[dh]>", row)]
        cells = [c for c in cells if c]
        if len(cells) == 2 and re.search(r"Available through|Date of EOL", cells[1]):
            section = f"{cells[0]}: {cells[1]}"
            continue
        name = re.sub(r"\s+", " ", re.sub(r"[()]", " ", cells[0] if cells else "")).strip()   # 'AGX Xavier (32GB)'
        if len(cells) == 2 and (m := re.fullmatch(r"([A-Z][a-z]+) (\d{4})", cells[1])) and m.group(1) in MONTHS:
            out.append(Record("NVIDIA Jetson", name, "", _month(cells[1]), "official", source,
                              f"{cells[0]} — {section} {cells[1]}"))
        elif len(cells) == 1 and "Developer Kit" in cells[0]:
            out.append(Record("NVIDIA Jetson", cells[0], "", "", "notice", source,
                              f"{cells[0]}: listed as having reached End of Life (no lifecycle date published for kits)"))
    return out


TORADEX_BSP_URL = ("https://developer.toradex.com/software/toradex-embedded-software/"
                   "toradex-embedded-linux-support-strategy")


def parse_toradex_bsp_lifecycle(page: str, source: str = TORADEX_BSP_URL) -> list[Record]:
    """Toradex BSP Layers lifecycle table (minified HTML, unclosed <tr>/<td>): version, state, initial release,
    projected EOL. The state is kept as its own notice record so Active -> Maintenance -> EOL shows up as a change."""
    out = []
    table = page.split("Projected EOL", 1)[-1].split("</table>", 1)[0]
    for row in re.split(r"(?i)<tr[^>]*>", table)[1:]:
        cells = [html.unescape(re.sub(r"<[^>]+>|\s+", " ", c)).strip() for c in re.split(r"(?i)<td[^>]*>", row)[1:]]
        version = re.sub(r"^Torizon\s*/\s*", "", cells[0]) if cells else ""   # 'Torizon/BSP 7' until ~2026
        if len(cells) < 4 or not version.startswith("BSP"):
            continue
        state, initial, eol = cells[1:4]
        released = _month(initial) if re.fullmatch(r"[A-Z][a-z]+ \d{4}", initial) else ""
        eol = eol if re.fullmatch(r"\d{4}", eol) else ""
        periodicity = cells[5] if len(cells) > 5 else ""
        out.append(Record("Toradex BSP", version, released, eol, "official", source,
                          f"{version}: initial release {initial}, projected EOL {eol or cells[3]}, state {state}"
                          + (f", release periodicity {periodicity}" if periodicity else "")))
        out.append(Record("Toradex BSP", f"{version} state: {state}", released, "", "notice", source,
                          f"{version} lifecycle state '{state}' (Toradex BSP Layers for Yocto)"))
    return out


JCI_EOS_URL = "https://www.johnsoncontrols.com/eos"
# Safety-related sections are never collected (filter: buyers would expect a safety verdict from them)
JCI_EXCLUDE = r"Fire|Life Safety|Security|Intrusion|Sensormatic|Room Pressure|Fume Hood|Combustion|^Digital"
JCI_EXCLUDE_PRODUCT = r"Fire|Smoke|Life Safety|Security|Intrusion|Access Control"


def parse_jci_eos(page: str, source: str = JCI_EOS_URL) -> list[Record]:
    """Johnson Controls End-of-Support notices: one table per section heading; rows 'Product | Version | Regions |
    End of Support Date | EOS Notice'. Building-automation and HVAC sections only."""
    out, seen = [], set()
    parts = re.split(r"(?s)<h[1-4][^>]*>(.*?)</h[1-4]>", page)
    for heading_html, body in zip(parts[1::2], parts[2::2]):
        section = html.unescape(re.sub(r"<[^>]+>|\s+", " ", heading_html)).strip()
        if "EOS" not in section or re.search(JCI_EXCLUDE, section):
            continue
        for row in re.findall(r"(?s)<tr.*?</tr>", body):
            cells = [html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c))).strip()
                     for c in re.findall(r"(?s)<td[^>]*>(.*?)</td>", row)]
            if len(cells) < 4 or not cells[0]:
                continue
            product, version, region, when = cells[:4]
            if re.search(JCI_EXCLUDE_PRODUCT, product):  # e.g. a security enclosure filed under panels
                continue
            notice = cells[4] if len(cells) > 4 else ""
            line = f"{product} [{region}]" if region and region != "Global" else product
            if version and len(version) <= 20:
                line = f"{line} {version}"
            if line in seen:
                continue
            seen.add(line)
            m = re.search(r"([A-Z][a-z]+) (\d{4})", when)
            eol = _month(m.group(0)) if m and m.group(1) in MONTHS else (re.search(r"\d{4}", when) or [""])[0]
            out.append(Record("Johnson Controls EOS", line, "", eol, "official", source,
                              f"{product} ({version or 'all versions'}, {region}): end of support {when}; "
                              f"notice {notice or 'n/a'}; section '{section}'"))
    return out


IGNITION_LTS_URL = "https://www.docs.inductiveautomation.com/long-term-support"


def _long_date(text: str) -> str:
    """'Sept 16th 2030' / 'Jul 31st 2019' -> '2030-09-16'; '' if unparsable."""
    m = re.search(r"([A-Za-z]{3,})\.? (\d{1,2})(?:st|nd|rd|th)? (\d{4})", text)
    if not m:
        return ""
    idx = next((i for i, n in enumerate(calendar.month_name) if n and n.lower().startswith(m.group(1).lower()[:3])), 0)
    return f"{m.group(3)}-{idx:02d}-{int(m.group(2)):02d}" if idx else ""


def parse_ignition_lts(page: str, source: str = IGNITION_LTS_URL) -> list[Record]:
    """Inductive Automation Ignition support table (minified HTML): version, released, LTS, active support end,
    limited support end. Two records per version, because the two end dates move independently."""
    out = []
    table = page.split("Limited Support End Date", 1)[-1].split("</table>", 1)[0]
    for row in re.split(r"(?i)<tr[^>]*>", table)[1:]:
        cells = [html.unescape(re.sub(r"<[^>]+>|\s+", " ", c)).strip() for c in re.split(r"(?i)<td[^>]*>", row)[1:]]
        if len(cells) < 5 or not re.match(r"\d+\.\d+", cells[0]):
            continue
        version = cells[0].split()[0]
        line = f"{version} LTS" if cells[2].lower().startswith("yes") else version
        released, active, limited = _long_date(cells[1]), _long_date(cells[3]), _long_date(cells[4])
        out.append(Record("Ignition", line, released, limited, "official", source,
                          f"Ignition {version}: released {cells[1]}, active support until {cells[3]}, "
                          f"limited support until {cells[4]}"))
        out.append(Record("Ignition", f"{line} active support", released, active, "official", source,
                          f"Ignition {version}: active support end {cells[3]}"))
    return out


TRIDIUM_N5_FAQ_URL = "https://pages1.tridium.com/rs/808-SGM-271/images/N5-FAQ.pdf"
QUARTER_END = {"Q1": "03", "Q2": "06", "Q3": "09", "Q4": "12"}


def parse_tridium_n5_faq(text: str, source: str = TRIDIUM_N5_FAQ_URL) -> list[Record]:
    """Tridium Niagara 5 FAQ (PDF text): N4.15 LTS update end ('through Q3 of 2028'), JACE-8000 ordering close dates
    per region, Niagara 5.0 GA target. Quarter-only ends are derived (end of quarter); stated days are official."""
    flat, out = re.sub(r"\s+", " ", text), []
    m = re.search(r"(4\.\d+) is planned to continue to receive updates through (Q[1-4]) of (\d{4})", flat)
    if m:
        out.append(Record("Tridium Niagara", f"Niagara {m.group(1)} LTS", "", f"{m.group(3)}-{QUARTER_END[m.group(2)]}",
                          "derived", source, f"Niagara {m.group(1)} 'is planned to continue to receive updates through "
                          f"{m.group(2)} of {m.group(3)}' (end of quarter used)"))
    m = re.search(r"JACE-8000 ordering closed in Europe on ([A-Z][a-z]+ \d{1,2}, \d{4}), and closes on "
                  r"([A-Z][a-z]+ \d{1,2}, \d{4}), in the ([^.?]+?)(?: regions?)?[.?]", flat)
    if m:
        for region, when in (("Europe", m.group(1)), (m.group(3).strip(), m.group(2))):
            day = _long_date(when.replace(",", ""))
            out.append(Record("Tridium Niagara", f"JACE-8000 ordering [{region}]", "", day, "official", source,
                              f"JACE-8000 ordering closes {when} in {region} (end of ordering, not end of support)"))
    m = re.search(r"([A-Z][a-z]+ \d{4}) \(target\): Niagara (5\.\d+) general availability", flat)
    if m:
        out.append(Record("Tridium Niagara", f"Niagara {m.group(2)} general availability (target)", _month(m.group(1)), "",
                          "notice", source, f"Niagara {m.group(2)} general availability targeted for {m.group(1)}"))
    return out


NUVOTON_PLP_URL = "https://www.nuvoton.com/export/sites/nuvoton/files/PLP_ProductList.pdf"


def parse_nuvoton_plp(text: str, source: str = NUVOTON_PLP_URL) -> list[Record]:
    """Nuvoton Product Longevity Program list (pdftotext -layout). Layouts seen: 2023 'Part Line Family YYYY',
    2025 'Part Line Family YYYY/M', 2026 'No. Part Line Family YYYY/M Status'. PLP year -> end date; the status
    (MP, NRND, ...) is kept as its own notice so MP -> NRND shows up as a change."""
    published = re.search(r"Publish Date:\s*(\d{4})/(\d{1,2})/(\d{1,2})", text)
    pub = f"{published.group(1)}-{int(published.group(2)):02d}-{int(published.group(3)):02d}" if published else ""
    out, seen = [], set()
    for page in text.split("\f"):
        out += _nuvoton_page(page, source, pub, seen)
    return out


def _nuvoton_page(page: str, source: str, pub: str, seen: set) -> list[Record]:
    """One PDF page. In the 2023 layout the PLP year is a cell merged across rows (printed once, mid-block); rows
    without a year take it only when it is the single year printed on the page, otherwise they are skipped."""
    years = set(re.findall(r"(?m)\s(\d{4}(?:/\d{1,2})?)\s*$", page))
    merged = next(iter(years)) if len(years) == 1 else None
    out = []
    for line in page.splitlines():
        cells = re.split(r"\s{2,}", line.strip())
        if cells and cells[0].isdigit():
            cells = cells[1:]                         # 'No.' column (2026 layout)
        year_at = next((i for i, c in enumerate(cells) if re.fullmatch(r"\d{4}(?:/\d{1,2})?", c)), None)
        if year_at == 1 and " " in cells[0]:          # 'M0A23EC1ACU Microcontrollers Arm Cortex-M0 MCUs   2033'
            cells, year_at = cells[0].split(" ", 1) + cells[1:], 2
        if (year_at is None and merged and len(cells) >= 3 and re.fullmatch(r"[\d.]+[nu]m\b.*", cells[-1])
                and re.fullmatch(r"[A-Z0-9][A-Z0-9-]{4,}", cells[0]) and cells[0] not in seen):
            seen.add(cells[0])                        # 'I2115SYI   SMIC   0.18um EF' (line, family, year merged)
            out.append(Record("Nuvoton PLP", cells[0], "", merged.replace("/", "-"), "official", source,
                              f"{cells[0]}: PLP year {merged} (merged table cell, the only year on this page)"
                              + (f"; list published {pub}" if pub else "")))
            continue
        if year_at is None or year_at < 2 or not re.fullmatch(r"[A-Z0-9][A-Z0-9-]{4,}", cells[0]) or cells[0] in seen:
            continue                                  # year_at 2: line and family merged (single-spaced, 2023 layout)
        part, product_line, family = cells[0], cells[1], " ".join(cells[2:year_at])
        y, _, mo = cells[year_at].partition("/")
        eol = f"{y}-{int(mo):02d}" if mo else y
        status = cells[year_at + 1] if len(cells) > year_at + 1 else ""
        seen.add(part)
        out.append(Record("Nuvoton PLP", part, "", eol, "official", source,
                          f"{part} ({product_line}{', ' + family if family else ''}): PLP year {cells[year_at]}"
                          + (f", status {status}" if status else "") + (f"; list published {pub}" if pub else "")))
        if status:
            out.append(Record("Nuvoton PLP", f"{part} status: {status}", "", "", "notice", source,
                              f"{part} status '{status}' in the Nuvoton PLP list" + (f" published {pub}" if pub else "")))
    return out


BECKHOFF_PAGES = {"Beckhoff IPC": "https://www.beckhoff.com/en-gb/support/service-products/ipc-service-products/",
                  "Beckhoff Motion": "https://www.beckhoff.com/en-gb/support/service-products/motion-service-products/"}


def parse_beckhoff_service(page: str, component: str, source: str) -> list[Record]:
    """Beckhoff service-products table: product, (description, processor), status, discontinuation (dd.mm.yyyy),
    successor. Rows with merged cells have fewer columns, so fields are found by pattern, not position.
    'Discontinuation' = end of delivery; the status (e.g. 'Service phase') says repairs/service continue."""
    out, seen = [], set()
    for row in re.findall(r"(?s)<tr.*?</tr>", page):
        cells = [html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c))).strip()
                 for c in re.findall(r"(?s)<td[^>]*>(.*?)</td>", row)]
        at = next((i for i, c in enumerate(cells) if re.fullmatch(r"\d{2}\.\d{2}\.\d{4}", c)), None)
        if at is None or at < 1 or not cells[0] or cells[0] in seen:
            continue
        d, mo, y = cells[at].split(".")
        status = cells[at - 1] if at >= 2 else ""
        successor = cells[at + 1] if len(cells) > at + 1 else ""
        seen.add(cells[0])
        out.append(Record(component, cells[0], "", f"{y}-{mo}-{d}", "official", source,
                          f"{cells[0]}: discontinued (end of delivery) {cells[at]}"
                          + (f"; status '{status}'" if status else "") + (f"; successor named by Beckhoff: {successor}" if successor else "")))
    return out
