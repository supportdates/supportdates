import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from supportdates.eolcheck import (Finding, Row, support_gap, addendum_csv, enrich_cyclonedx, fda_addendum, idf_from_lock, markdown_report, match, months_until, newer_lines,
                                   release_line, report, resolve, sbom_components, sbom_entries, sbom_finding, scan, yocto_series,
                                   zephyr_from_west)
from supportdates.sources import Record

WEST = """manifest:
  remotes:
    - name: zephyrproject-rtos
      url-base: https://github.com/zephyrproject-rtos
  projects:
    - name: hal_nordic
      revision: abc123
    - name: zephyr
      remote: zephyrproject-rtos
      revision: v3.7.0
      import: true
"""
LOCK = """dependencies:
  espressif/led_strip:
    version: 2.5.3
  idf:
    source:
      type: idf
    version: 5.2.1
manifest_hash: abc
"""
LAYER = 'BBFILE_COLLECTIONS += "mylayer"\nLAYERSERIES_COMPAT_mylayer = "scarthgap wrynose"\n'
RECS = [Record("Zephyr", "3.7 LTS", "2024-07-26", "2029-07-27", "official", "z", "e"),
        Record("ESP-IDF", "5.2", "", "2026-08", "official", "esp", "e"),
        Record("Yocto Project", "5.0 Scarthgap", "2024-04", "2028-04", "official", "y", "e"),
        Record("Yocto Project", "6.0 Wrynose", "2026-04", "2030-04", "official", "y", "e"),
        Record("Variscite SoM", "DART-MX6", "", "2026", "official", "v", "e")]


class ParseTest(unittest.TestCase):
    def test_parsers(self):
        self.assertEqual(zephyr_from_west(WEST), "v3.7.0")
        self.assertEqual(zephyr_from_west(WEST.replace("v3.7.0", "main")), "main")
        self.assertIsNone(zephyr_from_west("manifest:\n  projects:\n    - name: other\n"))
        self.assertEqual(idf_from_lock(LOCK), "5.2.1")
        self.assertEqual(yocto_series(LAYER), ["scarthgap", "wrynose"])

    def test_release_line(self):
        self.assertEqual(release_line("v3.7.0"), "3.7")
        self.assertEqual(release_line("v4.4.2"), "4.4")
        self.assertIsNone(release_line("main"))
        self.assertIsNone(release_line("0123abcd"))

    def test_months_until(self):
        self.assertEqual(months_until("2026-08", date(2026, 10, 16)), -2)
        self.assertEqual(months_until("2026", date(2026, 10, 16)), 2)
        self.assertIsNone(months_until("", date(2026, 10, 16)))


class ScanReportTest(unittest.TestCase):
    def test_project_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "west.yml").write_text(WEST)
            (p / "dependencies.lock").write_text(LOCK)
            (p / "meta-x" / "conf").mkdir(parents=True)
            (p / "meta-x" / "conf" / "layer.conf").write_text(LAYER)
            (p / "modules.txt").write_text("# modules\nDART-MX6\nUnknown-SoM\n")
            findings = scan([p])
            lines, months = report(findings, RECS, date(2026, 10, 16))
        text = "\n".join(lines)
        self.assertIn("Zephyr 3.7 LTS: end of support 2029-07-27 (+33 months)", text)
        self.assertIn("ESP-IDF 5.2: end of support 2026-08 (-2 months)", text)
        self.assertIn("Yocto Project 5.0 Scarthgap", text)
        self.assertIn("DART-MX6: end of support 2026 (+2 months)", text)
        self.assertIn("Unknown-SoM", text)
        self.assertIn(-2, months)

    def test_support_gap_names_the_shortest_software_line(self):
        zephyr = Record("Zephyr", "3.7 LTS", "", "2029-07-27", "official", "z", "e")
        idf = Record("ESP-IDF", "5.2", "", "2026-08", "derived", "i", "e")
        som = Record("Variscite SoM", "DART-MX6", "", "2026", "official", "v", "e")
        rows = [Row(Finding("w", "Zephyr v3.7.0", "Zephyr", "3.7"), zephyr, 0, ""),
                Row(Finding("d", "ESP-IDF 5.2.1", "ESP-IDF", "5.2"), idf, 0, ""),
                Row(Finding("m", "DART-MX6", "", "DART-MX6"), som, 0, "")]        # a module: not compared
        lines = support_gap(rows, "2032-01")
        self.assertEqual(lines[0], "shortest published software support: ESP-IDF 5.2, end 2026-08, 65 months before 2032-01")
        self.assertEqual(lines[1], "2 of 2 dated software lines end before 2032-01")
        self.assertIn("asknau.com", lines[2])
        self.assertEqual(support_gap(rows[:1], "2029-01"),
                         ["all 1 dated software lines reach 2029-01; shortest: Zephyr 3.7 LTS, end 2029-07-27"])
        self.assertIn("no dated software line", support_gap(rows[2:], "2032-01")[0])

    def test_unpinned_revision_is_reported(self):
        lines, months = report([Finding("west.yml", "Zephyr main", "Zephyr", "")], RECS, date(2026, 10, 16))
        self.assertIn("not a release", lines[0])
        self.assertEqual(months, [])

    def test_ncs_application_manifest(self):
        west = """manifest:
  remotes:
    - name: ncs
      url-base: https://github.com/nrfconnect
  projects:
    - name: nrf
      remote: ncs
      repo-path: sdk-nrf
      revision: v3.4.1
      import: true
"""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "west.yml").write_text(west)
            found = scan([Path(tmp)])
        self.assertEqual([(f.component, f.line_hint) for f in found], [("nRF Connect SDK", "3.4")])
        recs = [Record("nRF Connect SDK", "3.4 LTS", "2026-07-01", "2031-07", "derived", "n", "e"),
                Record("nRF Connect SDK", "3.4 last release with nRF52 Series devices", "2026-07-01", "", "notice", "n",
                       "v3.4.0 and its patch releases are the last releases that include support for nRF52")]
        lines, months = report(found, recs, date(2026, 10, 17))
        self.assertIn("end of support 2031-07 (+57 months)", lines[0])
        self.assertIn("notice: v3.4.0 and its patch releases are the last", lines[1])
        self.assertEqual(months, [57])

    def test_sbom_cyclonedx_and_spdx(self):
        cdx = json.dumps({"bomFormat": "CycloneDX", "components": [
            {"name": "linux-yocto", "version": "6.6.52+git", "components": [{"name": "mbedtls", "version": "3.6.2"}]},
            {"name": "poky", "version": "5.0.12"}, {"name": "zlib", "version": "1.3.1"},
            {"name": "FreeRTOS-Kernel", "version": "V11.1.0"}]})
        spdx = json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "zephyr", "versionInfo": "v3.7.0"}]})
        self.assertEqual(sbom_components(spdx), [("zephyr", "v3.7.0")])
        hints = [(f.component, f.line_hint) for c in sbom_components(cdx) if (f := sbom_finding(*c, "bom.json"))]
        self.assertEqual(hints, [("Linux kernel LTS", "6.6"), ("Yocto Project", "5.0"), ("", "FreeRTOS Kernel 11.1.0"),
                                 ("Mbed TLS", "3.6")])
        recs = [Record("Yocto Project", "5.0 Scarthgap", "2024-04", "2028-04", "official", "y", "e")]
        self.assertEqual(match(Finding("bom.json", "poky 5.0.12", "Yocto Project", "5.0"), recs)[0].line, "5.0 Scarthgap")
        self.assertEqual(sbom_components("not json"), [])

    def test_enrich_cyclonedx_adds_sourced_properties(self):
        doc = {"bomFormat": "CycloneDX", "components": [{"name": "poky", "version": "5.0.12"},
                                                         {"name": "zlib", "version": "1.3.1"}]}
        recs = [Record("Yocto Project", "5.0 Scarthgap", "2024-04", "2028-04", "official", "y", "e")]
        out = enrich_cyclonedx(doc, recs, "2026-10-18")
        props = {p["name"]: p["value"] for p in out["components"][0]["properties"]}
        self.assertEqual((props["supportdates:eol"], props["supportdates:source"]), ("2028-04", "y"))
        self.assertNotIn("properties", out["components"][1])
        self.assertNotIn("properties", doc["components"][0])          # input left unchanged

    def test_match_rules(self):
        self.assertEqual(len(match(Finding("f", "x", "Zephyr", "3.7"), RECS)), 1)
        self.assertEqual(match(Finding("f", "x", "Zephyr", "3.6"), RECS), [])
        self.assertEqual(match(Finding("f", "x", "", "dart-mx6"), RECS)[0].line, "DART-MX6")
        self.assertEqual(match(Finding("f", "x", "", "dart - mx6"), RECS)[0].line, "DART-MX6")


class MarkdownReportTest(unittest.TestCase):
    TODAY = date(2026, 10, 17)
    FINDINGS = [Finding("meta/conf/layer.conf", "Yocto series scarthgap", "Yocto Project", "scarthgap"),
                Finding("west.yml", "Zephyr main", "Zephyr", ""),
                Finding("modules.txt", "Unknown-SoM", "", "Unknown-SoM"),
                Finding("modules.txt", "DART-MX6", "", "DART-MX6")]

    def test_newer_lines_same_component_only(self):
        rows = resolve(self.FINDINGS, RECS, self.TODAY)
        self.assertEqual([r.line for r in newer_lines(rows, RECS, self.TODAY)], ["6.0 Wrynose"])

    def test_report_facts_sorted_and_no_verdict_words(self):
        md = markdown_report(self.FINDINGS, RECS, self.TODAY, "2026-10-17")
        self.assertIn("| Yocto series scarthgap | meta/conf/layer.conf | Yocto Project 5.0 Scarthgap | 2028-04 | +18 |", md)
        self.assertNotIn("DART-MX6: end of support", md)          # modules never get "newer" suggestions
        self.assertIn("not a release", md)
        self.assertIn("no published date in the dataset", md)
        self.assertIn("- Yocto Project 6.0 Wrynose: end of support 2030-04", md)
        for word in ("secure", "compliant", "safe ", "recommended"):
            self.assertNotIn(word, md.lower())


class FdaAddendumTest(unittest.TestCase):
    RECS = [Record("Linux kernel LTS", "6.6", "2023-10-29", "2026-12", "official", "https://kernel.org", "e"),
            Record("Linux kernel LTS", "5.4", "2019-11-24", "2025-12", "official", "https://kernel.org", "e"),
            Record("Yocto Project", "5.0 Scarthgap", "2024-04", "2028-04", "official", "https://yocto", "e"),
            Record("Zephyr", "3.7 LTS", "2024-07-26", "", "official", "https://zephyr", "e")]

    def test_one_row_per_component_with_sources_or_reasons(self):
        sbom = json.dumps({"bomFormat": "CycloneDX", "components": [
            {"name": "linux-yocto", "version": "6.6.52+git", "purl": "pkg:generic/linux-yocto@6.6.52"},
            {"name": "linux", "version": "5.4.200"}, {"name": "poky", "version": "5.0.12"},
            {"name": "zephyr", "version": "v3.7.0"}, {"name": "zephyr", "version": "main"},
            {"name": "uci", "version": "2025.01"}]})
        rows = fda_addendum(sbom_entries(sbom), self.RECS, date(2026, 10, 19), "2026-10-19 sha256:ab")
        got = [(r["component"], r["level_of_support"], r["end_of_support"]) for r in rows]
        self.assertEqual(got, [("linux-yocto", "actively maintained", "2026-12"),
                               ("linux", "no longer maintained", "2025-12"),
                               ("poky", "actively maintained", "2028-04"),
                               ("zephyr", "unknown", "not announced"),
                               ("zephyr", "unknown", ""), ("uci", "unknown", "")])
        self.assertEqual(rows[0]["purl"], "pkg:generic/linux-yocto@6.6.52")
        self.assertIn("as published", rows[0]["basis"])
        self.assertIn("not a release", rows[4]["basis"])
        self.assertEqual(rows[5]["basis"], "not covered by the dataset")
        csv_text = addendum_csv(rows)
        self.assertTrue(csv_text.startswith("component,version,purl,level_of_support,end_of_support,basis,source,"))
        self.assertIn("2026-10-19 sha256:ab", csv_text)

    def test_ended_versions_and_package_names(self):
        recs = [Record("OpenSSL", "3.5 LTS", "", "2030-04-08", "official", "o", "e"),
                Record("OpenSSL", "3.0 no longer supported", "", "", "notice", "o", "Versions 3.0 are no longer supported"),
                Record("OpenSSL", "1.1.1 no longer supported", "", "", "notice", "o", "Versions 1.1.1 are no longer supported"),
                Record("Mbed TLS", "3.6", "2024-03", "2027-03", "official", "m", "e")]
        entries = [{"name": n, "version": v, "purl": ""} for n, v in
                   (("libssl3", "3.5.1"), ("openssl", "3.0.13"), ("openssl", "1.1.1w"), ("libmbedtls", "3.6.7"))]
        rows = fda_addendum(entries, recs, date(2026, 10, 19), "s")
        self.assertEqual([(r["level_of_support"], r["end_of_support"]) for r in rows],
                         [("actively maintained", "2030-04-08"), ("no longer maintained", "passed (date not stated)"),
                          ("no longer maintained", "passed (date not stated)"), ("actively maintained", "2027-03")])

    def test_checked_policies_explain_missing_dates(self):
        entries = [{"name": n, "version": v, "purl": ""} for n, v in (("zlib", "1.3.1"), ("rust", "1.80.0"))]
        rows = fda_addendum(entries, [], date(2026, 10, 19), "s")
        self.assertEqual([r["level_of_support"] for r in rows], ["unknown", "unknown"])
        self.assertIn("no support period found at the URLs checked on 2026-10-19", rows[0]["basis"])
        self.assertEqual(rows[0]["source"], "https://zlib.net/")
        self.assertIn("most recent stable release", rows[1]["basis"])

    def test_major_only_lines_and_dated_eol_notices(self):
        recs = [Record("Node.js", "22 LTS", "2024-04-24", "2027-04-30", "official", "n", "e"),
                Record("Docker Engine", "28 no longer supported", "", "", "notice", "d", "Unmaintained"),
                Record("Mender Client", "5.0 no longer supported", "2025-01", "2026-09", "notice", "m", "EOL")]
        entries = [{"name": n, "version": v, "purl": ""} for n, v in
                   (("nodejs", "22.11.0"), ("docker-ce", "28.5.1"), ("mender-client", "5.0.3"))]
        rows = fda_addendum(entries, recs, date(2026, 10, 19), "s")
        self.assertEqual([(r["level_of_support"], r["end_of_support"]) for r in rows],
                         [("actively maintained", "2027-04-30"), ("no longer maintained", "passed (date not stated)"),
                          ("no longer maintained", "2026-09")])

    def test_spdx_purl(self):
        spdx = json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "zephyr", "versionInfo": "v3.7.0",
            "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:github/zephyrproject-rtos/zephyr@v3.7.0"}]}]})
        self.assertEqual(sbom_entries(spdx)[0]["purl"], "pkg:github/zephyrproject-rtos/zephyr@v3.7.0")


if __name__ == "__main__":
    unittest.main()
