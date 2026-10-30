import json
import unittest
from datetime import date

from supportdates.evidencepack import (Fact, coverage, dataset_facts, history, installed_recipes, later_lines, months_to,
                                       name, render, shipped_entries, tracked_since)
from supportdates.sources import Record

KERNEL = Record("Linux kernel LTS", "6.6", "2023-10-29", "2027-12", "official", "https://www.kernel.org/category/releases.html",
                "6.6: projected EOL Dec, 2027")
KERNEL_NEW = Record("Linux kernel LTS", "6.12", "2024-11-17", "2028-12", "official", KERNEL.source, "6.12")
BSP = Record("Toradex BSP", "BSP 7", "2024-10", "2028", "official", "https://developer.toradex.com/x", "BSP 7 ...")
BSP_STATE = Record("Toradex BSP", "BSP 7 state: Active", "2024-10", "", "notice", BSP.source, "Active")
RECORDS = [KERNEL, KERNEL_NEW, BSP, BSP_STATE]


def package_doc(pkg: str, recipe: str, version: str) -> str:
    return json.dumps({"spdxVersion": "SPDX-2.2", "packages": [{"name": pkg, "versionInfo": version}],
                       "relationships": [{"relationshipType": "GENERATED_FROM", "spdxElementId": f"SPDXRef-Package-{pkg}",
                                          "relatedSpdxElement": f"DocumentRef-recipe-{recipe}:SPDXRef-Recipe-{recipe}"}]})


def fact(record: Record) -> Fact:
    return Fact("x", record.component, record.line, record.eol, record.kind, "software support (as published)",
                record.source, record.evidence, "dataset 2026-10-29")


class EvidencePackTest(unittest.TestCase):
    def test_installed_recipes_groups_packages(self):
        docs = [package_doc("kernel-module-8021q", "linux-toradex-ti", "6.6.157+git"),
                package_doc("kernel", "linux-toradex-ti", "6.6.157+git"), package_doc("libssl3", "openssl", "3.5.8"),
                json.dumps({"spdxVersion": "SPDX-2.2", "packages": [{"name": "image", "versionInfo": "1.0"}]})]
        self.assertEqual(installed_recipes(docs), [
            {"name": "linux-toradex-ti", "version": "6.6.157+git", "purl": "", "packages": 2},
            {"name": "openssl", "version": "3.5.8", "purl": "", "packages": 1}])

    def test_shipped_entries_drop_build_host_tools(self):
        doc = json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "openssl", "version": "3.5.8"},
                                                                   {"name": "openssl-native", "version": "3.5.8"},
                                                                   {"name": "openssl", "version": "3.5.8"}]})
        self.assertEqual([e["name"] for e in shipped_entries([doc])], ["openssl"])

    def test_dataset_facts_platform_exact_and_sbom_match(self):
        product = {"platform": [{"what": "BSP 7.8.0", "component": "Toradex BSP", "line": "BSP 7"}]}
        entries = [{"name": "linux-toradex-ti", "version": "6.6.157+git", "purl": "", "packages": 436}]
        facts = {f.line: f for f in dataset_facts(product, entries, RECORDS, "2026-10-29")}
        self.assertEqual(set(facts), {"BSP 7", "6.6"})              # the state notice is not a support end
        self.assertEqual(facts["6.6"].what, "linux-toradex-ti 6.6.157+git (436 packages)")

    def test_months_and_coverage_against_declared_end(self):
        self.assertEqual(months_to("2027-12", "2032-01"), -49)
        self.assertEqual(months_to("2028", "2032-01"), -37)         # year-only = end of that year
        self.assertEqual(coverage(fact(KERNEL), "2032-01"), "**ends 49 months before**")
        self.assertEqual(coverage(fact(KERNEL), "2027-06"), "covers (+6 months)")
        self.assertEqual(coverage(fact(BSP_STATE), "2032-01"), "no end date published")

    def test_name_drops_repeated_word(self):
        self.assertEqual(name(fact(BSP)), "Toradex BSP 7")
        self.assertEqual(name(fact(KERNEL)), "Linux kernel LTS 6.6")

    def test_history_and_tracking(self):
        events = [{"date": "2023-09-25", "change": "baseline", "snapshot": "https://web.archive.org/web/1id_/" + BSP.source},
                  {"date": "2024-12-09", "change": "added", "component": "Toradex BSP", "line": "BSP 7 state: Active"},
                  {"date": "2024-12-09", "change": "added", "component": "Toradex BSP", "line": "BSP 7", "eol": "2028"},
                  {"date": "2026-10-18", "change": "source added", "component": "Toradex BSP", "line": "12 records"},
                  {"date": "2024-12-09", "change": "added", "component": "Toradex BSP", "line": "BSP 70"}]
        self.assertEqual(len(history(fact(BSP), events)), 2)
        self.assertEqual(tracked_since(fact(BSP), events, {("Toradex BSP", "BSP 7"): "2026-10-18"}),
                         "archive from 2023-09-25, own daily snapshots from 2026-10-18")

    def test_later_lines(self):
        self.assertEqual(later_lines([fact(KERNEL)], RECORDS), [KERNEL_NEW])

    def test_render_names_the_limit_and_proofs(self):
        product = {"product": "p", "placed_on_market": "2027-01", "declared_support_end": "2032-01", "notes": ["n1"]}
        proof = {"day": "2026-10-29", "snapshot_name": "snapshot-2026-10-29.json", "manifest_name": "2026-10-29.json",
                 "snapshot_sha256": "a" * 64, "tokens": [("2026-10-29.digicert.tsr", "digicert", "Oct 29 2026")]}
        text = render(product, [fact(BSP), fact(KERNEL)], [], {}, [], [KERNEL_NEW], proof, date(2026, 10, 29))
        self.assertIn("Shortest published software support:** Linux kernel LTS 6.6, end 2027-12", text)
        self.assertIn("2 of 2 dated software lines end before 2032-01", text)
        self.assertIn("## 5. Reading notes", text)
        self.assertIn("openssl ts -verify -in proof/2026-10-29.digicert.tsr", text)


if __name__ == "__main__":
    unittest.main()
