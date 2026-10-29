import gzip
import json
import re
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from supportdates.backfill import history_events, snapshots, ts_date
from supportdates.cli import (SITE_CONFIG, sitemap_xml, alerts_section, api_date, bms_page, carry_over_hashes, services_section, bridge_events, carry_over, eol_api, gunzip_if_needed,
                            item_pages, public_only, raw_keeper, rss_feed, slug)
from supportdates.sources import (Record, espidf_policy_months, freertos_lts_branches, parse_espidf,
                                  parse_criticallink, parse_espressif_advisories, parse_nxp_longevity, parse_phytec, parse_somlabs, parse_toradex_module, toradex_module_pages, _toradex_pdf_date, parse_rpi_eol_notice, rpi_notice_links, parse_freertos_lts, prefer_official, parse_kernel, parse_mbedtls, parse_openwrt, parse_rpi_brief,
                                  parse_variscite, parse_yocto, parse_zephyr, parse_sma_support,
                                  parse_apsystems_support, parse_solaredge_support, parse_renesas_plp,
                                  parse_ncs_release_notes, ncs_major_releases,
                                  parse_jetson_lifecycle, parse_toradex_bsp_lifecycle,
                                  parse_jci_eos, parse_ignition_lts, parse_tridium_n5_faq,
                                  parse_nuvoton_plp, parse_beckhoff_service, parse_openssl, parse_python, parse_nodejs, parse_containerd, parse_qt, parse_mender, parse_moby)
from supportdates.store import collapse_new_sources, diff, document_changes

ZEPHYR = """    * - `Zephyr 4.3.0`_
      - 2025-11-14
      - 2026-10-15
      - Stable
      - * :doc:`Release Notes <release-notes-4.3>`
    * - `Zephyr 3.7.0 (LTS3)`_
      - 2024-07-26
      - 2029-07-27
      - Long Term Support
+-------------------------+---------------+
| `Zephyr 2.7.6 (LTS2)`_  | 2025-01-26    |
"""
MBEDTLS = """lifetime of three years.On this basis, Mbed TLS 3.6 LTS (released in March 2024)
will be supported until March 2027. Due to the size and scope of the 4.0 release,
the first 4.x LTS, version 4.1, was released two years after 3.6, in March 2026,
and will be supported until March 2029."""
KERNEL = "<tr><td>6.6</td><td>Greg Kroah-Hartman &amp; Sasha Levin</td><td>2023-10-29</td><td>Dec, 2027</td></tr>"


class ParseTest(unittest.TestCase):
    def test_zephyr(self):
        recs = {r.line: r for r in parse_zephyr(ZEPHYR)}
        self.assertEqual(recs["4.3"].eol, "2026-10-15")
        self.assertEqual(recs["3.7 LTS"].eol, "2029-07-27")
        self.assertEqual(recs["2.7 LTS"].eol, "2025-01-26")

    def test_mbedtls(self):
        recs = {r.line: r for r in parse_mbedtls(MBEDTLS)}
        self.assertEqual((recs["3.6"].released, recs["3.6"].eol), ("2024-03", "2027-03"))
        self.assertEqual((recs["4.1"].released, recs["4.1"].eol), ("2026-03", "2029-03"))

    def test_kernel(self):
        r = parse_kernel(KERNEL)[0]
        self.assertEqual((r.line, r.released, r.eol), ("6.6", "2023-10-29", "2027-12"))

    def test_espidf_derived(self):
        self.assertEqual(espidf_policy_months("is supported for 30 months after the initial stable release date."), 30)
        rel = [{"tag_name": "v5.5", "published_at": "2025-07-21T00:00:00Z"},
               {"tag_name": "v5.5.1", "published_at": "2025-09-01T00:00:00Z"},
               {"tag_name": "v6.0", "published_at": "2026-03-20T00:00:00Z", "prerelease": False}]
        recs = {r.line: r for r in parse_espidf(rel, 30)}
        self.assertEqual(recs["5.5"].eol, "2028-01-21")
        self.assertEqual(recs["6.0"].kind, "derived")
        self.assertNotIn("5.5.1", recs)

YOCTO = """<table><tr><th>Codename</th><th>Yocto Project Version</th><th>Release Date</th><th>Current Version</th>
<th>Support Level</th></tr>
<tr><td>Wrynose (like 'rhinos')</td><td>6.0</td><td>April 2026</td><td>6.0 (May 2026)</td>
<td>Long Term Support (until April 2030)</td></tr>
<tr><td>Walnascar (aka Walna)
<td>5.2
<td>May 2025
<td>5.2.4 (October 2025)
<td>EOL since November 2025
<tr><td>Kirkstone</td><td>4.0</td><td>May 2022</td><td>4.0.33 (February 2026)</td><td>EOL</td></tr>
<tr><td>Gatesgarth</td><td>3.2</td><td>Oct 2020</td><td>3.2.4</td><td>Support for 6 months (until Apr 2021)</td></tr></table>"""
OPENWRT = """<table><tr><th>Version</th><th>Current status</th><th>Initial Release</th><th>EoL (Projected)</th></tr>
<tr><td>25.12</td><td>Supported</td><td>2026, March 06</td><td>TBD</td></tr>
<tr><td>24.10</td><td>End of Life</td><td>2025, February 06</td><td>2026, September</td></tr></table>"""
FREERTOS = """| Library | Version | LTS Until | LTS Repo URL |
|---|---|---|---|
| FreeRTOS Kernel             | 11.3.1              | 04/30/2028 | https://github.com/FreeRTOS/FreeRTOS-Kernel/tree/V11.3.1 |
"""


class MoreSourcesTest(unittest.TestCase):
    def test_yocto_only_dated_rows(self):
        recs = {r.line: r for r in parse_yocto(YOCTO)}
        self.assertEqual(sorted(recs), ["3.2 Gatesgarth", "5.2 Walnascar", "6.0 Wrynose"])
        self.assertEqual((recs["6.0 Wrynose"].released, recs["6.0 Wrynose"].eol), ("2026-04", "2030-04"))
        self.assertEqual(recs["5.2 Walnascar"].eol, "2025-11")
        self.assertEqual((recs["3.2 Gatesgarth"].released, recs["3.2 Gatesgarth"].eol), ("2020-10", "2021-04"))

    def test_openwrt(self):
        recs = {r.line: r for r in parse_openwrt(OPENWRT)}
        self.assertEqual((recs["25.12"].released, recs["25.12"].eol), ("2026-03-06", ""))
        self.assertEqual(recs["24.10"].eol, "2026-09")

    def test_freertos_branch_names_and_dates(self):
        self.assertEqual(freertos_lts_branches([{"name": "main"}, {"name": "202604-LTS"}, {"name": "202406-LTS"}]),
                         ["202406-LTS", "202604-LTS"])
        r = parse_freertos_lts(FREERTOS, "202604-LTS")[0]
        self.assertEqual((r.component, r.line, r.released, r.eol),
                         ("FreeRTOS 202604-LTS", "FreeRTOS Kernel 11.3.1", "2026-04", "2028-04-30"))
        self.assertIn("/202604-LTS/", r.source)

VARISCITE_NEW = """<div>Product Longevity</div><p>Variscite is committed ...</p>
<div><span>System on Module</span><span>Expected Longevity</span></div>
<div><a>VAR-SOM-AM62P</a><span>2040</span></div><div><a>DART-MX6</a><span>2026</span></div>
<div>Note</div><p>The expected longevity is based on relevant vendor longevity.</p>"""
VARISCITE_OLD = """<table><tr><th>System on Module</th><th>Longevity</th></tr>
<tr><td>VAR-SOM-MX6</td><td>2027</td></tr><tr><td>DART-6UL</td><td>2030+</td></tr></table><p>Note: ...</p>"""
RPI = """Production lifetime Raspberry Pi Compute Module 4 will remain in production until at least
January 2034 Compliance"""


class VendorSourcesTest(unittest.TestCase):
    def test_variscite_both_layouts(self):
        new = {r.line: r.eol for r in parse_variscite(VARISCITE_NEW)}
        self.assertEqual(new, {"VAR-SOM-AM62P": "2040", "DART-MX6": "2026"})
        old = {r.line: r.eol for r in parse_variscite(VARISCITE_OLD)}
        self.assertEqual(old, {"VAR-SOM-MX6": "2027", "DART-6UL": "2030"})
        self.assertEqual(parse_variscite("<p>maintenance page</p>"), [])

    def test_rpi_brief(self):
        r = parse_rpi_brief(RPI, "Compute Module 4", "u")[0]
        self.assertEqual((r.line, r.eol), ("Compute Module 4", "2034-01"))
        self.assertTrue(r.evidence.startswith("Raspberry Pi Compute Module 4 will remain"))


class CriticalLinkTest(unittest.TestCase):
    def test_only_pcn_rows_with_dates(self):
        page = """<table><tr><th>Document Type</th><th>Device</th><th>Document Link</th><th>Title</th><th>Release/Update Date</th></tr>
<tr><td>Errata</td><td>MitySOM-AM62</td><td>MitySOM-AM62 Errata</td><td>Revision History</td><td>11-Jun-2025</td></tr>
<tr><td>PCN</td><td>MitySOM-AM62</td><td><a href="x.pdf">PCN20230205000</a></td><td>Resolution of FAI Issues</td><td>5-June-2023</td></tr>
<tr><td>PCN</td><td>MitySOM-AM62A</td><td>PCN20250611001</td><td>EOL of 32 GB eMMC Variants</td><td>11-June-2025</td></tr></table>"""
        recs = parse_criticallink(page, "u")
        self.assertEqual([(r.component, r.line, r.released, r.kind) for r in recs],
                         [("Critical Link MitySOM-AM62", "PCN20230205000", "2023-06-05", "notice"),
                          ("Critical Link MitySOM-AM62A", "PCN20250611001", "2025-06-11", "notice")])
        self.assertEqual(recs[1].evidence, "PCN: EOL of 32 GB eMMC Variants")

    def test_four_column_layout_uses_page_family(self):
        page = """<table><tr><td>PCN</td><td>PCN20230101000</td><td>Substitute Power Supplies</td><td>1-Jan-2023</td></tr></table>"""
        r = parse_criticallink(page, "https://x/redmine/projects/armc8-platforms/wiki/Y")[0]
        self.assertEqual((r.component, r.line, r.released), ("Critical Link armc8-platforms", "PCN20230101000", "2023-01-01"))


LIVE_CONFIG = {**SITE_CONFIG, "alerts_form_action": "https://forms.example/alerts", "checkout_pro": "https://pay.example/pro",
               "checkout_team": "https://pay.example/team", "services_contact": "hello@example.com",
               "sample_report_url": "https://example.com/sample", "checkout_fact_sheet": "https://pay.example/sheet",
               "checkout_bms_watch": "https://pay.example/watch"}


class SiteTest(unittest.TestCase):
    def test_alerts_fake_door_shown_only_when_configured_and_honest(self):
        page = alerts_section(LIVE_CONFIG)
        for k in ("forms.example/alerts", "pay.example/pro", "pay.example/team", "asknau.com/en/privacy-policy/"):
            self.assertIn(k, page)
        self.assertIn("in preparation", page)                 # alerts are not claimed as live
        self.assertIn("money-back guarantee", page)
        self.assertIn("as they go live", page)
        self.assertIn("stays free and open", page)
        self.assertNotIn("reserv", page.lower())              # merchants of record restrict pre-orders

    def test_unconfigured_placeholders_never_reach_the_site(self):
        page = alerts_section(SITE_CONFIG) + services_section(SITE_CONFIG) + bms_page([], SITE_CONFIG)
        self.assertIsNone(re.search(r"\b(ALERTS_FORM_ACTION|CHECKOUT_[A-Z_]+|SERVICES_CONTACT|SAMPLE_REPORT_URL)\b", page))
        self.assertIn("in preparation", page)
        self.assertIn("mailto:supportdates@asknau.com", page)  # the one configured contact stays


class EspressifTest(unittest.TestCase):
    def test_advisories_and_preference(self):
        page = """<table><tr><td></td><td>End-of-Life Advisory for ESP-IDF v5.2 Release Branch</td>
<td>ESP-IDF v5.2 Release Branch reaches End-of-Life in August of 2026.</td><td>V1.0</td><td>AR2026-008</td></tr>
<tr><td></td><td>x</td><td>ESP-IDF v4.3 Release Branch reaches End-of-Life in end of 2023.</td><td>V1.0</td><td>AR2023-011</td></tr></table>"""
        recs = {r.line: r for r in parse_espressif_advisories(page)}
        self.assertEqual((recs["5.2"].eol, recs["4.3"].eol), ("2026-08", "2023"))
        self.assertTrue(recs["5.2"].evidence.startswith("AR2026-008:"))
        derived = Record("ESP-IDF", "5.2", "2024-02-06", "2026-08-06", "derived", "p", "e")
        other = Record("ESP-IDF", "6.0", "2026-03-20", "2028-09-20", "derived", "p", "e")
        kept = prefer_official([derived, other, recs["5.2"]])
        self.assertEqual([(r.line, r.kind) for r in kept], [("6.0", "derived"), ("5.2", "official")])


class ItemPagesTest(unittest.TestCase):
    def test_page_per_item_with_history(self):
        recs = [Record("Variscite SoM", "VAR-SOM-MX6", "", "2035", "official", "https://v/", "e")]
        ev = [{"date": "2022-10-06", "change": "eol changed", "component": "Variscite SoM", "line": "VAR-SOM-MX6",
               "old": "2027", "new": "2035", "snapshot": "https://web.archive.org/x"}]
        pages = item_pages(recs, ev, SITE_CONFIG)
        self.assertEqual(list(pages), ["variscite-som-var-som-mx6.html"])
        page = pages["variscite-som-var-som-mx6.html"]
        self.assertIn("2027 → 2035", page)
        self.assertIn("Get notified when a date moves", page)
        self.assertEqual(slug("Zephyr", "3.7 LTS"), "zephyr-3-7-lts")


class RssTest(unittest.TestCase):
    def test_newest_first_and_escaped(self):
        ev = [{"date": "2022-10-06", "change": "eol changed", "component": "Variscite SoM", "line": "VAR-SOM-MX6",
               "old": "2027", "new": "2035", "snapshot": "https://web.archive.org/x"},
              {"date": "2026-10-16", "change": "added", "component": "A&B", "line": "1", "eol": "2030"}]
        xml = rss_feed(ev, "https://s/")
        self.assertLess(xml.index("A&amp;B"), xml.index("VAR-SOM-MX6"))
        self.assertIn("2027 → 2035", xml)


class RpiEolTest(unittest.TestCase):
    def test_notice_fields(self):
        text = ("Product Obsolescence Notification Notification ID 2 Notification date 6 Oct 2025 Products Affected "
                "Raspberry Pi Compute Module 3 and Raspberry Pi Compute Module 3 Lite Reason for obsolescence x "
                "End of Life (EOL) Date 16 Oct 2025 Last time buy (LTB) Date 28 Nov 2025 Last time ship (LTS) date 30 June 2026")
        r = parse_rpi_eol_notice(text, "https://a/documents/RP-009286-PC-3-OBS2.pdf")[0]
        self.assertEqual((r.line, r.released, r.eol, r.kind), ("RP-009286", "2025-10-06", "2025-10-16", "notice"))
        self.assertIn("Compute Module 3 Lite: EOL 16 Oct 2025, LTB 28 Nov 2025, LTS 30 June 2026", r.evidence)
        self.assertEqual(parse_rpi_eol_notice("no dates here", "u"), [])

    def test_links(self):
        html_text = '<a href="https://x/documents/RP-1.pdf">a</a><a href="documents/RP-1.pdf">b</a>'
        self.assertEqual(rpi_notice_links(html_text),
                         ["https://pip-assets.raspberrypi.com/categories/1284-eol-notices/documents/RP-1.pdf"])


class SomlabsTest(unittest.TestCase):
    def test_name_split_at_code(self):
        page = """<table><tr><th>Product</th><th>Expected Longevity</th><th>Comments</th></tr>
<tr><td>SpaceSOM-8Mplus (SLS35)ARM Cortex-A53 (quad core)</td><td>2036</td><td>Longevity based on NXP production plan</td></tr>
<tr><td>Plain Board</td><td>2032+</td></tr></table>"""
        recs = {r.line: r for r in parse_somlabs(page)}
        self.assertEqual(sorted(recs), ["Plain Board", "SpaceSOM-8Mplus (SLS35)"])
        self.assertEqual(recs["SpaceSOM-8Mplus (SLS35)"].eol, "2036")
        self.assertIn("NXP production plan", recs["SpaceSOM-8Mplus (SLS35)"].evidence)
        self.assertEqual(recs["Plain Board"].eol, "2032")

    def test_tbd_rows_are_kept_without_a_date(self):
        page = "<table><tr><td>VisionSOM-V2L (SLS22)ARM Cortex-A55</td><td>TBD</td></tr></table>"
        r = parse_somlabs(page)[0]
        self.assertEqual((r.line, r.eol), ("VisionSOM-V2L (SLS22)", ""))
        self.assertIn("TBD", r.evidence)


class BridgeTest(unittest.TestCase):
    def test_change_between_archive_and_first_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "backfill").mkdir()
            (d / "snapshots").mkdir()
            old = Record("Variscite SoM", "DART-MX6", "", "2029", "official", "v", "e")
            new = Record("Variscite SoM", "DART-MX6", "", "2026", "official", "v", "e")
            other = Record("Zephyr", "4.4", "", "2027", "official", "z", "e")
            (d / "backfill" / "variscite.last.json").write_text(json.dumps(
                {"date": "2026-04-15", "snapshot": "https://web.archive.org/x", "records": [asdict(old)]}))
            (d / "snapshots" / "2026-10-16.json").write_text(json.dumps(
                {"date": "2026-10-16", "sources": {}, "records": [asdict(new), asdict(other)]}))
            ev = bridge_events(d, [d / "snapshots" / "2026-10-16.json"])
        self.assertEqual(len(ev), 1)                       # Zephyr is not part of that archive source
        self.assertEqual((ev[0]["old"], ev[0]["new"], ev[0]["date"]), ("2029", "2026", "2026-10-16"))
        self.assertIn("after 2026-04-15", ev[0]["between"])

    def test_source_added_later_bridges_to_its_own_first_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "backfill").mkdir()
            (d / "snapshots").mkdir()
            old = Record("SMA security updates", "STP50-41", "", "2030", "official", "s", "e")
            new = Record("SMA security updates", "STP50-41", "", "2026", "official", "s", "e")
            other = Record("Zephyr", "4.4", "", "2027", "official", "z", "e")
            (d / "backfill" / "sma.last.json").write_text(json.dumps(
                {"date": "2024-07-15", "snapshot": "https://web.archive.org/y", "records": [asdict(old)]}))
            snaps = [d / "snapshots" / "2026-10-15.json", d / "snapshots" / "2026-10-17.json"]
            snaps[0].write_text(json.dumps({"date": "2026-10-15", "sources": {}, "records": [asdict(other)]}))
            snaps[1].write_text(json.dumps({"date": "2026-10-17", "sources": {}, "records": [asdict(other), asdict(new)]}))
            ev = bridge_events(d, snaps)
        self.assertEqual([(e["old"], e["new"], e["date"]) for e in ev], [("2030", "2026", "2026-10-17")])


class ToradexTest(unittest.TestCase):
    def test_sitemap_and_pcn_links(self):
        sm = ("<loc>https://d/hardware/verdin-som-family/modules/</loc>"
              "<loc>https://d/hardware/verdin-som-family/modules/verdin-imx8m-plus</loc>"
              "<loc>https://d/hardware/legacy-products/other/colibri-evaluation-board</loc>"
              "<loc>https://d/hardware/hardware-resources/recommendations/x</loc>")
        self.assertEqual(toradex_module_pages(sm), ["https://d/hardware/legacy-products/other/colibri-evaluation-board",
                                                    "https://d/hardware/verdin-som-family/modules/verdin-imx8m-plus"])
        page = ('<a href="https://docs.toradex.com/111148-eol-pcn-for-0058-verdin-imx8m-plus-quad-4gb-wb-it.pdf">a</a>'
                '<a href="https://docs.toradex.com/114345-pcn-0058-v11a-v11b-20231127.pdf">b</a>'
                '<a href="https://docs.toradex.com/118679-product-change-notification-pcn_-00641100-_-x-270326-133937.pdf">c</a>')
        recs = {r.line: r for r in parse_toradex_module(page, "https://d/modules/verdin-imx8m-plus")}
        self.assertEqual(sorted(recs), ["111148", "114345", "118679"])
        self.assertEqual(recs["114345"].released, "2023-11-27")
        self.assertEqual(recs["118679"].released, "2026-03-27")
        self.assertEqual(_toradex_pdf_date("119197-pcn-apalis-imx8qp-2gb-v1.1e-2026-07-07.pdf"), "2026-07-07")
        self.assertTrue(recs["111148"].evidence.startswith("EOL notice:"))
        self.assertEqual(recs["111148"].component, "Toradex verdin-imx8m-plus")


class NxpTest(unittest.TestCase):
    def test_rows(self):
        page = """<table><tr><th>Category</th><th>Family/Series</th><th>Products</th><th>LaunchDate</th><th>10Years</th>
<th>15Years</th><th>Extended</th><th>Remains in Longevity Program until</th></tr>
<tr><td>Applications Processor</td><td>i.MX Family</td><td>MCIMX6Q6AVT10AD</td><td>Nov 2011</td><td>-</td><td></td>
<td>-</td><td>Nov 2026</td></tr></table>"""
        r = parse_nxp_longevity(page)[0]
        self.assertEqual((r.component, r.line, r.released, r.eol), ("NXP longevity", "MCIMX6Q6AVT10AD", "2011-11", "2026-11"))
        self.assertIn("i.MX Family", r.evidence)

    def test_listed_without_end_date(self):
        page = """<table><tr><td>Processors</td><td>Layerscape</td><td>LX2120A , LX2122A</td><td>Feb 2020</td><td>-</td>
<td>-</td><td></td><td>-</td></tr></table>"""
        r, = parse_nxp_longevity(page)
        self.assertEqual((r.line, r.eol, r.kind), ("LX2120A, LX2122A", "", "official"))
        self.assertIn("no end date given", r.evidence)

    def test_transition_pages_keep_parts_only_in_the_old_table(self):
        page = """<table><tr><td>Processors</td><td>PowerQUICC III</td><td>MPC8548</td><td>Jul 2004</td><td></td><td>-</td>
<td>-</td><td>Jul 2019</td></tr></table><table><tr><td>Networking</td><td>PowerQUICC III</td><td>MPC8560</td>
<td><span class="icon-checkmark"></span></td><td>-</td><td>Jul 2002</td></tr><tr><td>Networking</td><td>PowerQUICC III</td>
<td>MPC8548</td><td><span class="icon-checkmark"></span></td><td>-</td><td>Jul 2004</td></tr></table>"""
        recs = {r.line: r for r in parse_nxp_longevity(page)}
        self.assertEqual({k: (r.eol, r.kind) for k, r in recs.items()},
                         {"MPC8548": ("2019-07", "official"), "MPC8560": ("2012-07", "derived")})


class NxpOldLayoutTest(unittest.TestCase):
    def test_checkmark_tier(self):
        page = """<table><tr><td>Applications Processor</td><td>i.MX Family</td><td><a href="x">MCIMX6S6AVM08AC</a></td>
<td></td><td><span class="icon-checkmark text-center"></span></td><td>Nov 2012</td></tr>
<tr><td>Microcontrollers</td><td>S32</td><td>S32K11x</td><td><span class="icon-checkmark"></span></td><td></td>
<td>Nov 2018</td></tr><tr><td>A</td><td>B</td><td>NoTier</td><td></td><td></td><td>Jan 2015</td></tr></table>"""
        recs = {r.line: r for r in parse_nxp_longevity(page)}
        self.assertEqual(sorted(recs), ["MCIMX6S6AVM08AC", "S32K11x"])
        self.assertEqual((recs["MCIMX6S6AVM08AC"].eol, recs["MCIMX6S6AVM08AC"].kind), ("2027-11", "derived"))
        self.assertEqual(recs["S32K11x"].eol, "2028-11")

    def test_malformed_rows_and_both_tiers(self):
        page = """<table><tr><td>Microcontrollers </td><td>16-bit S12 MagniV </td><td><a href="x">S12ZVFP </a> <td></td>
<td><span class="icon-checkmark text-center"></span></td><td>Feb 2014</td></tr>
<td>Analog and Power Management</td><tr><td>Audio</td><td><a href="y">SGTL5000</a></td>
<td><span class="icon-checkmark text-center"></span></td><td></td><td>Jun 2008</td></tr>
<tr><td>Processors</td><td>i.MX 6 Series</td><td>i.MX 6Dual</td><td>i.MX 6Dual (Industrial, Auto)</td>
<td>November 2012</td></tr></table>"""
        recs = {r.line: r.eol for r in parse_nxp_longevity(page)}
        self.assertEqual(recs, {"S12ZVFP": "2029-02", "SGTL5000": "2018-06", "i.MX 6Dual": "2022-11",
                                "i.MX 6Dual (Industrial, Auto)": "2027-11"})


class PhytecTest(unittest.TestCase):
    def test_cards(self):
        page = """<div><h3>phyCORE-RK3288</h3><p>Root Part #: PCM-059</p><p>Launch Date: 2018</p>
<p>Expected Longevity: 2021+</p><p>Processor: RK3288</p><a>Get a Quote</a></div>
<div><h3>phyCORE-AM62x</h3><p>Launch Date: 2023</p><p>Expected Longevity: 2036+</p></div>
<div><h3>phyBOARD-Nash</h3><p>Processor: x</p></div>"""
        recs = {r.line: r for r in parse_phytec(page, "u")}
        self.assertEqual(sorted(recs), ["phyCORE-AM62x", "phyCORE-RK3288 (PCM-059)"])
        self.assertEqual((recs["phyCORE-RK3288 (PCM-059)"].released, recs["phyCORE-RK3288 (PCM-059)"].eol), ("2018", "2021"))
        self.assertEqual(recs["phyCORE-AM62x"].eol, "2036")


class NxpDuplicateTest(unittest.TestCase):
    def test_repeated_names_merge_to_latest_end(self):
        page = """<table><tr><th>h</th></tr>
<tr><td>Analog</td><td>Fam A</td><td>MC33742</td><td>Jun 2008</td><td>-</td><td></td><td>-</td><td>Jun 2023</td></tr>
<tr><td>Automotive</td><td>Fam B</td><td>MC33742</td><td>Jan 2004</td><td>-</td><td></td><td>-</td><td>Jan 2019</td></tr>
<tr><td>Analog</td><td>Fam C</td><td>UNIQUE1</td><td>Jan 2010</td><td>-</td><td></td><td>-</td><td>Jan 2025</td></tr></table>"""
        recs = {r.line: r for r in parse_nxp_longevity(page)}
        self.assertEqual(sorted(recs), ["MC33742", "UNIQUE1"])
        self.assertEqual(recs["MC33742"].eol, "2023-06")
        self.assertIn("listed in 2 rows", recs["MC33742"].evidence)


class Nxp2017LayoutTest(unittest.TestCase):
    def test_name_in_tier_column(self):
        page = """<table><tr><th>Category</th><th>Family/Series</th><th>10-Year</th><th>15-Year</th><th>Product Launched</th></tr>
<tr><td>Applications Processor</td><td>i.MX Family</td><td>-</td><td title="i.MX6Q">MCIMX6Q6AVT10AD</td><td>November 2011</td></tr>
<tr><td>Applications Processor</td><td>i.MX Family</td><td><a href="x">MCIMX6Q7CVT08AD</a></td><td>-</td><td>November 2011</td></tr></table>"""
        recs = {r.line: r for r in parse_nxp_longevity(page)}
        self.assertEqual((recs["MCIMX6Q6AVT10AD"].released, recs["MCIMX6Q6AVT10AD"].eol), ("2011-11", "2026-11"))
        self.assertEqual(recs["MCIMX6Q7CVT08AD"].eol, "2021-11")


class CarryOverTest(unittest.TestCase):
    def test_only_failed_sources_are_carried(self):
        prev = [Record("OpenWrt", "24.10", "", "2026-09", "official", "ow", "e"),
                Record("Zephyr", "4.3", "", "2026-10-15", "official", "z", "e")]
        self.assertEqual([r.line for r in carry_over(prev, {"ow"})], ["24.10"])
        self.assertEqual(carry_over(prev, set()), [])


class BackfillTest(unittest.TestCase):
    def test_snapshots_only_200(self):
        cdx = '[["timestamp","statuscode","digest"],["20180406211658","200","A"],["20190523143651","301","B"],' \
              '["20200726000000","200","C"]]'
        self.assertEqual(snapshots(cdx), ["20180406211658", "20200726000000"])
        self.assertEqual(ts_date("20200726000000"), "2020-07-26")

    def test_events_skip_unparsable_captures(self):
        a = [Record("V", "X", "", "2027", "official", "u", "e")]
        b = [Record("V", "X", "", "2035", "official", "u", "e")]
        ev = history_events([("20180101000000", a), ("20190101000000", []), ("20221006000000", b)], "url")
        self.assertEqual([e["change"] for e in ev], ["baseline", "eol changed"])
        self.assertEqual((ev[1]["date"], ev[1]["old"], ev[1]["new"]), ("2022-10-06", "2027", "2035"))
        self.assertIn("/web/20221006000000id_/url", ev[1]["snapshot"])
        self.assertIn("/web/20180101000000id_/url", ev[1]["previous"])

    def test_method_switch_derived_to_stated_is_not_a_vendor_change(self):
        a = [Record("NXP", "i.MX53", "2011", "2025", "derived", "u", "e"),
             Record("NXP", "K64", "2014", "2029", "official", "u", "e")]
        b = [Record("NXP", "i.MX53", "2011", "2027-12", "official", "u", "e"),
             Record("NXP", "K64", "2014", "2031", "official", "u", "e")]
        ev = history_events([("20200101000000", a), ("20210304000000", b)], "url")
        self.assertEqual([(e["change"], e.get("line")) for e in ev], [("baseline", None), ("eol changed", "K64")])


class CollapseNewSourcesTest(unittest.TestCase):
    def test_new_component_becomes_one_event(self):
        changes = [{"change": "added", "component": "NVIDIA Jetson", "line": f"m{i}", "eol": "2032"} for i in range(3)]
        changes += [{"change": "added", "component": "Zephyr", "line": "4.5", "eol": "2027"},
                    {"change": "eol changed", "component": "Zephyr", "line": "3.7 LTS", "old": "a", "new": "b"}]
        out = collapse_new_sources(changes, {"Zephyr"})
        self.assertEqual([c["change"] for c in out], ["added", "eol changed", "source added"])
        self.assertEqual(out[-1], {"change": "source added", "component": "NVIDIA Jetson", "line": "3 records"})


class DocumentChangesTest(unittest.TestCase):
    def test_changed_added_removed(self):
        old = {"variscite": "aaa", "rpi:CM4": "bbb", "gone": "ccc", "carried_over_from": "x"}
        new = {"variscite": "aaa", "rpi:CM4": "ddd", "new": "eee"}
        ch = {c["line"]: c["change"] for c in document_changes(old, new)}
        self.assertEqual(ch, {"rpi:CM4": "document changed", "gone": "document removed", "new": "document added"})


class DiffTest(unittest.TestCase):
    def test_moved_eol_is_reported(self):
        old = [Record("Zephyr", "3.7 LTS", "2024-07-26", "2027-01-26", "official", "u", "e")]
        new = [Record("Zephyr", "3.7 LTS", "2024-07-26", "2029-07-27", "official", "u", "e"),
               Record("Zephyr", "4.4", "2026-04-14", "2027-04-12", "official", "u", "e")]
        changes = diff(old, new)
        self.assertIn({"change": "eol changed", "component": "Zephyr", "line": "3.7 LTS",
                       "old": "2027-01-26", "new": "2029-07-27", "kind": "official", "old_kind": "official"}, changes)
        self.assertEqual(sum(1 for c in changes if c["change"] == "added"), 1)

    def test_combined_cell_is_a_rename(self):
        old = [Record("NXP longevity", "LX2080A", "2020-02", "2035-02", "derived", "u", "e")]
        new = [Record("NXP longevity", "LX2080A, LX2082A", "2020-02", "2035-02", "derived", "u", "e")]
        self.assertEqual(diff(old, new), [{"change": "renamed", "component": "NXP longevity",
                                           "line": "LX2080A, LX2082A", "old": "LX2080A", "new": "LX2080A, LX2082A"}])

    def test_added_precision_is_a_refinement_not_a_move(self):
        old = [Record("Nuvoton PLP", "I2361SYI", "", "2033", "official", "u", "e"),
               Record("Nuvoton PLP", "ML51PC0AE", "", "2033", "official", "u", "e")]
        new = [Record("Nuvoton PLP", "I2361SYI", "", "2033-06", "official", "u", "e"),
               Record("Nuvoton PLP", "ML51PC0AE", "", "2034-06", "official", "u", "e")]
        self.assertEqual([(c["line"], c["change"]) for c in diff(old, new)],
                         [("I2361SYI", "eol refined"), ("ML51PC0AE", "eol changed")])


SMA_RAW = """Technical Information
Support time of SMA products with regard to
security updates
Product Minimum support time1)
SUNNY TRIPOWER STP 50-41 until the end of 2026
STPS30-20, STPS50-20 until the end of 2027
STP5.0-3SE-40, STP6.0-3SE-40,
STP10.0-3SE-40
until the end of 2026
SUNNY ISLAND SI30-20, SI50-20 until the end of 2027
1) *The support time is reviewed regularly and adjusted as necessary to meet current requirements.
Update-Support-TI-en-16 | Version 1.6
Product Minimum support time1)
Charging Stations EVCB-LB-3AC-10, EVCB-LB-3AC-
EC-10
until the end of 2026
"""

APS_RAW = """Product Security Update Support
improvements. We will maintain the security updates for at least 2 years from the launch day of
Product List
Product Name Type designation Launch Date
End date of security
update support
Microinverter
EZ1-H, EZ1-M,
EZ1-SPE
2023-06 2025-06
... ... ... ...
Software List
Software Name Launch Date
AP EasyPower 2023-04 2025-04
"""

SE_RAW = """Version 1.1 June 2024
Product Name Part Number Security Updates
Support Period
SolarEdge Home Hub Inverter –
Single-Phase
SExxxxH-RWBMNBF54 End of 2029
SolarEdge Three Phase Commercial
Inverter
SE20K-SE40K SExxK-RW0xIBNx4 End of 2029
SE50K-SE120K - SExxxK-
RW0xIBxx4
End of 2029
SolarEdge Home Load Controller SEM-DCS-R08-00 End of 2025
"""


class EnergySupportPeriodTest(unittest.TestCase):
    def test_sma_groups_models_and_normalises_spaces(self):
        recs = {r.line: r for r in parse_sma_support(SMA_RAW)}
        self.assertEqual(recs["STP50-41"].eol, "2026")
        self.assertEqual(recs["STPS50-20"].eol, "2027")
        self.assertEqual(recs["STP10.0-3SE-40"].eol, "2026")
        self.assertEqual(recs["SI30-20"].eol, "2027")
        self.assertEqual(recs["EVCB-LB-3AC-EC-10"].eol, "2026")
        self.assertIn("v1.6", recs["SI30-20"].evidence)
        self.assertEqual(len(recs), 10)

    def test_apsystems_models_and_software(self):
        recs = {r.line: r for r in parse_apsystems_support(APS_RAW)}
        self.assertEqual(sorted(recs), ["AP EasyPower", "EZ1-H", "EZ1-M", "EZ1-SPE"])
        self.assertEqual((recs["EZ1-M"].released, recs["EZ1-M"].eol), ("2023-06", "2025-06"))

    def test_solaredge_rows_and_inherited_name(self):
        recs = parse_solaredge_support(SE_RAW)
        self.assertEqual([r.eol for r in recs], ["2029", "2029", "2029", "2025"])
        self.assertEqual(recs[0].line, "SolarEdge Home Hub Inverter – Single-Phase SExxxxH-RWBMNBF54")
        self.assertEqual(recs[2].line, "SolarEdge Three Phase Commercial Inverter SE50K-SE120K - SExxxK-RW0xIBxx4")


class RenesasPlpTest(unittest.TestCase):
    PAGE = """<table><tr><td>Product</td><td>Main applicable products</td></tr>
<tr><td><a>Microcontrollers</a></td><td><a>RA</a> , <a>RZ</a> , etc.</td></tr>
<tr><td><a>Other MCUs &amp; MPUs</a></td><td><p>SuperH RISC engine Family<br><a>SH7124</a>, <a>SH7125</a></p>
<p>H8S Family<br><a>H8S/2456</a>, <a>H8S/2456R</a></p></td></tr>
<tr><td>MRAM</td><td>M30042040108X0I ,&nbsp; M30042040108X0P</td></tr></table>"""

    def test_members_with_family_context(self):
        recs = {r.line: r for r in parse_renesas_plp(self.PAGE)}
        self.assertEqual(sorted(recs), ["H8S/2456", "H8S/2456R", "M30042040108X0I", "M30042040108X0P", "RA", "RZ",
                                        "SH7124", "SH7125"])
        self.assertIn("Other MCUs & MPUs / SuperH RISC engine Family", recs["SH7124"].evidence)
        self.assertIn("(MRAM)", recs["M30042040108X0P"].evidence)
        self.assertEqual(recs["RA"].eol, "")

    def test_single_entry_cell_is_an_item_not_a_heading(self):
        recs = parse_renesas_plp("<tr><td>Power devices</td><td><a>Smart Power Stages</a></td></tr>")
        self.assertEqual([r.line for r in recs], ["Smart Power Stages"])

    def test_trademark_and_file_links_normalised(self):
        page = ("<tr><td>Renesas Synergy&trade; Platform</td><td>Renesas SynergyTM Microcontrollers S7 Series, PDF, "
                "612 KB</td></tr>")
        recs = parse_renesas_plp(page)
        self.assertEqual([r.line for r in recs], ["Renesas Synergy Microcontrollers S7 Series"])
        self.assertIn("(Renesas Synergy Platform)", recs[0].evidence)

    def test_wildcard_generalisation_is_not_a_removal(self):
        old = [Record("Renesas PLP", "ISL28130", "", "", "official", "s", "e")]
        new = [Record("Renesas PLP", "ISL*", "", "", "official", "s", "e")]
        changes = {c["change"]: c for c in diff(old, new)}
        self.assertEqual(sorted(changes), ["added", "listed under wildcard"])
        self.assertEqual(changes["listed under wildcard"]["new"], "ISL*")


class NcsTest(unittest.TestCase):
    NOTES = """Highlights
**********

* The |NCS| v3.4.0 is based on Zephyr 4.4.

  This release has long-term support (LTS) for a period of five years.

* The |NCS| v3.4.0 and its patch releases are the last |NCS| releases that include support for nRF52 Series devices.
"""

    def test_lts_and_last_series_notice(self):
        recs = parse_ncs_release_notes(self.NOTES, "3.4", "2026-07-01", "u")
        self.assertEqual([(r.line, r.eol, r.kind) for r in recs],
                         [("3.4 LTS", "2031-07", "derived"), ("3.4 last release with nRF52 Series devices", "", "notice")])

    def test_non_lts_release_gives_nothing(self):
        self.assertEqual(parse_ncs_release_notes("Highlights\n* Added things.", "3.3", "2026-03-01", "u"), [])

    def test_major_release_listing(self):
        names = ["release-notes-3.3.0.rst", "release-notes-3.3.1.rst", "release-notes-3.10.0.rst",
                 "release-notes-3.4.0-preview1.rst", "release-notes-2.9.0.rst"]
        self.assertEqual(ncs_major_releases([{"name": n} for n in names], last=2), ["3.3", "3.10"])


class JetsonTest(unittest.TestCase):
    PAGE = """<table><tr><th>Commercial Module</th><th>Available through</th></tr>
<tr><td>Jetson AGX Orin 64GB</td><td>January 2032</td></tr></table>
<table><tr><th>Industrial Module</th><th>Available through</th></tr>
<tr><td>Jetson AGX Xavier Industrial</td><td>July 2027</td></tr><tr><td>Jetson AGX Xavier (32GB)</td><td>January 2028</td></tr></table>
<table><tr><th>Module</th><th>Date of EOL</th></tr><tr><td>Jetson TX1</td><td>January 2021</td></tr>
<tr><td>Jetson Nano Developer Kit</td></tr></table>"""

    def test_sections_dates_and_devkit_notices(self):
        recs = {r.line: r for r in parse_jetson_lifecycle(self.PAGE)}
        self.assertEqual(recs["Jetson AGX Xavier Industrial"].eol, "2027-07")
        self.assertIn("Industrial Module: Available through July 2027", recs["Jetson AGX Xavier Industrial"].evidence)
        self.assertIn("Date of EOL", recs["Jetson TX1"].evidence)
        self.assertEqual(recs["Jetson AGX Xavier 32GB"].eol, "2028-01")      # parentheses dropped: renames stay one line
        self.assertEqual((recs["Jetson Nano Developer Kit"].kind, recs["Jetson Nano Developer Kit"].eol), ("notice", ""))


class ToradexBspTest(unittest.TestCase):
    PAGE = ("<table><thead><tr><th>Version<th>State<th>Initial Release Date<th>Projected EOL<th>Extended EOL"
            "<th>Release Periodicity<tbody><tr><td>BSP 7<td>Active<td>October 2024<td>2028<td><a href=#!>Contact us</a>"
            "<td>Quarterly<tr><td>BSP 6<td>Maintenance<td>October 2022<td>2026<td><a>Contact us</a><td>No Releases</table>")

    def test_versions_dates_and_state_records(self):
        recs = {r.line: r for r in parse_toradex_bsp_lifecycle(self.PAGE)}
        self.assertEqual((recs["BSP 7"].released, recs["BSP 7"].eol), ("2024-10", "2028"))
        self.assertIn("release periodicity Quarterly", recs["BSP 7"].evidence)
        self.assertEqual(recs["BSP 6 state: Maintenance"].kind, "notice")
        self.assertEqual(len(recs), 4)

    def test_old_torizon_prefix_is_the_same_line(self):
        page = self.PAGE.replace("<td>BSP 7<td>", "<td>Torizon/BSP 7<td>")
        self.assertIn("BSP 7", {r.line for r in parse_toradex_bsp_lifecycle(page)})


class JciEosTest(unittest.TestCase):
    ROW = "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
    PAGE = ("<h3>Metasys - EOS notices</h3><table>" + ROW.format("Metasys Release 12 (Server & Engine)", "12.x", "Global",
            "February 2025", "EOS") + "</table><h3>Controls – Fire &amp; Life Safety – EOS Notices</h3><table>"
            + ROW.format("Smoke Panel X", "", "Global", "May 2024", "F-1") + "</table>"
            "<h3>Controls – Control Panels &amp; Enclosures – EOS Notices</h3><table>"
            + ROW.format("S300 Security Enclosure", "", "Global", "May 2024", "P-1")
            + ROW.format("Digital Thermostat T1000", "", "Europe", "August 2026", "TC-1") + "</table>")

    def test_bms_sections_only_and_safety_excluded(self):
        recs = {r.line: r for r in parse_jci_eos(self.PAGE)}
        self.assertEqual(sorted(recs), ["Digital Thermostat T1000 [Europe]", "Metasys Release 12 (Server & Engine) 12.x"])
        self.assertEqual(recs["Metasys Release 12 (Server & Engine) 12.x"].eol, "2025-02")
        self.assertIn("notice TC-1", recs["Digital Thermostat T1000 [Europe]"].evidence)


class EolApiTest(unittest.TestCase):
    def test_endoflife_date_compatible_cycles(self):
        recs = [Record("Zephyr", "3.7 LTS", "2024-07-26", "2029-07-27", "official", "z", "e"),
                Record("NVIDIA Jetson", "Jetson AGX Xavier Industrial", "", "2027-07", "official", "n", "e"),
                Record("Toradex BSP", "BSP 7", "2024-10", "2028", "official", "t", "e"),
                Record("Toradex BSP", "BSP 7 state: Active", "2024-10", "", "notice", "t", "e"),
                Record("Renesas PLP", "RA", "", "", "official", "r", "e")]
        api = eol_api(recs)
        self.assertEqual(sorted(api), ["nvidia-jetson", "toradex-bsp", "zephyr"])
        z = api["zephyr"][0]
        self.assertEqual((z["cycle"], z["label"], z["eol"], z["lts"]), ("3.7", "3.7 LTS", "2029-07-27", True))
        j = api["nvidia-jetson"][0]
        self.assertEqual((j["cycle"], j["eol"], j["eolPrecision"]), ("Jetson AGX Xavier Industrial", "2027-07-31", "month"))
        self.assertEqual(len(api["toradex-bsp"]), 1)                     # notices are not cycles
        self.assertEqual((api["toradex-bsp"][0]["eol"], api["toradex-bsp"][0]["releaseDate"]), ("2028-12-31", "2024-10-01"))
        self.assertIsNone(api_date(""))


class IgnitionTest(unittest.TestCase):
    PAGE = ("<table><thead><tr><th>Version<th>Date Released<th>Is LTS<th>Active Support End Date"
            "<th>Limited Support End Date<tbody><tr><td style=x>8.1 <br/> (Active Support)<td>Nov 2nd 2020<td>Yes"
            "<td>Sept 16th 2027<td>Sept 16th 2029<tr><td>8.0<td>Apr 8th 2019<td>No<td>Nov 12th 2020<td>Nov 30th 2022</table>")

    def test_two_records_per_version(self):
        recs = {r.line: r for r in parse_ignition_lts(self.PAGE)}
        self.assertEqual((recs["8.1 LTS"].released, recs["8.1 LTS"].eol), ("2020-11-02", "2029-09-16"))
        self.assertEqual(recs["8.1 LTS active support"].eol, "2027-09-16")
        self.assertEqual(recs["8.0"].eol, "2022-11-30")


class TridiumFaqTest(unittest.TestCase):
    TEXT = """WILL N4.15 BE THE LAST VERSION OF N4? Yes, Niagara 4.15 will be the last version of N4 and will serve as
our Long-Term Support (LTS) Release. As part of that support, 4.15 is planned to continue to receive updates
through Q3 of 2028. CAN I STILL ORDER NIAGARA 4 JACES? Yes, the JACE-8000 ordering closed in Europe on December
31, 2025, and closes on December 31, 2026, in the America, Middle East, Africa and Asia Pacific regions.
\u2022 December 2026 (target): Niagara 5.0 general availability."""

    def test_lts_end_ordering_close_and_ga(self):
        recs = {r.line: r for r in parse_tridium_n5_faq(self.TEXT)}
        self.assertEqual((recs["Niagara 4.15 LTS"].eol, recs["Niagara 4.15 LTS"].kind), ("2028-09", "derived"))
        self.assertEqual(recs["JACE-8000 ordering [Europe]"].eol, "2025-12-31")
        self.assertEqual(recs["JACE-8000 ordering [America, Middle East, Africa and Asia Pacific]"].eol, "2026-12-31")
        self.assertEqual(recs["Niagara 5.0 general availability (target)"].released, "2026-12")


class CarryOverPrefixTest(unittest.TestCase):
    def test_failed_listing_keeps_whole_source_family(self):
        prev = [Record("FreeRTOS 202406-LTS", "coreMQTT 2.3.1", "", "2026-06", "official",
                       "https://raw.githubusercontent.com/FreeRTOS/FreeRTOS-LTS/202406-LTS/README.md", "e"),
                Record("Zephyr", "4.4", "", "2027-04", "official", "z", "e")]
        kept = carry_over(prev, {"https://raw.githubusercontent.com/FreeRTOS/FreeRTOS-LTS/*"})
        self.assertEqual([r.line for r in kept], ["coreMQTT 2.3.1"])
        self.assertEqual(carry_over(prev, {"z"}), [prev[1]])


class LandingSectionsTest(unittest.TestCase):
    def test_services_and_bms_page(self):
        svc = services_section(LIVE_CONFIG)
        self.assertIn(SITE_CONFIG["services_url"], svc)
        self.assertNotIn("€", svc)                     # prices live only on asknau.com
        self.assertNotIn("business days", svc)        # no SLA promise
        self.assertIn("mailto:hello@example.com", svc)
        self.assertIn("example.com/sample", svc)
        self.assertNotIn("compliant", svc.lower())
        recs = [Record("Tridium Niagara", "Niagara 4.15 LTS", "", "2028-09", "derived", "t", "e"),
                Record("Zephyr", "3.7 LTS", "", "2029-07", "official", "z", "e")]
        page = bms_page(recs, LIVE_CONFIG)
        self.assertIn("Niagara 4.15 LTS", page)
        self.assertNotIn("Zephyr", page)
        self.assertIn("pay.example/sheet", page)
        for word in ("compliant", "secure ", "recommended"):
            self.assertNotIn(word, (svc + page).lower())


class CarryOverHashesTest(unittest.TestCase):
    def test_failed_documents_keep_previous_hash(self):
        prev = {"pdf:sma-support": "aa", "rpi-eol:RP-1.pdf": "bb", "rpi:CM4": "cc", "gone": "dd"}
        now = {"rpi:CM4": "ee"}
        out = carry_over_hashes(prev, now, {"doc:pdf:sma-support", "doc:rpi-eol:*", "https://x"})
        self.assertEqual(out, {"rpi:CM4": "ee", "pdf:sma-support": "aa", "rpi-eol:RP-1.pdf": "bb"})   # 'gone' stays gone


class NuvotonPlpTest(unittest.TestCase):
    TEXT = """             Nuvoton Product Longevity Program (PLP) Product List
No.   Part No.                        Product Line                       Product Family          PLP Year      Status
 7    ML51EB9AE                       Microcontrollers                   8bit 8051 MCUs            2034/6       NRND
279   NAU7802KGI                      Audio Converter                    Audio Component           2033/6        MP
                                                              Publish Date: 2026/08/06"""

    def test_parts_dates_and_status_notices(self):
        recs = {r.line: r for r in parse_nuvoton_plp(self.TEXT)}
        self.assertEqual(recs["ML51EB9AE"].eol, "2034-06")
        self.assertIn("list published 2026-08-06", recs["NAU7802KGI"].evidence)
        self.assertEqual(recs["ML51EB9AE status: NRND"].kind, "notice")
        self.assertEqual(len(recs), 4)

    def test_older_layouts_without_number_or_status(self):
        old = """   Part No.      Product Line       Product Family     PLP Year
  ML51BB9AE     Microcontrollers   8bit 8051 MCUs       2033
   M463KGCAE          Microcontrollers         Arm® Cortex®-M4 MCUs                  2033/6"""
        recs = {r.line: r.eol for r in parse_nuvoton_plp(old)}
        self.assertEqual(recs, {"ML51BB9AE": "2033", "M463KGCAE": "2033-06"})
        merged = " M030GGC1AE     Microcontrollers Arm Cortex-M0 MCUs    2033"
        self.assertEqual([(r.line, r.eol) for r in parse_nuvoton_plp(merged)], [("M030GGC1AE", "2033")])

    def test_merged_year_cell_only_when_unambiguous_on_the_page(self):
        page = """      Part No.       Product Line        Fab       Process    PLP Year
     I2115SYI                       SMIC       0.18um EF
     I2361SYI                       HHG        0.11um EF       2033
     NSP2340A                       HHG        90nm EF
                                                               2033
M0A23EC1ACU Microcontrollers Arm Cortex-M0 MCUs        2033"""
        recs = {r.line: r for r in parse_nuvoton_plp(page)}
        self.assertEqual({k: r.eol for k, r in recs.items()},
                         {"I2115SYI": "2033", "I2361SYI": "2033", "NSP2340A": "2033", "M0A23EC1ACU": "2033"})
        self.assertIn("merged table cell", recs["I2115SYI"].evidence)
        mixed = page + "\n     I9160FI                        TSMC       55nm EF         2034/6"
        self.assertNotIn("I2115SYI", {r.line for r in parse_nuvoton_plp(mixed)})   # two years: not attributable
        self.assertIn("I2115SYI", {r.line for r in parse_nuvoton_plp(mixed.replace("2034/6", "") + "\f")})


class BeckhoffTest(unittest.TestCase):
    PAGE = ("<table><tr><th>Product</th><th>Short description</th><th>Product status</th><th>Discontinuation</th>"
            "<th>Successor product</th></tr><tr><td>C3320-0070</td><td>Panel PC</td><td>Service phase</td>"
            "<td>31.01.2023</td><td>CP22xx</td></tr><tr><td>C3330-0070</td><td>Service phase</td><td>31.01.2023</td>"
            "<td>CP22xx</td></tr></table>")

    def test_rows_with_merged_cells(self):
        recs = {r.line: r for r in parse_beckhoff_service(self.PAGE, "Beckhoff IPC", "u")}
        self.assertEqual(recs["C3330-0070"].eol, "2023-01-31")
        self.assertIn("status 'Service phase'; successor named by Beckhoff: CP22xx", recs["C3330-0070"].evidence)
        self.assertIn("end of delivery", recs["C3320-0070"].evidence)


class SuffixRenameTest(unittest.TestCase):
    def test_suffix_with_same_dates_is_a_rename(self):
        old = [Record("Node.js", "27", "2026-04-22", "2030-04-30", "official", "n", "e")]
        new = [Record("Node.js", "27 LTS", "2026-04-22", "2030-04-30", "official", "n", "e")]
        self.assertEqual(diff(old, new), [{"change": "renamed", "component": "Node.js", "line": "27 LTS",
                                           "old": "27", "new": "27 LTS"}])

    def test_suffix_with_other_dates_stays_removed_and_added(self):
        old = [Record("Node.js", "27", "2026-04-22", "2030-04-30", "official", "n", "e")]
        new = [Record("Node.js", "27 LTS", "2026-04-22", "2031-04-30", "official", "n", "e")]
        self.assertEqual(sorted(c["change"] for c in diff(old, new)), ["added", "removed"])


class GunzipTest(unittest.TestCase):
    def test_gzip_bodies_are_decompressed_plain_kept(self):
        self.assertEqual(gunzip_if_needed(gzip.compress(b"<table>")), b"<table>")
        self.assertEqual(gunzip_if_needed(b"<table>"), b"<table>")


class PublicOnlyTest(unittest.TestCase):
    def test_private_components_never_published(self):
        recs = [Record("SolarEdge security updates", "SE50K", "", "2029", "official", "s", "e"),
                Record("SMA security updates", "STP50-41", "", "2026", "official", "s", "e"),
                Record("Variscite SoM", "DART-MX6", "", "2026", "official", "v", "e")]
        events = [{"component": "SolarEdge security updates", "change": "added"}, {"change": "document changed"},
                  {"component": "source", "line": "pdf:solaredge-support", "change": "document changed"},
                  {"component": "source", "line": "pdf:sma-support", "change": "document changed"}]
        self.assertEqual([r.line for r in public_only(recs)], ["STP50-41", "DART-MX6"])
        self.assertEqual(public_only(events), [{"change": "document changed"},
                                               {"component": "source", "line": "pdf:sma-support",
                                                "change": "document changed"}])


class RawKeeperTest(unittest.TestCase):
    def test_each_document_stored_once_by_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            keep = raw_keeper(Path(tmp) / "raw")
            keep("abc", b"<table>v1</table>")
            keep("abc", b"ignored: same hash")
            keep("def", b"%PDF-1.7")
            files = sorted(p.name for p in (Path(tmp) / "raw").iterdir())
            self.assertEqual(files, ["abc.gz", "def.gz"])
            self.assertEqual(gzip.decompress((Path(tmp) / "raw" / "abc.gz").read_bytes()), b"<table>v1</table>")


class OpensslPythonTest(unittest.TestCase):
    def test_openssl_supported_lines_and_ended_versions(self):
        page = ("<p>Version 4.0 will be supported until 2027-05-14</p><p>Version 3.5 will be supported until "
                "2030-04-08 (LTS)</p><p>Versions 3.0, 1.1.1 and 1.0.2 are no longer supported. Extended support "
                "for 3.0 is available.</p>")
        recs = {r.line: r for r in parse_openssl(page)}
        self.assertEqual(recs["3.5 LTS"].eol, "2030-04-08")
        self.assertEqual(recs["4.0"].kind, "official")
        self.assertEqual(sorted(k for k, r in recs.items() if r.kind == "notice"),
                         ["1.0.2 no longer supported", "1.1.1 no longer supported", "3.0 no longer supported"])

    def test_python_release_cycle_skips_unreleased(self):
        text = json.dumps({"3.16": {"status": "feature", "first_release": "2027-10-06", "end_of_life": "2032-10"},
                           "3.13": {"status": "security", "first_release": "2024-10-07", "end_of_life": "2029-10",
                                    "pep": 719}})
        r, = parse_python(text)
        self.assertEqual((r.component, r.line, r.released, r.eol), ("Python", "3.13", "2024-10-07", "2029-10"))
        self.assertIn("PEP 719", r.evidence)


class NodeContainerdTest(unittest.TestCase):
    def test_nodejs_schedule(self):
        text = json.dumps({"v0.10": {"start": "2013-03-11", "end": "2016-10-31"},
                           "v22": {"start": "2024-04-24", "lts": "2024-10-29", "end": "2027-04-30", "codename": "Jod"},
                           "v23": {"start": "2024-10-16", "end": "2025-06-01"}})
        recs = {r.line: r.eol for r in parse_nodejs(text)}
        self.assertEqual(recs, {"22 LTS": "2027-04-30", "23": "2025-06-01"})

    def test_containerd_table_and_estimates(self):
        md = """| Release | Status | Start | End of Life | Owners |
| [2.0](https://x/v2.0.13) | LTS            | November 5, 2024               | March 2027*                    | @a |
| [2.3](https://x/v2.3.6)  | LTS            | Apr 30, 2026                   | April 30, 2028                 | @b |
| [1.7](https://x/v1.7.36) | End of Life    | March 10, 2023                 | September 30, 2026             |    |"""
        recs = {r.line: r for r in parse_containerd(md)}
        self.assertEqual({k: (r.released, r.eol) for k, r in recs.items()},
                         {"2.0 LTS": ("2024-11-05", "2027-03"), "2.3 LTS": ("2026-04-30", "2028-04-30"),
                          "1.7": ("2023-03-10", "2026-09-30")})
        self.assertIn("marked * in the source", recs["2.0 LTS"].evidence)


class QtMenderMobyTest(unittest.TestCase):
    def test_qt_tables(self):
        page = ("<table><tr><th>Version</th><th>Latest release</th><th>Standard support until</th></tr>"
                "<tr><td>Qt 6.8 LTS</td><td>Qt 6.8.8 (LTS, commercial only)</td><td>2029-10-08</td></tr>"
                "<tr><td>Qt 6.9</td><td>Qt 6.9.3</td><td>Ended (ES is available)</td></tr></table>"
                "<table><tr><td>Qt 6.8 LTS</td><td>Qt 6.8.8</td><td>2029-10-08</td></tr></table>")
        recs = {r.line: r for r in parse_qt(page)}
        self.assertEqual(sorted(recs), ["6.8 LTS", "6.9 no longer supported"])
        self.assertIn("commercial only", recs["6.8 LTS"].evidence)

    def test_mender_status_cells(self):
        page = ("<table><tr><td>Mender Client 6.0</td><td>2026-03</td><td>Supported until 2027-04</td></tr>"
                "<tr><td>Mender Client 5.0</td><td>2025-01</td><td>EOL (since 2026-09)</td></tr>"
                "<tr><td>Mender Gateway 2.1</td><td>2026-06</td><td>Supported</td></tr></table>")
        got = [(r.component, r.line, r.eol, r.kind) for r in parse_mender(page)]
        self.assertEqual(got, [("Mender Client", "6.0", "2027-04", "official"),
                               ("Mender Client", "5.0 no longer supported", "2026-09", "notice"),
                               ("Mender Gateway", "2.1", "", "official")])

    def test_moby_branches(self):
        md = """| docker-29.x | The Moby Project | Maintained | After docker-30.x | Docker |
| docker-28.x |  | Unmaintained |  |  |
| 25.0 | @corhere | Maintained | [2026-12-04][mcr25-maint] | Amazon |
| 22.06 |  | Maintained (security) | 2026-01-01 |  |"""
        got = [(r.line, r.eol, r.kind) for r in parse_moby(md)]
        self.assertEqual(got, [("29", "", "official"), ("28 no longer supported", "", "notice"),
                               ("25.0", "2026-12-04", "official"), ("22.06", "2026-01-01", "official")])
        self.assertIn("informational and not binding", parse_moby(md)[0].evidence)


if __name__ == "__main__":
    unittest.main()


class SitemapTest(unittest.TestCase):
    def test_index_maps_to_root(self):
        xml = sitemap_xml(["index.html", "zephyr-3-7.html"], "https://supportdates.com/")
        self.assertIn("<loc>https://supportdates.com/</loc>", xml)
        self.assertIn("<loc>https://supportdates.com/zephyr-3-7.html</loc>", xml)
