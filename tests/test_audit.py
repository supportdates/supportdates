import unittest
from unittest import mock

from supportdates.audit import audit_history, check, check_event, date_forms, raw_text
from supportdates.sources import Record


class AuditTest(unittest.TestCase):
    def test_date_forms(self):
        self.assertIn("March 2027", date_forms("2027-03"))
        self.assertIn("04/30/2028", date_forms("2028-04-30"))
        self.assertIn("2035", date_forms("2035"))

    def test_split_cells_and_url_ids(self):
        yocto = Record("Yocto Project", "6.1 Blacksail", "", "2027-04", "official", "u", "e")
        self.assertEqual(check(yocto, "<td>Blacksail</td><td>6.1</td><td>until April 2027</td>"), (True, True))
        tdx = Record("Toradex x", "110167", "", "", "notice", "https://docs.toradex.com/110167-pcn.pdf", "e")
        self.assertEqual(check(tdx, "Product Change Notification"), (True, True))
        wrong = Record("Variscite SoM", "DART-MX6", "", "2029", "official", "u", "e")
        self.assertEqual(check(wrong, "DART-MX6 2026"), (True, False))
        sma = Record("SMA security updates", "EVCB-LB-3AC-EC-10", "", "2026", "official", "u", "e")
        self.assertEqual(check(sma, "EVCB-LB-3AC-\nEC-10 until the end of 2026"), (True, True))
        self.assertEqual(check(Record("S", "STP50-41", "", "2026", "official", "u", "e"), "STP 50-41 2026"), (True, True))


class HistoryAuditTest(unittest.TestCase):
    BEFORE = "<tr><td>Jetson AGX Xavier Industrial</td><td>July 2031</td></tr><tr><td>IGBTs, MOSFETs</td></tr>"
    AFTER = "<tr><td>Jetson AGX Xavier Industrial</td><td>July 2027</td></tr>"

    def test_events_against_both_pages(self):
        moved = {"change": "eol changed", "line": "Jetson AGX Xavier Industrial", "old": "2031-07", "new": "2027-07"}
        self.assertEqual(check_event(moved, self.BEFORE, self.AFTER), "confirmed")
        self.assertEqual(check_event({**moved, "old": "2030-07"}, self.BEFORE, self.AFTER), "contradicted")
        self.assertEqual(check_event({"change": "removed", "line": "MOSFETs"}, self.BEFORE, self.AFTER), "confirmed")
        self.assertEqual(check_event({"change": "added", "line": "MOSFETs"}, self.BEFORE, self.AFTER), "contradicted")
        self.assertEqual(check_event({"change": "removed", "line": "RA"}, self.BEFORE, self.AFTER), "unverifiable")

    def test_menu_mentions_outside_tables_do_not_count(self):
        before = "<ul><li>VisionSOM-6ULL</li></ul><table><tr><td>VisionSOM-6ULL</td><td>2030</td></tr></table>"
        after = "<ul><li>VisionSOM-6ULL</li></ul><table><tr><td>VisionSOM-8M</td><td>2033</td></tr></table>"
        self.assertEqual(check_event({"change": "removed", "line": "VisionSOM-6ULL"}, before, after), "confirmed")
        self.assertEqual(check_event({"change": "removed", "line": "BSP 6 state: Active"}, before, after), "unverifiable")

    def test_prefixed_cells_and_derived_old_side(self):
        before = "<table><tr><td>BSP 6</td></tr></table>"
        after = "<table><tr><td>Torizon/BSP 7</td></tr></table>"
        self.assertEqual(check_event({"change": "added", "line": "BSP 7"}, before, after), "confirmed")
        switched = {"change": "eol changed", "line": "i.MX53", "old": "2025", "new": "2027-12", "kind": "official",
                    "old_kind": "derived"}
        self.assertEqual(check_event(switched, "<td>i.MX53</td>", "<td>i.MX53</td>"), "unverifiable")

    def test_pdf_layout_columns_and_slash_dates(self):
        before = "  ML51TD1AE     Microcontrollers   8bit 8051 MCUs       2033\n"
        after = " 17    ML51TD1AE        Microcontrollers       8bit 8051 MCUs        2034/6        MP\n 18    MG51XC9AE    Microcontrollers   8bit 8051 MCUs   2034/6   MP\n"
        moved = {"change": "eol changed", "line": "ML51TD1AE", "old": "2033", "new": "2034-06"}
        self.assertEqual(check_event(moved, before, after), "confirmed")
        self.assertEqual(check_event({"change": "added", "line": "MG51XC9AE"}, before, after), "confirmed")

    def test_parentheses_in_date_changes(self):
        moved = {"change": "eol changed", "line": "Jetson Xavier NX 8GB", "old": "2028-01", "new": "2027-07"}
        before = "<table><tr><td>Jetson Xavier NX (8GB)</td><td>January 2028</td></tr></table>"
        after = "<table><tr><td>Jetson Xavier NX 8GB</td><td>July 2027</td></tr></table>"
        self.assertEqual(check_event(moved, before, after), "confirmed")

    def test_derived_dates_and_comma_names(self):
        derived = {"change": "eol changed", "line": "LPC4078FET180", "old": "2030", "new": "2035", "kind": "derived"}
        self.assertEqual(check_event(derived, "<td>LPC4078FET180</td>", "<td>LPC4078FET180</td>"), "unverifiable")
        gone = {"change": "removed", "line": "LPC4078FET180", "kind": "derived"}
        self.assertEqual(check_event(gone, "<table><td>LPC4078FET180</td></table>", "<table></table>"), "confirmed")
        added = {"change": "added", "line": "i.MX 6UltraLite (Industrial, Auto)"}
        self.assertEqual(check_event(added, "<td>i.MX 7</td>", "<td>i.MX 6UltraLite (Industrial, Auto)</td>"), "confirmed")

    def test_prefix_names_are_not_found_inside_longer_names(self):
        before = "<td>Jetson Xavier NX</td><td>Jetson Xavier NX 16GB</td>"
        after = "<td>Jetson Xavier NX 16GB</td><td>Jetson Xavier NX (8GB)</td>"
        self.assertEqual(check_event({"change": "removed", "line": "Jetson Xavier NX"}, before, after), "confirmed")
        self.assertEqual(check_event({"change": "added", "line": "Jetson Xavier NX 8GB"}, before, after), "confirmed")

    def test_composed_names_in_one_row(self):
        before = "<table><tr><td>Nanbield</td><td>4.3</td><td>until April 2024</td></tr></table>"
        after = ("<table><tr><td>Nanbield</td><td>4.3</td><td>until May 2024</td></tr>"
                 "<tr><td>Walnascar (aka Walna)</td><td>5.2</td><td>until November 2025</td></tr></table>")
        moved = {"change": "eol changed", "line": "4.3 Nanbield", "old": "2024-04", "new": "2024-05"}
        self.assertEqual(check_event(moved, before, after), "confirmed")
        added = {"change": "added", "line": "5.2 Walnascar", "eol": "2025-11"}
        self.assertEqual(check_event(added, before, after), "confirmed")
        prefix = "<table><tr><td>Jetson Nano</td></tr></table>"       # one word: no first-word match
        self.assertEqual(check_event({"change": "removed", "line": "Jetson"}, prefix, ""), "contradicted")
        split = "<table><tr><td>Nanbield</td><td>4.3</td></tr><tr><td>Walnascar</td><td>5.2</td></tr></table>"
        self.assertEqual(check_event({"change": "added", "line": "5.2 Nanbield"}, "", split), "contradicted")   # other rows

    def test_prose_items_and_dated_lines(self):
        before = "<ul><li>Version 3.5 will be supported until 2030-04-08 (LTS)</li></ul>"
        after = "<ul><li>Version 3.5 will be supported until 2030-04-08 (LTS)</li><li>Version 4.0 until 2027-05-14</li></ul>"
        self.assertEqual(check_event({"change": "added", "line": "4.0", "eol": "2027-05-14"}, before, after), "confirmed")
        self.assertEqual(check_event({"change": "added", "line": "3.5 LTS", "eol": "2030-04-08"}, "", after), "confirmed")
        # a line whose date became unreadable ('End of 2015') is a dated line removed, the row itself stays
        k_before = "<table><tr><td>3.10</td><td>2013-06-30</td><td>Sep, 2015</td></tr></table>"
        k_after = "<table><tr><td>3.10</td><td>2013-06-30</td><td>End of 2015</td></tr></table>"
        self.assertEqual(check_event({"change": "removed", "line": "3.10", "eol": "2015-09"}, k_before, k_after),
                         "confirmed")
        self.assertEqual(check_event({"change": "eol changed", "line": "3.10", "old": "2015-09", "new": "2015"},
                                     k_before, k_after), "confirmed")

    def test_sampling_reads_each_page_once(self):
        pages = {"p": self.BEFORE, "s": self.AFTER}
        reads = []
        events = [{"change": "removed", "line": "MOSFETs", "previous": "p", "snapshot": "s"},
                  {"change": "removed", "line": "IGBTs", "previous": "p", "snapshot": "s"},
                  {"change": "baseline", "snapshot": "s"}]
        counts, bad = audit_history(events, 10, 1, read=lambda u: reads.append(u) or pages[u])
        self.assertEqual((counts["confirmed"], bad, sorted(reads)), (2, [], ["p", "s"]))

    def test_unreadable_archive_pages_are_fetch_errors_not_contradictions(self):
        with mock.patch("supportdates.audit.fetch_bytes", return_value=b"<html>Too Many Requests</html>"):
            with self.assertRaises(ValueError):
                raw_text("https://web.archive.org/web/1id_/https://x/list.pdf")
        def read(url):
            raise ValueError("not a PDF")
        events = [{"change": "added", "line": "M253LE3BE", "previous": "p.pdf", "snapshot": "s.pdf"}]
        counts, bad = audit_history(events, 5, 1, read=read)
        self.assertEqual((counts["contradicted"], len(bad)), (0, 1))
        self.assertIn("fetch error", bad[0][1])

    def test_first_stated_date_after_tbd(self):
        e = {"change": "eol changed", "line": "VisionSOM-V2L (SLS22)", "old": "", "new": "2032"}
        before = "<table><tr><td>VisionSOM-V2L (SLS22)</td><td>TBD</td></tr></table>"
        after = "<table><tr><td>VisionSOM-V2L (SLS22)</td><td>2032</td></tr></table>"
        self.assertEqual(check_event(e, before, after), "confirmed")
        self.assertEqual(check_event(e, "<table></table>", after), "contradicted")


if __name__ == "__main__":
    unittest.main()
