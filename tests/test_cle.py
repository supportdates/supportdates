import unittest

from supportdates.cle import cle_document, version_range
from supportdates.sources import Record


class CleTest(unittest.TestCase):
    def test_ranges(self):
        self.assertEqual(version_range("6.6"), "vers:generic/>=6.6|<6.7")
        self.assertEqual(version_range("22 LTS"), "vers:generic/>=22|<23")
        self.assertEqual(version_range("3.5 LTS"), "vers:generic/>=3.5|<3.6")
        self.assertIsNone(version_range("Scarthgap"))

    def test_moved_date_becomes_withdrawn_plus_new_event(self):
        recs = [Record("Zephyr", "3.7 LTS", "2024-07-26", "2029-07-27", "official", "https://z", "e"),
                Record("Zephyr", "3.6", "2024-02-23", "2025-03", "derived", "https://z", "e")]
        history = [{"date": "2025-06-01", "change": "eol changed", "component": "Zephyr", "line": "3.7 LTS",
                    "old": "2027-01-26", "new": "2029-07-27"}]
        doc = cle_document("Zephyr", recs, history, "2024-08-01", "2026-10-20")
        events = doc["events"]
        self.assertEqual([e["id"] for e in events], [4, 3, 2, 1])            # descending ids
        self.assertEqual([e["type"] for e in reversed(events)],
                         ["released", "endOfSupport", "withdrawn", "endOfSupport"])
        first_eos, withdrawn, new_eos = events[2], events[1], events[0]
        self.assertEqual(first_eos["effective"], "2027-01-26T00:00:00Z")
        self.assertEqual(withdrawn["eventId"], first_eos["id"])
        self.assertIn("2027-01-26 to 2029-07-27", withdrawn["reason"])
        self.assertEqual((new_eos["effective"], new_eos["published"]), ("2029-07-27T00:00:00Z", "2025-06-01T00:00:00Z"))
        self.assertEqual(doc["identifier"], "pkg:github/zephyrproject-rtos/zephyr")
        self.assertNotIn("3.6", str(doc["events"]))                         # derived dates are not exported

    def test_month_precision_ends_at_period_end(self):
        doc = cle_document("Mbed TLS", [Record("Mbed TLS", "3.6", "2024-03", "2027-03", "official", "m", "e")],
                           [], "2026-10-16", "2026-10-20")
        eos = [e for e in doc["events"] if e["type"] == "endOfSupport"][0]
        self.assertEqual(eos["effective"], "2027-03-31T00:00:00Z")
        released = [e for e in doc["events"] if e["type"] == "released"][0]
        self.assertEqual((released["effective"], released["version"]), ("2024-03-01T00:00:00Z", "3.6"))


if __name__ == "__main__":
    unittest.main()
