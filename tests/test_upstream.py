import unittest

from supportdates.sources import Record
from supportdates.upstream import PRODUCTS, first_tag, latest_patch, render


class UpstreamTest(unittest.TestCase):
    def test_latest_patch_skips_prereleases(self):
        tags = ["v4.4.0", "v4.4.1-rc1", "v4.4.1", "v4.4.2-rc1", "v4.5.0-rc1", "v4.3.9"]
        self.assertEqual(latest_patch(tags, PRODUCTS["zephyr"]["tag"], "4.4"), "4.4.1")
        self.assertEqual(latest_patch(["v6.0", "v6.0.3", "v6.1-rc1"], PRODUCTS["esp-idf"]["tag"], "6.0"), "6.0.3")
        self.assertIsNone(latest_patch(["v1.0.0"], PRODUCTS["zephyr"]["tag"], "4.4"))

    def test_first_tag(self):
        self.assertEqual(first_tag(["v3.7.1", "v3.7.0", "v3.7.0-rc1"], PRODUCTS["zephyr"]["tag"], "3.7"), "v3.7.0")
        self.assertEqual(first_tag(["v5.2", "v5.2.1"], PRODUCTS["esp-idf"]["tag"], "5.2"), "v5.2")

    def test_render_marks_unknowns_as_todo(self):
        recs = [Record("Mbed TLS", "3.6", "2024-03", "2027-03", "official", "u", "e")]
        text = render("mbed-tls", PRODUCTS["mbed-tls"], recs, ["v3.6.7"])
        self.assertIn('releaseCycle: "3.6"', text)
        self.assertIn('latest: "3.6.7"', text)
        self.assertIn("releaseDate: TODO", text)       # month-only source date is not guessed
        self.assertIn("# source: u", text)


if __name__ == "__main__":
    unittest.main()
