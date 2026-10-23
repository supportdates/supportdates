import unittest
from datetime import date

from supportdates.mcp import handle, lookup
from supportdates.sources import Record

RECS = [Record("Zephyr", "3.7 LTS", "2024-07-26", "2029-07-27", "official", "z", "e"),
        Record("NVIDIA Jetson", "Jetson Orin NX 16GB", "", "2032-01", "official", "n", "e")]
TODAY = date(2026, 10, 18)


class McpTest(unittest.TestCase):
    def test_handshake_and_tool_list(self):
        init = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, RECS, TODAY)
        self.assertEqual(init["result"]["serverInfo"]["name"], "supportdates")
        self.assertIsNone(handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, RECS, TODAY))
        tools = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, RECS, TODAY)["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], ["support_dates", "check_manifest"])

    def test_lookup_tool_returns_sourced_facts(self):
        resp = handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "support_dates", "arguments": {"query": "orin nx"}}}, RECS, TODAY)
        text = resp["result"]["content"][0]["text"]
        self.assertIn("Jetson Orin NX 16GB | end: 2032-01 | official | n", text)
        self.assertIn("not an assessment of security, safety or compliance", text)
        self.assertEqual(lookup("zephyr 3.7", RECS), ["Zephyr | 3.7 LTS | end: 2029-07-27 | official | z"])

    def test_errors(self):
        self.assertEqual(handle({"jsonrpc": "2.0", "id": 4, "method": "nope"}, RECS, TODAY)["error"]["code"], -32601)
        bad = handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "x"}}, RECS, TODAY)
        self.assertEqual(bad["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
