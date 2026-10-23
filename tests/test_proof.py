import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from supportdates.proof import tsa_label, tsr_path, build_chain, manifest, manifest_bytes, verify_chain


class ProofChainTest(unittest.TestCase):
    def _data(self, tmp: str) -> Path:
        d = Path(tmp)
        (d / "snapshots").mkdir()
        for day, eol in (("2026-10-16", "2031-07"), ("2026-10-17", "2027-07")):
            (d / "snapshots" / f"{day}.json").write_text(json.dumps(
                {"date": day, "sources": {"jetson": "ab" + day}, "records": [{"eol": eol}]}))
        return d

    def test_chain_links_and_detects_rewrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self._data(tmp)
            self.assertEqual(len(build_chain(d)), 2)
            self.assertEqual(build_chain(d), [])                       # existing manifests are never rewritten
            ms = [json.loads(p.read_text()) for p in sorted((d / "proofs").glob("*.json"))]
            self.assertIsNone(ms[0]["previous_manifest_sha256"])
            self.assertEqual(ms[1]["previous_manifest_sha256"],
                             hashlib.sha256((d / "proofs" / "2026-10-16.json").read_bytes()).hexdigest())
            shas = {p.stem: hashlib.sha256(p.read_bytes()).hexdigest() for p in (d / "snapshots").glob("*.json")}
            self.assertEqual(verify_chain(ms, shas), [])
            (d / "snapshots" / "2026-10-16.json").write_text("rewritten history")      # someone edits the past
            shas["2026-10-16"] = hashlib.sha256(b"rewritten history").hexdigest()
            self.assertEqual(verify_chain(ms, shas), ["2026-10-16: snapshot changed after its manifest was written"])

    def test_canonical_encoding_and_broken_link(self):
        m1 = manifest("2026-10-16", "aa", {"b": "2", "a": "1"}, None)
        self.assertEqual(manifest_bytes(m1), manifest_bytes(manifest("2026-10-16", "aa", {"a": "1", "b": "2"}, None)))
        m2 = manifest("2026-10-17", "bb", {}, "not-the-real-hash")
        self.assertEqual(verify_chain([m1, m2], {}), ["2026-10-17: link to previous manifest broken"])


class TsaNamingTest(unittest.TestCase):
    def test_one_response_file_per_authority(self):
        self.assertEqual(tsa_label("http://timestamp.digicert.com"), "digicert")
        self.assertEqual(tsa_label("https://freetsa.org/tsr"), "freetsa")
        self.assertEqual(tsr_path(Path("proofs/2026-10-20.tsq"), "http://timestamp.sectigo.com").name,
                         "2026-10-20.sectigo.tsr")


if __name__ == "__main__":
    unittest.main()
