"""Exercise the ledger bridge against both actual Select evidence collections."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_crypto_obligations as obligations


class SelectClaimIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="select-claim-")
        cls.root = Path(cls.tmp.name)
        current = Path(__file__).resolve().parents[2]
        shutil.copytree(current / "formal", cls.root / "formal",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def claim(self):
        return {"evidence": [path for path, _ in obligations.SELECT_SOURCE_CLAIM_EVIDENCE]}

    def test_actual_both_platforms_support_the_scoped_claim(self):
        facts = obligations._validate_select_source_claim(self.root, self.claim(), "select")
        self.assertGreater(facts, 0)

    def test_valid_mac_cannot_hide_missing_linux_report(self):
        report = self.root / obligations.SELECT_SOURCE_LINUX_REPORT
        contents = report.read_bytes()
        report.unlink()
        try:
            with self.assertRaises(obligations.LedgerError):
                obligations._validate_select_source_claim(self.root, self.claim(), "select")
        finally:
            report.write_bytes(contents)

    def test_report_counts_cannot_replace_linux_companion_maps(self):
        collection = self.root / obligations.SELECT_SOURCE_LINUX_COLLECTION
        index = json.loads((collection / "COLLECTION-FILES.json").read_text())
        name = next(path for path in index["files"] if "java-base" in path)
        path = collection / name
        contents = path.read_bytes()
        path.unlink()
        try:
            with self.assertRaises(obligations.LedgerError):
                obligations._validate_select_source_claim(self.root, self.claim(), "select")
        finally:
            path.write_bytes(contents)


if __name__ == "__main__":
    unittest.main()
