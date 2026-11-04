"""The erasure comparison must use authenticated historical source bytes."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "poly_baseline", Path(__file__).with_name("prepare_poly_baseline.py"))
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


class BaselineTests(unittest.TestCase):
    def test_changed_manifest_rejected_before_materializing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text('{"files": {}}\n')
            with self.assertRaisesRegex(RuntimeError, "manifest digest"):
                baseline.prepare(root / "out", manifest=manifest)
            self.assertFalse((root / "out").exists())

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sentinel").write_text("preserve")
            with self.assertRaises(FileExistsError):
                baseline.prepare(root)
            self.assertEqual((root / "sentinel").read_text(), "preserve")

    def test_symlink_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                baseline.prepare(root / "link")


if __name__ == "__main__":
    unittest.main()
