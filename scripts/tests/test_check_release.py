import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_release.py"
SPEC = importlib.util.spec_from_file_location("check_release", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("Cargo.toml", '[workspace]\nmembers = ["core", "derive"]\n')
        self.write("core/Cargo.toml", '''[package]
name = "fatoora-core"
version = "0.2.0"
[dependencies]
fatoora-derive = { path = "../derive", version = "0.2.0" }
''')
        self.write("derive/Cargo.toml", '[package]\nname = "fatoora-derive"\nversion = "0.2.0"\n')
        self.write("Cargo.lock", '''[[package]]
name = "fatoora-core"
version = "0.2.0"
[[package]]
name = "fatoora-derive"
version = "0.2.0"
''')
        self.write("bindings/python/pyproject.toml", '[project]\nname = "fatoora-rs"\nversion = "0.2.0"\n')
        self.write("bindings/python/uv.lock", '[[package]]\nname = "fatoora-rs"\nversion = "0.2.0"\n')

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def replace(self, name, before, after):
        path = self.root / name
        path.write_text(path.read_text().replace(before, after))

    def test_consistent_candidate_and_tag(self):
        self.assertEqual(release.check_release(self.root), "0.2.0")
        self.assertEqual(release.check_release(self.root, "v0.2.0"), "0.2.0")

    def test_rejects_wrong_tag_or_manual_branch(self):
        for tag in ("v0.1.3", "0.2.0", "main", "v0.2.0-rc.1", ""):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.check_release(self.root, tag)

    def test_rejects_stale_versions(self):
        for name in ("derive/Cargo.toml", "Cargo.lock", "bindings/python/pyproject.toml", "bindings/python/uv.lock"):
            with self.subTest(name=name):
                self.replace(name, 'version = "0.2.0"', 'version = "0.1.3"')
                with self.assertRaises(ValueError):
                    release.check_release(self.root)
                self.replace(name, 'version = "0.1.3"', 'version = "0.2.0"')

    def test_rejects_stale_internal_dependency(self):
        self.replace("core/Cargo.toml", 'path = "../derive", version = "0.2.0"', 'path = "../derive", version = "0.1.3"')
        with self.assertRaises(ValueError):
            release.check_release(self.root)

    def test_rejects_unversioned_path_dependency(self):
        self.replace("core/Cargo.toml", ', version = "0.2.0"', '')
        with self.assertRaises(ValueError):
            release.check_release(self.root)

    def test_rejects_missing_lock_entry(self):
        self.write("Cargo.lock", '[[package]]\nname = "fatoora-derive"\nversion = "0.2.0"\n')
        with self.assertRaises(ValueError):
            release.check_release(self.root)


if __name__ == "__main__":
    unittest.main()
