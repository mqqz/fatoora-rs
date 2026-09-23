import importlib.util
import io
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check_native_packages.py"
SPEC = importlib.util.spec_from_file_location("check_native_packages", SCRIPT)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativePackageChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        source = self.root / "fatoora-core/tests/fixtures/business-rules"
        source.mkdir(parents=True)
        self.entries = []
        for name in native.RULE_NOTICES:
            content = f"Pinned source: {name}\n".encode()
            (source / name).write_bytes(content)
            self.entries.append((f"licenses/zatca/{name}", content))

    def package(self, extension, entries):
        path = self.dist / f"native.{extension}"
        if extension == "zip":
            with zipfile.ZipFile(path, "w") as archive:
                for name, content in entries:
                    archive.writestr(name, content)
        else:
            with tarfile.open(path, "w:gz") as archive:
                for name, content in entries:
                    member = tarfile.TarInfo(f"./{name}")
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
        return path

    def test_checks_tar_and_zip_notices(self):
        for extension in ("tar.gz", "zip"):
            self.package(extension, self.entries + [("executable", b"binary")])
        self.assertEqual(native.check_packages(self.dist, self.root), 2)

    def test_rejects_missing_changed_misplaced_or_duplicate_notices(self):
        name, content = self.entries[0]
        variants = {
            "missing": (self.entries[1:], "missing"),
            "changed": ([(name, b"stale")] + self.entries[1:], "differs"),
            "misplaced": ([(f"../{name}", content)] + self.entries[1:], "missing"),
            "duplicate": (self.entries + [self.entries[0]], "duplicate"),
        }
        for extension in ("tar.gz", "zip"):
            for case, (entries, message) in variants.items():
                with self.subTest(extension=extension, case=case):
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        path = self.package(extension, entries)
                    with self.assertRaisesRegex(ValueError, message):
                        native.check_packages(self.dist, self.root)
                    path.unlink()

    def test_rejects_notice_symlink(self):
        path = self.dist / "native.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo(self.entries[0][0])
            member.type = tarfile.SYMTYPE
            member.linkname = "elsewhere"
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, "regular file"):
            native.check_packages(self.dist, self.root)

    def test_rejects_empty_directory_or_loose_binary(self):
        with self.assertRaisesRegex(ValueError, "no native release archives"):
            native.check_packages(self.dist, self.root)
        (self.dist / "fatoora-rs-cli").write_bytes(b"binary")
        with self.assertRaisesRegex(ValueError, "expected a .tar.gz or .zip archive"):
            native.check_packages(self.dist, self.root)


if __name__ == "__main__":
    unittest.main()
