"""Capture failures must never turn into compatibility passes."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sdk_parity as sdk


class CaptureContracts(unittest.TestCase):
    def test_missing_sdk(self):
        with self.assertRaises(sdk.CaptureError):
            sdk.sdk_root(Path("/definitely/missing/sdk"))

    def test_missing_command_preserves_failure(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(sdk.CaptureError):
                sdk.run(
                    ["/definitely/missing/java"], Path(d), {}, Path(d) / "evidence", 1
                )
            self.assertTrue((Path(d) / "evidence/process.json").exists())

    def test_timeout_is_failure(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(sdk.CaptureError):
            sdk.run(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                Path(d),
                {},
                Path(d) / "evidence",
                0.05,
            )

    def test_failed_command_preserves_streams_and_status(self):
        with tempfile.TemporaryDirectory() as d:
            record = sdk.run(
                [
                    sys.executable,
                    "-c",
                    'import sys; print("out"); print("err",file=sys.stderr); sys.exit(3)',
                ],
                Path(d),
                {},
                Path(d) / "evidence",
                1,
            )
            self.assertEqual(record["exit_code"], 3)
            self.assertEqual((Path(d) / "evidence/stdout.txt").read_text(), "out\n")
            self.assertEqual((Path(d) / "evidence/stderr.txt").read_text(), "err\n")
            with self.assertRaises(sdk.CaptureError):
                sdk.parse_hash("INVOICE HASH = " + "A" * 43 + "=", 3)

    def test_hash_requires_one_valid_digest(self):
        good = "INVOICE HASH = " + "A" * 43 + "="
        self.assertEqual(sdk.parse_hash(good, 0), "A" * 43 + "=")
        for bad in ["", "INVOICE HASH = nonsense", good + "\n" + good]:
            with self.subTest(bad=bad), self.assertRaises(sdk.CaptureError):
                sdk.parse_hash(bad, 0)

    def test_validation_distinguishes_rejection_and_crash(self):
        self.assertEqual(
            sdk.parse_validation("[XSD] validation result : FAILED", 0)["xsd"], "failed"
        )
        self.assertEqual(
            sdk.parse_validation("[XSD] validation result : PASSED", 0)["xsd"], "passed"
        )
        for bad in [
            "",
            "Exception",
            "[XSD] validation result : UNKNOWN",
            "[XSD] validation result : PASSED\n[XSD] validation result : FAILED",
        ]:
            with self.subTest(bad=bad), self.assertRaises(sdk.CaptureError):
                sdk.parse_validation(bad, 0)
        with self.assertRaises(sdk.CaptureError):
            sdk.parse_validation("Exception", 1)

    def test_missing_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(sdk.CaptureError):
                sdk.require_artifact(Path(d) / "missing")
            p = Path(d) / "empty"
            p.touch()
            with self.assertRaises(sdk.CaptureError):
                sdk.require_artifact(p)

    def test_candidate_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(sdk.CaptureError):
            sdk.new_output(Path(d))

    def test_manifest_rejects_empty_missing_and_corrupted_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaises(sdk.CaptureError):
                sdk.load_manifest(root)
            manifest = {
                "schema_version": 1,
                "sdk": {"jar_sha256": sdk.JAR_SHA256},
                "cases": [],
                "artifacts": {},
            }
            sdk.write_json(root / "manifest.json", manifest)
            with self.assertRaises(sdk.CaptureError):
                sdk.load_manifest(root)
            (root / "data").write_text("original")
            manifest.update(
                cases=[{"id": "one"}], artifacts={"data": sdk.digest(root / "data")}
            )
            sdk.write_json(root / "manifest.json", manifest)
            sdk.load_manifest(root)
            (root / "data").write_text("corrupted")
            with self.assertRaises(sdk.CaptureError):
                sdk.load_manifest(root)
            (root / "data").unlink()
            with self.assertRaises(sdk.CaptureError):
                sdk.load_manifest(root)

    def test_isolation_rewrites_paths_and_preserves_install(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "SDK with spaces"
            files = [
                "Apps/global.json",
                "Data/Schemas/xsds/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd",
                "Data/Rules/Schematrons/CEN-EN16931-UBL.xsl",
                "Data/Rules/Schematrons/20210819_ZATCA_E-invoice_Validation_Rules.xsl",
                "Data/Certificates/cert.pem",
                "Data/Certificates/ec-secp256k1-priv-key.pem",
                "Data/PIH/pih.txt",
                "Configuration/usage.txt",
                "Configuration/config.json",
            ]
            for relative in files:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("unchanged")
            (root / "Data/Input").mkdir()
            with sdk.isolated_sdk(root) as (scratch, env):
                config = json.loads((scratch / "Configuration/config.json").read_text())
                for path in config.values():
                    self.assertTrue(Path(path).exists())
                    self.assertTrue(Path(path).is_relative_to(scratch))
                self.assertEqual(
                    env["SDK_CONFIG"], str(scratch / "Configuration/config.json")
                )
                (scratch / "Data/Certificates/cert.pem").write_text("scratch change")
            for relative in files:
                self.assertEqual((root / relative).read_text(), "unchanged")

    def test_unknown_layer_status_is_not_a_pass(self):
        with self.assertRaises(sdk.CaptureError):
            sdk.parse_validation(
                "[XSD] validation result : PASSED\n[SIGNATURE] validation result : UNKNOWN",
                0,
            )
        with self.assertRaises(sdk.CaptureError):
            sdk.parse_validation("[XSD] validation result : PASSED", 1)


if __name__ == "__main__":
    unittest.main()
