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


class FindingContracts(unittest.TestCase):
    def test_real_sdk_output_keeps_errors_and_warnings(self):
        path = sdk.CORPUS / "cases/foreign-currency/evidence/validate/stdout.txt"
        report = sdk.parse_validation_report(path.read_text(), 0)
        self.assertEqual(report["layers"]["ksa"], "failed")
        self.assertEqual(
            report["findings"],
            [
                {
                    "source": "ksa",
                    "severity": "error",
                    "code": "BR-KSA-EN16931-02",
                    "message": '[BR-KSA-EN16931-02]-VAT accounting currency code (BT-6) must be "SAR".',
                },
                {
                    "source": "ksa",
                    "severity": "warning",
                    "code": "BR-KSA-97",
                    "message": '[BR-KSA-97]-If the Document Currency Code (BT-5) is different from "SAR", then the value in "Invoice total VAT amount (BT-110)" cannot be the same as the value in "Invoice total VAT amount in accounting currency (BT-111)".',
                },
                {
                    "source": "ksa",
                    "severity": "warning",
                    "code": "BR-KSA-15",
                    "message": '[BR-KSA-15]-The tax invoice ((invoice type code (BT-30) = 388) and (invoice transaction code (KSA-2) has "01" as first 2 digits)) must contain the supply date (KSA-5).',
                },
            ],
        )

    def test_repeated_codes_and_passed_layer_warnings_are_retained(self):
        log = """[XSD] validation result : PASSED
[EN] validation result : PASSED
en validation warnings :
CODE : BR-01, MESSAGE : first
CODE : BR-01, MESSAGE : first
[KSA] validation result : PASSED
ksa validation warnings :
CODE : BR-01, MESSAGE : second, MESSAGE : remains part of text
"""
        report = sdk.parse_validation_report(log, 0)
        self.assertEqual(len(report["findings"]), 3)
        self.assertEqual(report["findings"][0], report["findings"][1])
        self.assertEqual(report["findings"][2]["source"], "ksa")
        self.assertEqual(
            report["findings"][2]["message"], "second, MESSAGE : remains part of text"
        )

    def test_continued_messages_and_log_prefixes(self):
        log = """2026-09-23 12:00:00,000 [INFO] ValidationProcessorImpl - [XSD] validation result : PASSED
2026-09-23 12:00:00,001 [INFO] ValidationProcessorImpl - [KSA] validation result : PASSED
2026-09-23 12:00:00,002 [ERROR] ValidationProcessorImpl - ksa validation warnings :
2026-09-23 12:00:00,003 [WARN] ValidationProcessorImpl - CODE : BR-EXAMPLE, MESSAGE : first line
   second line
2026-09-23 12:00:00,004 [INFO] InvoiceValidationService - *** GLOBAL VALIDATION RESULT = PASSED
"""
        report = sdk.parse_validation_report(log, 0)
        self.assertEqual(report["findings"][0]["severity"], "warning")
        self.assertEqual(report["findings"][0]["message"], "first line\n   second line")

    def test_unattributed_malformed_or_contradictory_findings_fail_capture(self):
        prefix = "[XSD] validation result : PASSED\n"
        for body in [
            "CODE : BR-01, MESSAGE : invalid",
            "ksa validation warnings :\nCODE : broken",
            "ksa validation errors :\nCODE : BR-01, MESSAGE : invalid",
            "[KSA] validation result : PASSED\nksa validation errors :\nCODE : BR-01, MESSAGE : invalid",
            "[KSA] validation result : PASSED\nunknown validation warnings :\nCODE : BR-01, MESSAGE : invalid",
        ]:
            with self.subTest(body=body), self.assertRaises(sdk.CaptureError):
                sdk.parse_validation_report(prefix + body, 0)


if __name__ == "__main__":
    unittest.main()
