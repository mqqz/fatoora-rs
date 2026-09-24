"""Rule provenance and SDK observations must not be mistaken for coverage."""

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import business_rules as rules
import sdk_parity as sdk

SOURCE = b"""<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:cbc="urn:cbc" version="2.0">
 <xsl:variable name="limit" select="2"/>
 <xsl:template match="cbc:Amount" mode="rules" priority="10">
  <xsl:choose>
   <xsl:when test="$matched"><xsl:next-match/></xsl:when>
   <xsl:otherwise>
    <xsl:variable name="limit" select="3"/>
    <xsl:if test="number(.) &gt; $limit">
     <svrl:failed-assert id="BR-EXAMPLE" flag="warning" location="{location(.)}">
      <xsl:attribute name="test">. &lt;= 99</xsl:attribute>
      <svrl:text>[BR-EXAMPLE] - Amount exceeds limit.</svrl:text>
     </svrl:failed-assert>
    </xsl:if>
   </xsl:otherwise>
  </xsl:choose>
 </xsl:template>
 <xsl:template match="cbc:Amount" mode="rules" priority="1">
  <xsl:if test="not(.)">
   <svrl:failed-assert id="BR-EXAMPLE" flag="error">
    <svrl:text>Missing amount.</svrl:text>
   </svrl:failed-assert>
  </xsl:if>
 </xsl:template>
 <xsl:template match="*" mode="rules" priority="0"><xsl:apply-templates/></xsl:template>
</xsl:transform>"""


class InventoryContracts(unittest.TestCase):
    def test_executable_guard_is_distinct_from_diagnostic_test(self):
        source = rules.extract_source(SOURCE, "cen", "example.xsl")
        assertion = source["assertions"][0]
        self.assertEqual(assertion["reported_test"], ". <= 99")
        self.assertEqual(
            assertion["control_flow"][-1]["attributes"]["test"], "number(.) > $limit"
        )
        self.assertEqual(assertion["control_flow"][-2]["tag"], rules.XSL + "otherwise")
        self.assertEqual(source["namespaces"]["cbc"], "urn:cbc")

    def test_duplicate_ids_are_independent_sites_and_order_is_preserved(self):
        source = rules.extract_source(SOURCE, "cen", "example.xsl")
        assertions = source["assertions"]
        self.assertEqual([a["rule_id"] for a in assertions], ["BR-EXAMPLE"] * 2)
        self.assertEqual(len({a["site"] for a in assertions}), 2)
        self.assertEqual([a["severity"] for a in assertions], ["warning", "error"])
        self.assertEqual(
            [t["attributes"].get("priority") for t in source["templates"]],
            ["10", "1", "0"],
        )
        self.assertEqual(
            len(source["templates"]), 3
        )  # Include zero-assertion dispatch.

    def test_scoped_variables_and_dispatch_survive_extraction(self):
        source = rules.extract_source(SOURCE, "cen", "example.xsl")
        self.assertEqual(source["globals"][0]["attributes"]["select"], "2")
        program = source["templates"][0]["body"]
        encoded = json.dumps(program)
        self.assertIn('"select": "3"', encoded)
        self.assertIn("next-match", encoded)
        self.assertIn('"test": "$matched"', encoded)
        self.assertEqual(rules.extract_source(SOURCE, "cen", "example.xsl"), source)

    def test_rejects_malformed_or_incomplete_rules_and_entities(self):
        for bad in [
            SOURCE[:-10],
            SOURCE.replace(b'flag="warning"', b'flag="unknown"'),
            SOURCE.replace(b'id="BR-EXAMPLE"', b'id=""'),
            b'<!DOCTYPE x [<!ENTITY a "x">]>' + SOURCE,
        ]:
            with self.subTest(bad=bad[:40]), self.assertRaises(sdk.CaptureError):
                rules.extract_source(bad, "cen", "example.xsl")

    def test_unknown_sdk_hash_is_rejected_before_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for source in rules.SOURCES.values():
                p = root / source["path"]
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(SOURCE)
            with self.assertRaisesRegex(sdk.CaptureError, "checksum"):
                rules.build_catalog(root)

    def test_bundled_inventory_is_complete_and_has_no_inferred_coverage(self):
        catalog = rules.load_catalog()
        self.assertEqual(catalog["sdk_version"], sdk.VERSION)
        self.assertEqual(
            [(s["source"], len(s["assertions"])) for s in catalog["sources"]],
            [("cen", 105), ("ksa", 152)],
        )
        sites = [a["site"] for s in catalog["sources"] for a in s["assertions"]]
        self.assertEqual(len(sites), len(set(sites)))
        coverage = rules.load_coverage(catalog)
        self.assertEqual(set(sites), set(coverage["sites"]))
        # Generating an inventory must never infer implementation coverage.
        self.assertTrue(
            all(
                s["status"] == "pending"
                for s in rules.pending_coverage(catalog)["sites"].values()
            )
        )

    def test_missing_or_invented_coverage_site_is_rejected(self):
        catalog = rules.load_catalog()
        coverage = rules.load_coverage(catalog)
        for invent in [False, True]:
            bad = copy.deepcopy(coverage)
            if invent:
                bad["sites"]["imaginary-rule"] = {"status": "pending", "tests": []}
            else:
                del bad["sites"][next(iter(bad["sites"]))]
            with self.assertRaises(sdk.CaptureError):
                rules.validate_coverage(catalog, bad)

    def test_claimed_coverage_requires_implementation_and_tests(self):
        catalog = rules.load_catalog()
        coverage = rules.load_coverage(catalog)
        site = next(iter(coverage["sites"]))
        coverage["sites"][site] = {"status": "implemented", "tests": []}
        with self.assertRaises(sdk.CaptureError):
            rules.validate_coverage(catalog, coverage)

    def test_frozen_observations_cover_manifest_cases_without_java(self):
        observations = rules.load_observations()
        manifest = sdk.load_manifest(sdk.CORPUS)
        expected = {
            c["id"]
            for c in manifest["cases"]
            if (
                sdk.CORPUS / "cases" / c["id"] / "evidence/validate/stdout.txt"
            ).exists()
        }
        self.assertEqual(set(observations["cases"]), expected)


class MutationContracts(unittest.TestCase):
    def test_each_mutation_has_independent_targets_and_changes_input(self):
        cases = rules.mutation_cases()
        ids = [c["id"] for c in cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(cases), 20)
        for case in cases:
            self.assertIn(case["expected_xsd"], ["passed", "failed"])
            self.assertTrue(case["targets"] or case["id"] == "baseline")
            if case["id"] != "baseline":
                self.assertNotEqual(case["xml"], cases[0]["xml"])

    def test_family_cases_are_unique_and_have_positive_and_negative_targets(self):
        cases = rules.mutation_cases("identity")
        self.assertEqual(len(cases), len({case["id"] for case in cases}))
        targets = {}
        for case in cases:
            self.assertTrue(case["targets"])
            for target in case["targets"]:
                targets.setdefault(target["code"], set()).add(target["count"])
        self.assertEqual(len(targets), 20)
        for code, counts in targets.items():
            self.assertIn(1, counts, code)
            if code != "BR-KSA-09":  # Address presence also has baseline evidence.
                self.assertIn(0, counts, code)
        with self.assertRaisesRegex(sdk.CaptureError, "Unknown rule family"):
            rules.mutation_cases("unknown")

    def test_identity_corpus_replays_with_its_own_definition(self):
        manifest = rules.load_mutations(rules.ROOT / "identity")
        self.assertEqual(manifest["family"], "identity")
        self.assertEqual(len(manifest["cases"]), len(rules.mutation_cases("identity")))

    def test_structural_corpus_replays_with_catalog_severities(self):
        manifest = rules.load_mutations(rules.ROOT / "structural")
        self.assertEqual(manifest["family"], "structural")
        self.assertEqual(len(manifest["cases"]), 57)
        catalog = rules.load_catalog()["sources"][0]["assertions"]
        known = {(r["rule_id"], r["severity"]) for r in catalog}
        for case in rules.mutation_cases("structural"):
            for target in case["targets"]:
                self.assertIn((target["code"], target["severity"]), known)

    def test_totals_corpus_keeps_binary_cast_boundaries(self):
        manifest = rules.load_mutations(rules.ROOT / "totals")
        self.assertEqual(len(manifest["cases"]), 18)
        for name in [
            "positive-half",
            "negative-half",
            "two-sixty-seven",
            "large-double",
        ]:
            cases = {c["id"]: c for c in manifest["cases"]}
            self.assertEqual(cases[name + "-binary"]["targets"][0]["count"], 0)
            self.assertEqual(cases[name + "-display"]["targets"][0]["count"], 1)

    def test_empty_or_missing_mutation_does_not_silently_pass(self):
        for old, new in [("missing", "new"), ("same", "same")]:
            with self.assertRaises(sdk.CaptureError):
                rules.replace_once("same", old, new)

    def test_expected_rule_result_is_checked_before_capture_is_accepted(self):
        case = {
            "expected_xsd": "passed",
            "targets": [
                {
                    "source": "ksa",
                    "code": "BR-KSA-EN16931-02",
                    "severity": "error",
                    "count": 1,
                }
            ],
        }
        report = {
            "layers": {"xsd": "passed", "cen": "passed", "ksa": "passed"},
            "findings": [],
        }
        with self.assertRaises(sdk.CaptureError):
            rules.check_targets(case, report)
        report["findings"] = [
            {
                "source": "ksa",
                "code": "BR-KSA-EN16931-02",
                "severity": "error",
                "message": "",
            }
        ]
        rules.check_targets(case, report)
        report["findings"] *= 2
        with self.assertRaises(sdk.CaptureError):
            rules.check_targets(case, report)

    def test_absent_rule_is_not_a_pass_when_its_layer_did_not_run(self):
        case = {
            "expected_xsd": "passed",
            "targets": [
                {
                    "source": "ksa",
                    "code": "BR-KSA-EN16931-02",
                    "severity": "error",
                    "count": 0,
                }
            ],
        }
        with self.assertRaises(sdk.CaptureError):
            rules.check_targets(
                case, {"layers": {"xsd": "passed", "ksa": "not_run"}, "findings": []}
            )

    def test_mutation_corpus_replays_offline_and_records_sdk_deduplication(self):
        manifest = rules.load_mutations()
        case = next(
            c for c in manifest["cases"] if c["id"] == "repeated-empty-item-name"
        )
        self.assertEqual(case["targets"][0]["count"], 1)
        self.assertEqual(case["native_occurrences"], 2)

    def test_corrupted_mutation_evidence_or_removed_case_fails(self):
        for remove_case in [False, True]:
            with (
                self.subTest(remove_case=remove_case),
                tempfile.TemporaryDirectory() as d,
            ):
                corpus = Path(d) / "mutations"
                shutil.copytree(rules.ROOT / "mutations", corpus)
                if remove_case:
                    path = corpus / "manifest.json"
                    manifest = json.loads(path.read_text())
                    manifest["cases"].pop()
                    sdk.write_json(path, manifest)
                else:
                    (corpus / "cases/baseline/expected.json").write_text("{}")
                with self.assertRaises(sdk.CaptureError):
                    rules.load_mutations(corpus)


if __name__ == "__main__":
    unittest.main()
