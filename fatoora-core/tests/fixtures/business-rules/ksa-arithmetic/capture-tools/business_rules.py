#!/usr/bin/env python3
"""Inventory pinned SDK rules and preserve reference observations; never run XSLT.

The executable trees are audit data, not a runtime rule interpreter. Extraction
does not establish reachability or claim that any rule has been implemented.
"""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import business_rule_cases as families
import sdk_parity as sdk

ROOT = sdk.REPO / "fatoora-core/tests/fixtures/business-rules"
XSL = "{http://www.w3.org/1999/XSL/Transform}"
SVRL = "{http://purl.oclc.org/dsdl/svrl}"
SOURCES = {
    "cen": {
        "path": "Data/Rules/Schematrons/CEN-EN16931-UBL.xsl",
        "sha256": "378a7a4d697aa96e05edb4649ab4536b33546b8e288453324a5668c3e15735b0",
        "assertions": 105,
    },
    "ksa": {
        "path": "Data/Rules/Schematrons/20210819_ZATCA_E-invoice_Validation_Rules.xsl",
        "sha256": "3312e1938829b8972dacf19a3d933deeb97cb71c7e982c56a434b76cc0e5f0c4",
        "assertions": 152,
    },
}


def tree(node):
    """Retain ordering, variables, branch guards and dispatch, including empty rules."""
    result = {"tag": node.tag, "attributes": dict(node.attrib)}
    if node.text and node.text.strip():
        result["text"] = node.text
    if len(node):
        result["children"] = [tree(child) for child in node]
    if node.tail and node.tail.strip():
        result["tail"] = node.tail
    return result


def extract_source(data, source, filename):
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)", data):
        raise sdk.CaptureError("Rule inventory must not resolve DTDs or entities")
    try:
        namespaces = {}
        for _, (prefix, uri) in ET.iterparse(io.BytesIO(data), events=["start-ns"]):
            if prefix in namespaces and namespaces[prefix] != uri:
                raise sdk.CaptureError(
                    f"Rebound namespace needs explicit review: {prefix}"
                )
            namespaces[prefix] = uri
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise sdk.CaptureError(f"Malformed rule source: {filename}: {exc}") from exc
    if (
        root.tag not in [XSL + "transform", XSL + "stylesheet"]
        or root.get("version") != "2.0"
    ):
        raise sdk.CaptureError("Expected an XSLT 2.0 source")
    parents = {child: parent for parent in root.iter() for child in parent}
    paths = {root: "/"}
    for node in root.iter():
        counts = Counter()
        for child in node:
            counts[child.tag] += 1
            paths[child] = (
                paths[node].rstrip("/") + f"/{child.tag}[{counts[child.tag]}]"
            )
    templates, assertions = [], []
    for node in root.findall(XSL + "template"):
        key = f"{source}:template:{len(templates) + 1:03}"
        templates.append(
            {"key": key, "attributes": dict(node.attrib), "body": tree(node)}
        )
        for assertion in node.iter(SVRL + "failed-assert"):
            rule_id, flag = assertion.get("id"), assertion.get("flag")
            if not rule_id or flag not in ["warning", "error"]:
                raise sdk.CaptureError(
                    f"Missing rule ID or unknown severity: {rule_id}, {flag}"
                )
            text = assertion.find(SVRL + "text")
            if text is None or not "".join(text.itertext()).strip():
                raise sdk.CaptureError(f"Missing rule message: {rule_id}")
            ancestry = []
            ancestor = parents[assertion]
            while ancestor is not node:
                ancestry.append(
                    {"tag": ancestor.tag, "attributes": dict(ancestor.attrib)}
                )
                ancestor = parents[ancestor]
            reported = assertion.find(f"{XSL}attribute[@name='test']")
            assertions.append(
                {
                    "site": f"{source}:{len(assertions) + 1:03}:{rule_id}",
                    "rule_id": rule_id,
                    "template": key,
                    "source_path": paths[assertion],
                    "control_flow": list(reversed(ancestry)),
                    "reported_test": "".join(reported.itertext())
                    if reported is not None
                    else None,
                    "severity": flag,
                    "message": "".join(text.itertext()),
                    "location_expression": assertion.get("location"),
                }
            )
    if len(assertions) != len(list(root.iter(SVRL + "failed-assert"))):
        raise sdk.CaptureError("Assertion outside a top-level template needs review")
    return {
        "source": source,
        "file": filename,
        "sha256": hashlib.sha256(data).hexdigest(),
        "namespaces": namespaces,
        "globals": [
            tree(n) for n in root if n.tag.startswith(XSL) and n.tag != XSL + "template"
        ],
        "templates": templates,
        "assertions": assertions,
    }


def build_catalog(root):
    root = root.parent if root.name == "Apps" else root
    sources = []
    for name, expected in SOURCES.items():
        path = root / expected["path"]
        if not path.is_file() or sdk.digest(path) != expected["sha256"]:
            raise sdk.CaptureError(f"Rule source checksum mismatch: {path}")
        source = extract_source(path.read_bytes(), name, expected["path"])
        if len(source["assertions"]) != expected["assertions"]:
            raise sdk.CaptureError(f"Incomplete assertion extraction: {name}")
        sources.append(source)
    return {"schema_version": 1, "sdk_version": sdk.VERSION, "sources": sources}


def load_catalog():
    path = ROOT / "catalog.json"
    checksum = (ROOT / "catalog.sha256").read_text().strip()
    if sdk.digest(path) != checksum:
        raise sdk.CaptureError("Rule catalog checksum mismatch")
    catalog = json.loads(path.read_text())
    if catalog["schema_version"] != 1 or catalog["sdk_version"] != sdk.VERSION:
        raise sdk.CaptureError("Unsupported rule catalog")
    if [s["source"] for s in catalog["sources"]] != list(SOURCES):
        raise sdk.CaptureError("Missing, duplicate or unexpected rule source")
    for source in catalog["sources"]:
        expected = SOURCES[source["source"]]
        if (
            source["sha256"] != expected["sha256"]
            or len(source["assertions"]) != expected["assertions"]
        ):
            raise sdk.CaptureError("Rule catalog differs from the pinned baseline")
    return catalog


def pending_coverage(catalog):
    return {
        "schema_version": 1,
        "sdk_version": sdk.VERSION,
        "sites": {
            a["site"]: {"status": "pending", "implementation": None, "tests": []}
            for s in catalog["sources"]
            for a in s["assertions"]
        },
    }


def validate_coverage(catalog, coverage):
    expected = {a["site"] for s in catalog["sources"] for a in s["assertions"]}
    if (
        coverage.get("schema_version") != 1
        or coverage.get("sdk_version") != sdk.VERSION
    ):
        raise sdk.CaptureError("Unsupported coverage schema or profile")
    if set(coverage.get("sites", {})) != expected:
        raise sdk.CaptureError(
            "Coverage inventory has missing or unexpected assertion sites"
        )
    for site, entry in coverage["sites"].items():
        status = entry.get("status")
        if status not in ["pending", "implemented", "unreachable"]:
            raise sdk.CaptureError(f"Unknown coverage disposition: {site}")
        if status == "implemented":
            if not entry.get("implementation") or not entry.get("tests"):
                raise sdk.CaptureError(
                    f"Coverage needs implementation and tests: {site}"
                )
            for path in [entry["implementation"], *entry["tests"]]:
                resolved = (sdk.REPO / path).resolve()
                if not resolved.is_relative_to(sdk.REPO) or not resolved.is_file():
                    raise sdk.CaptureError(f"Missing coverage evidence: {path}")
        if status == "unreachable" and not entry.get("evidence"):
            raise sdk.CaptureError(f"Unreachable assertion needs evidence: {site}")


def load_coverage(catalog):
    coverage = json.loads((ROOT / "coverage.json").read_text())
    validate_coverage(catalog, coverage)
    return coverage


def frozen_observations():
    manifest = sdk.load_manifest(sdk.CORPUS)
    cases = {}
    for case in manifest["cases"]:
        directory = sdk.CORPUS / "cases" / case["id"]
        if not (directory / "evidence/validate/stdout.txt").is_file():
            continue
        observations = {}
        for operation in ["validate", "signed-validate"]:
            evidence = directory / "evidence" / operation
            if not evidence.exists():
                continue
            process = json.loads((evidence / "process.json").read_text())
            output = (evidence / "stdout.txt").read_text() + (
                evidence / "stderr.txt"
            ).read_text()
            if case["kind"] == "malformed":
                # This is an observed parser rejection, not completed business validation.
                layers = json.loads((directory / "expected.json").read_text())[
                    "validation"
                ]
                report = {"layers": layers, "findings": []}
            else:
                report = sdk.parse_validation_report(output, process["exit_code"])
            observations[operation] = {
                "report": report,
                "evidence": {
                    str((evidence / name).relative_to(sdk.CORPUS)): sdk.digest(
                        evidence / name
                    )
                    for name in ["stdout.txt", "stderr.txt", "process.json"]
                },
            }
        cases[case["id"]] = observations
    return {
        "schema_version": 1,
        "sdk_version": sdk.VERSION,
        "corpus_manifest_sha256": sdk.digest(sdk.CORPUS / "manifest.json"),
        "cases": cases,
    }


def load_observations():
    expected = json.loads((ROOT / "observations.json").read_text())
    if expected != frozen_observations():
        raise sdk.CaptureError(
            "SDK finding observations no longer match frozen evidence"
        )
    return expected


def replace_once(xml, old, new):
    if old not in xml or old == new:
        raise sdk.CaptureError(f"Ineffective invoice mutation: {old!r}")
    return xml.replace(old, new, 1)


def mutation_cases(family="mutations"):
    if family == "ksa-prepayment":
        return families.ksa_prepayment_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-date-casts":
        return families.ksa_date_cast_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-arithmetic":
        return families.ksa_arithmetic_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-dates":
        return families.ksa_date_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-currency":
        return families.ksa_currency_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-exemptions":
        return families.ksa_exemption_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-adjustments":
        return families.ksa_adjustment_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "vat":
        return families.vat_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-common":
        return families.ksa_common_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-buyer":
        return families.ksa_buyer_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "ksa-fields":
        return families.ksa_field_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "totals":
        return families.totals_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "structural":
        return families.structural_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family == "identity":
        return families.identity_cases(
            (sdk.CORPUS / "cases/standard-invoice/input.xml").read_text()
        )
    if family != "mutations":
        raise sdk.CaptureError(f"Unknown rule family: {family}")
    return initial_mutation_cases()


def initial_mutation_cases():
    """Expectations are written from the pinned predicates before SDK capture."""
    base_path = sdk.CORPUS / "cases/standard-invoice/input.xml"
    base = base_path.read_text()
    cases = [{"id": "baseline", "xml": base, "expected_xsd": "passed", "targets": []}]

    def case(name, xml, source, code, severity, count=1):
        cases.append(
            {
                "id": name,
                "xml": xml,
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": source,
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    currency = "<cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode>"
    for name, value, count in [
        ("foreign-tax-currency", "USD", 1),
        ("lowercase-tax-currency", "sar", 0),
        ("xml-whitespace-tax-currency", " \tSAR\n", 0),
        ("unicode-whitespace-tax-currency", "\u00a0SAR\u00a0", 1),
    ]:
        case(
            name,
            replace_once(
                base, currency, f"<cbc:TaxCurrencyCode>{value}</cbc:TaxCurrencyCode>"
            ),
            "ksa",
            "BR-KSA-EN16931-02",
            "error",
            count,
        )
    case(
        "missing-tax-currency",
        replace_once(base, currency, ""),
        "ksa",
        "BR-KSA-EN16931-02",
        "error",
        0,
    )
    for name, field, value, code in [
        ("line-sum", "LineExtensionAmount", "1400.00", "BR-DEC-09"),
        ("allowance", "AllowanceTotalAmount", "20.00", "BR-DEC-10"),
        ("charge", "ChargeTotalAmount", "12.50", "BR-DEC-11"),
        ("exclusive", "TaxExclusiveAmount", "1392.50", "BR-DEC-12"),
        ("inclusive", "TaxInclusiveAmount", "1511.38", "BR-DEC-14"),
        ("prepaid", "PrepaidAmount", "0.00", "BR-DEC-16"),
        ("rounding", "PayableRoundingAmount", "0.00", "BR-DEC-17"),
        ("payable", "PayableAmount", "1511.38", "BR-DEC-18"),
    ]:
        old = f'<cbc:{field} currencyID="SAR">{value}</cbc:{field}>'
        new = old.replace(f">{value}<", f">{value}0<")
        case(
            "excess-scale-" + name, replace_once(base, old, new), "en", code, "warning"
        )
    for name, field, value, changed, code, severity in [
        (
            "wrong-line-sum",
            "LineExtensionAmount",
            "1400.00",
            "1400.01",
            "BR-CO-10",
            "warning",
        ),
        (
            "wrong-inclusive",
            "TaxInclusiveAmount",
            "1511.38",
            "1511.39",
            "BR-CO-15",
            "error",
        ),
    ]:
        old = f'<cbc:{field} currencyID="SAR">{value}</cbc:{field}>'
        case(
            name,
            replace_once(base, old, old.replace(value, changed)),
            "en",
            code,
            severity,
        )
    tax = '<cbc:TaxAmount currencyID="SAR">118.88</cbc:TaxAmount>'
    with_subtotal = tax + "\n    <cac:TaxSubtotal>"
    case(
        "wrong-tax-total",
        replace_once(base, with_subtotal, with_subtotal.replace("118.88", "118.89")),
        "en",
        "BR-CO-14",
        "error",
    )
    bare_tax = f"<cac:TaxTotal>\n    {tax}\n  </cac:TaxTotal>"
    case(
        "duplicate-tax-total",
        replace_once(base, bare_tax, bare_tax + "\n  " + bare_tax),
        "ksa",
        "BR-KSA-EN16931-09",
        "warning",
    )
    case(
        "missing-bare-tax-total",
        replace_once(base, bare_tax, ""),
        "ksa",
        "BR-KSA-EN16931-09",
        "warning",
    )
    two_names = replace_once(
        base, "<cbc:Name>Consulting Services</cbc:Name>", "<cbc:Name/>"
    )
    two_names = replace_once(
        two_names, "<cbc:Name>Software License</cbc:Name>", "<cbc:Name/>"
    )
    case("repeated-empty-item-name", two_names, "en", "BR-25", "warning", 1)
    cases[-1]["native_occurrences"] = 2
    cases[-1]["observation_note"] = (
        "The pinned SDK emits one BR-25 warning for two empty line item names. "
        "SDK-observable finding count does not prove per-node execution coverage."
    )
    case(
        "renamed-prefixes",
        base.replace("xmlns:cbc=", "xmlns:basic=").replace("cbc:", "basic:"),
        "ksa",
        "BR-KSA-EN16931-02",
        "error",
        0,
    )
    case(
        "currency-character-reference",
        replace_once(
            base, currency, "<cbc:TaxCurrencyCode>&#83;AR</cbc:TaxCurrencyCode>"
        ),
        "ksa",
        "BR-KSA-EN16931-02",
        "error",
        0,
    )
    case(
        "future-issue-date",
        replace_once(
            base,
            "<cbc:IssueDate>2024-02-10</cbc:IssueDate>",
            "<cbc:IssueDate>2099-01-01</cbc:IssueDate>",
        ),
        "ksa",
        "BR-KSA-04",
        "error",
    )
    case(
        "old-simplified-invoice",
        replace_once(
            base,
            '<cbc:InvoiceTypeCode name="0100000">',
            '<cbc:InvoiceTypeCode name="0200000">',
        ),
        "ksa",
        "BR-KSA-98",
        "warning",
    )
    return cases


def check_targets(case, report):
    if report["layers"]["xsd"] != case["expected_xsd"]:
        raise sdk.CaptureError(f"Unexpected XSD outcome: {case.get('id')}")
    counts = Counter(
        (f["source"], f["code"], f["severity"]) for f in report["findings"]
    )
    for target in case["targets"]:
        key = (target["source"], target["code"], target["severity"])
        if report["layers"].get(target["source"], "not_run") == "not_run":
            raise sdk.CaptureError(
                f"Target rule source did not run: {target['source']}"
            )
        if counts[key] != target["count"]:
            raise sdk.CaptureError(
                f"SDK differs from the predicate expectation for "
                f"{case.get('id')}, {key}: expected {target['count']}, got {counts[key]}"
            )


def capture_mutations(root, output, family="mutations"):
    """Run only the unmodified SDK's public -validate command in an isolated copy."""
    root = sdk.sdk_root(root)
    build_catalog(root)  # Verify both stylesheet pins, not only the JAR.
    sdk.load_manifest(sdk.CORPUS)
    before = {
        str(p.relative_to(root)): sdk.digest(p) for p in root.rglob("*") if p.is_file()
    }
    cases = mutation_cases(family)
    sdk.new_output(output)
    snapshots = output / "capture-tools"
    snapshots.mkdir()
    shutil.copyfile(__file__, snapshots / "business_rules.py")
    shutil.copyfile(sdk.__file__, snapshots / "sdk_parity.py")
    shutil.copyfile(families.__file__, snapshots / "business_rule_cases.py")
    manifest = {
        "schema_version": 1,
        "sdk_version": sdk.VERSION,
        "jar_sha256": sdk.JAR_SHA256,
        "sources": {name: value["sha256"] for name, value in SOURCES.items()},
        "source_corpus_sha256": sdk.digest(sdk.CORPUS / "manifest.json"),
        "family": family,
        "family_tool_sha256": sdk.digest(Path(families.__file__)),
        "capture_tool_sha256": sdk.digest(Path(__file__)),
        "sdk_tool_sha256": sdk.digest(Path(sdk.__file__)),
        "java_version": subprocess.run(
            ["java", "-version"], capture_output=True, text=True, check=True
        ).stderr,
        "timezone": "UTC (TZ=UTC; JAVA_TOOL_OPTIONS=-Duser.timezone=UTC)",
        "cases": [],
    }
    errors = []
    try:
        with sdk.isolated_sdk(root) as (scratch, env):
            # Replace inherited options so reference captures have a known timezone.
            env = {**env, "TZ": "UTC", "JAVA_TOOL_OPTIONS": "-Duser.timezone=UTC"}
            for case in cases:
                directory = output / "cases" / case["id"]
                directory.mkdir(parents=True)
                invoice = directory / "input.xml"
                invoice.write_text(case["xml"], encoding="utf-8")
                started = datetime.now(timezone.utc).isoformat()
                tick = time.monotonic()
                process, raw = sdk.invoke(
                    scratch,
                    env,
                    ["-validate", "-invoice", invoice],
                    directory / "evidence",
                )
                finished = datetime.now(timezone.utc).isoformat()
                report = sdk.parse_validation_report(raw, process["exit_code"])
                sdk.write_json(directory / "expected.json", report)
                recorded = {k: v for k, v in case.items() if k != "xml"}
                recorded.update(
                    started_at=started,
                    finished_at=finished,
                    duration_seconds=time.monotonic() - tick,
                )
                manifest["cases"].append(recorded)
                try:
                    check_targets(case, report)
                except sdk.CaptureError as exc:
                    errors.append(str(exc))
                print(
                    f"Captured {case['id']}: {len(report['findings'])} findings",
                    flush=True,
                )
    finally:
        after = {
            str(p.relative_to(root)): sdk.digest(p)
            for p in root.rglob("*")
            if p.is_file()
        }
        if before != after:
            raise sdk.CaptureError("Installed SDK changed during capture")
    manifest["artifacts"] = {
        str(p.relative_to(output)): sdk.digest(p)
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }
    manifest["expectation_mismatches"] = errors
    sdk.write_json(output / "manifest.json", manifest)
    if errors:
        raise sdk.CaptureError("\n".join(errors))
    print("SDK mutation capture passed; installed SDK unchanged.")


def load_mutations(corpus=None):
    corpus = corpus or ROOT / "mutations"
    manifest = json.loads((corpus / "manifest.json").read_text())
    if (
        manifest.get("schema_version") != 1
        or manifest.get("sdk_version") != sdk.VERSION
        or manifest.get("jar_sha256") != sdk.JAR_SHA256
        or manifest.get("expectation_mismatches") != []
        or manifest.get("sources") != {k: v["sha256"] for k, v in SOURCES.items()}
        or manifest.get("source_corpus_sha256")
        != sdk.digest(sdk.CORPUS / "manifest.json")
    ):
        raise sdk.CaptureError("Mutation corpus has an unreviewed profile or mismatch")
    cases = mutation_cases(manifest.get("family", "mutations"))
    if [c["id"] for c in manifest.get("cases", [])] != [c["id"] for c in cases]:
        raise sdk.CaptureError(
            "Mutation corpus has missing, duplicate or unexpected cases"
        )
    artifacts = manifest.get("artifacts", {})
    present = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p != corpus / "manifest.json"
    }
    if present != set(artifacts):
        raise sdk.CaptureError("Mutation corpus has missing or unlisted artifacts")
    for path, checksum in artifacts.items():
        p = corpus / path
        if (
            not p.resolve().is_relative_to(corpus.resolve())
            or sdk.digest(p) != checksum
        ):
            raise sdk.CaptureError(f"Mutation artifact checksum mismatch: {path}")
    if (
        "family_tool_sha256" in manifest
        and sdk.digest(corpus / "capture-tools/business_rule_cases.py")
        != manifest["family_tool_sha256"]
    ):
        raise sdk.CaptureError("Family script provenance mismatch")
    for script, expected in [
        ("business_rules.py", manifest["capture_tool_sha256"]),
        ("sdk_parity.py", manifest["sdk_tool_sha256"]),
    ]:
        if sdk.digest(corpus / "capture-tools" / script) != expected:
            raise sdk.CaptureError(f"Capture script provenance mismatch: {script}")
    for expected, captured in zip(cases, manifest["cases"]):
        directory = corpus / "cases" / expected["id"]
        if (directory / "input.xml").read_bytes() != expected["xml"].encode("utf-8"):
            raise sdk.CaptureError(
                f"Mutation differs from its definition: {expected['id']}"
            )
        for key in set(expected) - {"xml"}:
            if captured.get(key) != expected[key]:
                raise sdk.CaptureError(
                    f"Mutation expectations changed: {expected['id']}"
                )
        process = json.loads((directory / "evidence/process.json").read_text())
        raw = (directory / "evidence/stdout.txt").read_text() + (
            directory / "evidence/stderr.txt"
        ).read_text()
        report = sdk.parse_validation_report(raw, process["exit_code"])
        if report != json.loads((directory / "expected.json").read_text()):
            raise sdk.CaptureError(
                f"Mutation findings differ from SDK evidence: {expected['id']}"
            )
        check_targets(expected, report)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser(
        "inventory", help="Extract a candidate; never execute the SDK"
    )
    inventory.add_argument(
        "--sdk-root", type=Path, default=os.environ.get("FATOORA_HOME")
    )
    inventory.add_argument("--output", type=Path, required=True)
    capture = commands.add_parser(
        "capture", help="Capture rule mutations using the official SDK"
    )
    capture.add_argument(
        "--sdk-root", type=Path, default=os.environ.get("FATOORA_HOME")
    )
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument(
        "--family",
        choices=[
            "mutations",
            "identity",
            "structural",
            "totals",
            "ksa-fields",
            "ksa-buyer",
            "ksa-common",
            "vat",
            "ksa-adjustments",
            "ksa-exemptions",
            "ksa-currency",
            "ksa-dates",
            "ksa-arithmetic",
            "ksa-date-casts",
            "ksa-prepayment",
        ],
        default="mutations",
    )
    commands.add_parser(
        "check", help="Verify catalog, coverage and observations offline"
    )
    args = parser.parse_args()
    try:
        if args.command == "capture":
            if not args.sdk_root:
                raise sdk.CaptureError("Provide --sdk-root or FATOORA_HOME")
            capture_mutations(args.sdk_root, args.output.resolve(), args.family)
        elif args.command == "inventory":
            if not args.sdk_root:
                raise sdk.CaptureError("Provide --sdk-root or FATOORA_HOME")
            catalog = build_catalog(args.sdk_root)
            observations = frozen_observations()
            sdk.new_output(args.output)
            sdk.write_json(args.output / "catalog.json", catalog)
            (args.output / "catalog.sha256").write_text(
                sdk.digest(args.output / "catalog.json") + "\n"
            )
            sdk.write_json(args.output / "coverage.json", pending_coverage(catalog))
            sdk.write_json(args.output / "observations.json", observations)
            print(
                f"Extracted 257 assertion sites to {args.output}; all coverage is pending."
            )
        else:
            catalog = load_catalog()
            coverage = load_coverage(catalog)
            observations = load_observations()
            mutations = load_mutations()
            identity = load_mutations(ROOT / "identity")
            structural = load_mutations(ROOT / "structural")
            totals = load_mutations(ROOT / "totals")
            ksa_fields = load_mutations(ROOT / "ksa-fields")
            ksa_buyer = load_mutations(ROOT / "ksa-buyer")
            ksa_common = load_mutations(ROOT / "ksa-common")
            vat = load_mutations(ROOT / "vat")
            adjustments = load_mutations(ROOT / "ksa-adjustments")
            exemptions = load_mutations(ROOT / "ksa-exemptions")
            currency = load_mutations(ROOT / "ksa-currency")
            dates = load_mutations(ROOT / "ksa-dates")
            date_casts = load_mutations(ROOT / "ksa-date-casts")
            prepayment = load_mutations(ROOT / "ksa-prepayment")
            counts = Counter(e["status"] for e in coverage["sites"].values())
            print(
                f"SDK {sdk.VERSION}: {len(coverage['sites'])} inventoried assertion sites; "
                f"{counts['implemented']} implemented, {counts['pending']} pending, "
                f"{counts['unreachable']} documented unreachable."
            )
            print(
                f"Verified SDK observations for {len(observations['cases'])} cases; "
                "inventory integrity does not establish rule coverage."
            )
            print(f"Verified {len(mutations['cases'])} targeted SDK mutation cases.")
            print(f"Verified {len(identity['cases'])} identity/address SDK cases.")
            print(f"Verified {len(structural['cases'])} structure/code-list SDK cases.")
            print(f"Verified {len(totals['cases'])} monetary SDK cases.")
            print(f"Verified {len(ksa_fields['cases'])} Saudi field SDK cases.")
            print(f"Verified {len(ksa_buyer['cases'])} Saudi buyer SDK cases.")
            print(f"Verified {len(ksa_common['cases'])} Saudi document SDK cases.")
            print(f"Verified {len(vat['cases'])} VAT rounding SDK cases.")
            print(f"Verified {len(adjustments['cases'])} Saudi adjustment SDK cases.")
            print(f"Verified {len(exemptions['cases'])} Saudi exemption SDK cases.")
            print(f"Verified {len(currency['cases'])} Saudi currency SDK cases.")
            print(f"Verified {len(dates['cases'])} Saudi date SDK cases.")
            print(f"Verified {len(date_casts['cases'])} Saudi date cast SDK cases.")
            print(f"Verified {len(prepayment['cases'])} Saudi prepayment SDK cases.")
    except (sdk.CaptureError, OSError, KeyError, ValueError) as exc:
        parser.exit(1, f"business rules: {exc}\n")


if __name__ == "__main__":
    main()
