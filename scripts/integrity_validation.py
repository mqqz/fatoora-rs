#!/usr/bin/env python3
"""Freeze local integrity mutations through the unmodified official SDK CLI."""

import argparse
import base64
import json
import os
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import business_rules as rules
import sdk_parity as sdk

CORPUS = rules.ROOT / "integrity"
NS = {
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
}
SEED = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="


def replace(xml, old, new):
    if xml.count(old) != 1:
        raise sdk.CaptureError(f"Mutation requires unique original: {old}")
    return xml.replace(old, new)


def text(xml, path):
    nodes = ET.fromstring(xml).findall(path, NS)
    if len(nodes) != 1 or not nodes[0].text:
        raise sdk.CaptureError(f"Mutation requires unique text: {path}")
    return nodes[0].text


def cases():
    result = []
    for kind in ["standard", "simplified"]:
        for document in ["invoice", "credit", "debit"]:
            name = f"{kind}-{document}"
            xml = (sdk.CORPUS / "cases" / name / "sdk-signed.xml").read_text()
            result.append({"id": name, "xml": xml, "native": {}, "policy": None})
    base = result[3]["xml"]

    def add(name, xml, stage, code, policy=None):
        result.append(
            {"id": name, "xml": xml, "native": {stage: code}, "policy": policy}
        )

    add(
        "content",
        replace(base, "<cbc:ID>INV-1</cbc:ID>", "<cbc:ID>INV-2</cbc:ID>"),
        "signature",
        "SIGNATURE_DIGEST",
    )
    value = text(base, ".//ds:SignatureValue")
    raw = bytearray(base64.b64decode(value))
    raw[-1] ^= 1
    add(
        "signature-value",
        replace(base, value, base64.b64encode(raw).decode()),
        "signature",
        "SIGNATURE_VALUE",
    )
    for name, old, new, code in [
        (
            "digest",
            text(base, ".//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue"),
            base64.b64encode(bytes(32)).decode(),
            "SIGNATURE_DIGEST",
        ),
        (
            "properties",
            text(base, ".//xades:SigningTime"),
            "2000-01-01T00:00:00Z",
            "SIGNED_PROPERTIES_DIGEST",
        ),
        (
            "certificate",
            text(base, ".//ds:X509Certificate"),
            "AAAA",
            "SIGNATURE_CERTIFICATE",
        ),
        (
            "algorithm",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            "urn:unsupported",
            "SIGNATURE_ALGORITHM",
        ),
        (
            "reference",
            'URI="#xadesSignedProperties"',
            'URI="#missing"',
            "SIGNATURE_REFERENCES",
        ),
        ("target", 'Target="signature"', 'Target="another"', "SIGNATURE_REFERENCES"),
        (
            "duplicate-id",
            "<ds:Object>",
            '<ds:Object Id="signature">',
            "SIGNATURE_DUPLICATE_ID",
        ),
        (
            "transform-namespace",
            "<ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)",
            '<ds:XPath xmlns:ext="urn:wrong">not(//ancestor-or-self::ext:UBLExtensions)',
            "SIGNATURE_TRANSFORMS",
        ),
    ]:
        add(
            name,
            replace(base, old, new),
            "signature",
            code,
            "LOCAL-INTEGRITY-001"
            if name
            in [
                "algorithm",
                "reference",
                "target",
                "duplicate-id",
                "transform-namespace",
            ]
            else None,
        )
    old = text(
        base,
        ".//cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
    )
    raw = base64.b64decode(old)
    tags = []
    at = 0
    while at < len(raw):
        tag, size = raw[at : at + 2]
        tags.append((tag, raw[at + 2 : at + 2 + size]))
        at += 2 + size

    def qr(name, changed, code, policy=None):
        encoded = base64.b64encode(changed).decode()
        add(name, replace(base, old, encoded), "qr", code, policy)

    for name, tag, value, code, policy in [
        ("qr-seller", 1, b"Other", "QR_VALUE", None),
        ("qr-vat-id", 2, b"300000000000013", "QR_VALUE", None),
        ("qr-total", 4, b"116.00", "QR_VALUE", None),
        ("qr-total-scale", 4, b"115.0", "QR_VALUE", None),
        ("qr-vat", 5, b"16.0", "QR_VAT", "SDK-QR-003"),
        ("qr-vat-scale", 5, b"15.0", None, None),
        ("qr-vat-nan", 5, b"NaN", "QR_VAT", "SDK-QR-003"),
        ("qr-vat-exponent", 5, b"15e0", "QR_VAT", "SDK-QR-003"),
        (
            "qr-vat-float-collision",
            5,
            b"15.00000000000000000001",
            "QR_VAT",
            "SDK-QR-003",
        ),
        ("qr-time-z", 3, b"2024-01-01T12:30:00Z", None, None),
        ("qr-time-offset", 3, b"2024-01-01T15:30:00+03:00", None, None),
        (
            "qr-time-wrong-offset",
            3,
            b"2024-01-01T12:30:00+03:00",
            "QR_TIMESTAMP",
            "SDK-QR-002",
        ),
        (
            "qr-time-garbage",
            3,
            b"2024-01-01T12:30:00garbage",
            "QR_TIMESTAMP",
            "SDK-QR-002",
        ),
        ("qr-time-wrong", 3, b"2024-01-02T12:30:00Z", "QR_TIMESTAMP", "SDK-QR-002"),
        ("qr-hash", 6, b"A" * 44, "QR_VALUE", None),
        ("qr-signature", 7, b"A" * 96, "QR_VALUE", None),
        ("qr-public-key", 8, b"A" * 88, "QR_VALUE", None),
        ("qr-certificate-signature", 9, b"A" * 72, "QR_VALUE", None),
    ]:
        changed = b"".join(
            bytes([t, len(value if t == tag else v)]) + (value if t == tag else v)
            for t, v in tags
        )
        qr(name, changed, code, policy)
    qr("qr-truncated", raw[:-1], "QR_TLV", "LOCAL-INTEGRITY-001")
    qr("qr-duplicate", raw + bytes([1, 1, 65]), "QR_TLV", "LOCAL-INTEGRITY-001")
    qr(
        "qr-missing-tag",
        b"".join(bytes([t, len(v)]) + v for t, v in tags if t != 9),
        "QR_TLV",
        "LOCAL-INTEGRITY-001",
    )
    standard = result[0]["xml"]
    for name, value, code in [
        ("pih-mismatch", base64.b64encode(bytes(32)).decode(), "PIH_MISMATCH"),
        ("pih-invalid", "bad", "PIH_FORMAT"),
        ("pih-whitespace", f" {SEED} ", "PIH_FORMAT"),
    ]:
        add(name, replace(standard, SEED, value), "previous_invoice_hash", code)
    return result


def capture(root, output):
    root = sdk.sdk_root(root)
    rules.build_catalog(root)
    sdk.load_manifest(sdk.CORPUS)
    inputs = cases()
    before = {
        str(p.relative_to(root)): sdk.digest(p) for p in root.rglob("*") if p.is_file()
    }
    sdk.new_output(output)
    snapshots = output / "capture-tools"
    snapshots.mkdir()
    for tool in [
        Path(__file__),
        Path(sdk.__file__),
        Path(rules.__file__),
        Path(rules.families.__file__),
    ]:
        shutil.copyfile(tool, snapshots / tool.name)
    manifest = {
        "schema_version": 1,
        "sdk_version": sdk.VERSION,
        "jar_sha256": sdk.JAR_SHA256,
        "sources": {k: v["sha256"] for k, v in rules.SOURCES.items()},
        "source_corpus_sha256": sdk.digest(sdk.CORPUS / "manifest.json"),
        "timezone": "UTC",
        "cases": [],
    }
    try:
        with sdk.isolated_sdk(root) as (scratch, env):
            env = {**env, "TZ": "UTC", "JAVA_TOOL_OPTIONS": "-Duser.timezone=UTC"}
            for case in inputs:
                directory = output / "cases" / case["id"]
                directory.mkdir(parents=True)
                invoice = directory / "input.xml"
                invoice.write_text(case["xml"])
                started = datetime.now(timezone.utc).isoformat()
                process, raw = sdk.invoke(
                    scratch,
                    env,
                    ["-validate", "-invoice", invoice],
                    directory / "evidence",
                )
                report = sdk.parse_validation_report(raw, process["exit_code"])
                sdk.write_json(directory / "expected.json", report)
                manifest["cases"].append(
                    {
                        **{k: v for k, v in case.items() if k != "xml"},
                        "started_at": started,
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                print(case["id"], report["layers"], flush=True)
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
    sdk.write_json(output / "manifest.json", manifest)


def check(corpus):
    manifest = json.loads((corpus / "manifest.json").read_text())
    if (
        manifest["schema_version"] != 1
        or manifest["sdk_version"] != sdk.VERSION
        or manifest["jar_sha256"] != sdk.JAR_SHA256
        or manifest["sources"] != {k: v["sha256"] for k, v in rules.SOURCES.items()}
        or manifest["source_corpus_sha256"] != sdk.digest(sdk.CORPUS / "manifest.json")
    ):
        raise sdk.CaptureError("Integrity source pins differ")
    artifacts = {
        str(p.relative_to(corpus)): sdk.digest(p)
        for p in corpus.rglob("*")
        if p.is_file() and p != corpus / "manifest.json"
    }
    if artifacts != manifest["artifacts"]:
        raise sdk.CaptureError("Integrity artifact inventory differs")
    defined = cases()
    if len(defined) != len(manifest["cases"]):
        raise sdk.CaptureError("Integrity case inventory differs")
    for definition, recorded in zip(defined, manifest["cases"], strict=True):
        directory = corpus / "cases" / definition["id"]
        if (
            any(definition[k] != recorded[k] for k in ["id", "native", "policy"])
            or (directory / "input.xml").read_text() != definition["xml"]
        ):
            raise sdk.CaptureError("Integrity case definition differs")
        process = json.loads((directory / "evidence/process.json").read_text())
        raw = (directory / "evidence/stdout.txt").read_text() + (
            directory / "evidence/stderr.txt"
        ).read_text()
        report = sdk.parse_validation_report(raw, process["exit_code"])
        if report != json.loads((directory / "expected.json").read_text()):
            raise sdk.CaptureError(
                "Integrity expected results differ from SDK evidence"
            )
        if not definition["native"] and report["layers"]["global"] != "passed":
            raise sdk.CaptureError(
                "Baseline integrity case did not pass SDK validation"
            )
        for stage, code in definition["native"].items():
            source = "pih" if stage == "previous_invoice_hash" else stage
            outcome = report["layers"][source]
            if outcome == "not_run":
                raise sdk.CaptureError("Target SDK integrity stage did not run")
            if definition["policy"] is None and outcome != (
                "failed" if code else "passed"
            ):
                raise sdk.CaptureError(
                    "Undocumented native-versus-SDK integrity difference"
                )
    print(f"Verified {len(defined)} integrity cases and all evidence hashes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["capture", "check"])
    parser.add_argument("--sdk-root", type=Path, default=os.environ.get("FATOORA_HOME"))
    parser.add_argument("--output", type=Path, default=CORPUS)
    args = parser.parse_args()
    if args.command == "capture":
        if not args.sdk_root:
            parser.error("Provide --sdk-root or FATOORA_HOME")
        capture(args.sdk_root, args.output.resolve())
    else:
        check(args.output)


if __name__ == "__main__":
    main()
