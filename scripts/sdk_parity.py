#!/usr/bin/env python3
"""Explicit, isolated capture of official ZATCA SDK evidence (Python stdlib only)."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "fatoora-core/tests/fixtures/sdk-parity"
VERSION = "238-R3.4.8"
JAR_SHA256 = "48abeb828d453ef6fafba792fddbbb2701da5c7018c24bde918853e80ff5d530"


class CaptureError(RuntimeError):
    pass


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sdk_root(path):
    root = path.resolve()
    if root.name == "Apps":
        root = root.parent
    if not (root / "Apps/global.json").is_file():
        raise CaptureError(f"SDK root missing Apps/global.json: {root}")
    if json.loads((root / "Apps/global.json").read_text())["version"] != VERSION:
        raise CaptureError(f"Expected pinned SDK {VERSION}")
    jar = root / f"Apps/zatca-einvoicing-sdk-{VERSION}.jar"
    if not jar.is_file() or digest(jar) != JAR_SHA256:
        raise CaptureError("SDK JAR checksum differs from pinned baseline")
    fixtures = REPO / "fatoora-core/tests/fixtures"
    cert = base64.b64decode((root / "Data/Certificates/cert.pem").read_bytes())
    key = base64.b64decode(
        (root / "Data/Certificates/ec-secp256k1-priv-key.pem").read_bytes()
    )
    expected_cert = base64.b64decode(
        base64.b64decode((fixtures / "certs/zatca_cert_b64.txt").read_bytes())
    )
    if (
        cert != expected_cert
        or key != (fixtures / "pkeys/test_zatca_pkey.der").read_bytes()
    ):
        raise CaptureError("SDK credentials differ from the known dummy test fixtures")
    return root


def new_output(path):
    if path.exists():
        raise CaptureError(
            f"Output already exists; choose a new candidate directory: {path}"
        )
    path.mkdir(parents=True)


def require_artifact(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise CaptureError(f"Missing or empty SDK artifact: {path}")
    return path.read_bytes()


def run(argv, cwd, env, evidence, timeout=60):
    evidence.mkdir(parents=True, exist_ok=True)
    record = {"argv": [str(a) for a in argv], "cwd": str(cwd)}
    try:
        p = subprocess.run(
            record["argv"],
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        record["exit_code"] = p.returncode
        stdout, stderr = p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        record["error"] = str(e)
        stdout, stderr = (
            getattr(e, "stdout", None) or b"",
            getattr(e, "stderr", None) or b"",
        )
    (evidence / "stdout.txt").write_bytes(stdout)
    (evidence / "stderr.txt").write_bytes(stderr)
    write_json(evidence / "process.json", record)
    if "error" in record:
        raise CaptureError(f"Command failed; evidence: {evidence}: {record['error']}")
    return record


def parse_hash(output, exit_code):
    matches = re.findall(r"INVOICE HASH\s*=\s*([^\s]+)", output)
    if exit_code != 0 or len(matches) != 1:
        raise CaptureError("Expected one successful SDK hash result")
    try:
        value = base64.b64decode(matches[0], validate=True)
    except ValueError as e:
        raise CaptureError("Invalid SDK digest base64") from e
    if len(value) != 32:
        raise CaptureError("SDK hash must contain 32 bytes")
    return matches[0]


def parse_validation(output, exit_code):
    results = {}
    for key, marker in [
        (k.lower(), rf"\[{k}\] validation result")
        for k in ["XSD", "EN", "KSA", "QR", "SIGNATURE", "PIH"]
    ] + [("global", r"GLOBAL VALIDATION RESULT")]:
        lines = [
            line
            for line in output.splitlines()
            if re.search(marker, line, re.IGNORECASE)
        ]
        if len(lines) > 1 or (key == "xsd" and not lines):
            raise CaptureError(
                f"Missing or ambiguous {key} validation result (exit {exit_code})"
            )
        if not lines:
            results[key] = "not_run"
            continue
        outcomes = re.findall(r"\b(PASSED|FAILED)\b", lines[0], re.IGNORECASE)
        if len(outcomes) != 1:
            raise CaptureError(f"Unrecognized {key} validation result")
        results[key] = outcomes[0].lower()
    # This SDK reports document rejection with exit zero. Nonzero is a harness failure.
    if exit_code != 0:
        raise CaptureError(f"SDK validation process failed: {exit_code}")
    return results


def parse_validation_report(output, exit_code):
    """Preserve SDK-observable findings without inferring XML locations or coverage.

    The SDK logs warning section headings at ERROR level. Section headings,
    rather than the logger level, identify a finding's severity. Duplicate
    findings are intentionally retained in their observed order.
    """
    layers = parse_validation(output, exit_code)
    findings = []
    section = None
    continuing = False
    for line in output.splitlines():
        prefix = re.match(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d+ "
            r"\[[A-Z]+\] [\w.$]+ - (.*)$",
            line,
        )
        payload = prefix[1] if prefix else line
        header = re.fullmatch(
            r"\s*(\w+) validation (errors|warnings)\s*:\s*", payload, re.IGNORECASE
        )
        if header:
            source = header[1].lower()
            if source not in layers or source == "global":
                raise CaptureError(f"Unknown SDK finding source: {source}")
            section = (source, "error" if header[2].lower() == "errors" else "warning")
            continuing = False
        elif re.match(r"\s*CODE\s*:", payload):
            finding = re.fullmatch(
                r"\s*CODE\s*:\s*([^,\r\n]*\S)\s*, MESSAGE\s*:\s*(.*)", payload
            )
            if not section or not finding:
                raise CaptureError("Malformed or unattributed SDK finding")
            source, severity = section
            if layers[source] == "not_run" or (
                severity == "error" and layers[source] == "passed"
            ):
                raise CaptureError(f"Finding contradicts SDK {source} outcome")
            findings.append(
                {
                    "source": source,
                    "severity": severity,
                    "code": finding[1].strip(),
                    "message": finding[2],
                }
            )
            continuing = True
        elif prefix or re.search(
            r"validation result|GLOBAL VALIDATION RESULT", payload, re.IGNORECASE
        ):
            section = None
            continuing = False
        elif continuing and payload.strip():
            findings[-1]["message"] += "\n" + payload
        elif not payload.strip():
            continuing = False
    return {"layers": layers, "findings": findings}


@contextmanager
def isolated_sdk(root):
    with tempfile.TemporaryDirectory(prefix="fatoora sdk parity ") as directory:
        scratch = Path(directory) / "sdk"
        shutil.copytree(root, scratch)
        paths = {
            "xsdPath": "Data/Schemas/xsds/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd",
            "enSchematron": "Data/Rules/Schematrons/CEN-EN16931-UBL.xsl",
            "zatcaSchematron": "Data/Rules/Schematrons/20210819_ZATCA_E-invoice_Validation_Rules.xsl",
            "certPath": "Data/Certificates/cert.pem",
            "privateKeyPath": "Data/Certificates/ec-secp256k1-priv-key.pem",
            "pihPath": "Data/PIH/pih.txt",
            "inputPath": "Data/Input",
            "usagePathFile": "Configuration/usage.txt",
        }
        for relative in paths.values():
            if not (scratch / relative).exists():
                raise CaptureError(f"SDK resource missing: {relative}")
        config = scratch / "Configuration/config.json"
        write_json(config, {k: str(scratch / v) for k, v in paths.items()})
        env = {
            **os.environ,
            "FATOORA_HOME": str(scratch / "Apps"),
            "SDK_CONFIG": str(config),
        }
        yield scratch, env


def invoke(scratch, env, args, evidence):
    record = run(
        [
            "java",
            "-Djdk.sunec.disableNative=false",
            "-jar",
            scratch / f"Apps/zatca-einvoicing-sdk-{VERSION}.jar",
            "--globalVersion",
            VERSION,
            *args,
        ],
        scratch / "Apps",
        env,
        evidence,
    )
    output = (evidence / "stdout.txt").read_text(errors="strict") + (
        evidence / "stderr.txt"
    ).read_text(errors="strict")
    return record, output


def prepare_inputs(inputs):
    cases = []
    for path in sorted(inputs.glob("*.xml")):
        cases.append(
            {
                "id": path.stem,
                "kind": "invoice",
                "source": "repository test builder",
                "bytes": path.read_bytes(),
            }
        )
    base = (inputs / "simplified-invoice.xml").read_text()

    def mutation(name, old, new, kind="xml"):
        if old not in base or old == new:
            raise CaptureError(f"Mutation {name} did not change input")
        cases.append(
            {
                "id": name,
                "kind": kind,
                "source": "simplified-invoice: " + name,
                "bytes": base.replace(old, new, 1).encode(),
            }
        )

    mutation(
        "comments",
        "<cbc:ID>INV-1</cbc:ID>",
        "<!-- corpus -->" + "<cbc:ID>INV-1</cbc:ID>",
    )
    mutation(
        "processing-instruction",
        "<cbc:ID>INV-1</cbc:ID>",
        "<?corpus test?><cbc:ID>INV-1</cbc:ID>",
    )
    mutation("arabic", "Acme Inc", "شركة الاختبار")
    mutation("text-whitespace", "Acme Inc", " Acme Inc ")
    mutation("character-reference", "Acme Inc", "&#65;cme Inc")
    mutation("cdata", "Acme Inc", "<![CDATA[Acme Inc]]>")
    mutation(
        "unused-namespace", "<Invoice ", '<Invoice xmlns:unused="urn:corpus:unused" '
    )
    mutation(
        "included-amount",
        ">115.00</cbc:TaxInclusiveAmount>",
        ">116.00</cbc:TaxInclusiveAmount>",
    )
    mutation("missing-id", "  <cbc:ID>INV-1</cbc:ID>\n", "", "invalid")
    mutation(
        "invalid-datatype",
        "<cbc:IssueDate>2024-01-01",
        "<cbc:IssueDate>not-a-date",
        "invalid",
    )
    mutation(
        "wrong-order",
        "  <cbc:ProfileID>reporting:1.0</cbc:ProfileID>\n  <cbc:ID>INV-1</cbc:ID>",
        "  <cbc:ID>INV-1</cbc:ID>\n  <cbc:ProfileID>reporting:1.0</cbc:ProfileID>",
        "invalid",
    )
    mutation(
        "wrong-namespace",
        "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
        "urn:wrong",
        "invalid",
    )
    mutation("malformed", "</Invoice>", "", "malformed")
    mutation(
        "excluded-extension",
        "  <cbc:ProfileID>",
        '<ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent><test xmlns="urn:test">excluded</test></ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions>\n  <cbc:ProfileID>',
    )
    mutation(
        "excluded-signature",
        "  <cac:AccountingSupplierParty>",
        "<cac:Signature><cbc:ID>excluded</cbc:ID></cac:Signature>\n  <cac:AccountingSupplierParty>",
    )
    mutation(
        "excluded-qr",
        "  <cac:AccountingSupplierParty>",
        '<cac:AdditionalDocumentReference><cbc:ID>QR</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">excluded</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference>\n  <cac:AccountingSupplierParty>',
    )
    for name, xml in [
        ("crlf", base.replace("\n", "\r\n")),
        (
            "alternate-prefix",
            base.replace("cbc:", "basic:").replace("xmlns:cbc=", "xmlns:basic="),
        ),
        (
            "explicit-default-namespace",
            base.replace(
                "<cbc:ID>INV-1</cbc:ID>",
                '<ID xmlns="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">INV-1</ID>',
            ),
        ),
        (
            "namespace-order",
            base.replace(
                'xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" ',
                "",
            ).replace(
                "<Invoice ",
                '<Invoice xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" ',
            ),
        ),
        (
            "attribute-order-a",
            base.replace(
                "<cbc:ID>INV-1", '<cbc:ID schemeID="test" schemeName="corpus">INV-1'
            ),
        ),
        (
            "attribute-order-b",
            base.replace(
                "<cbc:ID>INV-1", '<cbc:ID schemeName="corpus" schemeID="test">INV-1'
            ),
        ),
        ("empty-element-a", base.replace("<cbc:ID>INV-1</cbc:ID>", "<cbc:ID/>")),
        (
            "empty-element-b",
            base.replace("<cbc:ID>INV-1</cbc:ID>", "<cbc:ID></cbc:ID>"),
        ),
    ]:
        if xml == base:
            raise CaptureError(name)
        cases.append(
            {
                "id": name,
                "kind": "xml",
                "source": "simplified-invoice: " + name,
                "bytes": xml.encode(),
            }
        )
    for name, relative in [
        (
            "payable-rounding",
            "Standard/Invoice/Standard Invoice with Payable Rounding Adjustment.xml",
        ),
        ("exempt", "Standard/Invoice/Exempt Tax Invoice.xml"),
        (
            "zero-rated",
            "Simplified/Invoice/Simplified Tax Invoice with Zero Rated Item.xml",
        ),
        (
            "document-charge",
            "Standard/Invoice/Standard Invoice with Document Level Charge.xml",
        ),
    ]:
        path = REPO / "fatoora-core/tests/fixtures/invoices" / relative
        cases.append(
            {
                "id": name,
                "kind": "invoice",
                "source": "existing SDK sample: " + relative,
                "bytes": path.read_bytes(),
            }
        )
    return cases


def pem_or_base64_der(data):
    if not data.startswith(b"-----BEGIN"):
        data = base64.b64decode(data, validate=True)
    if data.startswith(b"-----BEGIN"):
        data = base64.b64decode(b"".join(data.splitlines()[1:-1]), validate=True)
    return data


def capture(root, output, inputs):
    import concurrent.futures
    import xml.etree.ElementTree as ET

    new_output(output)
    before = {
        str(p.relative_to(root)): digest(p) for p in root.rglob("*") if p.is_file()
    }
    manifest = {
        "schema_version": 1,
        "sdk": {
            "version": VERSION,
            "jar_sha256": JAR_SHA256,
            "source_url": "https://www.zatca.gov.sa/en/E-Invoicing/SystemsDevelopers/ComplianceEnablementToolbox/Pages/DownloadSDK.aspx",
            "resource_sha256": before,
        },
        "capture": {
            "tool_sha256": digest(Path(__file__)),
            "canonical_adapter_sha256": digest(
                REPO / "scripts/sdk-parity/CanonicalBytes.java"
            ),
            "git_revision": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
            ).strip(),
            "java_version": subprocess.run(
                ["java", "-version"], capture_output=True, text=True, check=True
            ).stderr,
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "cases": [],
    }
    # Preserve the precise capture implementation even when run before committing.
    tools_dir = output / "evidence" / "capture-tools"
    tools_dir.mkdir(parents=True)
    for source in [
        Path(__file__),
        REPO / "scripts/sdk-parity/CanonicalBytes.java",
        REPO / "scripts/sdk-parity/SignedPropertiesBytes.java",
    ]:
        shutil.copyfile(source, tools_dir / source.name)
    credentials = output / "credentials"
    credentials.mkdir()
    for src, dest in [
        ("cert.pem", "certificate.der"),
        ("ec-secp256k1-priv-key.pem", "private-key.der"),
    ]:
        (credentials / dest).write_bytes(
            base64.b64decode((root / "Data/Certificates" / src).read_bytes())
        )
    manifest["credentials"] = {
        "source": "SDK dummy test credentials; see THIRD_PARTY_NOTICES.md",
        "certificate": "credentials/certificate.der",
        "key": "credentials/private-key.der",
    }
    with isolated_sdk(root) as (scratch, env):
        # Avoid environment-specific hostname lookup by Log4j; logs still captured verbatim.
        env["JAVA_TOOL_OPTIONS"] = "-Dlog4j2.hostName=localhost -Dfile.encoding=UTF-8"
        adapter = scratch / "CanonicalBytes.java"
        shutil.copyfile(REPO / "scripts/sdk-parity/CanonicalBytes.java", adapter)
        properties_adapter = scratch / "SignedPropertiesBytes.java"
        shutil.copyfile(
            REPO / "scripts/sdk-parity/SignedPropertiesBytes.java", properties_adapter
        )
        compile_record = run(
            [
                "javac",
                "-cp",
                scratch / f"Apps/zatca-einvoicing-sdk-{VERSION}.jar",
                adapter,
                properties_adapter,
            ],
            scratch,
            env,
            output / "evidence/compile-adapter",
        )
        if compile_record["exit_code"] != 0:
            raise CaptureError("Canonical adapter compilation failed")

        def invoice_case(case):
            case = dict(case)
            data = case.pop("bytes")
            directory = output / "cases" / case["id"]
            directory.mkdir(parents=True)
            xml = directory / "input.xml"
            xml.write_bytes(data)
            expected = {}

            def op(name, args):
                rec, raw = invoke(scratch, env, args, directory / "evidence" / name)
                return rec["exit_code"], raw

            code, raw = op("validate", ["-validate", "-invoice", xml])
            if case["kind"] == "malformed":
                try:
                    ET.fromstring(data)
                except ET.ParseError:
                    pass
                else:
                    raise CaptureError("Malformed fixture unexpectedly parses")
                if not re.search(
                    r"SAXParseException|must be terminated|XML document structures|Premature end",
                    raw,
                ):
                    raise CaptureError(
                        "Expected explicit SDK XML parse rejection: " + raw
                    )
                expected["validation"] = {
                    "xsd": "not_run",
                    "parse": "failed",
                    "global": "not_run",
                }
            else:
                expected["validation"] = parse_validation(raw, code)
                code, raw = op("hash", ["-generateHash", "-invoice", xml])
                expected["hash"] = parse_hash(raw, code)
                rec = run(
                    [
                        "java",
                        "-cp",
                        str(scratch)
                        + os.pathsep
                        + str(scratch / f"Apps/zatca-einvoicing-sdk-{VERSION}.jar"),
                        "CanonicalBytes",
                        xml,
                        directory / "canonical.xml",
                    ],
                    scratch,
                    env,
                    directory / "evidence/canonical",
                )
                if rec["exit_code"] != 0:
                    raise CaptureError("Canonical capture failed")
                canonical = require_artifact(directory / "canonical.xml")
                if (
                    base64.b64encode(hashlib.sha256(canonical).digest()).decode()
                    != expected["hash"]
                ):
                    raise CaptureError(
                        "SDK adapter canonical bytes differ from public CLI digest"
                    )
                if case["kind"] == "invoice":
                    signed = directory / "sdk-signed.xml"
                    code, raw = op(
                        "sign", ["-sign", "-invoice", xml, "-signedInvoice", signed]
                    )
                    if code or "signed successfully" not in raw.lower():
                        raise CaptureError("SDK signing missing success marker: " + raw)
                    require_artifact(signed)
                    rec = run(
                        [
                            "java",
                            "-cp",
                            str(scratch)
                            + os.pathsep
                            + str(scratch / f"Apps/zatca-einvoicing-sdk-{VERSION}.jar"),
                            "SignedPropertiesBytes",
                            xml,
                            signed,
                            directory / "signed-properties.xml",
                        ],
                        scratch,
                        env,
                        directory / "evidence/signed-properties",
                    )
                    if rec["exit_code"] != 0:
                        raise CaptureError("SignedProperties capture failed")
                    require_artifact(directory / "signed-properties.xml")
                    code, raw = op("signed-validate", ["-validate", "-invoice", signed])
                    expected["signed_validation"] = parse_validation(raw, code)
                    code, raw = op("qr", ["-qr", "-invoice", signed])
                    qr = re.findall(r"QR code\s*=\s*(\S+)", raw)
                    if code or len(qr) != 1:
                        raise CaptureError("Expected one SDK QR result")
                    base64.b64decode(qr[0], validate=True)
                    expected["qr"] = qr[0]
            write_json(directory / "expected.json", expected)
            case["input_sha256"] = digest(xml)
            print("captured", case["id"], flush=True)
            return case

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            manifest["cases"] = list(pool.map(invoice_case, prepare_inputs(inputs)))
        # Independent SDK key generation is intentional; compare ASN.1 properties and
        # verify proof of possession rather than comparing randomized CSR bytes.
        for language in ["EN", "AR"]:
            for group in [False, True]:
                filename = (
                    f"csr-config-example-{language}"
                    + ("-VAT-group" if language == "EN" else "-VAT-Group")
                    if group
                    else f"csr-config-example-{language}"
                )
                properties = (
                    scratch / "Data/Input" / (filename + ".properties")
                ).read_bytes()
                for environment, flag in [
                    ("production", []),
                    ("simulation", ["-sim"]),
                    ("nonproduction", ["-nonprod"]),
                ]:
                    case_id = f"csr-{language.lower()}-{'group' if group else 'individual'}-{environment}"
                    directory = output / "cases" / case_id
                    directory.mkdir(parents=True)
                    (directory / "csr.properties").write_bytes(properties)
                    rec, raw = invoke(
                        scratch,
                        env,
                        [
                            "-csr",
                            *flag,
                            "-csrConfig",
                            directory / "csr.properties",
                            "-privateKey",
                            directory / "sdk-key.pem",
                            "-generatedCsr",
                            directory / "sdk.csr",
                        ],
                        directory / "evidence/csr",
                    )
                    if rec["exit_code"] or "generated successfully" not in raw:
                        raise CaptureError("CSR capture failed: " + raw)
                    (directory / "sdk.csr.der").write_bytes(
                        pem_or_base64_der(require_artifact(directory / "sdk.csr"))
                    )
                    (directory / "sdk-key.der").write_bytes(
                        pem_or_base64_der(require_artifact(directory / "sdk-key.pem"))
                    )
                    manifest["cases"].append(
                        {
                            "id": case_id,
                            "kind": "csr",
                            "environment": environment,
                            "source": "SDK Data/Input/" + filename + ".properties",
                            "input_sha256": digest(directory / "csr.properties"),
                        }
                    )
                    print("captured", case_id, flush=True)
        base = (scratch / "Data/Input/csr-config-example-EN.properties").read_text()
        for name, data, marker in [
            (
                "csr-missing-property",
                "\n".join(
                    x for x in base.splitlines() if not x.startswith("csr.common.name=")
                ),
                "common name is mandatory field",
            ),
            (
                "csr-unsupported-value",
                base.replace("csr.invoice.type=1100", "csr.invoice.type=9999"),
                "invalid invoice type, please provide a valid invoice type",
            ),
        ]:
            directory = output / "cases" / name
            directory.mkdir(parents=True)
            (directory / "csr.properties").write_text(data)
            rec, raw = invoke(
                scratch,
                env,
                [
                    "-csr",
                    "-csrConfig",
                    directory / "csr.properties",
                    "-privateKey",
                    directory / "key",
                    "-generatedCsr",
                    directory / "csr",
                ],
                directory / "evidence/csr",
            )
            if (
                rec["exit_code"] != 0
                or raw.count(marker) != 1
                or (directory / "csr").exists()
            ):
                raise CaptureError("Expected explicit CSR rejection: " + name)
            write_json(
                directory / "expected.json", {"result": "failed", "marker": marker}
            )
            manifest["cases"].append(
                {
                    "id": name,
                    "kind": "csr-invalid",
                    "source": "SDK EN config mutation",
                    "input_sha256": digest(directory / "csr.properties"),
                }
            )
    after = {
        str(p.relative_to(root)): digest(p) for p in root.rglob("*") if p.is_file()
    }
    if before != after:
        raise CaptureError("Installed SDK changed")
    manifest["known_differences"] = [
        {
            "id": "SDK-QR-001",
            "case": "payable-rounding",
            "field": "qr.tag4",
            "sdk": "1000.00",
            "rust": "1000.01",
            "reason": "SDK output differs from XML TaxInclusiveAmount; preserve guideline mapping in Rust",
            "tracking": "https://github.com/mqqz/fatoora-rs/issues/2",
            "source": "https://www.zatca.gov.sa/en/E-Invoicing/Introduction/Guidelines/Documents/E-invoicing-Detailed-Technical-Guideline.pdf#page=61",
        }
    ]
    manifest["capture"]["signed_properties_adapter_sha256"] = digest(
        REPO / "scripts/sdk-parity/SignedPropertiesBytes.java"
    )
    manifest["artifacts"] = {
        str(p.relative_to(output)): digest(p)
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }
    write_json(output / "manifest.json", manifest)
    print("Capture complete; installed SDK unchanged:", output)


def load_manifest(corpus):
    path = corpus / "manifest.json"
    if not path.is_file():
        raise CaptureError(f"Missing manifest: {path}")
    m = json.loads(path.read_text())
    if m.get("schema_version") != 1 or m.get("sdk", {}).get("jar_sha256") != JAR_SHA256:
        raise CaptureError("Unknown manifest schema or SDK baseline")
    if not m.get("cases") or not m.get("artifacts"):
        raise CaptureError("Empty corpus")
    ids = [c["id"] for c in m["cases"]]
    if len(ids) != len(set(ids)):
        raise CaptureError("Duplicate case ID")
    for name, expected in m["artifacts"].items():
        path = corpus / name
        if not path.resolve().is_relative_to(corpus.resolve()):
            raise CaptureError("Artifact escapes corpus")
        if not path.is_file() or digest(path) != expected:
            raise CaptureError(f"Artifact checksum mismatch: {name}")
    present = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p.name != "manifest.json"
    }
    if present != set(m["artifacts"]):
        raise CaptureError("Unlisted or missing corpus artifacts")
    return m


def semantic_diff(candidate, baseline):
    def results(root):
        if not (root / "manifest.json").exists():
            return {}
        m = json.loads((root / "manifest.json").read_text())
        values = {}
        for case in m["cases"]:
            directory = root / "cases" / case["id"]
            if (directory / "expected.json").exists():
                v = json.loads((directory / "expected.json").read_text())
                # A new SDK signature changes tag 7 even if semantics are unchanged.
                # All raw changes remain checksum-visible; replay verifies the signature.
                if "qr" in v:
                    raw = base64.b64decode(v.pop("qr"))
                    tags = {}
                    i = 0
                    while i < len(raw):
                        tag, size = raw[i : i + 2]
                        value = raw[i + 2 : i + 2 + size]
                        i += size + 2
                        if tag != 7:
                            tags[str(tag)] = base64.b64encode(value).decode()
                    v["deterministic_qr_tags"] = tags
                values[case["id"]] = v
            else:
                values[case["id"]] = {
                    "input_sha256": case["input_sha256"],
                    "environment": case.get("environment"),
                }
        return values

    old, new = results(baseline), results(candidate)
    return {
        k: {"before": old.get(k), "after": new.get(k)}
        for k in sorted(old.keys() | new.keys())
        if old.get(k) != new.get(k)
    }


def verify(root, output, corpus):
    import concurrent.futures

    m = load_manifest(corpus)
    if corpus.resolve() != CORPUS.resolve():
        raise CaptureError(
            "Fresh Rust exporter currently requires the repository corpus"
        )
    typed_corpus = corpus.with_name("sdk-parity-typed")
    typed_manifest = load_manifest(typed_corpus)
    typed_cases = {case["id"] for case in typed_manifest["cases"]}
    new_output(output)
    before = {
        str(p.relative_to(root)): digest(p) for p in root.rglob("*") if p.is_file()
    }
    exported = output / "rust"
    rec = run(
        [
            "cargo",
            "run",
            "-p",
            "fatoora-core",
            "--locked",
            "--offline",
            "--example",
            "sdk_parity_export",
            "--",
            exported,
            "--signed",
        ],
        REPO,
        os.environ.copy(),
        output / "evidence/export",
        120,
    )
    if rec["exit_code"] != 0:
        raise CaptureError("Rust artifact export failed")
    expected_cases = {c["id"]: c for c in m["cases"] if c["kind"] == "invoice"}
    typed = {
        "simplified-invoice",
        "standard-invoice",
        "standard-credit",
        "standard-debit",
        "simplified-credit",
        "simplified-debit",
        "mixed-vat",
        "prepayment",
        "foreign-currency",
        "out-of-scope",
        "export-self-billed",
    }
    wanted = set(expected_cases) | {c + "-typed" for c in typed}
    actual = {p.stem for p in exported.glob("*.xml")}
    if actual != wanted:
        raise CaptureError("Fresh Rust artifact inventory differs")
    reports = {}
    with isolated_sdk(root) as (scratch, env):
        env["JAVA_TOOL_OPTIONS"] = "-Dlog4j2.hostName=localhost -Dfile.encoding=UTF-8"

        def check(name):
            case_id = name.removesuffix("-typed")
            directory = corpus / "cases" / case_id
            if name.endswith("-typed") and case_id in typed_cases:
                directory = typed_corpus / "cases" / case_id
            expected = json.loads((directory / "expected.json").read_text())["signed_validation"]
            rec, raw = invoke(
                scratch,
                env,
                ["-validate", "-invoice", exported / (name + ".xml")],
                output / "evidence" / name,
            )
            result = parse_validation(raw, rec["exit_code"])
            if result != expected:
                raise CaptureError(
                    f"SDK validation changed for {name}: expected {expected}, got {result}"
                )
            print("verified", name, flush=True)
            return name, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            reports = dict(pool.map(check, sorted(wanted)))
        # Prove SDK verification actually notices a corrupted signature.
        xml = (exported / "simplified-invoice.xml").read_text()
        bad, count = re.subn(r"(<ds:SignatureValue>)[^<]+", r"\g<1>AAAA", xml)
        if count != 1:
            raise CaptureError("Signature mutation was ineffective")
        (exported / "tampered.xml").write_text(bad)
        rec, raw = invoke(
            scratch,
            env,
            ["-validate", "-invoice", exported / "tampered.xml"],
            output / "evidence/tampered",
        )
        reports["tampered"] = parse_validation(raw, rec["exit_code"])
        if reports["tampered"]["signature"] != "failed":
            raise CaptureError("SDK accepted corrupted signature")
    after = {
        str(p.relative_to(root)): digest(p) for p in root.rglob("*") if p.is_file()
    }
    if before != after:
        raise CaptureError("Installed SDK changed")
    write_json(
        output / "report.json",
        {
            "sdk_version": VERSION,
            "jar_sha256": JAR_SHA256,
            "corpus_manifest_sha256": digest(corpus / "manifest.json"),
            "typed_corpus_manifest_sha256": digest(typed_corpus / "manifest.json"),
            "results": reports,
        },
    )
    print("SDK verification passed; installed SDK unchanged:", output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["capture", "verify"])
    parser.add_argument(
        "--sdk-root",
        type=Path,
        default=Path(os.environ.get("FATOORA_HOME", "/missing-sdk")),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--inputs",
        type=Path,
        help="Explicit newly exported builder inputs; default: frozen corpus inputs",
    )
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    root = sdk_root(args.sdk_root)
    output = args.output.resolve()
    if args.command == "verify":
        verify(root, output, args.corpus.resolve())
    elif args.inputs:
        capture(root, output, args.inputs.resolve())
        write_json(
            output.parent / (output.name + "-diff.json"),
            semantic_diff(output, args.corpus),
        )
    else:
        m = load_manifest(args.corpus)
        with tempfile.TemporaryDirectory(prefix="fatoora frozen inputs ") as tmp:
            inputs = Path(tmp)
            for case in m["cases"]:
                if case["source"] == "repository test builder":
                    shutil.copyfile(
                        args.corpus / "cases" / case["id"] / "input.xml",
                        inputs / (case["id"] + ".xml"),
                    )
            capture(root, output, inputs)
        write_json(
            output.parent / (output.name + "-diff.json"),
            semantic_diff(output, args.corpus),
        )


if __name__ == "__main__":
    try:
        main()
    except CaptureError as e:
        raise SystemExit(str(e))
