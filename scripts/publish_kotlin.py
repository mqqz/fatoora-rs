#!/usr/bin/env python3
"""Validate, bundle, sign and optionally publish tested JVM/Android Maven artifacts."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import ZIP_DEFLATED, ZipFile

from check_release import check_release

ROOT = Path(__file__).resolve().parents[1]
GROUP = "com.fatoority"
ARTIFACTS = {"fatoority": "jar", "fatoority-android": "aar"}
API = "https://central.sonatype.com/api/v1/publisher"
NATIVES = {
    "jar": {
        "linux-x86-64/libfatoora_ffi.so",
        "win32-x86-64/fatoora_ffi.dll",
        "darwin-aarch64/libfatoora_ffi.dylib",
    },
    "aar": {"jni/arm64-v8a/libfatoora_ffi.so", "jni/x86_64/libfatoora_ffi.so"},
}


def collect(repository, version):
    """Select only the two release versions; never upload maven-metadata.xml."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected a stable release version")
    files = {}
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    for artifact, extension in ARTIFACTS.items():
        relative = Path(*GROUP.split(".")) / artifact / version
        base = f"{artifact}-{version}"
        directory = repository / relative
        expected = [
            f"{base}.{extension}",
            f"{base}.pom",
            f"{base}-sources.jar",
            f"{base}-javadoc.jar",
            f"{base}.module",
        ]
        for name in expected:
            path = directory / name
            if not path.is_file() or path.is_symlink():
                raise ValueError(f"Missing or invalid release artifact: {path}")
            files[(relative / name).as_posix()] = path.read_bytes()
        pom = ET.parse(directory / f"{base}.pom")
        for field, value in (
            ("groupId", GROUP),
            ("artifactId", artifact),
            ("version", version),
        ):
            if pom.findtext(f"m:{field}", namespaces=ns) != value:
                raise ValueError(f"Wrong {field} in {base}.pom")
        for field in (
            "name",
            "description",
            "url",
            "licenses/m:license/m:name",
            "licenses/m:license/m:url",
            "developers/m:developer/m:id",
            "developers/m:developer/m:name",
            "scm/m:url",
            "scm/m:connection",
            "scm/m:developerConnection",
        ):
            if not (pom.findtext(f"m:{field}", namespaces=ns) or "").strip():
                raise ValueError(f"Missing POM metadata: {field}")
        module = json.loads((directory / f"{base}.module").read_text())
        if any(
            module["component"].get(k) != v
            for k, v in (("group", GROUP), ("module", artifact), ("version", version))
        ):
            raise ValueError(f"Wrong Gradle module coordinates: {base}")
        with ZipFile(directory / f"{base}.{extension}") as archive:
            native = {
                n for n in archive.namelist() if n.endswith((".so", ".dll", ".dylib"))
            }
            if native != NATIVES[extension]:
                raise ValueError(
                    f"Incomplete or unexpected native platforms in {base}: {native}"
                )
        with ZipFile(directory / f"{base}-sources.jar") as archive:
            if not any(n.endswith("SigningKey.kt") for n in archive.namelist()):
                raise ValueError(f"Missing binding sources in {base}")
        with ZipFile(directory / f"{base}-javadoc.jar") as archive:
            if "index.html" not in archive.namelist():
                raise ValueError(f"Missing API documentation in {base}")
    return files


def secret(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Set {name} before signing/publishing")
    return value


def sign(files):
    """Use an isolated keyring and pass the passphrase via stdin, never argv."""
    key, password = secret("GPG_PRIVATE_KEY"), secret("GPG_PASSPHRASE")
    with tempfile.TemporaryDirectory(prefix="fatoority-sign-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        command = ["gpg", "--homedir", str(home), "--batch"]
        try:
            subprocess.run(
                [*command, "--import"],
                input=key.encode(),
                capture_output=True,
                check=True,
            )
            listing = subprocess.check_output(
                [*command, "--with-colons", "--list-secret-keys"], text=True
            )
            # Each exported secret key must have exactly one primary fingerprint.
            fingerprints = []
            primary = False
            for line in listing.splitlines():
                fields = line.split(":")
                if fields[0] == "sec":
                    primary = True
                elif fields[0] == "fpr" and primary:
                    fingerprints.append(fields[9])
                    primary = False
            if len(fingerprints) != 1:
                raise ValueError("GPG_PRIVATE_KEY must contain exactly one signing key")
            for name, content in list(files.items()):
                source, signature = home / "artifact", home / "artifact.asc"
                source.write_bytes(content)
                subprocess.run(
                    [
                        *command,
                        "--yes",
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase-fd",
                        "0",
                        "--local-user",
                        # Select this key, allowing GPG to use its signing subkey.
                        fingerprints[0],
                        "--armor",
                        "--output",
                        str(signature),
                        "--detach-sign",
                        str(source),
                    ],
                    input=password.encode(),
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    [*command, "--verify", str(signature), str(source)],
                    capture_output=True,
                    check=True,
                )
                files[name + ".asc"] = signature.read_bytes()
        finally:
            subprocess.run(
                ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                capture_output=True,
                check=False,
            )


def bundle(files, output):
    """Recompute checksums from the exact bytes included in the bundle."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content)
            if not name.endswith(".asc"):
                for algorithm in ("md5", "sha1", "sha256", "sha512"):
                    digest = hashlib.new(
                        algorithm, content, usedforsecurity=False
                    ).hexdigest()
                    archive.writestr(name + "." + algorithm, digest)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "Unexpected Central redirect", headers, fp)


def central(endpoint, token, data=b"", content_type="application/json"):
    request = Request(
        API + endpoint,
        data=data,
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": content_type,
        },
    )
    with build_opener(NoRedirect()).open(request, timeout=120) as response:
        return response.read()


def publish(output, version, timeout=1800):
    token = base64.b64encode(
        (
            secret("MAVEN_CENTRAL_USERNAME") + ":" + secret("MAVEN_CENTRAL_PASSWORD")
        ).encode()
    ).decode()
    boundary = uuid.uuid4().hex
    data = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="central-bundle.zip"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
        + output.read_bytes()
        + f"\r\n--{boundary}--\r\n".encode()
    )
    # Do not retry uploads: a lost response might still have created a deployment.
    deployment = (
        central(
            "/upload?"
            + urlencode(
                {"name": f"Fatoority {version}", "publishingType": "AUTOMATIC"}
            ),
            token,
            data,
            "multipart/form-data; boundary=" + boundary,
        )
        .decode()
        .strip()
    )
    deployment = str(uuid.UUID(deployment))
    record = output.with_suffix(".deployment.json")
    record.write_text(
        json.dumps({"deploymentId": deployment, "version": version}, indent=2) + "\n"
    )
    print(f"Central deployment: {deployment}", flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = json.loads(central("/status?" + urlencode({"id": deployment}), token))
        record.write_text(
            json.dumps(
                {**status, "deploymentId": deployment, "version": version}, indent=2
            )
            + "\n"
        )
        state = status.get("deploymentState")
        print(f"Central deployment {deployment}: {state}", flush=True)
        if state == "PUBLISHED":
            return deployment
        if state == "FAILED":
            raise ValueError(
                f"Central validation failed: {json.dumps(status.get('errors', {}))}"
            )
        if state not in {"PENDING", "VALIDATING", "VALIDATED", "PUBLISHING"}:
            raise ValueError(
                f"Unexpected deployment state: {state}; inspect {deployment} in Central"
            )
        time.sleep(15)
    raise TimeoutError(
        f"Central deployment {deployment} is still pending; inspect it in Central before retrying"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist/central/central-bundle.zip"
    )
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    if args.publish and not args.sign:
        parser.error("--publish requires --sign")
    version = check_release(ROOT)
    if args.publish:
        if os.environ.get("GITHUB_REF_TYPE") != "tag":
            parser.error("Publication requires a release-tag workflow run")
        check_release(ROOT, os.environ.get("GITHUB_REF_NAME", ""))
        secret("MAVEN_CENTRAL_USERNAME")
        secret("MAVEN_CENTRAL_PASSWORD")
    files = collect(args.repository, version)
    if args.sign:
        sign(files)
    bundle(files, args.output)
    print(f"{'Signed' if args.sign else 'Unsigned validation'} bundle: {args.output}")
    if args.publish:
        publish(args.output, version)


if __name__ == "__main__":
    main()
