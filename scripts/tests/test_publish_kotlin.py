import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "publish_kotlin", SCRIPTS / "publish_kotlin.py"
)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
VERSION = "0.4.2"


def archive_bytes(entries):
    result = io.BytesIO()
    with ZipFile(result, "w") as archive:
        for name in entries:
            archive.writestr(name, b"test fixture")
    return result.getvalue()


class CentralBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for artifact, extension in publisher.ARTIFACTS.items():
            directory = self.root / "com/fatoority" / artifact / VERSION
            directory.mkdir(parents=True)
            base = directory / f"{artifact}-{VERSION}"
            Path(
                str(base) + ".pom"
            ).write_text(f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
<groupId>com.fatoority</groupId><artifactId>{artifact}</artifactId><version>{VERSION}</version>
<name>Fatoority</name><description>Bindings</description><url>https://fatoority.com</url>
<licenses><license><name>Notices</name><url>https://fatoority.com/license</url></license></licenses>
<developers><developer><id>mqqz</id><name>mqqz</name></developer></developers>
<scm><url>https://github.com/mqqz/fatoority</url><connection>scm:git:https://github.com/mqqz/fatoority.git</connection><developerConnection>scm:git:ssh://git@github.com/mqqz/fatoority.git</developerConnection></scm>
</project>""")
            Path(str(base) + ".module").write_text(
                json.dumps(
                    {
                        "component": {
                            "group": publisher.GROUP,
                            "module": artifact,
                            "version": VERSION,
                        }
                    }
                )
            )
            Path(str(base) + "." + extension).write_bytes(
                archive_bytes(publisher.NATIVES[extension])
            )
            Path(str(base) + "-sources.jar").write_bytes(
                archive_bytes(["com/fatoora/SigningKey.kt"])
            )
            Path(str(base) + "-javadoc.jar").write_bytes(archive_bytes(["index.html"]))
        self.desktop = (
            self.root / f"com/fatoority/fatoority/{VERSION}/fatoority-{VERSION}"
        )

    def test_bundle_has_exact_release_payload_and_recomputed_checksums(self):
        (self.root / "com/fatoority/fatoority/maven-metadata.xml").write_text("stale")
        Path(str(self.desktop) + ".jar.sha1").write_text("stale")
        files = publisher.collect(self.root, VERSION)
        output = self.root / "central.zip"
        publisher.bundle(files, output)
        with ZipFile(output) as archive:
            self.assertEqual(len(archive.namelist()), 50)
            self.assertFalse(any("metadata" in name for name in archive.namelist()))
            for name, content in files.items():
                self.assertEqual(archive.read(name), content)
                self.assertEqual(
                    archive.read(name + ".sha1").decode(),
                    hashlib.sha1(content).hexdigest(),
                )

    def test_rejects_host_only_package(self):
        Path(str(self.desktop) + ".jar").write_bytes(
            archive_bytes(["linux-x86-64/libfatoora_ffi.so"])
        )
        with self.assertRaisesRegex(ValueError, "native platforms"):
            publisher.collect(self.root, VERSION)

    def test_rejects_missing_docs(self):
        Path(str(self.desktop) + "-javadoc.jar").unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            publisher.collect(self.root, VERSION)

    def test_rejects_empty_docs(self):
        Path(str(self.desktop) + "-javadoc.jar").write_bytes(
            archive_bytes(["README.md"])
        )
        with self.assertRaisesRegex(ValueError, "API documentation"):
            publisher.collect(self.root, VERSION)

    def test_rejects_wrong_coordinates(self):
        path = Path(str(self.desktop) + ".pom")
        path.write_text(path.read_text().replace("com.fatoority", "com.fatoora"))
        with self.assertRaisesRegex(ValueError, "groupId"):
            publisher.collect(self.root, VERSION)

    def test_rejects_incomplete_pom(self):
        path = Path(str(self.desktop) + ".pom")
        path.write_text(path.read_text().replace("<id>mqqz</id>", ""))
        with self.assertRaisesRegex(ValueError, "POM metadata"):
            publisher.collect(self.root, VERSION)

    def test_rejects_stale_module_version(self):
        path = Path(str(self.desktop) + ".module")
        path.write_text(path.read_text().replace(VERSION, "0.4.1"))
        with self.assertRaisesRegex(ValueError, "Gradle module"):
            publisher.collect(self.root, VERSION)

    def test_publication_rejects_branch_before_signing(self):
        with (
            patch.object(
                sys,
                "argv",
                [
                    "publish_kotlin.py",
                    "--repository",
                    str(self.root),
                    "--sign",
                    "--publish",
                ],
            ),
            patch.dict(os.environ, {"GITHUB_REF_TYPE": "branch"}),
            patch.object(publisher, "sign") as sign,
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaises(SystemExit):
                publisher.main()
            sign.assert_not_called()


class CentralProtocolTests(unittest.TestCase):
    def test_waits_for_published_and_saves_deployment_id(self):
        deployment = "fd641c91-baa2-4512-9d46-1e274136e87d"
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                os.environ,
                {
                    "MAVEN_CENTRAL_USERNAME": "test-user",
                    "MAVEN_CENTRAL_PASSWORD": "test-password",
                },
            ),
            patch.object(publisher.time, "sleep"),
            patch.object(
                publisher,
                "central",
                side_effect=[
                    deployment.encode(),
                    b'{"deploymentState":"VALIDATED"}',
                    b'{"deploymentState":"PUBLISHED"}',
                ],
            ) as api,
        ):
            output = Path(directory) / "bundle.zip"
            output.write_bytes(b"bundle payload")
            self.assertEqual(publisher.publish(output, VERSION), deployment)
            self.assertEqual(api.call_count, 3)
            upload = api.call_args_list[0].args
            self.assertIn("publishingType=AUTOMATIC", upload[0])
            self.assertEqual(base64.b64decode(upload[1]), b"test-user:test-password")
            self.assertIn(b'name="bundle"', upload[2])
            self.assertIn(b"bundle payload", upload[2])
            self.assertEqual(
                json.loads(output.with_suffix(".deployment.json").read_text())[
                    "deploymentState"
                ],
                "PUBLISHED",
            )

    def test_timeout_retains_id_without_reuploading(self):
        deployment = "fd641c91-baa2-4512-9d46-1e274136e87d"
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                os.environ,
                {
                    "MAVEN_CENTRAL_USERNAME": "test-user",
                    "MAVEN_CENTRAL_PASSWORD": "test-password",
                },
            ),
            patch.object(publisher, "central", return_value=deployment.encode()) as api,
        ):
            output = Path(directory) / "bundle.zip"
            output.write_bytes(b"bundle")
            with self.assertRaisesRegex(TimeoutError, deployment):
                publisher.publish(output, VERSION, timeout=0)
            api.assert_called_once()
            self.assertEqual(
                json.loads(output.with_suffix(".deployment.json").read_text())[
                    "deploymentId"
                ],
                deployment,
            )

    def test_lost_upload_response_does_not_retry(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                os.environ,
                {
                    "MAVEN_CENTRAL_USERNAME": "test-user",
                    "MAVEN_CENTRAL_PASSWORD": "test-password",
                },
            ),
            patch.object(
                publisher, "central", side_effect=TimeoutError("connection lost")
            ) as api,
        ):
            output = Path(directory) / "bundle.zip"
            output.write_bytes(b"bundle")
            with self.assertRaises(TimeoutError):
                publisher.publish(output, VERSION)
            api.assert_called_once()

    def test_failed_validation_is_not_success_or_reuploaded(self):
        deployment = b"fd641c91-baa2-4512-9d46-1e274136e87d"
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                os.environ,
                {
                    "MAVEN_CENTRAL_USERNAME": "test-user",
                    "MAVEN_CENTRAL_PASSWORD": "test-password",
                },
            ),
            patch.object(
                publisher,
                "central",
                side_effect=[
                    deployment,
                    b'{"deploymentState":"FAILED","errors":{"pom":"invalid"}}',
                ],
            ) as api,
        ):
            output = Path(directory) / "bundle.zip"
            output.write_bytes(b"bundle")
            with self.assertRaisesRegex(ValueError, "validation failed"):
                publisher.publish(output, VERSION)
            self.assertEqual(api.call_count, 2)


@unittest.skipUnless(
    shutil.which("gpg") and shutil.which("gpgconf"), "GnuPG is required"
)
class SigningTests(unittest.TestCase):
    def test_real_signature_verifies_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            home.chmod(0o700)
            command = [
                "gpg",
                "--homedir",
                str(home),
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
            ]
            password = b"temporary-test-passphrase"
            try:
                subprocess.run(
                    [
                        *command,
                        "--quick-generate-key",
                        "Fatoority test <test@example.invalid>",
                        "rsa2048",
                        "sign",
                        "1d",
                    ],
                    input=password,
                    capture_output=True,
                    check=True,
                )
                key = subprocess.run(
                    [*command, "--armor", "--export-secret-keys"],
                    input=password,
                    capture_output=True,
                    check=True,
                ).stdout.decode()
                files = {"test.jar": b"original artifact"}
                with patch.dict(
                    os.environ,
                    {"GPG_PRIVATE_KEY": key, "GPG_PASSPHRASE": password.decode()},
                ):
                    publisher.sign(files)
                source, signature = home / "test.jar", home / "test.jar.asc"
                source.write_bytes(files["test.jar"])
                signature.write_bytes(files["test.jar.asc"])
                verify = [
                    "gpg",
                    "--homedir",
                    str(home),
                    "--batch",
                    "--verify",
                    str(signature),
                    str(source),
                ]
                subprocess.run(verify, capture_output=True, check=True)
                source.write_bytes(b"tampered")
                self.assertNotEqual(
                    subprocess.run(verify, capture_output=True, check=False).returncode,
                    0,
                )
            finally:
                subprocess.run(
                    ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                    capture_output=True,
                    check=False,
                )


if __name__ == "__main__":
    unittest.main()
