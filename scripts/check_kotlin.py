#!/usr/bin/env python3
"""Test an isolated Java consumer of the staged Maven package (no native path override)."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "bindings/kotlin"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=PROJECT / "build/repository")
    args = parser.parse_args()
    repository = args.repository.resolve()
    version = tomllib.loads((ROOT / "fatoora-ffi/Cargo.toml").read_text())["package"][
        "version"
    ]
    package = repository / f"com/fatoority/fatoority/{version}/fatoority-{version}.jar"
    if not package.is_file():
        parser.error(f"Package missing: {package}; run scripts/build_kotlin.py first")
    with tempfile.TemporaryDirectory(prefix="fatoora-java-consumer-") as directory:
        consumer = Path(directory)
        (consumer / "settings.gradle").write_text(
            "rootProject.name = 'fatoora-consumer'\n"
        )
        (consumer / "build.gradle").write_text(
            """plugins { id 'java' }
repositories {
    exclusiveContent {
        forRepository { maven { url = uri(%s) } }
        filter { includeGroup('com.fatoority') }
    }
    mavenCentral()
}
dependencies {
    implementation 'com.fatoority:fatoority:%s'
    testImplementation 'junit:junit:4.13.2'
}
tasks.withType(JavaCompile).configureEach { options.encoding = 'UTF-8' }
test {
    systemProperty 'jna.nosys', 'true'
    systemProperty 'fatoora.fixtures', file('fixtures').absolutePath
}
"""
            % (json.dumps(repository.as_uri()), version)
        )
        source = consumer / "src/test/java/com/fatoora/JavaContractsTest.java"
        source.parent.mkdir(parents=True)
        shutil.copyfile(
            PROJECT / "src/test/java/com/fatoora/JavaContractsTest.java", source
        )
        fixtures = ROOT / "fatoora-core/tests/fixtures/sdk-parity"
        for name in (
            "cases/simplified-invoice/input.xml",
            "credentials/certificate.der",
            "credentials/private-key.der",
        ):
            destination = consumer / "fixtures" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixtures / name, destination)
        executable = PROJECT / ("gradlew.bat" if os.name == "nt" else "gradlew")
        subprocess.run(
            [str(executable), "--no-daemon", "-p", directory, "test"],
            cwd=consumer,
            check=True,
        )
    print("Isolated Java package consumer passed")


if __name__ == "__main__":
    main()
