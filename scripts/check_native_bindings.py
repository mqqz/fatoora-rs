#!/usr/bin/env python3
"""Build and run the generated C and C++ contract tests on Linux/macOS."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["cargo", "build", "-p", "fatoora-ffi", "--locked"], cwd=ROOT, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve() / "debug"
    with tempfile.TemporaryDirectory() as directory:
        for language, compiler, standard, suffix in (
            ("c", os.environ.get("CC", "cc"), "c11", "c"),
            ("cpp", os.environ.get("CXX", "c++"), "c++17", "cpp"),
        ):
            binary = str(Path(directory) / language)
            subprocess.run([
                *shlex.split(compiler), f"-std={standard}", "-Wall", "-Wextra", "-Werror",
                "-I", f"bindings/{language}", f"fatoora-ffi/tests/diplomat_contract.{suffix}",
                "-L", str(target), "-lfatoora_ffi", f"-Wl,-rpath,{target}", "-o", binary,
            ], cwd=ROOT, check=True)
            subprocess.run([binary, str(ROOT / "fatoora-core/tests/fixtures/sdk-parity/cases/standard-invoice/sdk-signed.xml")] if language == "cpp" else [binary], check=True)
            print(f"{language} contract passed", flush=True)


if __name__ == "__main__":
    main()
