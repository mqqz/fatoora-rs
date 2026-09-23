#!/usr/bin/env python3
"""Generate the checked-in bindings with diplomat-tool 0.16.1."""
import os
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if checked-in bindings differ")
    args = parser.parse_args()
    tool = os.environ.get("DIPLOMAT_TOOL", "diplomat-tool")
    for backend, output in (
        ("c", "bindings/c"),
        ("cpp", "bindings/cpp"),
        ("nanobind", "bindings/python/native/generated"),
    ):
        with tempfile.TemporaryDirectory() as generated:
            subprocess.run([
                tool, "--entry", "fatoora-ffi/src/lib.rs",
                *(["--config", "lib_name=_native", "--config", "custom_extra_code_location=fatoora-ffi/src"] if backend == "nanobind" else []),
                backend, generated,
            ], cwd=ROOT, check=True)
            expected = {p.relative_to(generated) for p in Path(generated).rglob("*") if p.is_file()}
            for existing in (ROOT / output).rglob("*"):
                if "examples" not in existing.relative_to(ROOT / output).parts and existing.is_file() and existing.suffix in (".h", ".hpp", ".cpp") and existing.relative_to(ROOT / output) not in expected:
                    if args.check:
                        raise SystemExit(f"Obsolete generated file: {existing.relative_to(ROOT)}")
                    existing.unlink()
            for source in Path(generated).rglob("*"):
                if not source.is_file():
                    continue
                destination = ROOT / output / source.relative_to(generated)
                if args.check:
                    if not destination.exists() or source.read_bytes() != destination.read_bytes():
                        raise SystemExit(f"Stale generated binding: {destination.relative_to(ROOT)}")
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())


if __name__ == "__main__":
    main()
