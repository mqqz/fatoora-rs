#!/usr/bin/env python3
"""Compile C reference declarations against the generated headers."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    headers = "\n".join(p.read_text() for p in (ROOT / "bindings/c").glob("*.h"))
    count = 0
    with tempfile.TemporaryDirectory() as directory:
        for page in sorted((ROOT / "docs/reference").glob("*.md")):
            declarations = []
            for block in re.findall(r"```c\n(.*?)```", page.read_text(), re.S):
                for symbol in re.findall(r"\bfatoora_\w+", block):
                    if not re.search(r"\b" + re.escape(symbol) + r"\b", headers):
                        raise SystemExit(f"{page.relative_to(ROOT)}: unknown C symbol {symbol}")
                # Declaration tabs include their generated type headers.
                if "#include" not in block:
                    continue
                declarations.append(block)
                count += 1
            if declarations:
                source = Path(directory) / (page.stem + ".c")
                source.write_text("\n".join(declarations))
                subprocess.run([
                    *shlex.split(os.environ.get("CC", "cc")), "-std=c11",
                    "-Wall", "-Wextra", "-Werror", "-fsyntax-only",
                    "-I", str(ROOT / "bindings/c"), str(source),
                ], check=True)
    print(f"Compiled {count} C reference blocks")


if __name__ == "__main__":
    main()
