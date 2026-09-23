from __future__ import annotations

import runpy
import os
from pathlib import Path


EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"


def test_doc_examples_run() -> None:
    examples = sorted(EXAMPLES_DIR.glob("*.py"))
    assert examples, "expected Python doc examples to exist"
    for example in examples:
        if example.name == "api.py" and os.environ.get("SKIP_ZATCA_LIVE_API"):
            continue
        runpy.run_path(str(example), run_name="__main__")
