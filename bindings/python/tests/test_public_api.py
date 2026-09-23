"""The pre-migration high-level API must remain available through generated bindings."""
import inspect
import json
from pathlib import Path

import fatoora
from fatoora import api


def test_public_methods_and_argument_names_are_preserved():
    contract = json.loads(Path(__file__).with_name("public_api.json").read_text())
    for name, methods in contract.items():
        cls = getattr(api, name)
        assert getattr(fatoora, name) is cls
        for method, expected in methods.items():
            parameters = inspect.signature(getattr(cls, method)).parameters
            actual = [p for p in parameters if p not in ("self", "cls")]
            assert actual == expected, (name, method, actual, expected)


def test_distribution_has_no_legacy_loader_or_runtime_dependency():
    from importlib.metadata import distribution
    dist = distribution("fatoora-rs")
    files = {str(p) for p in dist.files}
    assert "fatoora/_lib.py" not in files
    assert "fatoora/native.py" not in files
    assert "fatoora/fatoora_ffi.h" not in files
    assert not any(requirement.lower().startswith("cffi") for requirement in dist.requires or [])
    assert not hasattr(fatoora, "FfiLibrary")
