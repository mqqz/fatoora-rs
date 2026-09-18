"""Check synchronized stable release metadata; requires Python 3.11+."""

import argparse
from pathlib import Path
import re
import tomllib


def read_toml(path):
    with path.open("rb") as file:
        return tomllib.load(file)


def check_release(root, tag=None):
    workspace = read_toml(root / "Cargo.toml")["workspace"]
    manifests = {
        member: read_toml(root / member / "Cargo.toml")
        for member in workspace["members"]
    }
    versions = {manifest["package"]["version"] for manifest in manifests.values()}
    if len(versions) != 1:
        raise ValueError(f"Cargo package versions disagree: {sorted(versions)}")
    version = versions.pop()
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise ValueError(f"Expected a stable release version, found {version!r}")

    names = {manifest["package"]["name"] for manifest in manifests.values()}
    for member, manifest in manifests.items():
        for section in ("dependencies", "build-dependencies", "dev-dependencies"):
            for name, dependency in manifest.get(section, {}).items():
                if isinstance(dependency, dict) and "path" in dependency:
                    if dependency.get("package", name) not in names or dependency.get("version") != version:
                        raise ValueError(f"{member}: {name} must require workspace version {version}")

    python = read_toml(root / "bindings/python/pyproject.toml")["project"]
    if python["version"] != version:
        raise ValueError(f"Python version {python['version']} differs from Cargo version {version}")

    for path, expected in (("Cargo.lock", names), ("bindings/python/uv.lock", {python["name"]})):
        packages = read_toml(root / path)["package"]
        for name in expected:
            entries = [p for p in packages if p["name"] == name and "source" not in p]
            # uv records the editable source, unlike Cargo's workspace entries.
            if path.endswith("uv.lock"):
                entries = [p for p in packages if p["name"] == name]
            if len(entries) != 1 or entries[0]["version"] != version:
                raise ValueError(f"{path}: {name} must be locked at {version}")

    if tag is not None and tag != f"v{version}":
        raise ValueError(f"Release tag must be v{version}, found {tag!r}")
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Require this tag to match the package versions")
    args = parser.parse_args()
    try:
        version = check_release(Path(__file__).resolve().parents[1], args.tag)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"Release metadata check failed: {error}\n")
    print(f"Release metadata matches v{version}")


if __name__ == "__main__":
    main()
