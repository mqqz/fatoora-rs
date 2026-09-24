# Preparing a release

Rust crates and the Python package share a release version. A `v*` tag starts
three independent publication workflows: crates.io, PyPI, and GitHub native
assets. Creating or merging a release PR does not publish packages.

## Prepare the candidate

Use a branch named `release/<version>` so its PR runs the Linux, macOS, and
Windows wheel and native builds. Update all four crate manifests, their internal
dependency requirements, and `bindings/python/pyproject.toml`. Refresh the root
`Cargo.lock` and `bindings/python/uv.lock` without upgrading unrelated packages.
The root Cargo lockfile governs workspace builds; the historical member
lockfiles are not used by these commands.

Add a curated entry to the root [changelog](https://github.com/mqqz/fatoora-rs/blob/main/CHANGELOG.md).
Keep its date as `Unreleased` until publication. Include migration instructions
for Rust, C/C++, Python, and serialized data when their contracts change. A
breaking change to 0.1.x requires 0.2.0 under Cargo's compatibility conventions.

Release tooling needs Cargo 1.90+ for workspace publication and Python 3.11+ for
the metadata checker. This tooling requirement does not declare a minimum
supported Rust version for library consumers; CI currently tests stable Rust.

## Validate the committed candidate

```sh
python3 scripts/check_release.py --tag v0.2.0
python3 -m unittest discover -s scripts/tests -v
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
SKIP_ZATCA_LIVE_API=1 CARGO_INCREMENTAL=0 \
  cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
cargo package --workspace --list
cargo publish --workspace --locked --dry-run
```

Use the version being prepared in the tag check. Add `--offline` to ordinary
Cargo checks when dependencies are cached. Package verification resolves registry
dependencies and may need network access. Do not use `--no-verify` to bypass a
packaging failure.

Run the [Python binding tests](../contributing.md#tests) and
[C/C++ contract checks](diplomat.md#generate-and-verify) against the
candidate native build. Check generated headers for unexpected changes. Tests
using mock HTTP servers need local loopback access; live ZATCA requests are
disabled by the command above. The [SDK corpus](sdk-parity.md) runs offline and
does not establish full ZATCA business-rule compliance.

Inspect the `.crate` files, wheels, and native archives for the expected code,
schemas, templates, headers, and license material. Install the wheels and load
the native library in clean environments on each supported platform. Linux and
macOS standalone native assets currently rely on host `libxml2`; verify and
document the target runtime requirements. Windows native archives contain DLLs
alongside the executable or FFI library. Preserve that directory layout.

## Publication prerequisites

Before tagging, check the candidate commit's Rust tests, Python tests, Cargo
package verification, all wheel builds, and all native builds. Recheck the final
commit after any changes. Independent workflows can partially succeed, so a
green workflow alone does not prove that the whole release is ready.

Confirm these repository settings without exposing secret values:

- `CARGO_REGISTRY_TOKEN` can publish each of the four crates.
- PyPI trusted publishing matches this repository, `python.yml`, and the `pypi`
  environment; any configured environment approvals are satisfied.
- The tag and all package versions agree, and the version is unused on each
  destination registry.

Include the [third-party notice](https://github.com/mqqz/fatoora-rs/blob/main/THIRD_PARTY_NOTICES.md)
in the packages and retain the applicable upstream license text and attribution.
Keep remaining source questions recorded there for follow-up.

## Tag and publish

After review and successful checks, merge the release PR and tag the exact
tested release commit. Replace `TESTED_COMMIT_SHA` below with that commit:

```sh
git tag -a v0.2.0 TESTED_COMMIT_SHA -m "Release v0.2.0"
git push origin v0.2.0
```

The tag starts publication. Rust publishes derive, core, FFI, then CLI. Python
publishes after its binding tests and wheel builds. GitHub assets upload after
all native builds. Manual Rust/Python publishing must also run against the
matching tag; manual native releases check out their supplied tag.

Verify every package and asset, docs.rs builds, and installation in fresh
consumer projects. Copy the curated changelog into the GitHub release notes and
record the publication date.

If only part of a release succeeds, keep the tag fixed and determine which
versions already exist. Resume only missing publications from that commit.
The current sequential Cargo job will stop if an earlier crate already exists;
do not blindly rerun it after a partial upload. Published crate versions cannot
be overwritten. A code fix requires a new version; yank a broken crate when
appropriate.
