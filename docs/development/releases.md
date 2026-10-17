---
title: Release checklist
description: Prepare and verify a fatoority release across Rust, Python, JavaScript, C#, JVM and native packages.
---

# Release checklist

This page is for maintainers publishing a release. A version tag starts independent publication workflows for crates.io, PyPI, npm, NuGet, Maven Central and native release assets. Merging a release PR does not publish packages.

## Prepare the candidate

Create a `release/<version>` branch. Keep one version across all packages:

| Update | Files |
| --- | --- |
| Rust packages and internal dependencies | The four crate manifests and root `Cargo.lock` |
| Python | `bindings/python/pyproject.toml` and `bindings/python/uv.lock` |
| JavaScript | `bindings/js/package.json` and `bindings/js/package-lock.json` |
| C# | `bindings/dotnet/Fatoora.csproj` |
| Kotlin and Java | `bindings/kotlin/build.gradle.kts` |
| Independent Rust workspaces | `fuzz/Cargo.lock` and `scripts/xsd-compat/Cargo.lock` |

Avoid unrelated dependency upgrades. Add a curated changelog entry, including migration instructions for changed public contracts. Leave the release date as `Unreleased` until publication.

## Validate before tagging

Run the [workspace checks](../contributing.md#make-and-check-a-change), [affected binding checks](diplomat.md) and the following commands. Substitute the intended release tag:

```sh
python3 scripts/check_release.py --tag v0.4.4
python3 -m unittest discover -s scripts/tests -v
cargo doc --workspace --no-deps --locked
cargo package --workspace --list
cargo publish --workspace --locked --dry-run
```

The release checker requires Python 3.11+; workspace publication requires Cargo 1.90+. Package verification can require registry access. Fix failures rather than bypassing verification.

Inspect packages for expected code, schemas, native libraries, headers and licenses. Test installed packages in fresh consumers. Run `python3 scripts/check_xml_free_artifacts.py <artifact paths>` on the built native archives and wheels. Wait for the candidate's platform and package CI checks, and recheck the final commit after changes.

## Check publication access

Confirm registry ownership and credentials without printing secret values. Versions must be unused at each destination.

| Destination | Publication setup |
| --- | --- |
| crates.io | `CARGO_REGISTRY_TOKEN` with access to all four crates |
| PyPI | Trusted publisher for `python.yml` and the `pypi` environment |
| npm | `NPM_TOKEN` with access to `fatoority` |
| NuGet | Trusted publisher for `dotnet.yml` |
| Maven Central | Verified namespace, Central token and signing key |

The publication workflows in `.github/workflows/` define the registry configuration.

## Publish and verify

After the release PR is reviewed and merged, tag the exact tested commit. Replace the version and commit below:

```sh
git tag -a v0.4.4 TESTED_COMMIT_SHA -m "Release v0.4.4"
git push origin v0.4.4
```

Check each registry and native release asset independently. Verify installation in fresh consumers and the docs.rs build, then publish the curated release notes and date. An uploaded artifact or one green workflow is not proof that every package was published.

## Recover a partial release

Keep the tag fixed. Check which versions exist and whether a registry deployment is still pending before retrying. Resume only missing publications from that same commit.

The sequential Cargo publisher can stop on an already-published crate; do not blindly rerun it. npm, NuGet and Central support workflow-specific retries on the existing tag. For Central, inspect the deployment status before uploading another bundle. Published versions are immutable; a code fix needs a new version.
