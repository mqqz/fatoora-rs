# Preparing a release

Rust crates, Python, JS/TS, C#, and Kotlin/Java packages share a release version.
A `v*` tag starts six independent publication workflows: crates.io, PyPI, npm,
NuGet.org, Maven Central, and GitHub native assets. Creating or merging a release PR does not publish packages.

## Prepare the candidate

Use a branch named `release/<version>` so its PR runs the Linux, macOS, and
Windows wheel and native builds. Update all four crate manifests, their internal
dependency requirements, `bindings/python/pyproject.toml`, and the version in
`bindings/js/package.json` and `bindings/js/package-lock.json`. Update the
`Version` in `bindings/dotnet/Fatoora.csproj` and `version` in
`bindings/kotlin/build.gradle.kts`. Refresh the root
`Cargo.lock` and `bindings/python/uv.lock` without upgrading unrelated packages.
Refresh `fuzz/Cargo.lock` and `scripts/xsd-compat/Cargo.lock` as well; their
independent workspaces resolve SDK path dependencies at the new version.
The release metadata checker validates those local SDK entries.
The root Cargo lockfile governs workspace builds; the historical member
lockfiles are not used by these commands.

Add a curated entry to the root [changelog](https://github.com/mqqz/fatoority/blob/main/CHANGELOG.md).
Keep its date as `Unreleased` until publication. Include migration instructions
for Rust, C/C++, Python, and serialized data when their contracts change. A
breaking change before 1.0 requires a new minor version under Cargo's
compatibility conventions; the package-name and CLI changes in 0.3.x require
0.4.0.

Release tooling needs Cargo 1.90+ for workspace publication and Python 3.11+ for
the metadata checker. This tooling requirement does not declare a minimum
supported Rust version for library consumers; CI currently tests stable Rust.

## Validate the committed candidate

```sh
python3 scripts/check_release.py --tag v0.4.3
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
the native library in clean environments on each supported platform. Run
`python scripts/check_xml_free_artifacts.py <artifact paths>` against the actual
CLI/FFI archives and wheels. It inspects ELF imports and loader dependencies,
Mach-O load commands, and PE imports including delay imports. Distributed
artifacts must neither link nor bundle libxml2. Preserve the bundled FFI
library layout inside Python wheels.

## JavaScript artifact

Run the [JS/TS checks](../contributing.md#javascript-typescript-checks), including
the installed tarball test and size budget, on the release candidate. Build only
with `python3 scripts/build_js.py` so the size profile, `wasm-opt -Oz`, lossless
schema compression and host-import checks are applied. Inspect the tarball's
WASM module, declarations and license notices. Recheck Node and browser behavior
after optimization changes.

The `javascript` workflow publishes on `v*` tag pushes after metadata/tag checks,
optimized WASM builds, size checks, TypeScript, Node and browser tests, and an
installed-tarball test pass. The publish job downloads that exact tested tarball
and authenticates to npm with the `NPM_TOKEN` repository secret, exposed only to
`npm publish` as `NODE_AUTH_TOKEN`. The token needs publish access to `fatoority`.

For an npm-only retry, dispatch the `javascript` workflow on the existing release
tag with `publish: true`. Branch dispatches requesting publication fail the tag
check. Dispatch without publication builds and tests only. Do not recreate a tag
or bump versions to recover a failed publication; first check which registries
accepted the release. npm does not allow overwriting an existing version.

## NuGet artifact and trusted publishing

The `dotnet.yml` workflow builds native RID assets, combines them into the
`Fatoority` NuGet package, and tests fresh consumers on Linux, Windows, and macOS.
Only after all consumers pass does it download and publish that exact artifact.
The publish job requests a GitHub OIDC token with `id-token: write`, exchanges it
through `NuGet/login@v1`, and pushes using the short-lived key. No repository
API-key secret is required.

Configure the NuGet trusted publisher for owner/user `mqqz`, repository
`mqqz/fatoority`, workflow filename `dotnet.yml`, and package pattern `fatoority`.
Leave the optional environment field empty; the publishing job has no GitHub
environment. The policy must allow pushing new packages and versions. See the
[NuGet trusted publishing documentation](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing).

Tag pushes publish automatically after version validation. For a NuGet-only
retry, dispatch `dotnet.yml` on the existing release tag with `publish: true`.
Branch dispatches requesting publication fail the tag check; dispatches with
`publish: false` build and test only. Keep the existing tag fixed and verify
whether the version already exists before retrying. The push does not silently
skip duplicate versions.

## Maven Central publishing

The `kotlin.yml` workflow publishes `com.fatoority:fatoority` (desktop JAR) and
`com.fatoority:fatoority-android` (Android AAR). The namespace reflects ownership
of `fatoority.com`; it does not change the `com.fatoora` Java/Kotlin API package.

Before the first release:

1. Sign in to [Sonatype Central](https://central.sonatype.com/), add the
   `com.fatoority` namespace, and verify the DNS TXT record requested for
   `fatoority.com`.
2. Generate a user token from the Central account page. Store its username and
   password as repository Actions secrets `MAVEN_CENTRAL_USERNAME` and
   `MAVEN_CENTRAL_PASSWORD`. These are the token credentials, not your login
   password.
3. Create a dedicated signing key, or select an existing RSA signing key. For a
   new key, choose RSA (signing-capable), 4096 bits, an expiry such as two years,
   and a passphrase. The name and email on the public key will be public.

```sh
gpg --full-generate-key
gpg --list-secret-keys --keyid-format LONG
```

Use the full primary fingerprint from that output below. Publish the public key
so Central can verify signatures, then pipe the armored private key directly to
GitHub's encrypted Actions secret. No private-key file is needed.

```sh
export GPG_TTY="$(tty)"
SIGNING_FINGERPRINT=YOUR_FULL_PRIMARY_FINGERPRINT
gpg --keyserver hkps://keyserver.ubuntu.com --send-keys "$SIGNING_FINGERPRINT"
gpg --armor --export-secret-keys "$SIGNING_FINGERPRINT" |
  gh secret set GPG_PRIVATE_KEY --repo mqqz/fatoority

gh secret set GPG_PASSPHRASE --repo mqqz/fatoority
gh secret set MAVEN_CENTRAL_USERNAME --repo mqqz/fatoority
gh secret set MAVEN_CENTRAL_PASSWORD --repo mqqz/fatoority
```

The last three commands prompt for values. You can also add them under repository
**Settings → Secrets and variables → Actions → New repository secret**.
`GPG_PRIVATE_KEY` must contain the entire ASCII-armored private key, including
its BEGIN/END lines, with no base64 wrapping. `GPG_PASSPHRASE` is its passphrase.
Keep a backup of the key and its revocation certificate. When extending its
expiry, send the updated public key to the keyserver and replace the private-key
secret. See [Sonatype's GPG guide](https://central.sonatype.org/publish/requirements/gpg/)
and [token setup](https://central.sonatype.org/publish/generate-portal-token/).

Every Kotlin workflow validates a Central bundle without credentials after the
three desktop jobs, isolated JAR consumer, and both Android emulator consumers
pass. The bundle must contain both packages, all supported native platforms,
sources, Dokka API documentation, and complete POM metadata. It includes Gradle
module metadata and recalculated checksums; repository-level Maven metadata and
other versions are excluded.

The publish job runs only for `v*` tags or a manual dispatch with `publish: true`.
It checks that the selected ref is a tag matching every package version, imports
the signing key into a temporary keyring, signs the tested artifacts without
rebuilding them, and uploads a single bundle to Central using `AUTOMATIC`
publishing. It waits for `PUBLISHED`; an accepted upload alone is not success.
Normal commits, PRs, and dispatches with `publish: false` do not publish or receive
credentials. Tag workflows are not cancelled by a newer run.

For an unpublished local bundle check, download and combine the `kotlin-maven`
and `kotlin-android-maven` CI artifacts into one repository directory, then run:

```sh
python3 scripts/publish_kotlin.py --repository dist/maven
```

This creates an **unsigned validation bundle**, without contacting Central. Add
`--sign` with the GPG environment variables set to exercise signing locally.
Only the release workflow should use `--publish`.

For recovery, inspect the deployment ID in the job log or the
`kotlin-central-deployment` artifact and check its status in Central before
retrying. A timeout or lost upload response does not prove publication failed.
If Central already has a pending deployment, finish or drop it there; do not
blindly upload another bundle. Both artifact versions must be unused for a fresh
upload. When neither is published and no deployment is pending, dispatch
`kotlin.yml` on the unchanged release tag with `publish: true`. Central versions
are immutable. A tag created before this workflow exists cannot gain it by
rerunning; ship the publishing setup in a new release commit and tag.

After success, verify both coordinates in Central and resolve each in a fresh
Gradle/Maven consumer. The first publication still requires verified namespace,
valid secrets, and server-side validation; local tests cannot establish those.

## Publication prerequisites

Before tagging, check the candidate commit's Rust tests, Python tests, Cargo
package verification, all wheel builds, and all native builds. Recheck the final
commit after any changes. Independent workflows can partially succeed, so a
green workflow alone does not prove that the whole release is ready.

For the project rename, confirm ownership of the new `fatoora-cli` crates.io
name and `fatoority` PyPI name before publication. Configure PyPI trusted
publishing for `mqqz/fatoority`, workflow `python.yml`, environment `pypi`.
Existing `fatoora` Python imports and native interfaces are unchanged. Avoid
installing the old and new Python distributions together: both own the same
`fatoora` import package. Uninstall the previous distribution before switching.
Frozen SDK evidence retains historical repository URLs to preserve its checksums.

Confirm these repository settings without exposing secret values:

- `CARGO_REGISTRY_TOKEN` can publish each of the four crates.
- PyPI trusted publishing matches this repository, `python.yml`, and the `pypi`
  environment; any configured environment approvals are satisfied.
- The tag and all package versions agree, and the version is unused on each
  destination registry.

Include the [third-party notice](https://github.com/mqqz/fatoority/blob/main/THIRD_PARTY_NOTICES.md)
in the packages and retain the applicable upstream license text and attribution.
Keep remaining source questions recorded there for follow-up.

## Tag and publish

After review and successful checks, merge the release PR and tag the exact
tested release commit. Replace `TESTED_COMMIT_SHA` below with that commit:

```sh
git tag -a v0.4.3 TESTED_COMMIT_SHA -m "Release v0.4.3"
git push origin v0.4.3
```

The tag starts publication. Rust publishes derive, core, FFI, then CLI. Python
publishes after its binding tests and wheel builds. NuGet publishes after its
combined package passes all platform consumers. Maven Central publishes after
the desktop and Android consumers and Central bundle checks pass. GitHub assets upload after
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
