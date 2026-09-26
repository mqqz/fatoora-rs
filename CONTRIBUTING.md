# Contributing to fatoora-rs

Thanks for your interest in contributing. This document is a starting point for how to work on the repo.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Project Scope](#project-scope)
- [Getting Started](#getting-started)
- [Workspace Layout](#workspace-layout)
- [Documentation](#documentation)
- [Bindings Development](#bindings-development)
- [Development Workflow](#development-workflow)
- [Tests](#tests)
- [Benchmarks](#benchmarks)
- [CI/CD](#cicd)
- [Submitting Changes](#submitting-changes)
- [Releases](#releases)

## Code of Conduct
Please read and follow `CODE_OF_CONDUCT.md`.

## Project Scope
fatoora-rs is an unofficial toolkit for ZATCA Phase 1 and 2 compliant e-invoicing, with a Rust core and bindings/CLI.

## Getting Started
- Rust toolchain (stable) and Cargo
- `libxml2` installed for XML parsing (usually preinstalled on Linux/macOS)
- Optional: `uv` for Python bindings development and tests

Quick setup:
```bash
cargo check
```

If `libxml2` is missing, install it via your system package manager and re-run `cargo check`.

## Workspace Layout
- `fatoora-core`: Rust core library and business logic
- `fatoora-derive`: Proc-macro helpers used by the core crate
- `fatoora-rs-cli`: CLI tool wrapping `fatoora-core`
- `fatoora-ffi`: C FFI layer used by language bindings
- `bindings/`: Language bindings (e.g. `bindings/python`)
- `bench/`: Benchmarks and results for performance tracking

## Documentation
- Root overview and examples: `README.md`
- Rust API docs: https://docs.rs/fatoora-core/latest/fatoora_core/
- Python bindings details: `bindings/python/README.md`
- Bench results (CLI): `bench/cli/results/hash_bench.md`

## Bindings Development
Diplomat generates the native bindings. Follow the [binding workflow](docs/development/diplomat.md) for generation, native contract tests, and installed-wheel verification.

## Development Workflow
- Make small, focused changes
- Keep public API changes deliberate; open an issue for large changes first
- Update documentation and examples when behavior changes

Common commands:
```bash
# Build all workspace crates
cargo build

# Format
cargo fmt

# Lint
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

All crates inherit the Clippy lint policy from the root `Cargo.toml`. CI checks
formatting and runs Clippy with warnings treated as errors.

## Tests
Run the workspace suite without live ZATCA calls with:
```bash
SKIP_ZATCA_LIVE_API=1 cargo test --workspace --locked --all-features -- --skip doc_example_api
```

Local HTTP contract tests still require permission to bind loopback listeners.
`doc_example_api` is excluded separately because it makes a live request.

Python bindings tests:
```bash
uv pip install -e bindings/python[dev]
uv run --python .venv/bin/python pytest bindings/python/tests
```

Use the test layer that owns the contract:

- Core tests cover business rules, arithmetic, parsing, and cryptographic behavior,
  using pinned fixtures and independently calculated expected values.
- Rust FFI contract tests cover argument forwarding, error details, optional values,
  and ownership after failed operations or parent destruction. HTTP tests use a
  loopback gateway and check request bytes as well as response semantics.
- C/C++ contracts exercise the generated ABI (`python3 scripts/check_native_bindings.py`).
  Python tests cover wrapper behavior, closed handles, and GIL/argument locking.

Rust coverage does not include the separate Python or C/C++ test runs. Keep
binding regressions in Rust when they concern the shared adapter, and add language
contracts for behavior specific to that language. Prioritize failure recovery,
exact boundaries, and independent expected results over getter-only coverage.
The FFI HTTP test supplies its gateway URL through a child process environment so
parallel tests cannot redirect one another's requests.

## Benchmarks
Benchmark data lives in `bench/`. The CLI benchmark results are tracked in `bench/cli/results`.

## CI/CD
- Rust workflow: `.github/workflows/rust.yml` runs tests + coverage via `cargo llvm-cov` and uploads to Codecov.
- Python workflow: `.github/workflows/python.yml` runs bindings tests and builds wheels in CI.

## Submitting Changes
- Open an issue to discuss significant changes or new features
- Add or update tests when possible
- Make sure formatting and lint checks pass
- Submit a PR with a clear description and rationale

## Releases
If you need a release, open an issue with the scope and crate(s) to publish.

## Licensing contributions

By submitting original code for inclusion in this project, you agree to license it
under both MIT and Apache-2.0, allowing recipients to choose either license.
Identify any third-party material you include and preserve its applicable license
and notices.

The root `LICENSE-MIT`, `LICENSE-APACHE`, and `THIRD_PARTY_NOTICES.md` files
are the maintained copies.
Each Rust crate links to them with relative symlinks; Cargo includes the target
contents in published packages. On Windows, enable Git symlink support before
checking out the repository if you will package crates locally.
Python packaging stages the files automatically.

### Property tests

`fatoora-core` runs Proptest with 256 generated cases per property in CI.
Decimal properties compare checked arithmetic with an unbounded-integer oracle.
Invoice properties independently calculate rounded line amounts and VAT groups
in integer cents. XML properties compare the fields supported by both the builder
and importer; they do not assert that arbitrary UBL or signed documents can be
reconstructed without loss. Inputs cover reserved XML characters, Arabic text,
CR/LF, invoice types, transaction flags, mixed VAT rates, and adjustments.

Run a longer local pass with:

```bash
PROPTEST_CASES=10000 cargo test -p fatoora-core property_ --locked
```

Generators construct valid dependencies directly, including discount limits and
adjustment VAT groups. Avoid filtering arbitrary inputs until the builder accepts
them: that wastes cases and can make shrinking ineffective. Arithmetic bounds
keep reference calculations exact; separate properties exercise the 96-bit limit.

Commit discovered failure seeds (`fatoora-core/proptest-regressions/*.txt` or
`fatoora-core/tests/*.proptest-regressions`) and add a small explicit regression
for each bug. CI retains these files on failure. Keep the minimized input and the
seed from the test log; changing a strategy can change what an old seed generates.
The fixed examples and SDK corpus remain independent checks of the properties.
