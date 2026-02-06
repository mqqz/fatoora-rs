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
Python bindings use the `fatoora-ffi` shared library.
- Build FFI: `cargo build -p fatoora-ffi --release`
- Set `FATOORA_FFI_PATH` to point to a custom shared library build
- If a `fatoora_ffi.h` header exists (built with `FATOORA_CBINDGEN=1`), the wrapper loads it automatically

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
cargo clippy --all-targets --all-features
```

## Tests
Run the full test suite with:
```bash
cargo test
```

Python bindings tests:
```bash
uv pip install -e bindings/python[dev]
uv run --python .venv/bin/python pytest bindings/python/tests
```

Note: live API tests run by default. Set `SKIP_ZATCA_LIVE_API=1` to disable them locally or in CI.

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
