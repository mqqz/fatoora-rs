# Contributing to fatoority

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
fatoority is an unofficial toolkit for ZATCA Phase 1 and 2 compliant e-invoicing, with a Rust core and bindings/CLI.

## Getting Started
- Rust toolchain (stable) and Cargo
- Optional: `uv` for Python bindings development and tests
- For JS/TS: Node 22+, npm and the `wasm32-unknown-unknown` Rust target

Quick setup:
```bash
cargo check
```

Ordinary builds and tests require no system XML library. The isolated maintenance
probes in `scripts/xml-reference` and `scripts/xsd-compat` use libxml2 as a
reference oracle and require its development headers when run explicitly.

## Workspace Layout

- `fatoora-core`: Rust core library and business logic

- `fatoora-derive`: Proc-macro helpers used by the core crate

- `fatoora-cli`: CLI tool wrapping `fatoora-core`

- `fatoora-ffi`: C FFI layer used by language bindings

- `bindings/`: Language bindings (e.g. `bindings/python`)

- `bench/`: Benchmarks and results for performance tracking

## Documentation

- Root overview and examples: `README.md`

- Rust API docs: https://docs.rs/fatoora-core/latest/fatoora_core/

- JavaScript/TypeScript bindings: [reference](reference/bindings/javascript.md)

- Python bindings details: `bindings/python/README.md`

- Bench results (CLI): `bench/cli/results/hash_bench.md`

## Bindings Development

Diplomat generates C, C++, Python and JavaScript/TypeScript bindings from `fatoora-ffi`.
Regenerate with `python scripts/generate_bindings.py`, run
`python scripts/check_native_bindings.py`, and install the Python package with
`python -m pip install ./bindings/python`. See the
[binding workflow](development/diplomat.md) for generation and installed-wheel tests.

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
Run the full test suite with:
```bash
cargo test
```

C bindings tests:
```bash
python scripts/check_native_bindings.py
python scripts/check_c_reference.py
python scripts/check_c_examples.py
```

These checks compile real C/C++ callers and the C guide examples.
Example requests to the ZATCA API are not submitted during documentation checks.

Python bindings tests:
```bash
uv pip install -e "bindings/python[dev]"
uv run --python .venv/bin/python pytest bindings/python/tests
```

Note: live API tests run by default. Set `SKIP_ZATCA_LIVE_API=1` to disable them locally or in CI.

## Benchmarks

Benchmark data lives in `bench/`. The CLI benchmark results are tracked in `bench/cli/results`.
The C# comparison harness and reproduction instructions live in `bench/dotnet/`,
with dated results under `bench/dotnet/results/`. New runs write to ignored
`dist/benchmarks/dotnet/` by default, preserving the recorded measurements.

## CI/CD

- Rust workflow: `.github/workflows/rust.yml` runs tests + coverage via `cargo llvm-cov` and uploads to Codecov.

- Python workflow: `.github/workflows/python.yml` runs bindings tests and builds wheels in CI.

## Submitting Changes

- Open an issue to discuss significant changes or new features

- Add or update tests when possible

- Lint and format your code

- Submit a PR with a clear description and rationale

## Releases

See the [release procedure](development/releases.md) for version updates,
validation, publication, and recovery from a partial release.

## See also 

- [Development](development/index.md)

## JavaScript / TypeScript checks

```sh
npm ci --prefix bindings/js
python3 scripts/build_js.py
python3 scripts/check_wasm_size.py
npm run check --prefix bindings/js
node bindings/js/tests/runtime.test.mjs
npx --prefix bindings/js playwright install chromium
node bindings/js/tests/browser.mjs
python3 scripts/check_js_package.py
```

The WASM build uses its own size profile and pinned Binaryen `wasm-opt -Oz`.
It verifies compressed schemas byte-for-byte and enforces raw/gzip size budgets.
Run the size check above when changing dependencies; preserve validation functionality
when reducing artifact size.
