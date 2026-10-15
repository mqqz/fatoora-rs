---
title: Contributing to fatoority
description: Set up a fatoority checkout, run the relevant checks, preview documentation and submit a focused contribution.
---

# Contributing

Bug reports, documentation fixes, tests, and code improvements are welcome. For a large API or behavior change, [open an issue](https://github.com/mqqz/fatoority/issues) first so the approach can be discussed before implementation.

## Set up a checkout

Install stable Rust and Git, then run:

```sh
git clone https://github.com/mqqz/fatoority.git
cd fatoority
cargo check --workspace --locked
```

Ordinary builds and tests need neither Java, an installed ZATCA SDK, nor a system XML library. Language-binding work needs additional tools; see [binding development](development/diplomat.md).

## Find the right place

| Directory | Contents |
| --- | --- |
| `fatoora-core/` | Invoice model, signing, XML, validation and API client |
| `fatoora-cli/` | Command-line interface |
| `fatoora-ffi/` | Shared bridge for language bindings |
| `fatoora-derive/` | Procedural macros |
| `bindings/` | Language facades, packages and their tests |
| `docs/` | Guides and reference pages |
| `bench/` and `fuzz/` | Benchmark harnesses and fuzz targets |

## Make and check a change

Keep changes focused. Add a regression test for a bug, and update the relevant guide or reference when public behavior changes.

Run these checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
SKIP_ZATCA_LIVE_API=1 cargo test --workspace --all-features --locked -- --skip doc_example_api
```

The test command skips live ZATCA requests. Local HTTP tests still need loopback networking. Start with the test for the behavior you changed, then run the workspace checks before submitting.

| If you changed… | Also check… |
| --- | --- |
| A binding or shared bridge | [Generation, language tests and installed packages](development/diplomat.md) |
| Validation, signing or XML behavior | [Validation and SDK compatibility tests](development/business-rules.md) |
| Documentation | The strict documentation build below |
| Performance-sensitive code | The relevant harness in [`bench/`](https://github.com/mqqz/fatoority/tree/main/bench) |

For longer property-test runs, set `PROPTEST_CASES=10000` when running the relevant test. Keep minimized regression inputs and failure seeds. See [`fuzz/README.md`](https://github.com/mqqz/fatoority/blob/main/fuzz/README.md) for fuzzing instructions.

## Edit the documentation

```sh
python3 -m venv .venv
.venv/bin/python -m pip install mkdocs-material mkdocs-macros-plugin
.venv/bin/mkdocs serve
```

On Windows, use executables under `.venv\Scripts` instead of `.venv/bin`. The preview prints its local URL. Before submitting, run:

```sh
.venv/bin/mkdocs build --strict --site-dir /tmp/fatoority-docs
```

Use a temporary output directory suitable for your system. Guides should walk through a task; reference pages should document inputs, results and behavior. Keep language-specific examples and notes inside the appropriate language tab. Check changed links, narrow screens and every tab you edited.

## Submit a pull request

Explain the problem, the resulting behavior and how you checked it. Include any remaining limitations. CI runs additional platform and package checks; a local pass does not replace those checks.

Follow the [code of conduct](https://github.com/mqqz/fatoority/blob/main/CODE_OF_CONDUCT.md). Original contributions are licensed under both MIT and Apache-2.0. Identify third-party material and retain its licenses and notices. For security reports, use the [security policy](security.md).

Release maintainers can follow the [release checklist](development/releases.md).
