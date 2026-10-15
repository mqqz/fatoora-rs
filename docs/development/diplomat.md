---
title: Developing language bindings
description: Regenerate fatoority bindings and run native, language-specific and installed-package checks.
---

# Binding development

Use this page when changing the shared bridge or a language package. Installation and application code belong in the [binding reference](../reference/bindings/python.md).

## Change the API once

1. Implement the behavior and its tests in `fatoora-core`.
2. Expose it in the appropriate `fatoora-ffi/src` bridge: `crypto.rs`, `invoice.rs`, or `api.rs`. Shared errors and input conversion live in `common.rs`.
3. Regenerate the bindings. Update a handwritten facade when it needs language-specific conversion or resource handling.
4. Test the affected language and its installed package. Update public examples and reference documentation.

Preserve exact decimals, absent versus empty values, structured errors and ownership on failure. Test consumed objects, returned children after parent disposal, and concurrent close where relevant. Test HTTP behavior against a local server.

## Generate and verify

Generated files are checked in. Edit the bridge or generator, then regenerate; do not edit generated output directly.

Install the pinned generators once:

```sh
cargo install diplomat-tool --version 0.16.1 --locked
python3 scripts/install_dotnet_generator.py
python3 scripts/install_kotlin_generator.py
```

The installer scripts select the required fork revisions. Then run:

```sh
python3 scripts/generate_bindings.py
python3 scripts/generate_bindings.py --check
cargo test -p fatoora-ffi --locked
```

The combined check covers all generators, including C# and Kotlin. It requires all three installed tools. For work confined to a handwritten language facade, run that package's checks below without regenerating unchanged bridge code.

## Check the affected package

=== "C and C++"

    Install a C11 and C++17 compiler alongside Rust and Python. Run:

    ```sh
    python3 scripts/check_native_bindings.py
    python3 scripts/check_c_reference.py
    python3 scripts/check_c_examples.py
    ```

    These compile native callers and exercise ownership, errors and examples. The API example's check does not submit an invoice.

    The public C facade is generated from the native headers. Change `scripts/generate_c_facade.py` or `scripts/c_facade_runtime.c` when adjusting that facade, then run the combined generation check.

=== "Python"

    Source builds require Python development headers, CMake, a C++20 compiler and Rust. In an activated virtual environment:

    ```sh
    python -m pip install "./bindings/python[dev]"
    python -m pytest bindings/python/tests
    python -m pip wheel --no-deps ./bindings/python -w /tmp/fatoority-wheels
    ```

    Install the resulting wheel in a fresh environment and run `bindings/python/tests/wheel_smoke.py`. Keep the source package off `PYTHONPATH` so the check uses the installed package and its bundled native library.

    Add facade regressions for decimal conversion, exceptions, lifetime handling or GIL behavior when those contracts change.

=== "JavaScript"

    Install Node.js 22+, npm and the Rust WASM target:

    ```sh
    rustup target add wasm32-unknown-unknown
    npm ci --prefix bindings/js
    python3 scripts/build_js.py
    npm run check --prefix bindings/js
    node bindings/js/tests/runtime.test.mjs
    npx --prefix bindings/js playwright install chromium
    node bindings/js/tests/browser.mjs
    python3 scripts/check_js_package.py
    ```

    Use the build script so optimization and artifact-size checks run consistently. The checks cover declarations, runtime behavior, browser loading and an installed npm package.

=== "C#"

    Install the .NET SDK required by [`bindings/dotnet`](https://github.com/mqqz/fatoority/tree/main/bindings/dotnet), plus Rust and Python. Run:

    ```sh
    python3 scripts/generate_dotnet.py --check
    python3 scripts/check_dotnet.py
    ```

    To test an already built NuGet package as well, pass `--package-dir dist/dotnet`. Keep disposal, optional results, borrowed byte views and error ownership covered by the package tests.

=== "Kotlin and Java"

    Install the JDK required by [`bindings/kotlin`](https://github.com/mqqz/fatoority/tree/main/bindings/kotlin), plus Rust and Python. Use the checked-in Gradle wrapper:

    ```sh
    python3 scripts/generate_kotlin.py --check
    python3 scripts/build_kotlin.py
    bindings/kotlin/gradlew -p bindings/kotlin test -PnativeDir="$PWD/target/jvm-release"
    python3 scripts/check_kotlin.py
    ```

    The package check uses a fresh Java consumer. Android changes also need the Android build and emulator checks described in the package README. Preserve both language interfaces when changing factories, optional values or exceptions.

## Before submitting

Run the [workspace checks](../contributing.md#make-and-check-a-change), review generated diffs, and test the packaged library rather than only a build-tree import. Include the relevant license and notice files when changing packaging. Platform-specific changes need their platform CI results.
