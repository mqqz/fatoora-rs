# Diplomat bindings

Diplomat generates the C, C++, and Python native interfaces from `fatoora-ffi`.
The Rust core remains independent of the binding framework. The public Python
API in [api.py](../../bindings/python/fatoora/api.py) wraps the generated private
`fatoora._native` extension and supplies decimal conversion, exceptions, and
object lifetime management.

The bridge is divided by capability:

| Source | Responsibilities |
| --- | --- |
| [common.rs](../../fatoora-ffi/src/common.rs) | Structured errors, strict text conversion, panic boundaries, owned optional text |
| [crypto.rs](../../fatoora-ffi/src/crypto.rs) | Configuration, keys, CSRs, certificates, signing, owned bytes |
| [invoice.rs](../../fatoora-ffi/src/invoice.rs) | Invoice builders, parsing, snapshots, totals, XML, hashes, validation |
| [api.rs](../../fatoora-ffi/src/api.rs) | Credentials, ZATCA requests, response outcomes, validation messages |

C headers live in [bindings/c](../../bindings/c), C++ headers in
[bindings/cpp](../../bindings/cpp), and Nanobind sources in
[bindings/python/native/generated](../../bindings/python/native/generated).
The old C ABI and CFFI implementation have been removed. `FfiLibrary` and
`fatoora.native` are no longer public entry points; import from `fatoora` or its
documented Python modules.

## Python contracts

Install from the repository root:

```sh
python -m pip install ./bindings/python
```

Building requires Rust, the repository's native library dependencies, CMake,
Python development headers, and a C++20 compiler. Build isolation installs the
pinned Nanobind dependency. The wheel bundles `_native` and `fatoora_ffi`.

Decimal arguments accept `Decimal`, decimal strings, or integers. Floats and
booleans are rejected. Rust validates UTF-8 and rejects embedded NUL. Exceptions
retain `.code`, `.kind`, and structured `.details`; unknown numeric error codes
remain available. The facade copies error data before releasing its native owner.

Objects support `close()` and context managers. Closing releases the facade's
native reference; subsequent operations raise `InvalidInputError`. Builder setters
validate input before updating state, allowing correction after an input error.
`build()` consumes the builder's inner state on success and validation failure.
Signing consumes a finalized invoice, and `SignedInvoice.into_xml()` consumes a
signed invoice. Their outer owners remain safe to release after consumption.

Invoice data, parties, addresses, line items, and response getters return owned
snapshots. They remain usable after their source object is closed. Python copies
native byte views into `bytes` through a small Nanobind adapter, without NumPy; XML and other text outputs are owned strings.

## Blocking requests and concurrency

ZATCA methods are synchronous. The custom Nanobind bindings in
[client_bindings.cpp](../../fatoora-ffi/src/client_bindings.cpp) add private
`_blocking_*` methods that release the GIL during requests. The Python facade
acquires an `RLock` for every argument owner in a consistent order and holds those
locks through the call. This prevents concurrent close or consumption of a handle
while native code uses it. Other Python threads can continue running.

`_native` is an implementation detail. Calling its generated methods directly
bypasses the facade's locking and error conversion. Native C and C++ callers must
provide their own synchronization, including exclusive access during mutation or
consumption. Mutable objects expose no borrowed child fields. `Bytes.as_slice()`
is a read-only view valid for the lifetime of its immutable `Bytes` owner.

## C and C++ ownership

Include `InvoiceBuilder.h` for C or `fatoora/InvoiceBuilder.hpp` for C++ and link
`fatoora_ffi`. C++ types live in namespace `fatoora`; standalone clients require
C++17. See the [C contract](../../fatoora-ffi/tests/diplomat_contract.c) and
[C++ contract](../../fatoora-ffi/tests/diplomat_contract.cpp) for complete clients.

Generated C symbols use `fatoora_Type_method`, such as
`fatoora_InvoiceBuilder_build`. This is a breaking ABI replacement. Recompile
clients against the generated headers distributed with their library version.

Fallible results contain a success value or an owned `BindingError`. Inspect
`is_ok` before reading the union. Destroy every owned object and error exactly
once with its generated destroy function. C++ uses `std::unique_ptr` to release
these owners automatically. Optional values use the generated optional
representation; absence is distinct from an empty string.

String inputs are length-delimited byte views. Malformed UTF-8 and embedded NUL
return InvalidInput errors. Enum-like inputs use validated integer values, so
unknown values produce errors. Callers must still supply valid pointers and obey
reference lifetimes.

Fallible Rust operations catch unwinding panics and return Internal errors,
including when a panic payload's destructor panics. Abort-mode panics, allocation
aborts, and invalid native pointers cannot be recovered through this boundary.

## Generate and verify

Generated files are checked-in build inputs. Regenerate them after changing bridge
signatures or documentation; do not edit generated files directly.

```sh
cargo install diplomat-tool --version 0.16.1 --locked
python scripts/generate_bindings.py
python scripts/generate_bindings.py --check
cargo test -p fatoora-ffi --locked
python scripts/check_native_bindings.py
python -m pip wheel --no-deps ./bindings/python -w /tmp/fatoora-wheels
```

Install the resulting wheel in a fresh virtual environment, then run
[wheel_smoke.py](../../bindings/python/tests/wheel_smoke.py) and the
[Python tests](../../bindings/python/tests). Do not add the source package to
`PYTHONPATH`. Verify that the installed extension loads its bundled shared library,
with the build-tree library unavailable. Linux dependency entries must use a
library basename with `$ORIGIN`; macOS uses `@rpath` and `@loader_path`.

[check_native_bindings.py](../../scripts/check_native_bindings.py) builds C11 and
C++17 clients on Linux/macOS, passes a signed XML fixture to the C++ contract, and
honors `CC`, `CXX`, and `CARGO_TARGET_DIR`. `DIPLOMAT_TOOL` selects an alternate
path to the generator.

Versions are pinned: Diplomat macro and generator 0.16.1, runtime 0.16.0, and
Nanobind 2.12.0. Update the macro and generator together. Nanobind's generated
deleter uses internal headers, so its pin also requires cross-language tests.

The replacement C11 and C++17 contracts have passed locally on Linux. The Linux CPython 3.14 installed wheel passed all 46 Python tests, including
HTTP concurrency checks, and the bundled-library smoke test. Windows, macOS, and other
Python versions require their platform CI checks; local Linux results do not
establish those outcomes. The [parity map](ffi-parity.md) records capability and
test coverage separately.
