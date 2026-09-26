# Fuzz targets

Run these commands from `fuzz/` on Linux with `libxml2-dev`, `pkg-config` and
Clang installed:

```sh
rustup toolchain install nightly-2026-08-28 --profile minimal --component rust-src
CARGO_NET_OFFLINE=false cargo +nightly-2026-08-28 install cargo-fuzz --version 0.13.2 --locked
CARGO_NET_OFFLINE=false cargo +nightly-2026-08-28 fetch --locked
cargo +nightly-2026-08-28 fuzz build
mkdir -p corpus/xml_parse
cp seeds/xml_parse/* corpus/xml_parse/
cargo +nightly-2026-08-28 fuzz run xml_parse -- -max_total_time=20 -timeout=5 -rss_limit_mb=2048 -max_len=32768
```

Repeat the last three commands with `qr_decode` or `signing_inputs`.
The separate workspace and lockfile keep fuzz dependencies out of published
crates. Builds run offline after the explicit fetch. The PR check replays all
seeds and runs each target for 20 seconds using AddressSanitizer. There is no
scheduled run. System libxml2 itself is not sanitizer-instrumented.

| Target | Input and checks |
| --- | --- |
| `xml_parse` | UTF-8 XML through finalized and signed invoice imports. Accepted models retain totals through export/import; signed imports retain exact XML bytes. |
| `qr_decode` | First byte modulo 2 selects raw TLV (0) or base64 text (1). Payload replaces QR content in a valid signed invoice, reaching the internal decoder through the public importer. |
| `signing_inputs` | First byte modulo 5 selects XML (0), DER certificate (1), DER key (2), PEM certificate (3), or PEM key (4). Other inputs remain valid. Successful signing preserves the invoice digest; the signer remains usable after XML failures. |

Invalid UTF-8 is skipped at APIs accepting Rust strings. QR text is escaped for
XML; disallowed control characters are skipped. Parse/signing errors are expected;
panics, sanitizer failures, timeouts and assertion failures stop the run.
A successful signed import does not establish signature authenticity or compliance.

Seeds are committed under `seeds/`; generated corpus files stay under ignored
`corpus/`. The signed XML and test signing material come from
`fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml`,
`certs/zatca_cert_b64.txt` and `pkeys/test_zatca_pkey.der`. The certificate seed
is decoded twice from the existing fixture; PEM seeds wrap the same DER bytes.
Keys are public test fixtures, unsuitable for production. Additional seeds cover
truncated XML/TLV/DER, duplicate tags, invalid UTF-8 and malformed base64/PEM.
The frozen SDK evidence corpus is unchanged.

Replay a crash downloaded from the CI `fuzz-failures` artifact:

```sh
cargo +nightly-2026-08-28 fuzz run xml_parse artifacts/xml_parse/crash-<hash>
cargo +nightly-2026-08-28 fuzz tmin xml_parse artifacts/xml_parse/crash-<hash>
```

Use the target named in the failing step. Add the minimized input to that target's
`seeds/` directory and a named regression test with the fix. CI preserves timeout
and OOM inputs in the same artifact directory, along with run logs. For target
setup and libFuzzer options, see the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html).
