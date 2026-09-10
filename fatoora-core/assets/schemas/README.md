# Bundled schemas

## UBL 2.1 — `UBL2.1/xsd/`

These files come from the OASIS UBL 2.1 release, with two deliberate changes.

**The directory tree is flattened.** Upstream ships `xsd/maindoc/` and
`xsd/common/`; here every `.xsd` sits directly in `xsd/`. uppsala resolves a
`schemaLocation` relative to the top-level schema and rejects any path that
escapes that directory, so upstream's `../common/UBL-CommonAggregateComponents-2.1.xsd`
from inside `maindoc/` cannot load.

**`UBL-Invoice-2.1.xsd` was edited to match.** Its three `schemaLocation`
attributes had their `../common/` prefix dropped. Nothing else in the file was
touched, so its header comment still describes the upstream layout.

Re-vendoring UBL 2.1 straight from OASIS reintroduces the layout uppsala cannot
resolve. Copy the files into `xsd/` flat, and strip the `../common/` prefixes
again.

Schema validation temporarily uses libxml2 while uppsala's inherited
simple-content validation and child-element rejection are fixed upstream.
The flattened layout is compatible with both engines and is retained for the
eventual switch back. The regression tests in `tests/validation.rs` must pass
with the replacement engine before removing libxml2.

The local import closure is checked before compiling the schema
(`invoice::validation::check_imports_present`), so a missing file is reported
as a schema-loading error regardless of the engine's import handling.
