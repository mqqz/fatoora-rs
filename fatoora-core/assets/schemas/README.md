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

Schema validation uses uppsala. Version 0.10.1 accepts invalid inherited
simple-content values and child elements in simple content. The PR remains
parked until an upstream fix passes the regression tests in `tests/validation.rs`.

The local import closure is checked before compiling the schema
(`invoice::validation::check_imports_present`), so a missing file is reported
as a schema-loading error regardless of the engine's import handling.
