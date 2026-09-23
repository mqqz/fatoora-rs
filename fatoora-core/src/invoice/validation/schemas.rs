//! Bundled UBL schemas, independent of the build machine's source checkout.
//!
//! libxml's safe schema API resolves imports from files. Extract the trusted,
//! embedded resources into a private directory for compilation; the resulting
//! schema owns its parsed resources and outlives the extracted files.
use super::XmlValidationError;
use libxml::schemas::{SchemaParserContext, SchemaValidationContext};
use std::path::Path;
use tempfile::TempDir;

macro_rules! resource {
    ($path:literal) => {
        (
            $path,
            include_bytes!(concat!("../../../assets/schemas/UBL2.1/xsd/", $path))
                as &'static [u8],
        )
    };
}

const RESOURCES: &[(&str, &[u8])] = &[
    resource!("maindoc/UBL-Invoice-2.1.xsd"),
    resource!("common/CCTS_CCT_SchemaModule-2.1.xsd"),
    resource!("common/UBL-CommonAggregateComponents-2.1.xsd"),
    resource!("common/UBL-CommonBasicComponents-2.1.xsd"),
    resource!("common/UBL-CommonExtensionComponents-2.1.xsd"),
    resource!("common/UBL-CommonSignatureComponents-2.1.xsd"),
    resource!("common/UBL-CoreComponentParameters-2.1.xsd"),
    resource!("common/UBL-ExtensionContentDataType-2.1.xsd"),
    resource!("common/UBL-QualifiedDataTypes-2.1.xsd"),
    resource!("common/UBL-SignatureAggregateComponents-2.1.xsd"),
    resource!("common/UBL-SignatureBasicComponents-2.1.xsd"),
    resource!("common/UBL-UnqualifiedDataTypes-2.1.xsd"),
    resource!("common/UBL-XAdESv132-2.1.xsd"),
    resource!("common/UBL-XAdESv141-2.1.xsd"),
    resource!("common/UBL-xmldsig-core-schema-2.1.xsd"),
];

pub(super) fn build_validation_context() -> Result<SchemaValidationContext, XmlValidationError> {
    let resources = materialize()?;
    compile(resources.path())
}

fn materialize() -> Result<TempDir, XmlValidationError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("fatoora-schema-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set permissions during creation, before writing any resource files.
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let resources = builder
        .tempdir()
        .map_err(|error| setup_error("creating a private temporary directory", error))?;
    for directory in ["common", "maindoc"] {
        std::fs::create_dir(resources.path().join(directory))
            .map_err(|error| setup_error("creating schema directories", error))?;
    }
    for (relative, bytes) in RESOURCES {
        std::fs::write(resources.path().join(relative), bytes)
            .map_err(|error| setup_error(&format!("writing {relative}"), error))?;
    }
    Ok(resources)
}

fn compile(directory: &Path) -> Result<SchemaValidationContext, XmlValidationError> {
    let path = directory.join("maindoc/UBL-Invoice-2.1.xsd");
    let path = path
        .to_str()
        .ok_or_else(|| XmlValidationError::InvalidXsdPath {
            path: path.display().to_string(),
        })?;
    // Preserve the schema files byte-for-byte, including the trusted XMLDSig
    // schema's internal DTD. Invoice input follows its separate parsing policy.
    let mut parser = SchemaParserContext::from_file(path);
    SchemaValidationContext::from_parser(&mut parser).map_err(|errors| {
        XmlValidationError::SchemaParse {
            errors: errors
                .into_iter()
                .map(crate::Diagnostic::from_xml)
                .collect(),
        }
    })
}

fn setup_error(operation: &str, error: std::io::Error) -> XmlValidationError {
    XmlValidationError::SchemaParse {
        errors: vec![crate::Diagnostic::new(format!(
            "bundled XSD resource setup failed while {operation}: {error}"
        ))],
    }
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
