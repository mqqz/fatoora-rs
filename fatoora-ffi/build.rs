use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/types.rs");
    println!("cargo:rerun-if-changed=src/error.rs");
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = PathBuf::from(&crate_dir).join("include");
    std::fs::create_dir_all(&out_dir).expect("create include dir");

    let header_path = out_dir.join("fatoora_ffi.h");
    let config = match cbindgen::Config::from_file("cbindgen.toml") {
        Ok(config) => config,
        Err(err) => {
            println!("cargo:warning=Skipping cbindgen: {err}");
            return;
        }
    };

    match cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&header_path);
            if let Err(err) = write_alias_header(&header_path, &out_dir.join("fatoora.h")) {
                println!("cargo:warning=Skipping alias header generation: {err}");
            }
        }
        Err(err) => {
            println!("cargo:warning=Skipping cbindgen generation: {err}");
        }
    }
}

fn write_alias_header(header_path: &PathBuf, out_path: &PathBuf) -> Result<(), String> {
    let header = std::fs::read_to_string(header_path)
        .map_err(|err| format!("read header: {err}"))?;
    let mut type_aliases = std::collections::BTreeSet::new();
    let mut func_aliases = std::collections::BTreeSet::new();
    let mut enums: Vec<(String, Vec<String>)> = Vec::new();
    let mut current_enum: Option<(String, Vec<String>)> = None;

    for line in header.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("typedef enum ") {
            let name = trimmed
                .split_whitespace()
                .nth(2)
                .unwrap_or_default()
                .trim_end_matches('{')
                .to_string();
            current_enum = Some((name, Vec::new()));
            continue;
        }

        if let Some((ref enum_name, ref mut values)) = current_enum {
            if trimmed.starts_with('}') {
                enums.push((enum_name.clone(), values.clone()));
                current_enum = None;
                continue;
            }
            if trimmed.starts_with(enum_name) {
                let value = trimmed
                    .trim_end_matches(',')
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                values.push(value);
            }
            continue;
        }

        if trimmed.starts_with("typedef struct ") {
            let name = trimmed
                .split_whitespace()
                .nth(2)
                .unwrap_or_default()
                .trim_end_matches('{')
                .to_string();
            if name.starts_with("Ffi") && !name.starts_with("FfiResult_") {
                let short = match name.as_str() {
                    "FfiString" => "FatooraString".to_string(),
                    _ => name.trim_start_matches("Ffi").to_string(),
                };
                type_aliases.insert((short, name));
            }
        }

        for token in trimmed.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            if let Some(name) = token.strip_prefix("fatoora_") && !name.is_empty() {
                func_aliases.insert((name.to_string(), token.to_string()));
            }
        }
    }

    let mut output = String::new();
    output.push_str("#ifndef FATOORA_H\n#define FATOORA_H\n\n");
    output.push_str("#include \"fatoora_ffi.h\"\n\n");
    output.push_str("#ifdef FATOORA_FFI_NO_PREFIX\n\n");

    for (short, full) in &type_aliases {
        output.push_str(&format!("typedef {full} {short};\n"));
    }

    for (enum_name, values) in &enums {
        if !enum_name.starts_with("Ffi") {
            continue;
        }
        let short_enum = enum_name.trim_start_matches("Ffi");
        for value in values {
            if let Some(suffix) = value.strip_prefix(&format!("{enum_name}_")) {
                output.push_str(&format!(
                    "#define {short_enum}_{suffix} {value}\n"
                ));
            }
        }
    }

    for (short, full) in &func_aliases {
        output.push_str(&format!("#define {short} {full}\n"));
    }

    output.push_str("\n#endif\n\n#endif\n");
    std::fs::write(out_path, output).map_err(|err| format!("write alias header: {err}"))?;
    Ok(())
}
