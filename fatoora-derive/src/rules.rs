//! Central registry of builtin validation rules.
//!
//! Add more rules here using `define_rule!{ ... }`
//! All rules must declare which Rust type they support (e.g., String, u32).

use quote::quote;
use fatoora_derive::define_rule;

// ============================================================
// STRING RULES
// ============================================================

/// Rule: non_empty — only for String
define_rule! {
    non_empty for String => |value| {
        quote! {
            if #value.trim().is_empty() {
                return Err(format!("{} must be non-empty", stringify!(#value)));
            }
        }
    }
}

/// Rule: no_special_chars — only for String
define_rule! {
    no_special_chars for String => |value| {
        quote! {
            if #value.contains(|c: char| !(c.is_alphanumeric() || c.is_whitespace())) {
                return Err(format!("{} must not contain special characters", stringify!(#value)));
            }
        }
    }
}

/// Rule: is_country_code — only for String
/// This is a ZATCA-style short CC validation
define_rule! {
    is_country_code for String => |value| {
        quote! {
            {
                let v = #value.to_uppercase();
                if !matches!(
                    v.as_str(),
                    "SA" | "AE" | "KW" | "BH" |
                    "OM" | "QA" | "US" | "UK"
                ) {
                    return Err(format!("{} must be a valid country code", stringify!(#value)));
                }
            }
        }
    }
}