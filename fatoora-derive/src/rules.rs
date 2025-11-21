use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

/// --- Rule Implementations --------------------------------------------------

pub fn non_empty(field: &Ident) -> TokenStream {
    quote! {
        if #field.trim().is_empty() {
            return Err(E::from(format!(
                "{} must be non-empty",
                stringify!(#field)
            )));
        }
    }
}

pub fn no_special_chars(field: &Ident) -> TokenStream {
    quote! {
        {
            let val = #field.as_str();

            const FORBIDDEN: &[char] = &['!', '@', '#', '$', '%', '&', '*', '_', '<'];

            if val.chars().any(|c| FORBIDDEN.contains(&c)) {
                return Err(E::from(format!(
                    "Invalid {}, The {} should only contain alphanumeric characters, whitespace, dashes, Arabic letters, and special characters except these: !@#$%&*_<",
                    stringify!(#field),
                    stringify!(#field)
                )));
            }
        }
    }
}

pub fn is_country_code(field: &Ident) -> TokenStream {
    quote! {
        let code = #field.as_str();
        if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(E::from(format!(
                // TODO : actually validate against a list of country codes
                "{} must be a valid 2-letter ISO-3166-1 alpha-2 country code",
                stringify!(#field)
            )));
        }
    }
    
}


/// --- Dispatch Table --------------------------------------------------------

/// Very simple and clean rule lookup.
/// Add new rules by adding new match arms.
pub fn dispatch(name: &str, field: &Ident) -> Option<TokenStream> {
    match name {
        "non_empty" => Some(non_empty(field)),
        "no_special_chars" => Some(no_special_chars(field)),
        "is_country_code" => Some(is_country_code(field)),
        _ => None,
    }
}
