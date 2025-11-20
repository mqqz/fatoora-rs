use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse_macro_input, Data, DeriveInput, Fields, Meta, NestedMeta,
};
use std::collections::HashMap;
use std::sync::RwLock;

// ===========================================================
// RULE REGISTRY
// ===========================================================
//
// RULES: HashMap<rule_name, HashMap<type_name, RuleFn>>
//
// RuleFn takes (field_ident) as a TokenStream and returns TokenStream
//
// ===========================================================

type RuleFn = fn(proc_macro2::TokenStream) -> proc_macro2::TokenStream;

pub static RULES: RwLock<HashMap<&'static str, HashMap<&'static str, RuleFn>>> =
    RwLock::new(HashMap::new());

// ===========================================================
// DEFINE RULE MACRO
// ===========================================================
//
// Usage:
//
// define_rule! {
//     non_empty for String => |value| {
//         quote! {
//             if #value.trim().is_empty() {
//                 return Err(format!("{} must be non-empty", stringify!(#value)));
//             }
//         }
//     }
// }
//
// ===========================================================

#[macro_export]
macro_rules! define_rule {
    ($name:ident for $ty:ident => $gen:expr) => {
        #[ctor::ctor]
        fn register_rule() {
            let mut rules = $crate::RULES.write().unwrap();
            rules
                .entry(stringify!($name))
                .or_insert_with(std::collections::HashMap::new)
                .insert(stringify!($ty), $gen);
        }
    };
}

// ===========================================================
// DERIVE MACRO: #[derive(Validate)]
// ===========================================================

#[proc_macro_derive(Validate, attributes(validate))]
pub fn derive_validate(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let struct_name = ast.ident.clone();

    // --------------------------
    // Extract struct-level rules
    // --------------------------
    let mut struct_rules = Vec::<String>::new();

    for attr in &ast.attrs {
        if attr.path().is_ident("validate") {
            let meta = attr.parse_args_with(
                syn::punctuated::Punctuated::<NestedMeta, syn::Token![,]>::parse_terminated,
            ).unwrap();

            for rule in meta {
                if let NestedMeta::Meta(Meta::Path(path)) = rule {
                    struct_rules.push(path.get_ident().unwrap().to_string());
                }
            }
        }
    }

    // --------------------------
    // Walk fields and collect validations
    // --------------------------
    let mut ctor_params = Vec::new();
    let mut ctor_assign = Vec::new();
    let mut validations = Vec::new();

    if let Data::Struct(data_struct) = ast.data {
        if let Fields::Named(fields) = data_struct.fields {
            for field in fields.named {
                let name = field.ident.unwrap();
                let ty = field.ty.clone();
                let ty_string = ty.into_token_stream().to_string();

                ctor_params.push(quote! { #name: #ty });
                ctor_assign.push(quote! { #name });

                // Field-level rules
                let mut field_rules = Vec::<String>::new();

                for attr in &field.attrs {
                    if attr.path().is_ident("validate") {
                        let meta = attr.parse_args_with(
                            syn::punctuated::Punctuated::<NestedMeta, syn::Token![,]>::parse_terminated,
                        ).unwrap();

                        for rule in meta {
                            if let NestedMeta::Meta(Meta::Path(path)) = rule {
                                field_rules.push(path.get_ident().unwrap().to_string());
                            }
                        }
                    }
                }

                // Skip field
                if field_rules.contains(&"skip".to_string()) {
                    continue;
                }

                // final list of rules
                let applied_rules = if field_rules.is_empty() {
                    struct_rules.clone()
                } else {
                    field_rules.clone()
                };

                // apply rules by type lookup
                for rule_name in applied_rules {
                    let rules = RULES.read().unwrap();

                    let type_map = rules
                        .get(rule_name.as_str())
                        .unwrap_or_else(|| panic!("Unknown validation rule `{}`", rule_name));

                    let validator = type_map
                        .get(ty_string.as_str())
                        .unwrap_or_else(|| {
                            panic!(
                                "Rule `{}` does not support type `{}`",
                                rule_name, ty_string
                            )
                        });

                    let field_token = quote! { #name };
                    let expanded = validator(field_token);
                    validations.push(expanded);
                }
            }
        }
    }

    // --------------------------
    // Generate constructor
    // --------------------------
    let expanded = quote! {
        impl #struct_name {
            pub fn new( #(#ctor_params),* ) -> Result<Self, String> {

                #(#validations)*

                Ok(Self {
                    #(#ctor_assign),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}
