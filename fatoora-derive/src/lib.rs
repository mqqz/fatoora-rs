use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, Type
};

mod rules;

fn extract_error_type(attrs: &[Attribute]) -> TokenStream2 {
    for attr in attrs.iter().filter(|a| a.path().is_ident("validate_error")) {
        let mut ty = None;
        attr.parse_nested_meta(|meta| {
            ty = Some(meta.path.to_token_stream());
            Ok(())
        }).unwrap();
        if let Some(t) = ty {
            return t;
        }
    }
    quote! { String }
}

fn extract_rules(attrs: &[Attribute]) -> Vec<String> {
    let mut out = vec![];
    for attr in attrs.iter().filter(|a| a.path().is_ident("validate")) {
        attr.parse_nested_meta(|meta| {
            if let Some(id) = meta.path.get_ident() {
                out.push(id.to_string());
            }
            Ok(())
        }).unwrap();
    }
    out
}

/// Only allow rules on String for now.
fn is_string_type(ty: &Type) -> bool {
    match ty {
        Type::Path(p) => p.path.segments.last().map(|s| s.ident == "String").unwrap_or(false),
        Type::Reference(r) => {
            if let Type::Path(p) = &*r.elem {
                p.path.segments.last().map(|s| s.ident == "String").unwrap_or(false)
            } else { false }
        }
        _ => false,
    }
}

#[proc_macro_derive(Validate, attributes(validate, validate_error))]
pub fn derive_validate(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let struct_name = ast.ident;
    let error_type = extract_error_type(&ast.attrs);
    let struct_rules = extract_rules(&ast.attrs);

    let mut ctor_params = vec![];
    let mut ctor_assigns = vec![];
    let mut validations = vec![];

    let fields = match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(n) => n.named,
            _ => return quote! { compile_error!("Validate supports named structs only"); }.into(),
        },
        _ => return quote! { compile_error!("Validate can only be used on structs"); }.into(),
    };

    for field in fields {
        let ident = field.ident.unwrap();
        let ty = field.ty;

        ctor_params.push(quote! { #ident: #ty });
        ctor_assigns.push(quote! { #ident });

        let mut field_rules = extract_rules(&field.attrs);
        if field_rules.iter().any(|r| r == "skip") {
            continue;
        }
        if field_rules.is_empty() {
            field_rules = struct_rules.clone();
        }
        if field_rules.is_empty() {
            continue;
        }

        if !is_string_type(&ty) {
            let msg = format!("Validation rules can only be applied to String fields: {}", ident);
            return quote! { compile_error!(#msg); }.into();
        }

        for rule in field_rules {
            let ts = match rules::dispatch(&rule, &ident) {
                Some(ts) => ts,
                None => {
                    let msg = format!("Unknown rule `{}`", rule);
                    return quote! { compile_error!(#msg); }.into();
                }
            };
            validations.push(ts);
        }
    }

    let out = quote! {
        impl #struct_name {
            pub fn new(
                #(#ctor_params),*
            ) -> Result<Self, #error_type> {

                type E = #error_type;

                #(
                    #validations
                )*

                Ok(Self {
                    #(#ctor_assigns),*
                })
            }
        }
    };

    out.into()
}
