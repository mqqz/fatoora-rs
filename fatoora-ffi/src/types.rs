use std::ffi::CString;
use std::os::raw::c_void;

use fatoora_core::config::EnvironmentType;
use fatoora_core::invoice::{InvoiceSubType, VatCategory};

#[repr(C)]
pub struct FfiConfig {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub enum FfiEnvironment {
    NonProduction,
    Simulation,
    Production,
}

impl From<FfiEnvironment> for EnvironmentType {
    fn from(env: FfiEnvironment) -> Self {
        match env {
            FfiEnvironment::NonProduction => EnvironmentType::NonProduction,
            FfiEnvironment::Simulation => EnvironmentType::Simulation,
            FfiEnvironment::Production => EnvironmentType::Production,
        }
    }
}

#[repr(C)]
pub enum FfiInvoiceSubType {
    Standard,
    Simplified,
}

impl From<FfiInvoiceSubType> for InvoiceSubType {
    fn from(value: FfiInvoiceSubType) -> Self {
        match value {
            FfiInvoiceSubType::Standard => InvoiceSubType::Standard,
            FfiInvoiceSubType::Simplified => InvoiceSubType::Simplified,
        }
    }
}

#[repr(C)]
pub enum FfiInvoiceTypeKind {
    Tax,
    Prepayment,
    CreditNote,
    DebitNote,
}

#[repr(C)]
pub enum FfiVatCategory {
    Exempt,
    Standard,
    Zero,
    OutOfScope,
}

impl From<FfiVatCategory> for VatCategory {
    fn from(value: FfiVatCategory) -> Self {
        match value {
            FfiVatCategory::Exempt => VatCategory::Exempt,
            FfiVatCategory::Standard => VatCategory::Standard,
            FfiVatCategory::Zero => VatCategory::Zero,
            FfiVatCategory::OutOfScope => VatCategory::OutOfScope,
        }
    }
}

#[repr(C)]
pub struct FfiString {
    pub ptr: *mut std::os::raw::c_char,
}

impl From<String> for FfiString {
    fn from(value: String) -> Self {
        let c = CString::new(value).unwrap_or_else(|_| {
            CString::new("ffi string").expect("ffi string CString")
        });
        FfiString { ptr: c.into_raw() }
    }
}

#[repr(C)]
pub struct FfiInvoiceBuilder {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiFinalizedInvoice {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiSignedInvoice {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiSigner {
    pub ptr: *mut c_void,
}

#[repr(u8)]
pub enum FfiInvoiceFlag {
    ThirdParty = 0b00001,
    Nominal = 0b00010,
    Export = 0b00100,
    Summary = 0b01000,
    SelfBilled = 0b10000,
}

#[repr(C)]
pub struct FfiCsrProperties {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiCsr {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiSigningKey {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiCsrBundle {
    pub csr: FfiCsr,
    pub key: FfiSigningKey,
}

#[repr(C)]
pub struct FfiZatcaClient {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiCsidCompliance {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiCsidProduction {
    pub ptr: *mut c_void,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_conversions() {
        assert_eq!(EnvironmentType::from(FfiEnvironment::NonProduction), EnvironmentType::NonProduction);
        assert_eq!(EnvironmentType::from(FfiEnvironment::Simulation), EnvironmentType::Simulation);
        assert_eq!(EnvironmentType::from(FfiEnvironment::Production), EnvironmentType::Production);

        assert_eq!(InvoiceSubType::from(FfiInvoiceSubType::Standard), InvoiceSubType::Standard);
        assert_eq!(InvoiceSubType::from(FfiInvoiceSubType::Simplified), InvoiceSubType::Simplified);

        assert_eq!(VatCategory::from(FfiVatCategory::Exempt), VatCategory::Exempt);
        assert_eq!(VatCategory::from(FfiVatCategory::Standard), VatCategory::Standard);
        assert_eq!(VatCategory::from(FfiVatCategory::Zero), VatCategory::Zero);
        assert_eq!(VatCategory::from(FfiVatCategory::OutOfScope), VatCategory::OutOfScope);
    }

    #[test]
    fn ffi_string_from_owned() {
        let value = FfiString::from("hello".to_string());
        assert!(!value.ptr.is_null());
        unsafe { drop(CString::from_raw(value.ptr)) };
    }
}
