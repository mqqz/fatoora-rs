use std::ffi::CString;
use std::os::raw::c_void;

use fatoora_core::config::EnvironmentType;
use fatoora_core::invoice::{InvoiceSubType, VatCategory};

#[repr(C)]
pub struct FfiConfig {
    pub ptr: *mut c_void,
}

#[repr(i32)]
pub enum FfiEnvironment {
    NonProduction = 0,
    Simulation = 1,
    Production = 2,
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

impl From<EnvironmentType> for FfiEnvironment {
    fn from(env: EnvironmentType) -> Self {
        match env {
            EnvironmentType::NonProduction => FfiEnvironment::NonProduction,
            EnvironmentType::Simulation => FfiEnvironment::Simulation,
            EnvironmentType::Production => FfiEnvironment::Production,
        }
    }
}

#[repr(i32)]
pub enum FfiInvoiceSubType {
    Standard = 0,
    Simplified = 1,
}

impl From<FfiInvoiceSubType> for InvoiceSubType {
    fn from(value: FfiInvoiceSubType) -> Self {
        match value {
            FfiInvoiceSubType::Standard => InvoiceSubType::Standard,
            FfiInvoiceSubType::Simplified => InvoiceSubType::Simplified,
        }
    }
}

impl From<InvoiceSubType> for FfiInvoiceSubType {
    fn from(value: InvoiceSubType) -> Self {
        match value {
            InvoiceSubType::Standard => FfiInvoiceSubType::Standard,
            InvoiceSubType::Simplified => FfiInvoiceSubType::Simplified,
        }
    }
}

#[repr(i32)]
pub enum FfiInvoiceTypeKind {
    Tax = 0,
    Prepayment = 1,
    CreditNote = 2,
    DebitNote = 3,
}

#[repr(i32)]
pub enum FfiVatCategory {
    Exempt = 0,
    Standard = 1,
    Zero = 2,
    OutOfScope = 3,
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

impl From<VatCategory> for FfiVatCategory {
    fn from(value: VatCategory) -> Self {
        match value {
            VatCategory::Exempt => FfiVatCategory::Exempt,
            VatCategory::Standard => FfiVatCategory::Standard,
            VatCategory::Zero => FfiVatCategory::Zero,
            VatCategory::OutOfScope => FfiVatCategory::OutOfScope,
        }
    }
}

#[repr(C)]
pub struct FfiString {
    pub ptr: *mut std::os::raw::c_char,
}

#[repr(C)]
pub struct FfiBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct FfiBytesList {
    pub ptr: *mut FfiBytes,
    pub len: usize,
}

impl From<String> for FfiString {
    fn from(value: String) -> Self {
        let c = CString::new(value).ok();
        match c {
            Some(value) => FfiString { ptr: value.into_raw() },
            None => FfiString { ptr: std::ptr::null_mut() },
        }
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

#[repr(C)]
pub struct FfiAddress {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiParty {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiVatId {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiOtherId {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiInvoiceNote {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiOriginalInvoiceRef {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiValidationResponse {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiValidationResults {
    pub ptr: *mut c_void,
}

#[repr(C)]
pub struct FfiValidationMessage {
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
