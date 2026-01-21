//! C ABI bindings for the fatoora SDK.
use std::ffi::CStr;
use std::os::raw::c_char;

use chrono::{TimeZone, Utc};
use iso_currency::Currency;
use isocountry::CountryCode;
use k256::ecdsa::SigningKey;
use k256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use tokio::runtime::Runtime;
use x509_cert::request::CertReq;

use fatoora_core::config::Config;
use fatoora_core::invoice::{
    Address, FinalizedInvoice, InvoiceBuilder, InvoiceData, InvoiceNote, InvoiceSubType, InvoiceType,
    LineItem, LineItemFields, OtherId, OriginalInvoiceRef, Party, PartyRole, RequiredInvoiceFields,
    SellerRole, SignedInvoice, VatCategory, VatId, InvoiceFlags,
};
use fatoora_core::api::{
    CsidCredentials, ZatcaClient, Compliance, MessageList, Production, ValidationMessage,
    ValidationResponse, ValidationResults,
};
use fatoora_core::csr::{CsrProperties, ToBase64String};
use fatoora_core::invoice::sign::InvoiceSigner;
use fatoora_core::invoice::xml::ToXml;
use fatoora_core::invoice::validation::{validate_xml_invoice_from_file, validate_xml_invoice_from_str};

mod error;
#[macro_use]
mod macros;
mod types;

pub use error::{
    FfiErrorDetails, FfiErrorKind, FfiResult, fatoora_error_free, ffi_error_from_api,
    ffi_error_from_csr, ffi_error_from_invoice, ffi_error_from_parse, ffi_error_from_qr,
    ffi_error_from_signing, ffi_error_from_validation, ffi_error_from_xml,
    ffi_error_internal, ffi_error_invalid_input,
};
pub use types::{
    FfiConfig, FfiEnvironment, FfiFinalizedInvoice, FfiInvoiceBuilder, FfiInvoiceSubType,
    FfiInvoiceTypeKind, FfiSignedInvoice, FfiSigner, FfiString, FfiVatCategory, FfiInvoiceFlag,
    FfiCsrProperties, FfiCsr, FfiSigningKey, FfiCsrBundle, FfiZatcaClient, FfiCsidCompliance,
    FfiCsidProduction, FfiValidationMessage, FfiValidationResponse, FfiValidationResults,
    FfiAddress, FfiParty, FfiVatId, FfiOtherId, FfiInvoiceNote, FfiOriginalInvoiceRef,
};

fn optional_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .trim()
        .to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn optional_str_to_ffi(value: Option<&str>) -> FfiString {
    match value {
        Some(value) => FfiString::from(value.to_string()),
        None => FfiString { ptr: std::ptr::null_mut() },
    }
}

fn optional_handle<T>(value: Option<T>) -> *mut std::os::raw::c_void {
    match value {
        Some(value) => Box::into_raw(Box::new(value)) as *mut std::os::raw::c_void,
        None => std::ptr::null_mut(),
    }
}

#[derive(Clone)]
struct PartyOwned {
    name: String,
    address: Address,
    vat_id: Option<VatId>,
    other_id: Option<OtherId>,
}

impl<R: PartyRole> From<&Party<R>> for PartyOwned {
    fn from(value: &Party<R>) -> Self {
        Self {
            name: value.name().to_string(),
            address: value.address().clone(),
            vat_id: value.vat_id().cloned(),
            other_id: value.other_id().cloned(),
        }
    }
}

fn message_list_len(list: &MessageList) -> usize {
    match list {
        MessageList::One(_) => 1,
        MessageList::Many(values) => values.len(),
        MessageList::Empty => 0,
    }
}

fn message_list_get<'a>(list: &'a MessageList, index: usize) -> Option<&'a ValidationMessage> {
    match list {
        MessageList::One(message) => (index == 0).then_some(message),
        MessageList::Many(values) => values.get(index),
        MessageList::Empty => None,
    }
}

fn required_string(ptr: *const c_char, label: &str) -> Result<String, FfiErrorDetails> {
    if ptr.is_null() {
        return Err(ffi_error_invalid_input(format!("{label} is null")));
    }
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| ffi_error_invalid_input(format!("{label} is not valid utf-8")))?;
    Ok(value.trim().to_string())
}

fn optional_other_id(value: Option<String>, scheme: Option<String>) -> Option<OtherId> {
    value.map(|val| match scheme {
        Some(scheme) => OtherId::with_scheme(val, scheme),
        None => OtherId::new(val),
    })
}

fn flags_from_bits(bits: u8) -> InvoiceFlags {
    InvoiceFlags::from_bits_truncate(bits)
}

fn flags_to_bits(flags: InvoiceFlags) -> u8 {
    flags.bits()
}

fn parse_country(code: &str) -> Result<CountryCode, FfiErrorDetails> {
    CountryCode::for_alpha3(code)
        .map_err(|_| ffi_error_invalid_input(format!("Invalid country code: {code}")))
}

fn parse_currency(code: &str) -> Result<Currency, FfiErrorDetails> {
    Currency::from_code(code)
        .ok_or_else(|| ffi_error_invalid_input(format!("Invalid currency code: {code}")))
}

fn parse_issue_datetime(seconds: i64, nanos: u32) -> Result<chrono::DateTime<Utc>, FfiErrorDetails> {
    Utc.timestamp_opt(seconds, nanos)
        .single()
        .ok_or_else(|| ffi_error_invalid_input("Invalid issue timestamp"))
}

fn run_async<T>(
    fut: impl std::future::Future<Output = Result<T, fatoora_core::api::ZatcaError>>,
) -> Result<T, FfiErrorDetails> {
    let rt = Runtime::new()
        .map_err(|err| ffi_error_internal(format!("runtime init failed: {err}")))?;
    rt.block_on(fut).map_err(ffi_error_from_api)
}

fn original_invoice_ref(
    id: Option<String>,
    uuid: Option<String>,
    issue_date: Option<String>,
) -> Result<fatoora_core::invoice::OriginalInvoiceRef, FfiErrorDetails> {
    let id = id.ok_or_else(|| ffi_error_invalid_input("Missing original invoice id"))?;
    let mut reference = fatoora_core::invoice::OriginalInvoiceRef::new(id);
    if let Some(uuid) = uuid {
        reference = reference.with_uuid(uuid);
    }
    if let Some(date) = issue_date {
        let parsed = chrono::NaiveDate::parse_from_str(&date, "%Y-%m-%d")
            .map_err(|_| ffi_error_invalid_input(format!("Invalid issue date: {date}")))?;
        reference = reference.with_issue_date(parsed);
    }
    Ok(reference)
}

fn invoice_type_from_parts(
    kind: FfiInvoiceTypeKind,
    sub_type: FfiInvoiceSubType,
    original_id: Option<String>,
    original_uuid: Option<String>,
    original_issue_date: Option<String>,
    reason: Option<String>,
) -> Result<InvoiceType, FfiErrorDetails> {
    let sub_type: InvoiceSubType = sub_type.into();
    match kind {
        FfiInvoiceTypeKind::Tax => Ok(InvoiceType::Tax(sub_type)),
        FfiInvoiceTypeKind::Prepayment => Ok(InvoiceType::Prepayment(sub_type)),
        FfiInvoiceTypeKind::CreditNote => {
            let reason = reason.ok_or_else(|| ffi_error_invalid_input("Missing credit note reason"))?;
            let reference = original_invoice_ref(original_id, original_uuid, original_issue_date)?;
            Ok(InvoiceType::CreditNote(sub_type, reference, reason))
        }
        FfiInvoiceTypeKind::DebitNote => {
            let reason = reason.ok_or_else(|| ffi_error_invalid_input("Missing debit note reason"))?;
            let reference = original_invoice_ref(original_id, original_uuid, original_issue_date)?;
            Ok(InvoiceType::DebitNote(sub_type, reference, reason))
        }
    }
}

fn take_handle<T>(handle: &mut *mut std::os::raw::c_void, label: &str) -> Result<Box<T>, FfiErrorDetails> {
    if handle.is_null() || (*handle).is_null() {
        return Err(ffi_error_invalid_input(format!("{label} handle is null")));
    }
    let ptr = *handle as *mut T;
    if ptr.is_null() {
        return Err(ffi_error_invalid_input(format!("{label} handle is null")));
    }
    *handle = std::ptr::null_mut();
    Ok(unsafe { Box::from_raw(ptr) })
}

fn borrow_handle<'a, T>(handle: *mut std::os::raw::c_void, label: &str) -> Result<&'a T, FfiErrorDetails> {
    if handle.is_null() {
        return Err(ffi_error_invalid_input(format!("{label} handle is null")));
    }
    let ptr = handle as *const T;
    if ptr.is_null() {
        return Err(ffi_error_invalid_input(format!("{label} handle is null")));
    }
    Ok(unsafe { &*ptr })
}

fn borrow_handle_mut<'a, T>(
    handle: *mut std::os::raw::c_void,
    label: &str,
) -> Result<&'a mut T, FfiErrorDetails> {
    if handle.is_null() {
        return Err(ffi_error_invalid_input(format!("{label} handle is null")));
    }
    let ptr = handle as *mut T;
    if ptr.is_null() {
        return Err(ffi_error_invalid_input(format!("{label} handle is null")));
    }
    Ok(unsafe { &mut *ptr })
}

fn borrow_config<'a>(config: *mut FfiConfig) -> Result<&'a Config, FfiErrorDetails> {
    let config = match unsafe { config.as_mut() } {
        Some(handle) => handle,
        None => return Err(ffi_error_invalid_input("config handle is null")),
    };
    borrow_handle::<Config>(config.ptr, "config")
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_string_free(value: FfiString) {
    if !value.ptr.is_null() {
        unsafe { drop(std::ffi::CString::from_raw(value.ptr)) };
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_config_new(env: FfiEnvironment) -> *mut FfiConfig {
    let config = Config::new(env.into());
    let handle = FfiConfig {
        ptr: Box::into_raw(Box::new(config)) as *mut std::os::raw::c_void,
    };
    Box::into_raw(Box::new(handle))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_config_with_xsd(
    env: FfiEnvironment,
    path: *const c_char,
) -> *mut FfiConfig {
    let config = if path.is_null() {
        Config::new(env.into())
    } else {
        let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().to_string();
        Config::with_xsd_path(env.into(), path)
    };
    let handle = FfiConfig {
        ptr: Box::into_raw(Box::new(config)) as *mut std::os::raw::c_void,
    };
    Box::into_raw(Box::new(handle))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_config_free(config: *mut FfiConfig) {
    if !config.is_null() {
        let config = unsafe { Box::from_raw(config) };
        if !config.ptr.is_null() {
            unsafe { drop(Box::from_raw(config.ptr as *mut Config)) };
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_properties_parse(path: *const c_char) -> FfiResult<FfiCsrProperties> {
    let path = ffi_required_string!(path, "csr properties path");
    match CsrProperties::parse_csr_config(std::path::Path::new(&path)) {
        Ok(props) => FfiResult::ok(FfiCsrProperties {
            ptr: Box::into_raw(Box::new(props)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_csr(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_properties_free(props: *mut FfiCsrProperties) {
    ffi_handle_free!(props, CsrProperties);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_from_pem(pem: *const c_char) -> FfiResult<FfiSigningKey> {
    let pem = ffi_required_string!(pem, "signing key pem");
    match SigningKey::from_pkcs8_pem(&pem) {
        Ok(key) => FfiResult::ok(FfiSigningKey {
            ptr: Box::into_raw(Box::new(key)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(FfiErrorDetails::new(
            FfiErrorKind::Crypto,
            err.to_string(),
        )),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_from_der(der: *const u8, len: usize) -> FfiResult<FfiSigningKey> {
    if der.is_null() {
        return FfiResult::err(ffi_error_invalid_input("null der pointer"));
    }
    let data = unsafe { std::slice::from_raw_parts(der, len) };
    match SigningKey::from_pkcs8_der(data) {
        Ok(key) => FfiResult::ok(FfiSigningKey {
            ptr: Box::into_raw(Box::new(key)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(FfiErrorDetails::new(
            FfiErrorKind::Crypto,
            err.to_string(),
        )),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_to_pem(key: *mut FfiSigningKey) -> FfiResult<FfiString> {
    let key = ffi_borrow!(key, "signing key", SigningKey);
    match key.to_pkcs8_pem(LineEnding::LF) {
        Ok(pem) => FfiResult::ok(FfiString::from(pem.to_string())),
        Err(err) => FfiResult::err(FfiErrorDetails::new(
            FfiErrorKind::Crypto,
            err.to_string(),
        )),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_free(key: *mut FfiSigningKey) {
    ffi_handle_free!(key, SigningKey);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_build_with_rng(
    props: *mut FfiCsrProperties,
    env: FfiEnvironment,
) -> FfiResult<FfiCsrBundle> {
    let props = ffi_borrow!(props, "csr properties", CsrProperties);
    match props.build_with_rng(env.into()) {
        Ok((csr, key)) => FfiResult::ok(FfiCsrBundle {
            csr: FfiCsr {
                ptr: Box::into_raw(Box::new(csr)) as *mut std::os::raw::c_void,
            },
            key: FfiSigningKey {
                ptr: Box::into_raw(Box::new(key)) as *mut std::os::raw::c_void,
            },
        }),
        Err(err) => FfiResult::err(ffi_error_from_csr(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_build(
    props: *mut FfiCsrProperties,
    key: *mut FfiSigningKey,
    env: FfiEnvironment,
) -> FfiResult<FfiCsr> {
    let props = ffi_borrow!(props, "csr properties", CsrProperties);
    let key = ffi_borrow!(key, "signing key", SigningKey);
    match props.build(key, env.into()) {
        Ok(csr) => FfiResult::ok(FfiCsr {
            ptr: Box::into_raw(Box::new(csr)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_csr(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_to_base64(csr: *mut FfiCsr) -> FfiResult<FfiString> {
    let csr = ffi_borrow!(csr, "csr", CertReq);
    match csr.to_base64_string() {
        Ok(value) => FfiResult::ok(FfiString::from(value)),
        Err(err) => FfiResult::err(ffi_error_from_csr(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_to_pem_base64(csr: *mut FfiCsr) -> FfiResult<FfiString> {
    let csr = ffi_borrow!(csr, "csr", CertReq);
    match csr.to_pem_base64_string() {
        Ok(value) => FfiResult::ok(FfiString::from(value)),
        Err(err) => FfiResult::err(ffi_error_from_csr(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_free(csr: *mut FfiCsr) {
    ffi_handle_free!(csr, CertReq);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_client_new(config: *mut FfiConfig) -> FfiResult<FfiZatcaClient> {
    let config = match borrow_config(config) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match ZatcaClient::new(config.clone()) {
        Ok(client) => FfiResult::ok(FfiZatcaClient {
            ptr: Box::into_raw(Box::new(client)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_api(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_client_free(client: *mut FfiZatcaClient) {
    ffi_handle_free!(client, ZatcaClient);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_compliance_new(
    env: FfiEnvironment,
    has_request_id: bool,
    request_id: u64,
    token: *const c_char,
    secret: *const c_char,
) -> FfiResult<FfiCsidCompliance> {
    let token = ffi_required_string!(token, "csid token");
    let secret = ffi_required_string!(secret, "csid secret");
    let creds = CsidCredentials::<Compliance>::new(
        env.into(),
        if has_request_id { Some(request_id) } else { None },
        token,
        secret,
    );
    FfiResult::ok(FfiCsidCompliance {
        ptr: Box::into_raw(Box::new(creds)) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_production_new(
    env: FfiEnvironment,
    has_request_id: bool,
    request_id: u64,
    token: *const c_char,
    secret: *const c_char,
) -> FfiResult<FfiCsidProduction> {
    let token = ffi_required_string!(token, "csid token");
    let secret = ffi_required_string!(secret, "csid secret");
    let creds = CsidCredentials::<Production>::new(
        env.into(),
        if has_request_id { Some(request_id) } else { None },
        token,
        secret,
    );
    FfiResult::ok(FfiCsidProduction {
        ptr: Box::into_raw(Box::new(creds)) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_compliance_request_id(creds: *mut FfiCsidCompliance) -> FfiResult<u64> {
    let creds = ffi_borrow!(creds, "csid", CsidCredentials<Compliance>);
    match creds.request_id() {
        Some(value) => FfiResult::ok(value),
        None => FfiResult::err(ffi_error_invalid_input("missing request id")),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_production_request_id(creds: *mut FfiCsidProduction) -> FfiResult<u64> {
    let creds = ffi_borrow!(creds, "csid", CsidCredentials<Production>);
    match creds.request_id() {
        Some(value) => FfiResult::ok(value),
        None => FfiResult::err(ffi_error_invalid_input("missing request id")),
    }
}

ffi_handle_getter!(
    fatoora_csid_compliance_token,
    FfiCsidCompliance,
    CsidCredentials<Compliance>,
    "csid",
    FfiString,
    |creds| FfiString::from(creds.binary_security_token().to_string())
);

ffi_handle_getter!(
    fatoora_csid_compliance_secret,
    FfiCsidCompliance,
    CsidCredentials<Compliance>,
    "csid",
    FfiString,
    |creds| FfiString::from(creds.secret().to_string())
);

ffi_handle_getter!(
    fatoora_csid_production_token,
    FfiCsidProduction,
    CsidCredentials<Production>,
    "csid",
    FfiString,
    |creds| FfiString::from(creds.binary_security_token().to_string())
);

ffi_handle_getter!(
    fatoora_csid_production_secret,
    FfiCsidProduction,
    CsidCredentials<Production>,
    "csid",
    FfiString,
    |creds| FfiString::from(creds.secret().to_string())
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_compliance_free(creds: *mut FfiCsidCompliance) {
    ffi_handle_free!(creds, CsidCredentials<Compliance>);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_production_free(creds: *mut FfiCsidProduction) {
    ffi_handle_free!(creds, CsidCredentials<Production>);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_post_csr_for_ccsid(
    client: *mut FfiZatcaClient,
    csr: *mut FfiCsr,
    otp: *const c_char,
) -> FfiResult<FfiCsidCompliance> {
    let client = ffi_borrow!(client, "client", ZatcaClient);
    let csr = ffi_borrow!(csr, "csr", CertReq);
    let otp = ffi_required_string!(otp, "otp");
    match run_async(client.post_csr_for_ccsid(csr, &otp)) {
        Ok(creds) => FfiResult::ok(FfiCsidCompliance {
            ptr: Box::into_raw(Box::new(creds)) as *mut std::os::raw::c_void,
        }),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_post_ccsid_for_pcsid(
    client: *mut FfiZatcaClient,
    ccsid: *mut FfiCsidCompliance,
) -> FfiResult<FfiCsidProduction> {
    let client = ffi_borrow!(client, "client", ZatcaClient);
    let ccsid = ffi_borrow!(ccsid, "csid", CsidCredentials<Compliance>);
    match run_async(client.post_ccsid_for_pcsid(ccsid)) {
        Ok(creds) => FfiResult::ok(FfiCsidProduction {
            ptr: Box::into_raw(Box::new(creds)) as *mut std::os::raw::c_void,
        }),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_renew_csid(
    client: *mut FfiZatcaClient,
    pcsid: *mut FfiCsidProduction,
    csr: *mut FfiCsr,
    otp: *const c_char,
    accept_language: *const c_char,
) -> FfiResult<FfiCsidProduction> {
    let client = ffi_borrow!(client, "client", ZatcaClient);
    let pcsid = ffi_borrow!(pcsid, "csid", CsidCredentials<Production>);
    let csr = ffi_borrow!(csr, "csr", CertReq);
    let otp = ffi_required_string!(otp, "otp");
    let language = optional_string(accept_language);
    match run_async(client.renew_csid(pcsid, csr, &otp, language.as_deref())) {
        Ok(creds) => FfiResult::ok(FfiCsidProduction {
            ptr: Box::into_raw(Box::new(creds)) as *mut std::os::raw::c_void,
        }),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_check_compliance(
    client: *mut FfiZatcaClient,
    invoice: *mut FfiSignedInvoice,
    ccsid: *mut FfiCsidCompliance,
) -> FfiResult<FfiValidationResponse> {
    let client = ffi_borrow!(client, "client", ZatcaClient);
    let invoice = ffi_borrow!(invoice, "invoice", SignedInvoice);
    let ccsid = ffi_borrow!(ccsid, "csid", CsidCredentials<Compliance>);
    match run_async(client.check_invoice_compliance(invoice, ccsid)) {
        Ok(response) => FfiResult::ok(FfiValidationResponse {
            ptr: Box::into_raw(Box::new(response)) as *mut std::os::raw::c_void,
        }),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_report_simplified_invoice(
    client: *mut FfiZatcaClient,
    invoice: *mut FfiSignedInvoice,
    pcsid: *mut FfiCsidProduction,
    clearance_status: bool,
    accept_language: *const c_char,
) -> FfiResult<FfiValidationResponse> {
    let client = ffi_borrow!(client, "client", ZatcaClient);
    let invoice = ffi_borrow!(invoice, "invoice", SignedInvoice);
    let pcsid = ffi_borrow!(pcsid, "csid", CsidCredentials<Production>);
    let language = optional_string(accept_language);
    match run_async(client.report_simplified_invoice(
        invoice,
        pcsid,
        clearance_status,
        language.as_deref(),
    )) {
        Ok(response) => FfiResult::ok(FfiValidationResponse {
            ptr: Box::into_raw(Box::new(response)) as *mut std::os::raw::c_void,
        }),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_clear_standard_invoice(
    client: *mut FfiZatcaClient,
    invoice: *mut FfiSignedInvoice,
    pcsid: *mut FfiCsidProduction,
    clearance_status: bool,
    accept_language: *const c_char,
) -> FfiResult<FfiValidationResponse> {
    let client = ffi_borrow!(client, "client", ZatcaClient);
    let invoice = ffi_borrow!(invoice, "invoice", SignedInvoice);
    let pcsid = ffi_borrow!(pcsid, "csid", CsidCredentials<Production>);
    let language = optional_string(accept_language);
    match run_async(client.clear_standard_invoice(
        invoice,
        pcsid,
        clearance_status,
        language.as_deref(),
    )) {
        Ok(response) => FfiResult::ok(FfiValidationResponse {
            ptr: Box::into_raw(Box::new(response)) as *mut std::os::raw::c_void,
        }),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validation_response_free(response: *mut FfiValidationResponse) {
    ffi_handle_free!(response, ValidationResponse);
}

ffi_handle_getter!(
    fatoora_validation_response_reporting_status,
    FfiValidationResponse,
    ValidationResponse,
    "response",
    FfiString,
    |response| optional_str_to_ffi(response.reporting_status())
);

ffi_handle_getter!(
    fatoora_validation_response_clearance_status,
    FfiValidationResponse,
    ValidationResponse,
    "response",
    FfiString,
    |response| optional_str_to_ffi(response.clearance_status())
);

ffi_handle_getter!(
    fatoora_validation_response_qr_seller_status,
    FfiValidationResponse,
    ValidationResponse,
    "response",
    FfiString,
    |response| optional_str_to_ffi(response.qr_seller_status())
);

ffi_handle_getter!(
    fatoora_validation_response_qr_buyer_status,
    FfiValidationResponse,
    ValidationResponse,
    "response",
    FfiString,
    |response| optional_str_to_ffi(response.qr_buyer_status())
);

ffi_handle_getter!(
    fatoora_validation_response_results,
    FfiValidationResponse,
    ValidationResponse,
    "response",
    FfiValidationResults,
    |response| {
        let results = response.validation_results().clone();
        FfiValidationResults {
            ptr: Box::into_raw(Box::new(results)) as *mut std::os::raw::c_void,
        }
    }
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validation_results_free(results: *mut FfiValidationResults) {
    ffi_handle_free!(results, ValidationResults);
}

ffi_handle_getter!(
    fatoora_validation_results_status,
    FfiValidationResults,
    ValidationResults,
    "results",
    FfiString,
    |results| optional_str_to_ffi(results.status())
);

ffi_handle_getter!(
    fatoora_validation_results_info_len,
    FfiValidationResults,
    ValidationResults,
    "results",
    u64,
    |results| message_list_len(results.info_messages()) as u64
);

ffi_handle_getter!(
    fatoora_validation_results_warning_len,
    FfiValidationResults,
    ValidationResults,
    "results",
    u64,
    |results| results.warning_messages().len() as u64
);

ffi_handle_getter!(
    fatoora_validation_results_error_len,
    FfiValidationResults,
    ValidationResults,
    "results",
    u64,
    |results| results.error_messages().len() as u64
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validation_results_info_message(
    results: *mut FfiValidationResults,
    index: u64,
) -> FfiResult<FfiValidationMessage> {
    let results = ffi_borrow!(results, "results", ValidationResults);
    let message = match message_list_get(results.info_messages(), index as usize) {
        Some(value) => value,
        None => return FfiResult::err(ffi_error_invalid_input("info message index out of range")),
    };
    FfiResult::ok(FfiValidationMessage {
        ptr: Box::into_raw(Box::new(message.clone())) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validation_results_warning_message(
    results: *mut FfiValidationResults,
    index: u64,
) -> FfiResult<FfiValidationMessage> {
    let results = ffi_borrow!(results, "results", ValidationResults);
    let message = match results.warning_messages().get(index as usize) {
        Some(value) => value,
        None => return FfiResult::err(ffi_error_invalid_input("warning message index out of range")),
    };
    FfiResult::ok(FfiValidationMessage {
        ptr: Box::into_raw(Box::new(message.clone())) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validation_results_error_message(
    results: *mut FfiValidationResults,
    index: u64,
) -> FfiResult<FfiValidationMessage> {
    let results = ffi_borrow!(results, "results", ValidationResults);
    let message = match results.error_messages().get(index as usize) {
        Some(value) => value,
        None => return FfiResult::err(ffi_error_invalid_input("error message index out of range")),
    };
    FfiResult::ok(FfiValidationMessage {
        ptr: Box::into_raw(Box::new(message.clone())) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validation_message_free(message: *mut FfiValidationMessage) {
    ffi_handle_free!(message, ValidationMessage);
}

ffi_handle_getter!(
    fatoora_validation_message_type,
    FfiValidationMessage,
    ValidationMessage,
    "message",
    FfiString,
    |message| optional_str_to_ffi(message.message_type())
);

ffi_handle_getter!(
    fatoora_validation_message_code,
    FfiValidationMessage,
    ValidationMessage,
    "message",
    FfiString,
    |message| optional_str_to_ffi(message.code())
);

ffi_handle_getter!(
    fatoora_validation_message_category,
    FfiValidationMessage,
    ValidationMessage,
    "message",
    FfiString,
    |message| optional_str_to_ffi(message.category())
);

ffi_handle_getter!(
    fatoora_validation_message_text,
    FfiValidationMessage,
    ValidationMessage,
    "message",
    FfiString,
    |message| optional_str_to_ffi(message.message())
);

ffi_handle_getter!(
    fatoora_validation_message_status,
    FfiValidationMessage,
    ValidationMessage,
    "message",
    FfiString,
    |message| optional_str_to_ffi(message.status())
);
#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validate_xml_str(
    config: *mut FfiConfig,
    xml: *const c_char,
) -> FfiResult<bool> {
    let config = match borrow_config(config) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let xml = ffi_required_string!(xml, "xml");
    match validate_xml_invoice_from_str(&xml, config) {
        Ok(()) => FfiResult::ok(true),
        Err(err) => FfiResult::err(ffi_error_from_validation(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_validate_xml_file(
    config: *mut FfiConfig,
    path: *const c_char,
) -> FfiResult<bool> {
    let config = match borrow_config(config) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let path = ffi_required_string!(path, "xml path");
    match validate_xml_invoice_from_file(std::path::Path::new(&path), config) {
        Ok(()) => FfiResult::ok(true),
        Err(err) => FfiResult::err(ffi_error_from_validation(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_new(
    invoice_type_kind: FfiInvoiceTypeKind,
    invoice_sub_type: FfiInvoiceSubType,
    id: *const c_char,
    uuid: *const c_char,
    issue_timestamp: i64,
    issue_nanos: u32,
    currency_code: *const c_char,
    previous_invoice_hash: *const c_char,
    invoice_counter: u64,
    payment_means_code: *const c_char,
    vat_category: FfiVatCategory,
    seller_name: *const c_char,
    seller_country_code: *const c_char,
    seller_city: *const c_char,
    seller_street: *const c_char,
    seller_additional_street: *const c_char,
    seller_building_number: *const c_char,
    seller_additional_number: *const c_char,
    seller_postal_code: *const c_char,
    seller_subdivision: *const c_char,
    seller_district: *const c_char,
    seller_vat_id: *const c_char,
    seller_other_id: *const c_char,
    seller_other_id_scheme: *const c_char,
    original_invoice_id: *const c_char,
    original_invoice_uuid: *const c_char,
    original_invoice_issue_date: *const c_char,
    original_invoice_reason: *const c_char,
) -> FfiResult<FfiInvoiceBuilder> {
    let currency_code = ffi_required_string!(currency_code, "currency code");
    let currency = match parse_currency(&currency_code) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let seller_country_code = ffi_required_string!(seller_country_code, "seller country code");
    let country_code = match parse_country(&seller_country_code) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let issue_datetime = match parse_issue_datetime(issue_timestamp, issue_nanos) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let invoice_type = match invoice_type_from_parts(
        invoice_type_kind,
        invoice_sub_type,
        optional_string(original_invoice_id),
        optional_string(original_invoice_uuid),
        optional_string(original_invoice_issue_date),
        optional_string(original_invoice_reason),
    ) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let seller_city = ffi_required_string!(seller_city, "seller city");
    let seller_street = ffi_required_string!(seller_street, "seller street");
    let seller_building_number =
        ffi_required_string!(seller_building_number, "seller building number");
    let seller_postal_code = ffi_required_string!(seller_postal_code, "seller postal code");
    let seller_address = Address {
        country_code,
        city: seller_city,
        street: seller_street,
        additional_street: optional_string(seller_additional_street),
        building_number: seller_building_number,
        additional_number: optional_string(seller_additional_number),
        postal_code: seller_postal_code,
        subdivision: optional_string(seller_subdivision),
        district: optional_string(seller_district),
    };

    let seller_other = optional_other_id(
        optional_string(seller_other_id),
        optional_string(seller_other_id_scheme),
    );

    let seller_name = ffi_required_string!(seller_name, "seller name");
    let seller_vat_id = ffi_required_string!(seller_vat_id, "seller vat id");
    let seller = match Party::<SellerRole>::new(seller_name, seller_address, seller_vat_id, seller_other) {
        Ok(value) => value,
        Err(err) => return FfiResult::err(ffi_error_from_invoice(err)),
    };

    let id = ffi_required_string!(id, "invoice id");
    let uuid = ffi_required_string!(uuid, "invoice uuid");
    let previous_invoice_hash =
        ffi_required_string!(previous_invoice_hash, "previous invoice hash");
    let payment_means_code = ffi_required_string!(payment_means_code, "payment means code");
    let required = RequiredInvoiceFields {
        invoice_type,
        id,
        uuid,
        issue_datetime,
        currency,
        previous_invoice_hash,
        invoice_counter,
        seller,
        line_items: Vec::new(),
        payment_means_code,
        vat_category: VatCategory::from(vat_category),
    };

    let builder = InvoiceBuilder::new(required);
    FfiResult::ok(FfiInvoiceBuilder {
        ptr: Box::into_raw(Box::new(builder)) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_set_flags(
    builder: *mut FfiInvoiceBuilder,
    flags: u8,
) -> FfiResult<bool> {
    let builder = ffi_borrow_mut!(builder, "builder", InvoiceBuilder);
    builder.flags(flags_from_bits(flags));
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_enable_flags(
    builder: *mut FfiInvoiceBuilder,
    flags: u8,
) -> FfiResult<bool> {
    let builder = ffi_borrow_mut!(builder, "builder", InvoiceBuilder);
    builder.enable_flags(flags_from_bits(flags));
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_disable_flags(
    builder: *mut FfiInvoiceBuilder,
    flags: u8,
) -> FfiResult<bool> {
    let builder = ffi_borrow_mut!(builder, "builder", InvoiceBuilder);
    builder.disable_flags(flags_from_bits(flags));
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_add_line_item(
    builder: *mut FfiInvoiceBuilder,
    description: *const c_char,
    quantity: f64,
    unit_code: *const c_char,
    unit_price: f64,
    vat_rate: f64,
    vat_category: FfiVatCategory,
) -> FfiResult<bool> {
    let builder = ffi_borrow_mut!(builder, "builder", InvoiceBuilder);

    let description = ffi_required_string!(description, "line item description");
    let unit_code = ffi_required_string!(unit_code, "line item unit code");
    let item = LineItem::new(LineItemFields {
        description,
        quantity,
        unit_code,
        unit_price,
        vat_rate,
        vat_category: vat_category.into(),
    });
    builder.add_line_item(item);
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_set_buyer(
    builder: *mut FfiInvoiceBuilder,
    name: *const c_char,
    country_code: *const c_char,
    city: *const c_char,
    street: *const c_char,
    additional_street: *const c_char,
    building_number: *const c_char,
    additional_number: *const c_char,
    postal_code: *const c_char,
    subdivision: *const c_char,
    district: *const c_char,
    vat_id: *const c_char,
    other_id_value: *const c_char,
    other_id_scheme: *const c_char,
) -> FfiResult<bool> {
    let builder = ffi_borrow_mut!(builder, "builder", InvoiceBuilder);

    let country_code = ffi_required_string!(country_code, "buyer country code");
    let buyer_country = match parse_country(&country_code) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let city = ffi_required_string!(city, "buyer city");
    let street = ffi_required_string!(street, "buyer street");
    let building_number = ffi_required_string!(building_number, "buyer building number");
    let postal_code = ffi_required_string!(postal_code, "buyer postal code");
    let address = Address {
        country_code: buyer_country,
        city,
        street,
        additional_street: optional_string(additional_street),
        building_number,
        additional_number: optional_string(additional_number),
        postal_code,
        subdivision: optional_string(subdivision),
        district: optional_string(district),
    };

    let other = optional_other_id(
        optional_string(other_id_value),
        optional_string(other_id_scheme),
    );
    let name = ffi_required_string!(name, "buyer name");
    let buyer = match Party::<fatoora_core::invoice::BuyerRole>::new(name, address, optional_string(vat_id), other) {
        Ok(value) => value,
        Err(err) => return FfiResult::err(ffi_error_from_invoice(err)),
    };
    builder.set_buyer(buyer);
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_set_note(
    builder: *mut FfiInvoiceBuilder,
    language: *const c_char,
    text: *const c_char,
) -> FfiResult<bool> {
    let builder = ffi_borrow_mut!(builder, "builder", InvoiceBuilder);
    let language = ffi_required_string!(language, "note language");
    let text = ffi_required_string!(text, "note text");
    let note = InvoiceNote::new(&language, &text);
    builder.set_note(note);
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_set_allowance(
    builder: *mut FfiInvoiceBuilder,
    reason: *const c_char,
    amount: f64,
) -> FfiResult<bool> {
    let builder = ffi_borrow_mut!(builder, "builder", InvoiceBuilder);
    let reason = ffi_required_string!(reason, "allowance reason");
    builder.set_allowance(&reason, amount);
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_free(builder: *mut FfiInvoiceBuilder) {
    ffi_handle_free!(builder, InvoiceBuilder);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_build(builder: *mut FfiInvoiceBuilder) -> FfiResult<FfiFinalizedInvoice> {
    let builder = ffi_take_handle!(builder, "builder", InvoiceBuilder);

    match builder.build() {
        Ok(invoice) => FfiResult::ok(FfiFinalizedInvoice {
            ptr: Box::into_raw(Box::new(invoice)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_invoice(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_parse_finalized_invoice_xml(
    xml: *const c_char,
) -> FfiResult<FfiFinalizedInvoice> {
    let xml = ffi_required_string!(xml, "xml");
    match fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml(&xml) {
        Ok(invoice) => FfiResult::ok(FfiFinalizedInvoice {
            ptr: Box::into_raw(Box::new(invoice)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_parse(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_parse_signed_invoice_xml(
    xml: *const c_char,
) -> FfiResult<FfiSignedInvoice> {
    let xml = ffi_required_string!(xml, "xml");
    match fatoora_core::invoice::xml::parse::parse_signed_invoice_xml(&xml) {
        Ok(invoice) => FfiResult::ok(FfiSignedInvoice {
            ptr: Box::into_raw(Box::new(invoice)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_parse(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_count(invoice: *mut FfiFinalizedInvoice) -> FfiResult<u64> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    FfiResult::ok(invoice.data().line_items().len() as u64)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_count(signed: *mut FfiSignedInvoice) -> FfiResult<u64> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    FfiResult::ok(signed.data().line_items().len() as u64)
}

fn line_item_from_invoice(invoice: &InvoiceData, index: u64) -> Result<&LineItem, FfiErrorDetails> {
    let idx = usize::try_from(index)
        .map_err(|_| ffi_error_invalid_input("index out of range"))?;
    invoice
        .line_items()
        .get(idx)
        .ok_or_else(|| ffi_error_invalid_input("index out of range"))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_description(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<FfiString> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(FfiString::from(item.description().to_string())),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_unit_code(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<FfiString> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(FfiString::from(item.unit_code().to_string())),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_quantity(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(item.quantity()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_unit_price(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(item.unit_price()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_total_amount(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(item.total_amount()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_vat_rate(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(item.vat_rate()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_vat_amount(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(item.vat_amount()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_vat_category(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<u8> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match line_item_from_invoice(invoice.data(), index) {
        Ok(item) => FfiResult::ok(item.vat_category() as u8),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_description(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(FfiString::from(item.description().to_string())),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_unit_code(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(FfiString::from(item.unit_code().to_string())),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_quantity(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(item.quantity()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_unit_price(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(item.unit_price()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_total_amount(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(item.total_amount()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_vat_rate(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(item.vat_rate()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_vat_amount(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<f64> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(item.vat_amount()),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_vat_category(
    signed: *mut FfiSignedInvoice,
    index: u64,
) -> FfiResult<u8> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(item.vat_category() as u8),
        Err(message) => FfiResult::err(message),
    }
}

ffi_handle_getter!(
    fatoora_invoice_totals_tax_inclusive,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    f64,
    |invoice| invoice.totals().tax_inclusive_amount()
);

ffi_handle_getter!(
    fatoora_invoice_totals_tax_amount,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    f64,
    |invoice| invoice.totals().tax_amount()
);

ffi_handle_getter!(
    fatoora_invoice_totals_line_extension,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    f64,
    |invoice| invoice.totals().line_extension()
);

ffi_handle_getter!(
    fatoora_invoice_totals_allowance_total,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    f64,
    |invoice| invoice.totals().allowance_total()
);

ffi_handle_getter!(
    fatoora_invoice_totals_charge_total,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    f64,
    |invoice| invoice.totals().charge_total()
);

ffi_handle_getter!(
    fatoora_invoice_totals_taxable_amount,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    f64,
    |invoice| invoice.totals().taxable_amount()
);

ffi_handle_getter!(
    fatoora_signed_invoice_totals_tax_inclusive,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    f64,
    |signed| signed.totals().tax_inclusive_amount()
);

ffi_handle_getter!(
    fatoora_signed_invoice_totals_tax_amount,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    f64,
    |signed| signed.totals().tax_amount()
);

ffi_handle_getter!(
    fatoora_signed_invoice_totals_line_extension,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    f64,
    |signed| signed.totals().line_extension()
);

ffi_handle_getter!(
    fatoora_signed_invoice_totals_allowance_total,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    f64,
    |signed| signed.totals().allowance_total()
);

ffi_handle_getter!(
    fatoora_signed_invoice_totals_charge_total,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    f64,
    |signed| signed.totals().charge_total()
);

ffi_handle_getter!(
    fatoora_signed_invoice_totals_taxable_amount,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    f64,
    |signed| signed.totals().taxable_amount()
);

ffi_handle_getter!(
    fatoora_invoice_flags,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    u8,
    |invoice| flags_to_bits(invoice.data().flags())
);

ffi_handle_getter!(
    fatoora_signed_invoice_flags,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    u8,
    |signed| flags_to_bits(signed.data().flags())
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_to_xml(invoice: *mut FfiFinalizedInvoice) -> FfiResult<FfiString> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match invoice.to_xml() {
        Ok(xml) => FfiResult::ok(FfiString::from(xml)),
        Err(err) => FfiResult::err(ffi_error_from_xml(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_hash_base64(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<FfiString> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    match invoice.hash_base64() {
        Ok(hash) => FfiResult::ok(FfiString::from(hash)),
        Err(err) => FfiResult::err(ffi_error_from_signing(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_free(invoice: *mut FfiFinalizedInvoice) {
    ffi_handle_free!(invoice, FinalizedInvoice);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signer_from_pem(
    cert_pem: *const c_char,
    key_pem: *const c_char,
) -> FfiResult<FfiSigner> {
    let cert_pem = ffi_required_string!(cert_pem, "cert pem");
    let key_pem = ffi_required_string!(key_pem, "key pem");
    match InvoiceSigner::from_pem(&cert_pem, &key_pem) {
        Ok(signer) => FfiResult::ok(FfiSigner {
            ptr: Box::into_raw(Box::new(signer)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_signing(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signer_from_der(
    cert_der: *const u8,
    cert_len: usize,
    key_der: *const u8,
    key_len: usize,
) -> FfiResult<FfiSigner> {
    if cert_der.is_null() || key_der.is_null() {
        return FfiResult::err(ffi_error_invalid_input("null der pointers"));
    }
    let cert = unsafe { std::slice::from_raw_parts(cert_der, cert_len) };
    let key = unsafe { std::slice::from_raw_parts(key_der, key_len) };
    match InvoiceSigner::from_der(cert, key) {
        Ok(signer) => FfiResult::ok(FfiSigner {
            ptr: Box::into_raw(Box::new(signer)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_signing(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signer_free(signer: *mut FfiSigner) {
    ffi_handle_free!(signer, InvoiceSigner);
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_sign(
    invoice: *mut FfiFinalizedInvoice,
    signer: *mut FfiSigner,
) -> FfiResult<FfiSignedInvoice> {
    let invoice = ffi_take_handle!(invoice, "invoice", FinalizedInvoice);

    let signer = ffi_borrow!(signer, "signer", InvoiceSigner);

    match invoice.sign(signer) {
        Ok(signed) => FfiResult::ok(FfiSignedInvoice {
            ptr: Box::into_raw(Box::new(signed)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(ffi_error_from_signing(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_xml(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    FfiResult::ok(FfiString::from(signed.xml().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_qr(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    FfiResult::ok(FfiString::from(signed.qr_code().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_uuid(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    FfiResult::ok(FfiString::from(signed.uuid().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_hash(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    FfiResult::ok(FfiString::from(signed.invoice_hash().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_hash_base64(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    match signed.hash_base64() {
        Ok(hash) => FfiResult::ok(FfiString::from(hash)),
        Err(err) => FfiResult::err(ffi_error_from_signing(err)),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_seller(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<FfiParty> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    let seller = PartyOwned::from(invoice.data().seller());
    FfiResult::ok(FfiParty {
        ptr: Box::into_raw(Box::new(seller)) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_buyer(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<FfiParty> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    let buyer = invoice.data().buyer().map(PartyOwned::from);
    FfiResult::ok(FfiParty {
        ptr: optional_handle(buyer),
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_note(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<FfiInvoiceNote> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    let note = invoice.data().note().cloned();
    FfiResult::ok(FfiInvoiceNote {
        ptr: optional_handle(note),
    })
}

fn invoice_type_parts(invoice_type: &InvoiceType) -> (FfiInvoiceTypeKind, FfiInvoiceSubType, Option<OriginalInvoiceRef>, Option<String>) {
    match invoice_type {
        InvoiceType::Tax(sub) => (FfiInvoiceTypeKind::Tax, (*sub).into(), None, None),
        InvoiceType::Prepayment(sub) => (FfiInvoiceTypeKind::Prepayment, (*sub).into(), None, None),
        InvoiceType::CreditNote(sub, reference, reason) => (
            FfiInvoiceTypeKind::CreditNote,
            (*sub).into(),
            Some(reference.clone()),
            Some(reason.clone()),
        ),
        InvoiceType::DebitNote(sub, reference, reason) => (
            FfiInvoiceTypeKind::DebitNote,
            (*sub).into(),
            Some(reference.clone()),
            Some(reason.clone()),
        ),
    }
}

ffi_handle_getter!(
    fatoora_invoice_type_kind,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    u8,
    |invoice| {
        let (kind, _, _, _) = invoice_type_parts(invoice.data().invoice_type());
        kind as u8
    }
);

ffi_handle_getter!(
    fatoora_invoice_sub_type,
    FfiFinalizedInvoice,
    FinalizedInvoice,
    "invoice",
    u8,
    |invoice| {
        let (_, sub_type, _, _) = invoice_type_parts(invoice.data().invoice_type());
        sub_type as u8
    }
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_original_ref(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<FfiOriginalInvoiceRef> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    let (_, _, reference, _) = invoice_type_parts(invoice.data().invoice_type());
    FfiResult::ok(FfiOriginalInvoiceRef {
        ptr: optional_handle(reference),
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_original_reason(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<FfiString> {
    let invoice = ffi_borrow!(invoice, "invoice", FinalizedInvoice);
    let (_, _, _, reason) = invoice_type_parts(invoice.data().invoice_type());
    FfiResult::ok(optional_str_to_ffi(reason.as_deref()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_seller(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<FfiParty> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    let seller = PartyOwned::from(signed.data().seller());
    FfiResult::ok(FfiParty {
        ptr: Box::into_raw(Box::new(seller)) as *mut std::os::raw::c_void,
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_buyer(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<FfiParty> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    let buyer = signed.data().buyer().map(PartyOwned::from);
    FfiResult::ok(FfiParty {
        ptr: optional_handle(buyer),
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_note(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<FfiInvoiceNote> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    let note = signed.data().note().cloned();
    FfiResult::ok(FfiInvoiceNote {
        ptr: optional_handle(note),
    })
}

ffi_handle_getter!(
    fatoora_signed_invoice_type_kind,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    u8,
    |signed| {
        let (kind, _, _, _) = invoice_type_parts(signed.data().invoice_type());
        kind as u8
    }
);

ffi_handle_getter!(
    fatoora_signed_invoice_sub_type,
    FfiSignedInvoice,
    SignedInvoice,
    "signed",
    u8,
    |signed| {
        let (_, sub_type, _, _) = invoice_type_parts(signed.data().invoice_type());
        sub_type as u8
    }
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_original_ref(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<FfiOriginalInvoiceRef> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    let (_, _, reference, _) = invoice_type_parts(signed.data().invoice_type());
    FfiResult::ok(FfiOriginalInvoiceRef {
        ptr: optional_handle(reference),
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_original_reason(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    let (_, _, _, reason) = invoice_type_parts(signed.data().invoice_type());
    FfiResult::ok(optional_str_to_ffi(reason.as_deref()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_party_free(party: *mut FfiParty) {
    ffi_handle_free!(party, PartyOwned);
}

ffi_handle_getter!(
    fatoora_party_name,
    FfiParty,
    PartyOwned,
    "party",
    FfiString,
    |party| FfiString::from(party.name.to_string())
);

ffi_handle_getter!(
    fatoora_party_address,
    FfiParty,
    PartyOwned,
    "party",
    FfiAddress,
    |party| {
        let address = party.address.clone();
        FfiAddress {
            ptr: Box::into_raw(Box::new(address)) as *mut std::os::raw::c_void,
        }
    }
);

ffi_handle_getter!(
    fatoora_party_vat_id,
    FfiParty,
    PartyOwned,
    "party",
    FfiVatId,
    |party| {
        let vat = party.vat_id.clone();
        FfiVatId {
            ptr: optional_handle(vat),
        }
    }
);

ffi_handle_getter!(
    fatoora_party_other_id,
    FfiParty,
    PartyOwned,
    "party",
    FfiOtherId,
    |party| {
        let other = party.other_id.clone();
        FfiOtherId {
            ptr: optional_handle(other),
        }
    }
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_address_free(address: *mut FfiAddress) {
    ffi_handle_free!(address, Address);
}

ffi_handle_getter!(
    fatoora_address_country_code,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| FfiString::from(address.country_code().to_string())
);

ffi_handle_getter!(
    fatoora_address_city,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| FfiString::from(address.city().to_string())
);

ffi_handle_getter!(
    fatoora_address_street,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| FfiString::from(address.street().to_string())
);

ffi_handle_getter!(
    fatoora_address_additional_street,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| optional_str_to_ffi(address.additional_street())
);

ffi_handle_getter!(
    fatoora_address_building_number,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| FfiString::from(address.building_number().to_string())
);

ffi_handle_getter!(
    fatoora_address_additional_number,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| optional_str_to_ffi(address.additional_number())
);

ffi_handle_getter!(
    fatoora_address_postal_code,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| FfiString::from(address.postal_code().to_string())
);

ffi_handle_getter!(
    fatoora_address_subdivision,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| optional_str_to_ffi(address.subdivision())
);

ffi_handle_getter!(
    fatoora_address_district,
    FfiAddress,
    Address,
    "address",
    FfiString,
    |address| optional_str_to_ffi(address.district())
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_vat_id_free(vat: *mut FfiVatId) {
    ffi_handle_free!(vat, VatId);
}

ffi_handle_getter!(
    fatoora_vat_id_value,
    FfiVatId,
    VatId,
    "vat id",
    FfiString,
    |vat| FfiString::from(vat.as_str().to_string())
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_other_id_free(other: *mut FfiOtherId) {
    ffi_handle_free!(other, OtherId);
}

ffi_handle_getter!(
    fatoora_other_id_value,
    FfiOtherId,
    OtherId,
    "other id",
    FfiString,
    |other| FfiString::from(other.as_str().to_string())
);

ffi_handle_getter!(
    fatoora_other_id_scheme,
    FfiOtherId,
    OtherId,
    "other id",
    FfiString,
    |other| optional_str_to_ffi(other.scheme_id())
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_note_free(note: *mut FfiInvoiceNote) {
    ffi_handle_free!(note, InvoiceNote);
}

ffi_handle_getter!(
    fatoora_invoice_note_language,
    FfiInvoiceNote,
    InvoiceNote,
    "invoice note",
    FfiString,
    |note| FfiString::from(note.language().to_string())
);

ffi_handle_getter!(
    fatoora_invoice_note_text,
    FfiInvoiceNote,
    InvoiceNote,
    "invoice note",
    FfiString,
    |note| FfiString::from(note.text().to_string())
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_original_invoice_ref_free(reference: *mut FfiOriginalInvoiceRef) {
    ffi_handle_free!(reference, OriginalInvoiceRef);
}

ffi_handle_getter!(
    fatoora_original_invoice_ref_id,
    FfiOriginalInvoiceRef,
    OriginalInvoiceRef,
    "original ref",
    FfiString,
    |reference| FfiString::from(reference.id().to_string())
);

ffi_handle_getter!(
    fatoora_original_invoice_ref_uuid,
    FfiOriginalInvoiceRef,
    OriginalInvoiceRef,
    "original ref",
    FfiString,
    |reference| optional_str_to_ffi(reference.uuid())
);

ffi_handle_getter!(
    fatoora_original_invoice_ref_issue_date,
    FfiOriginalInvoiceRef,
    OriginalInvoiceRef,
    "original ref",
    FfiString,
    |reference| {
        let date = reference.issue_date().map(|value| value.to_string());
        optional_str_to_ffi(date.as_deref())
    }
);

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_xml_base64(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = ffi_borrow!(signed, "signed", SignedInvoice);
    FfiResult::ok(FfiString::from(signed.to_xml_base64()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_free(signed: *mut FfiSignedInvoice) {
    ffi_handle_free!(signed, SignedInvoice);
}

#[cfg(test)]
mod test_support {
    use std::sync::{Mutex, OnceLock};

    fn base_url_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    pub(super) struct BaseUrlGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<String>,
    }

    impl BaseUrlGuard {
        pub(super) fn new(url: &str) -> Self {
            let lock = base_url_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var("FATOORA_ZATCA_BASE_URL").ok();
            unsafe {
                std::env::set_var("FATOORA_ZATCA_BASE_URL", url);
            }
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for BaseUrlGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => unsafe {
                    std::env::set_var("FATOORA_ZATCA_BASE_URL", value);
                },
                None => unsafe {
                    std::env::remove_var("FATOORA_ZATCA_BASE_URL");
                },
            }
        }
    }
}

#[cfg(test)]
mod ffi_zatca_tests {
    use std::ffi::CString;
    use std::os::raw::c_void;
    use std::path::Path;
    use std::str::FromStr;
    use std::time::Duration;

    use chrono::TimeZone;
    use fatoora_core::{
        api::ZatcaClient,
        config::{Config, EnvironmentType},
        csr::CsrProperties,
        invoice::{
            sign::InvoiceSigner,
            Address, InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, Party,
            RequiredInvoiceFields, SellerRole, SignedInvoice, VatCategory,
        },
    };
    use httpmock::{Method::PATCH, Method::POST, MockServer};
    use isocountry::CountryCode;
    use iso_currency::Currency;
    use k256::ecdsa::SigningKey;
    use k256::pkcs8::EncodePrivateKey;
    use x509_cert::builder::{Builder, CertificateBuilder, profile};
    use x509_cert::der::Encode;
    use x509_cert::name::Name;
    use x509_cert::request::CertReq;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::EncodePublicKey;
    use x509_cert::spki::SubjectPublicKeyInfo;
    use x509_cert::time::Validity;

    use super::*;

    fn cstr(value: &str) -> CString {
        CString::new(value).expect("CString")
    }

    fn mock_base_url(server: &MockServer) -> String {
        format!("{}/", server.base_url())
    }

    fn try_start_server() -> Option<MockServer> {
        std::panic::catch_unwind(MockServer::start).ok()
    }

    use super::test_support::BaseUrlGuard;

    fn build_csr() -> CertReq {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties");
        let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");
        let (csr, _key) = csr_config
            .build_with_rng(EnvironmentType::NonProduction)
            .expect("csr build");
        csr
    }

    fn build_signed_invoice(invoice_type: InvoiceType, signer: &InvoiceSigner) -> SignedInvoice {
        let seller = Party::<SellerRole>::new(
            "Acme Inc".into(),
            Address {
                country_code: CountryCode::SAU,
                city: "Riyadh".into(),
                street: "King Fahd".into(),
                additional_street: None,
                building_number: "1234".into(),
                additional_number: Some("5678".into()),
                postal_code: "12222".into(),
                subdivision: None,
                district: None,
            },
            "301121971500003",
            None,
        )
        .expect("seller");

        let line_item = LineItem::new(fatoora_core::invoice::LineItemFields {
            description: "Item".into(),
            quantity: 1.0,
            unit_code: "PCE".into(),
            unit_price: 100.0,
            vat_rate: 15.0,
            vat_category: VatCategory::Standard,
        });

        let issue_datetime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 30, 0)
            .unwrap();

        let invoice = InvoiceBuilder::new(RequiredInvoiceFields {
            invoice_type,
            id: "INV-TEST-1".into(),
            uuid: "uuid-test-1".into(),
            issue_datetime: chrono::Utc.from_utc_datetime(&issue_datetime),
            currency: Currency::SAR,
            previous_invoice_hash: "".into(),
            invoice_counter: 0,
            seller,
            line_items: vec![line_item],
            payment_means_code: "10".into(),
            vat_category: VatCategory::Standard,
        })
        .build()
        .expect("build invoice");
        invoice.sign(signer).expect("sign invoice")
    }

    fn build_test_cert(key: &SigningKey) -> Vec<u8> {
        let serial_number = SerialNumber::from(1u32);
        let validity = Validity::from_now(Duration::new(3600, 0)).expect("validity");
        let subject = Name::from_str("CN=Test,O=Fatoora,C=SA").expect("subject");
        let profile = profile::cabf::Root::new(false, subject).expect("profile");
        let public_key = key.verifying_key();
        let spki_der = public_key.to_public_key_der().expect("public key der");
        let pub_key = SubjectPublicKeyInfo::try_from(spki_der.as_bytes()).expect("spki");
        let builder =
            CertificateBuilder::new(profile, serial_number, validity, pub_key).expect("builder");
        let cert = builder
            .build::<_, k256::ecdsa::DerSignature>(key)
            .expect("certificate");
        cert.to_der().expect("cert der")
    }

    fn build_test_signer() -> InvoiceSigner {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties");
        let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");
        let (_csr, signer_key) = csr_config
            .build_with_rng(EnvironmentType::NonProduction)
            .expect("csr build");
        let key_der = signer_key.to_pkcs8_der().expect("key der");
        let cert_der = build_test_cert(&signer_key);
        InvoiceSigner::from_der(&cert_der, key_der.as_bytes()).expect("signer")
    }

    #[test]
    fn ffi_zatca_invoice_endpoints() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&mock_base_url(&server));
        let body = r#"{
          "validationResults": {
            "infoMessages": [],
            "warningMessages": [],
            "errorMessages": [],
            "status": "PASS"
          },
          "reportingStatus": "REPORTED",
          "clearanceStatus": null,
          "qrSellertStatus": null,
          "qrBuyertStatus": null
        }"#;

        let report_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/invoices/reporting/single")
                .header("accept-language", "ar");
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        });
        let clear_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/invoices/clearance/single")
                .header("accept-language", "en");
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        });
        let compliance_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/compliance/invoices")
                .header("accept-language", "en");
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        });

        let client = ZatcaClient::new(Config::default()).expect("client");
        let mut ffi_client = FfiZatcaClient {
            ptr: Box::into_raw(Box::new(client)) as *mut c_void,
        };

        unsafe {
            let signer = build_test_signer();
            let simplified =
                build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified), &signer);
            let mut ffi_simplified = FfiSignedInvoice {
                ptr: Box::into_raw(Box::new(simplified)) as *mut c_void,
            };

            let pcsid_result = fatoora_csid_production_new(
                FfiEnvironment::NonProduction,
                false,
                0,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(pcsid_result.ok);
            let mut pcsid = pcsid_result.value;

            let mut report_result = fatoora_zatca_report_simplified_invoice(
                &mut ffi_client,
                &mut ffi_simplified,
                &mut pcsid,
                false,
                cstr("ar").as_ptr(),
            );
            assert!(report_result.ok);
            fatoora_validation_response_free(&mut report_result.value);

            let standard =
                build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Standard), &signer);
            let mut ffi_standard = FfiSignedInvoice {
                ptr: Box::into_raw(Box::new(standard)) as *mut c_void,
            };

            let mut clear_result = fatoora_zatca_clear_standard_invoice(
                &mut ffi_client,
                &mut ffi_standard,
                &mut pcsid,
                true,
                std::ptr::null(),
            );
            assert!(clear_result.ok);
            fatoora_validation_response_free(&mut clear_result.value);

            let ccsid_result = fatoora_csid_compliance_new(
                FfiEnvironment::NonProduction,
                false,
                0,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(ccsid_result.ok);
            let mut ccsid = ccsid_result.value;

            let mut compliance_result =
                fatoora_zatca_check_compliance(&mut ffi_client, &mut ffi_simplified, &mut ccsid);
            assert!(compliance_result.ok);
            fatoora_validation_response_free(&mut compliance_result.value);

            fatoora_signed_invoice_free(&mut ffi_simplified);
            fatoora_signed_invoice_free(&mut ffi_standard);
            fatoora_csid_production_free(&mut pcsid);
            fatoora_csid_compliance_free(&mut ccsid);
            fatoora_zatca_client_free(&mut ffi_client);
        }

        report_mock.assert();
        clear_mock.assert();
        compliance_mock.assert();
    }

    #[test]
    fn ffi_zatca_csid_endpoints() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&mock_base_url(&server));
        let ccsid_body = r#"{
          "requestID": 42,
          "binarySecurityToken": "token",
          "secret": "secret"
        }"#;
        let pcsid_body = r#"{
          "requestID": 77,
          "binarySecurityToken": "ptoken",
          "secret": "psecret"
        }"#;
        let renew_body = r#"{
          "value": {
            "requestID": 88,
            "binarySecurityToken": "rtoken",
            "secret": "rsecret"
          }
        }"#;

        let csr_mock = server.mock(|when, then| {
            when.method(POST).path("/compliance").header("OTP", "123456");
            then.status(200)
                .header("content-type", "application/json")
                .body(ccsid_body);
        });
        let pcsid_mock = server.mock(|when, then| {
            when.method(POST).path("/production/csids");
            then.status(200)
                .header("content-type", "application/json")
                .body(pcsid_body);
        });
        let renew_mock = server.mock(|when, then| {
            when.method(PATCH)
                .path("/production/csids")
                .header("accept-language", "ar");
            then.status(428)
                .header("content-type", "application/json")
                .body(renew_body);
        });

        let client = ZatcaClient::new(Config::default()).expect("client");
        let mut ffi_client = FfiZatcaClient {
            ptr: Box::into_raw(Box::new(client)) as *mut c_void,
        };

        unsafe {
            let mut ffi_csr = FfiCsr {
                ptr: Box::into_raw(Box::new(build_csr())) as *mut c_void,
            };

            let ccsid_result = fatoora_zatca_post_csr_for_ccsid(
                &mut ffi_client,
                &mut ffi_csr,
                cstr("123456").as_ptr(),
            );
            assert!(ccsid_result.ok);
            let mut ccsid = ccsid_result.value;

            let pcsid_result = fatoora_zatca_post_ccsid_for_pcsid(&mut ffi_client, &mut ccsid);
            assert!(pcsid_result.ok);
            let mut pcsid = pcsid_result.value;

            let renewed_result = fatoora_zatca_renew_csid(
                &mut ffi_client,
                &mut pcsid,
                &mut ffi_csr,
                cstr("123456").as_ptr(),
                cstr("ar").as_ptr(),
            );
            assert!(renewed_result.ok);
            let mut renewed = renewed_result.value;

            fatoora_csr_free(&mut ffi_csr);
            fatoora_csid_compliance_free(&mut ccsid);
            fatoora_csid_production_free(&mut pcsid);
            fatoora_csid_production_free(&mut renewed);
            fatoora_zatca_client_free(&mut ffi_client);
        }

        csr_mock.assert();
        pcsid_mock.assert();
        renew_mock.assert();
    }
}

#[cfg(test)]
mod ffi_coverage_tests {
    use std::ffi::CString;
    use std::path::Path;
    use std::str::FromStr;
    use std::time::Duration;

    use fatoora_core::{
        config::EnvironmentType,
        csr::CsrProperties,
        invoice::{sign::InvoiceSigner},
    };
    use x509_cert::der::Decode;
    use k256::ecdsa::SigningKey;
    use k256::pkcs8::EncodePrivateKey;
    use x509_cert::builder::{Builder, CertificateBuilder, profile};
    use x509_cert::der::Encode;
    use x509_cert::der::EncodePem;
    use x509_cert::der::pem::LineEnding;
    use x509_cert::name::Name;
    use x509_cert::Certificate;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::EncodePublicKey;
    use x509_cert::spki::SubjectPublicKeyInfo;
    use x509_cert::time::Validity;

    use super::*;

    fn cstr(value: &str) -> CString {
        CString::new(value).expect("CString")
    }

    use super::test_support::BaseUrlGuard;

    fn build_test_cert(key: &SigningKey) -> Vec<u8> {
        let serial_number = SerialNumber::from(1u32);
        let validity = Validity::from_now(Duration::new(3600, 0)).expect("validity");
        let subject = Name::from_str("CN=Test,O=Fatoora,C=SA").expect("subject");
        let profile = profile::cabf::Root::new(false, subject).expect("profile");
        let public_key = key.verifying_key();
        let spki_der = public_key.to_public_key_der().expect("public key der");
        let pub_key = SubjectPublicKeyInfo::try_from(spki_der.as_bytes()).expect("spki");
        let builder =
            CertificateBuilder::new(profile, serial_number, validity, pub_key).expect("builder");
        let cert = builder
            .build::<_, k256::ecdsa::DerSignature>(key)
            .expect("certificate");
        cert.to_der().expect("cert der")
    }

    fn build_test_signer() -> (Vec<u8>, Vec<u8>) {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties");
        let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");
        let (_csr, signer_key) = csr_config
            .build_with_rng(EnvironmentType::NonProduction)
            .expect("csr build");
        let key_der = signer_key.to_pkcs8_der().expect("key der").as_bytes().to_vec();
        let cert_der = build_test_cert(&signer_key);
        let _ = InvoiceSigner::from_der(&cert_der, &key_der).expect("signer");
        (cert_der, key_der)
    }

    fn load_fixture(path: &str) -> String {
        let full_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fatoora-core/tests/fixtures")
            .join(path);
        std::fs::read_to_string(full_path).expect("fixture")
    }

    fn build_invoice_builder() -> FfiResult<FfiInvoiceBuilder> {
        unsafe {
            fatoora_invoice_builder_new(
                FfiInvoiceTypeKind::Tax,
                FfiInvoiceSubType::Simplified,
                cstr("INV-42").as_ptr(),
                cstr("123e4567-e89b-12d3-a456-426614174000").as_ptr(),
                1_700_000_000,
                0,
                cstr("SAR").as_ptr(),
                cstr("hash").as_ptr(),
                1,
                cstr("10").as_ptr(),
                FfiVatCategory::Standard,
                cstr("Acme Inc").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("King Fahd").as_ptr(),
                std::ptr::null(),
                cstr("1234").as_ptr(),
                std::ptr::null(),
                cstr("12222").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("399999999900003").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    }

    #[test]
    fn config_and_validation_paths() {
        let default_xsd = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fatoora-core/assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd");
        unsafe {
            let config = fatoora_config_new(FfiEnvironment::NonProduction);
            assert!(!config.is_null());
            let config_with_xsd =
                fatoora_config_with_xsd(FfiEnvironment::NonProduction, cstr(default_xsd.to_string_lossy().as_ref()).as_ptr());
            assert!(!config_with_xsd.is_null());

            let missing = fatoora_validate_xml_file(config, cstr("missing.xml").as_ptr());
            assert!(!missing.ok);
            if !missing.error.is_null() {
                fatoora_error_free(missing.error);
            }

            let invalid = fatoora_validate_xml_str(config, cstr("<Invoice>").as_ptr());
            assert!(!invalid.ok);
            if !invalid.error.is_null() {
                fatoora_error_free(invalid.error);
            }

            fatoora_config_free(config);
            fatoora_config_free(config_with_xsd);
        }
    }

    #[test]
    fn csr_and_key_paths() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties");
        unsafe {
            let props = fatoora_csr_properties_parse(cstr(config_path.to_string_lossy().as_ref()).as_ptr());
            assert!(props.ok);
            let mut props_handle = props.value;

            let bundle = fatoora_csr_build_with_rng(&mut props_handle, FfiEnvironment::NonProduction);
            assert!(bundle.ok);
            let mut bundle = bundle.value;

            let csr_b64 = fatoora_csr_to_base64(&mut bundle.csr);
            assert!(csr_b64.ok);
            fatoora_string_free(csr_b64.value);

            let csr_pem_b64 = fatoora_csr_to_pem_base64(&mut bundle.csr);
            assert!(csr_pem_b64.ok);
            fatoora_string_free(csr_pem_b64.value);

            let key_pem = fatoora_signing_key_to_pem(&mut bundle.key);
            assert!(key_pem.ok);

            let mut key_from_pem = fatoora_signing_key_from_pem(key_pem.value.ptr);
            assert!(key_from_pem.ok);

            let key_der = SigningKey::from_pkcs8_pem(
                std::ffi::CStr::from_ptr(key_pem.value.ptr).to_str().expect("pem"),
            )
            .expect("pem key")
            .to_pkcs8_der()
            .expect("der key");
            let mut key_from_der =
                fatoora_signing_key_from_der(key_der.as_bytes().as_ptr(), key_der.as_bytes().len());
            assert!(key_from_der.ok);

            let csr_with_key =
                fatoora_csr_build(&mut props_handle, &mut bundle.key, FfiEnvironment::NonProduction);
            assert!(csr_with_key.ok);
            let mut csr_with_key = csr_with_key.value;

            fatoora_csr_free(&mut csr_with_key);
            fatoora_signing_key_free(&mut bundle.key);
            fatoora_csr_free(&mut bundle.csr);
            fatoora_signing_key_free(&mut key_from_pem.value);
            fatoora_signing_key_free(&mut key_from_der.value);
            fatoora_csr_properties_free(&mut props_handle);
            fatoora_string_free(key_pem.value);
        }
    }

    #[test]
    fn invoice_builder_invalid_inputs() {
        unsafe {
            let bad_currency = fatoora_invoice_builder_new(
                FfiInvoiceTypeKind::Tax,
                FfiInvoiceSubType::Simplified,
                cstr("INV-INVALID").as_ptr(),
                cstr("uuid").as_ptr(),
                1_700_000_000,
                0,
                cstr("ZZZ").as_ptr(),
                cstr("hash").as_ptr(),
                1,
                cstr("10").as_ptr(),
                FfiVatCategory::Standard,
                cstr("Acme Inc").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("King Fahd").as_ptr(),
                std::ptr::null(),
                cstr("1234").as_ptr(),
                std::ptr::null(),
                cstr("12222").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("399999999900003").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert!(!bad_currency.ok);
            if !bad_currency.error.is_null() {
                fatoora_error_free(bad_currency.error);
            }

            let bad_country = fatoora_invoice_builder_new(
                FfiInvoiceTypeKind::Tax,
                FfiInvoiceSubType::Simplified,
                cstr("INV-INVALID").as_ptr(),
                cstr("uuid").as_ptr(),
                1_700_000_000,
                0,
                cstr("SAR").as_ptr(),
                cstr("hash").as_ptr(),
                1,
                cstr("10").as_ptr(),
                FfiVatCategory::Standard,
                cstr("Acme Inc").as_ptr(),
                cstr("ZZZ").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("King Fahd").as_ptr(),
                std::ptr::null(),
                cstr("1234").as_ptr(),
                std::ptr::null(),
                cstr("12222").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("399999999900003").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert!(!bad_country.ok);
            if !bad_country.error.is_null() {
                fatoora_error_free(bad_country.error);
            }

            let bad_timestamp = fatoora_invoice_builder_new(
                FfiInvoiceTypeKind::Tax,
                FfiInvoiceSubType::Simplified,
                cstr("INV-INVALID").as_ptr(),
                cstr("uuid").as_ptr(),
                1_700_000_000,
                2_000_000_000,
                cstr("SAR").as_ptr(),
                cstr("hash").as_ptr(),
                1,
                cstr("10").as_ptr(),
                FfiVatCategory::Standard,
                cstr("Acme Inc").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("King Fahd").as_ptr(),
                std::ptr::null(),
                cstr("1234").as_ptr(),
                std::ptr::null(),
                cstr("12222").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("399999999900003").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert!(!bad_timestamp.ok);
            if !bad_timestamp.error.is_null() {
                fatoora_error_free(bad_timestamp.error);
            }
        }
    }

    #[test]
    fn credit_note_builder_roundtrip() {
        unsafe {
            let builder = fatoora_invoice_builder_new(
                FfiInvoiceTypeKind::CreditNote,
                FfiInvoiceSubType::Simplified,
                cstr("CR-1").as_ptr(),
                cstr("uuid-credit").as_ptr(),
                1_700_000_000,
                0,
                cstr("SAR").as_ptr(),
                cstr("hash").as_ptr(),
                1,
                cstr("10").as_ptr(),
                FfiVatCategory::Standard,
                cstr("Acme Inc").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("King Fahd").as_ptr(),
                std::ptr::null(),
                cstr("1234").as_ptr(),
                std::ptr::null(),
                cstr("12222").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("399999999900003").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("INV-ORIG").as_ptr(),
                cstr("uuid-orig").as_ptr(),
                cstr("2024-01-01").as_ptr(),
                cstr("Return").as_ptr(),
            );
            assert!(builder.ok);
            let mut builder = builder.value;

            let add_result = fatoora_invoice_builder_add_line_item(
                &mut builder,
                cstr("Item").as_ptr(),
                1.0,
                cstr("PCE").as_ptr(),
                100.0,
                15.0,
                FfiVatCategory::Standard,
            );
            assert!(add_result.ok);

            let invoice_result = fatoora_invoice_builder_build(&mut builder);
            assert!(invoice_result.ok);
            let mut invoice = invoice_result.value;

            let xml = fatoora_invoice_to_xml(&mut invoice);
            assert!(xml.ok);
            fatoora_string_free(xml.value);

            fatoora_invoice_free(&mut invoice);
            fatoora_invoice_builder_free(&mut builder);
        }
    }

    #[test]
    fn invoice_builder_flags_enable_disable() {
        unsafe {
            let builder = build_invoice_builder();
            assert!(builder.ok);
            let mut builder = builder.value;

            let set_flags = fatoora_invoice_builder_set_flags(&mut builder, 0b00001);
            assert!(set_flags.ok);
            let enable_flags = fatoora_invoice_builder_enable_flags(&mut builder, 0b00100);
            assert!(enable_flags.ok);
            let disable_flags = fatoora_invoice_builder_disable_flags(&mut builder, 0b00001);
            assert!(disable_flags.ok);

            let add_result = fatoora_invoice_builder_add_line_item(
                &mut builder,
                cstr("Item").as_ptr(),
                1.0,
                cstr("PCE").as_ptr(),
                50.0,
                15.0,
                FfiVatCategory::Standard,
            );
            assert!(add_result.ok);

            let invoice_result = fatoora_invoice_builder_build(&mut builder);
            assert!(invoice_result.ok);
            let mut invoice = invoice_result.value;

            let flags = fatoora_invoice_flags(&mut invoice);
            assert!(flags.ok);

            fatoora_invoice_free(&mut invoice);
            fatoora_invoice_builder_free(&mut builder);
        }
    }

    #[test]
    fn zatca_client_new_free_paths() {
        unsafe {
            let config = fatoora_config_new(FfiEnvironment::NonProduction);
            assert!(!config.is_null());
            let client = fatoora_zatca_client_new(config);
            assert!(client.ok);
            let mut client = client.value;
            fatoora_zatca_client_free(&mut client);
            fatoora_config_free(config);
        }
    }

    #[test]
    fn debit_note_builder_with_optional_fields() {
        unsafe {
            let builder = fatoora_invoice_builder_new(
                FfiInvoiceTypeKind::DebitNote,
                FfiInvoiceSubType::Simplified,
                cstr("DB-1").as_ptr(),
                cstr("uuid-debit").as_ptr(),
                1_700_000_000,
                0,
                cstr("SAR").as_ptr(),
                cstr("hash").as_ptr(),
                1,
                cstr("10").as_ptr(),
                FfiVatCategory::Standard,
                cstr("Acme Inc").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("King Fahd").as_ptr(),
                cstr("").as_ptr(),
                cstr("1234").as_ptr(),
                cstr("5678").as_ptr(),
                cstr("12222").as_ptr(),
                cstr("").as_ptr(),
                cstr("District 1").as_ptr(),
                cstr("399999999900003").as_ptr(),
                cstr("12345").as_ptr(),
                cstr("CRN").as_ptr(),
                cstr("INV-ORIG").as_ptr(),
                cstr("uuid-orig").as_ptr(),
                cstr("2024-01-01").as_ptr(),
                cstr("Adjustment").as_ptr(),
            );
            assert!(builder.ok);
            let mut builder = builder.value;

            let buyer_result = fatoora_invoice_builder_set_buyer(
                &mut builder,
                cstr("Buyer Inc").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("Takhassusi").as_ptr(),
                cstr("").as_ptr(),
                cstr("555").as_ptr(),
                cstr("1234").as_ptr(),
                cstr("12222").as_ptr(),
                cstr("").as_ptr(),
                cstr("District 2").as_ptr(),
                cstr("399999999900003").as_ptr(),
                cstr("67890").as_ptr(),
                cstr("MOM").as_ptr(),
            );
            assert!(buyer_result.ok);

            let add_result = fatoora_invoice_builder_add_line_item(
                &mut builder,
                cstr("Item").as_ptr(),
                1.0,
                cstr("PCE").as_ptr(),
                25.0,
                15.0,
                FfiVatCategory::Standard,
            );
            assert!(add_result.ok);

            let invoice_result = fatoora_invoice_builder_build(&mut builder);
            assert!(invoice_result.ok);
            let mut invoice = invoice_result.value;

            let flags = fatoora_invoice_flags(&mut invoice);
            assert!(flags.ok);

            fatoora_invoice_free(&mut invoice);
            fatoora_invoice_builder_free(&mut builder);
        }
    }

    #[test]
    fn zatca_calls_fail_without_server() {
        let _guard = BaseUrlGuard::new("http://127.0.0.1:9/");
        unsafe {
            let config = fatoora_config_new(FfiEnvironment::NonProduction);
            assert!(!config.is_null());
            let client = fatoora_zatca_client_new(config);
            assert!(client.ok);
            let mut client = client.value;

            let csr_props_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties");
            let props = fatoora_csr_properties_parse(cstr(csr_props_path.to_string_lossy().as_ref()).as_ptr());
            assert!(props.ok);
            let mut props_handle = props.value;
            let bundle = fatoora_csr_build_with_rng(&mut props_handle, FfiEnvironment::NonProduction);
            assert!(bundle.ok);
            let mut bundle = bundle.value;

            let ccsid_result = fatoora_csid_compliance_new(
                FfiEnvironment::NonProduction,
                true,
                10,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(ccsid_result.ok);
            let mut ccsid = ccsid_result.value;

            let pcsid_result = fatoora_csid_production_new(
                FfiEnvironment::NonProduction,
                true,
                20,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(pcsid_result.ok);
            let mut pcsid = pcsid_result.value;

            let simplified_xml =
                load_fixture("invoices/Simplified/Invoice/Simplified_Invoice.xml");
            let standard_xml = load_fixture("invoices/Standard/Invoice/Standard_Invoice.xml");
            let simplified = fatoora_parse_signed_invoice_xml(cstr(&simplified_xml).as_ptr());
            assert!(simplified.ok);
            let mut simplified = simplified.value;
            let standard = fatoora_parse_signed_invoice_xml(cstr(&standard_xml).as_ptr());
            assert!(standard.ok);
            let mut standard = standard.value;

            let result = fatoora_zatca_post_csr_for_ccsid(&mut client, &mut bundle.csr, cstr("123456").as_ptr());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }
            let result = fatoora_zatca_post_ccsid_for_pcsid(&mut client, &mut ccsid);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }
            let result = fatoora_zatca_renew_csid(
                &mut client,
                &mut pcsid,
                &mut bundle.csr,
                cstr("123456").as_ptr(),
                std::ptr::null(),
            );
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }
            let result = fatoora_zatca_check_compliance(&mut client, &mut simplified, &mut ccsid);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }
            let result = fatoora_zatca_report_simplified_invoice(
                &mut client,
                &mut simplified,
                &mut pcsid,
                false,
                std::ptr::null(),
            );
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }
            let result = fatoora_zatca_clear_standard_invoice(
                &mut client,
                &mut standard,
                &mut pcsid,
                true,
                std::ptr::null(),
            );
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            fatoora_signed_invoice_free(&mut simplified);
            fatoora_signed_invoice_free(&mut standard);
            fatoora_csr_free(&mut bundle.csr);
            fatoora_signing_key_free(&mut bundle.key);
            fatoora_csr_properties_free(&mut props_handle);
            fatoora_csid_compliance_free(&mut ccsid);
            fatoora_csid_production_free(&mut pcsid);
            fatoora_zatca_client_free(&mut client);
            fatoora_config_free(config);
        }
    }

    #[test]
    fn ffi_error_paths_cover_more_lines() {
        unsafe {
            let null_key = fatoora_signing_key_to_pem(std::ptr::null_mut());
            assert!(!null_key.ok);
            if !null_key.error.is_null() {
                fatoora_error_free(null_key.error);
            }

            let null_csr = fatoora_csr_to_base64(std::ptr::null_mut());
            assert!(!null_csr.ok);
            if !null_csr.error.is_null() {
                fatoora_error_free(null_csr.error);
            }

            let null_client = fatoora_zatca_client_new(std::ptr::null_mut());
            assert!(!null_client.ok);
            if !null_client.error.is_null() {
                fatoora_error_free(null_client.error);
            }

            let builder = build_invoice_builder();
            assert!(builder.ok);
            let mut builder = builder.value;
            let add_result = fatoora_invoice_builder_add_line_item(
                &mut builder,
                cstr("Item").as_ptr(),
                1.0,
                cstr("PCE").as_ptr(),
                50.0,
                15.0,
                FfiVatCategory::Standard,
            );
            assert!(add_result.ok);
            let invoice_result = fatoora_invoice_builder_build(&mut builder);
            assert!(invoice_result.ok);
            let mut invoice = invoice_result.value;

            let out_of_range = fatoora_invoice_line_item_description(&mut invoice, 99);
            assert!(!out_of_range.ok);
            if !out_of_range.error.is_null() {
                fatoora_error_free(out_of_range.error);
            }

            let sign_err = fatoora_invoice_sign(&mut invoice, std::ptr::null_mut());
            assert!(!sign_err.ok);
            if !sign_err.error.is_null() {
                fatoora_error_free(sign_err.error);
            }
            fatoora_invoice_builder_free(&mut builder);

            let null_signed = fatoora_signed_invoice_xml(std::ptr::null_mut());
            assert!(!null_signed.ok);
            if !null_signed.error.is_null() {
                fatoora_error_free(null_signed.error);
            }

            let ccsid = fatoora_csid_compliance_new(
                FfiEnvironment::NonProduction,
                false,
                0,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(ccsid.ok);
            let mut ccsid = ccsid.value;
            let missing_id = fatoora_csid_compliance_request_id(&mut ccsid);
            assert!(!missing_id.ok);
            if !missing_id.error.is_null() {
                fatoora_error_free(missing_id.error);
            }
            fatoora_csid_compliance_free(&mut ccsid);

            let pcsid = fatoora_csid_production_new(
                FfiEnvironment::NonProduction,
                true,
                55,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(pcsid.ok);
            let mut pcsid = pcsid.value;
            let request_id = fatoora_csid_production_request_id(&mut pcsid);
            assert!(request_id.ok);
            fatoora_csid_production_free(&mut pcsid);
        }
    }

    #[test]
    fn ffi_null_and_parse_error_paths() {
        unsafe {
            let result = fatoora_invoice_builder_set_buyer(
                std::ptr::null_mut(),
                cstr("Buyer").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("Street").as_ptr(),
                std::ptr::null(),
                cstr("1234").as_ptr(),
                std::ptr::null(),
                cstr("12222").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("399999999900003").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_builder_set_note(
                std::ptr::null_mut(),
                cstr("en").as_ptr(),
                cstr("Note").as_ptr(),
            );
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result =
                fatoora_invoice_builder_set_allowance(std::ptr::null_mut(), cstr("Disc").as_ptr(), 1.0);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_builder_enable_flags(std::ptr::null_mut(), 0b1);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_builder_disable_flags(std::ptr::null_mut(), 0b1);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_builder_build(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_line_item_quantity(std::ptr::null_mut(), 0);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_signed_invoice_totals_tax_inclusive(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_signed_invoice_line_item_quantity(std::ptr::null_mut(), 0);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_totals_tax_amount(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_line_item_vat_category(std::ptr::null_mut(), 0);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_signed_invoice_line_item_total_amount(std::ptr::null_mut(), 0);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_signed_invoice_totals_tax_amount(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_signed_invoice_line_item_vat_rate(std::ptr::null_mut(), 0);
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_totals_charge_total(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_totals_allowance_total(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_signed_invoice_totals_line_extension(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_totals_taxable_amount(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_flags(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_signed_invoice_flags(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_invoice_to_xml(std::ptr::null_mut());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }

            let result = fatoora_parse_finalized_invoice_xml(cstr("<bad").as_ptr());
            assert!(!result.ok);
            if !result.error.is_null() {
                fatoora_error_free(result.error);
            }
        }
    }

    #[test]
    fn invoice_builder_and_signed_accessors() {
        let (cert_der, key_der) = build_test_signer();
        let key_pem = {
            let key = SigningKey::from_pkcs8_der(&key_der).expect("key");
            key.to_pkcs8_pem(x509_cert::der::pem::LineEnding::LF)
                .expect("pem")
                .to_string()
        };
        let cert_pem = {
            let cert = Certificate::from_der(&cert_der).expect("cert");
            cert.to_pem(LineEnding::LF).expect("cert pem").to_string()
        };

        unsafe {
            let builder = build_invoice_builder();
            assert!(builder.ok);
            let mut builder = builder.value;

            let add_result = fatoora_invoice_builder_add_line_item(
                &mut builder,
                cstr("Item").as_ptr(),
                2.0,
                cstr("PCE").as_ptr(),
                50.0,
                15.0,
                FfiVatCategory::Standard,
            );
            assert!(add_result.ok);

            let buyer_result = fatoora_invoice_builder_set_buyer(
                &mut builder,
                cstr("Buyer Inc").as_ptr(),
                cstr("SAU").as_ptr(),
                cstr("Riyadh").as_ptr(),
                cstr("Takhassusi").as_ptr(),
                std::ptr::null(),
                cstr("555").as_ptr(),
                std::ptr::null(),
                cstr("12222").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                cstr("399999999900003").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert!(buyer_result.ok);

            let note_result = fatoora_invoice_builder_set_note(
                &mut builder,
                cstr("en").as_ptr(),
                cstr("Note").as_ptr(),
            );
            assert!(note_result.ok);

            let allowance_result =
                fatoora_invoice_builder_set_allowance(&mut builder, cstr("Discount").as_ptr(), 5.0);
            assert!(allowance_result.ok);

            let flags_result = fatoora_invoice_builder_set_flags(&mut builder, 0b00101);
            assert!(flags_result.ok);

            let invoice_result = fatoora_invoice_builder_build(&mut builder);
            assert!(invoice_result.ok);
            let mut invoice = invoice_result.value;

            let count = fatoora_invoice_line_item_count(&mut invoice);
            assert!(count.ok);
            assert_eq!(count.value, 1);

            let description = fatoora_invoice_line_item_description(&mut invoice, 0);
            assert!(description.ok);
            fatoora_string_free(description.value);

            let unit_code = fatoora_invoice_line_item_unit_code(&mut invoice, 0);
            assert!(unit_code.ok);
            fatoora_string_free(unit_code.value);

            let quantity = fatoora_invoice_line_item_quantity(&mut invoice, 0);
            assert!(quantity.ok);

            let unit_price = fatoora_invoice_line_item_unit_price(&mut invoice, 0);
            assert!(unit_price.ok);

            let total_amount = fatoora_invoice_line_item_total_amount(&mut invoice, 0);
            assert!(total_amount.ok);

            let vat_rate = fatoora_invoice_line_item_vat_rate(&mut invoice, 0);
            assert!(vat_rate.ok);

            let vat_amount = fatoora_invoice_line_item_vat_amount(&mut invoice, 0);
            assert!(vat_amount.ok);

            let vat_category = fatoora_invoice_line_item_vat_category(&mut invoice, 0);
            assert!(vat_category.ok);
            assert_eq!(vat_category.value, FfiVatCategory::Standard as u8);

            let totals = fatoora_invoice_totals_tax_inclusive(&mut invoice);
            assert!(totals.ok);
            let totals = fatoora_invoice_totals_tax_amount(&mut invoice);
            assert!(totals.ok);
            let totals = fatoora_invoice_totals_line_extension(&mut invoice);
            assert!(totals.ok);
            let totals = fatoora_invoice_totals_allowance_total(&mut invoice);
            assert!(totals.ok);
            let totals = fatoora_invoice_totals_charge_total(&mut invoice);
            assert!(totals.ok);
            let totals = fatoora_invoice_totals_taxable_amount(&mut invoice);
            assert!(totals.ok);

            let flags = fatoora_invoice_flags(&mut invoice);
            assert!(flags.ok);

            let xml = fatoora_invoice_to_xml(&mut invoice);
            assert!(xml.ok);
            let xml_str = std::ffi::CStr::from_ptr(xml.value.ptr)
                .to_string_lossy()
                .to_string();
            fatoora_string_free(xml.value);

            let parsed = fatoora_parse_finalized_invoice_xml(cstr(&xml_str).as_ptr());
            assert!(parsed.ok);
            let mut parsed = parsed.value;
            let parsed_count = fatoora_invoice_line_item_count(&mut parsed);
            assert!(parsed_count.ok);
            fatoora_invoice_free(&mut parsed);

            let signer_der = fatoora_signer_from_der(
                cert_der.as_ptr(),
                cert_der.len(),
                key_der.as_ptr(),
                key_der.len(),
            );
            assert!(signer_der.ok);
            let mut signer_der = signer_der.value;

            let signer_pem =
                fatoora_signer_from_pem(cstr(&cert_pem).as_ptr(), cstr(&key_pem).as_ptr());
            assert!(signer_pem.ok);
            let mut signer_pem = signer_pem.value;

            let signed = fatoora_invoice_sign(&mut invoice, &mut signer_der);
            assert!(signed.ok);
            let mut signed = signed.value;

            let signed_xml = fatoora_signed_invoice_xml(&mut signed);
            assert!(signed_xml.ok);
            let signed_xml_str = std::ffi::CStr::from_ptr(signed_xml.value.ptr)
                .to_string_lossy()
                .to_string();
            fatoora_string_free(signed_xml.value);
            let signed_qr = fatoora_signed_invoice_qr(&mut signed);
            assert!(signed_qr.ok);
            fatoora_string_free(signed_qr.value);
            let signed_uuid = fatoora_signed_invoice_uuid(&mut signed);
            assert!(signed_uuid.ok);
            fatoora_string_free(signed_uuid.value);
            let signed_hash = fatoora_signed_invoice_hash(&mut signed);
            assert!(signed_hash.ok);
            fatoora_string_free(signed_hash.value);
            let signed_xml_b64 = fatoora_signed_invoice_xml_base64(&mut signed);
            assert!(signed_xml_b64.ok);
            fatoora_string_free(signed_xml_b64.value);

            let parsed_signed = fatoora_parse_signed_invoice_xml(cstr(&signed_xml_str).as_ptr());
            assert!(parsed_signed.ok);
            let mut parsed_signed = parsed_signed.value;
            let parsed_hash = fatoora_signed_invoice_hash(&mut parsed_signed);
            assert!(parsed_hash.ok);
            fatoora_string_free(parsed_hash.value);
            fatoora_signed_invoice_free(&mut parsed_signed);

            let signed_count = fatoora_signed_invoice_line_item_count(&mut signed);
            assert!(signed_count.ok);
            let signed_description = fatoora_signed_invoice_line_item_description(&mut signed, 0);
            assert!(signed_description.ok);
            fatoora_string_free(signed_description.value);
            let signed_unit_code = fatoora_signed_invoice_line_item_unit_code(&mut signed, 0);
            assert!(signed_unit_code.ok);
            fatoora_string_free(signed_unit_code.value);
            let signed_quantity = fatoora_signed_invoice_line_item_quantity(&mut signed, 0);
            assert!(signed_quantity.ok);
            let signed_unit_price = fatoora_signed_invoice_line_item_unit_price(&mut signed, 0);
            assert!(signed_unit_price.ok);
            let signed_total_amount = fatoora_signed_invoice_line_item_total_amount(&mut signed, 0);
            assert!(signed_total_amount.ok);
            let signed_vat_rate = fatoora_signed_invoice_line_item_vat_rate(&mut signed, 0);
            assert!(signed_vat_rate.ok);
            let signed_vat_amount = fatoora_signed_invoice_line_item_vat_amount(&mut signed, 0);
            assert!(signed_vat_amount.ok);
            let signed_vat_category = fatoora_signed_invoice_line_item_vat_category(&mut signed, 0);
            assert!(signed_vat_category.ok);
            assert_eq!(signed_vat_category.value, FfiVatCategory::Standard as u8);

            let signed_totals = fatoora_signed_invoice_totals_tax_inclusive(&mut signed);
            assert!(signed_totals.ok);
            let signed_totals = fatoora_signed_invoice_totals_tax_amount(&mut signed);
            assert!(signed_totals.ok);
            let signed_totals = fatoora_signed_invoice_totals_line_extension(&mut signed);
            assert!(signed_totals.ok);
            let signed_totals = fatoora_signed_invoice_totals_allowance_total(&mut signed);
            assert!(signed_totals.ok);
            let signed_totals = fatoora_signed_invoice_totals_charge_total(&mut signed);
            assert!(signed_totals.ok);
            let signed_totals = fatoora_signed_invoice_totals_taxable_amount(&mut signed);
            assert!(signed_totals.ok);

            let signed_flags = fatoora_signed_invoice_flags(&mut signed);
            assert!(signed_flags.ok);

            fatoora_signed_invoice_free(&mut signed);
            fatoora_signer_free(&mut signer_der);
            fatoora_signer_free(&mut signer_pem);
            fatoora_invoice_free(&mut invoice);
            fatoora_invoice_builder_free(&mut builder);
        }
    }

    #[test]
    fn csid_accessors_cover_paths() {
        unsafe {
            let ccsid_result = fatoora_csid_compliance_new(
                FfiEnvironment::NonProduction,
                true,
                77,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(ccsid_result.ok);
            let mut ccsid = ccsid_result.value;
            let request_id = fatoora_csid_compliance_request_id(&mut ccsid);
            assert!(request_id.ok);

            let token = fatoora_csid_compliance_token(&mut ccsid);
            assert!(token.ok);
            fatoora_string_free(token.value);
            let secret = fatoora_csid_compliance_secret(&mut ccsid);
            assert!(secret.ok);
            fatoora_string_free(secret.value);

            let pcsid_result = fatoora_csid_production_new(
                FfiEnvironment::NonProduction,
                false,
                0,
                cstr("ptoken").as_ptr(),
                cstr("psecret").as_ptr(),
            );
            assert!(pcsid_result.ok);
            let mut pcsid = pcsid_result.value;
            let request_id = fatoora_csid_production_request_id(&mut pcsid);
            assert!(!request_id.ok);
            if !request_id.error.is_null() {
                fatoora_error_free(request_id.error);
            }
            let token = fatoora_csid_production_token(&mut pcsid);
            assert!(token.ok);
            fatoora_string_free(token.value);
            let secret = fatoora_csid_production_secret(&mut pcsid);
            assert!(secret.ok);
            fatoora_string_free(secret.value);

            fatoora_csid_compliance_free(&mut ccsid);
            fatoora_csid_production_free(&mut pcsid);
        }
    }
}
