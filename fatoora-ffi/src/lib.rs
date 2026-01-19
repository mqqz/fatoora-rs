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
    LineItem, LineItemFields, OtherId, Party, RequiredInvoiceFields, SellerRole,
    SignedInvoice, VatCategory, InvoiceFlags,
};
use fatoora_core::api::{CsidCredentials, ZatcaClient, Compliance, Production};
use fatoora_core::csr::{CsrProperties, ToBase64String};
use fatoora_core::invoice::sign::InvoiceSigner;
use fatoora_core::invoice::xml::ToXml;
use fatoora_core::invoice::validation::{validate_xml_invoice_from_file, validate_xml_invoice_from_str};

mod error;
mod types;

pub use error::FfiResult;
pub use types::{
    FfiConfig, FfiEnvironment, FfiFinalizedInvoice, FfiInvoiceBuilder, FfiInvoiceSubType,
    FfiInvoiceTypeKind, FfiSignedInvoice, FfiSigner, FfiString, FfiVatCategory, FfiInvoiceFlag,
    FfiCsrProperties, FfiCsr, FfiSigningKey, FfiCsrBundle, FfiZatcaClient, FfiCsidCompliance,
    FfiCsidProduction,
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

fn required_string(ptr: *const c_char, label: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{label} is null"));
    }
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{label} is not valid utf-8"))?;
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

fn parse_country(code: &str) -> Result<CountryCode, String> {
    CountryCode::for_alpha3(code)
        .map_err(|_| format!("Invalid country code: {code}"))
}

fn parse_currency(code: &str) -> Result<Currency, String> {
    Currency::from_code(code)
        .ok_or_else(|| format!("Invalid currency code: {code}"))
}

fn parse_issue_datetime(seconds: i64, nanos: u32) -> Result<chrono::DateTime<Utc>, String> {
    Utc.timestamp_opt(seconds, nanos)
        .single()
        .ok_or_else(|| "Invalid issue timestamp".to_string())
}

fn run_async<T>(
    fut: impl std::future::Future<Output = Result<T, fatoora_core::api::ZatcaError>>,
) -> Result<T, String> {
    let rt = Runtime::new().map_err(|err| err.to_string())?;
    rt.block_on(fut).map_err(|err| err.to_string())
}

fn original_invoice_ref(
    id: Option<String>,
    uuid: Option<String>,
    issue_date: Option<String>,
) -> Result<fatoora_core::invoice::OriginalInvoiceRef, String> {
    let id = id.ok_or_else(|| "Missing original invoice id".to_string())?;
    let mut reference = fatoora_core::invoice::OriginalInvoiceRef::new(id);
    if let Some(uuid) = uuid {
        reference = reference.with_uuid(uuid);
    }
    if let Some(date) = issue_date {
        let parsed = chrono::NaiveDate::parse_from_str(&date, "%Y-%m-%d")
            .map_err(|_| format!("Invalid issue date: {date}"))?;
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
) -> Result<InvoiceType, String> {
    let sub_type: InvoiceSubType = sub_type.into();
    match kind {
        FfiInvoiceTypeKind::Tax => Ok(InvoiceType::Tax(sub_type)),
        FfiInvoiceTypeKind::Prepayment => Ok(InvoiceType::Prepayment(sub_type)),
        FfiInvoiceTypeKind::CreditNote => {
            let reason = reason.ok_or_else(|| "Missing credit note reason".to_string())?;
            let reference = original_invoice_ref(original_id, original_uuid, original_issue_date)?;
            Ok(InvoiceType::CreditNote(sub_type, reference, reason))
        }
        FfiInvoiceTypeKind::DebitNote => {
            let reason = reason.ok_or_else(|| "Missing debit note reason".to_string())?;
            let reference = original_invoice_ref(original_id, original_uuid, original_issue_date)?;
            Ok(InvoiceType::DebitNote(sub_type, reference, reason))
        }
    }
}

fn take_handle<T>(handle: &mut *mut std::os::raw::c_void, label: &str) -> Result<Box<T>, String> {
    if handle.is_null() || (*handle).is_null() {
        return Err(format!("{label} handle is null"));
    }
    let ptr = *handle as *mut T;
    if ptr.is_null() {
        return Err(format!("{label} handle is null"));
    }
    *handle = std::ptr::null_mut();
    Ok(unsafe { Box::from_raw(ptr) })
}

fn borrow_handle<'a, T>(handle: *mut std::os::raw::c_void, label: &str) -> Result<&'a T, String> {
    if handle.is_null() {
        return Err(format!("{label} handle is null"));
    }
    let ptr = handle as *const T;
    if ptr.is_null() {
        return Err(format!("{label} handle is null"));
    }
    Ok(unsafe { &*ptr })
}

fn borrow_handle_mut<'a, T>(
    handle: *mut std::os::raw::c_void,
    label: &str,
) -> Result<&'a mut T, String> {
    if handle.is_null() {
        return Err(format!("{label} handle is null"));
    }
    let ptr = handle as *mut T;
    if ptr.is_null() {
        return Err(format!("{label} handle is null"));
    }
    Ok(unsafe { &mut *ptr })
}

fn borrow_config<'a>(config: *mut FfiConfig) -> Result<&'a Config, String> {
    let config = match unsafe { config.as_mut() } {
        Some(handle) => handle,
        None => return Err("config handle is null".to_string()),
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
    let path = match required_string(path, "csr properties path") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match CsrProperties::parse_csr_config(std::path::Path::new(&path)) {
        Ok(props) => FfiResult::ok(FfiCsrProperties {
            ptr: Box::into_raw(Box::new(props)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_properties_free(props: *mut FfiCsrProperties) {
    if props.is_null() {
        return;
    }
    let props = unsafe { &mut *props };
    if props.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(props.ptr as *mut CsrProperties)) };
    props.ptr = std::ptr::null_mut();
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_from_pem(pem: *const c_char) -> FfiResult<FfiSigningKey> {
    let pem = match required_string(pem, "signing key pem") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match SigningKey::from_pkcs8_pem(&pem) {
        Ok(key) => FfiResult::ok(FfiSigningKey {
            ptr: Box::into_raw(Box::new(key)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_from_der(der: *const u8, len: usize) -> FfiResult<FfiSigningKey> {
    if der.is_null() {
        return FfiResult::err("null der pointer".to_string());
    }
    let data = unsafe { std::slice::from_raw_parts(der, len) };
    match SigningKey::from_pkcs8_der(data) {
        Ok(key) => FfiResult::ok(FfiSigningKey {
            ptr: Box::into_raw(Box::new(key)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_to_pem(key: *mut FfiSigningKey) -> FfiResult<FfiString> {
    let key = match unsafe { key.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signing key handle is null".to_string()),
    };
    let key = match borrow_handle::<SigningKey>(key.ptr, "signing key") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match key.to_pkcs8_pem(LineEnding::LF) {
        Ok(pem) => FfiResult::ok(FfiString::from(pem.to_string())),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signing_key_free(key: *mut FfiSigningKey) {
    if key.is_null() {
        return;
    }
    let key = unsafe { &mut *key };
    if key.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(key.ptr as *mut SigningKey)) };
    key.ptr = std::ptr::null_mut();
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_build_with_rng(
    props: *mut FfiCsrProperties,
    env: FfiEnvironment,
) -> FfiResult<FfiCsrBundle> {
    let props = match unsafe { props.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csr properties handle is null".to_string()),
    };
    let props = match borrow_handle::<CsrProperties>(props.ptr, "csr properties") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match props.build_with_rng(env.into()) {
        Ok((csr, key)) => FfiResult::ok(FfiCsrBundle {
            csr: FfiCsr {
                ptr: Box::into_raw(Box::new(csr)) as *mut std::os::raw::c_void,
            },
            key: FfiSigningKey {
                ptr: Box::into_raw(Box::new(key)) as *mut std::os::raw::c_void,
            },
        }),
        Err(err) => FfiResult::err(err.to_string()),
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
    let props = match unsafe { props.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csr properties handle is null".to_string()),
    };
    let props = match borrow_handle::<CsrProperties>(props.ptr, "csr properties") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let key = match unsafe { key.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signing key handle is null".to_string()),
    };
    let key = match borrow_handle::<SigningKey>(key.ptr, "signing key") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match props.build(key, env.into()) {
        Ok(csr) => FfiResult::ok(FfiCsr {
            ptr: Box::into_raw(Box::new(csr)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_to_base64(csr: *mut FfiCsr) -> FfiResult<FfiString> {
    let csr = match unsafe { csr.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csr handle is null".to_string()),
    };
    let csr = match borrow_handle::<CertReq>(csr.ptr, "csr") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match csr.to_base64_string() {
        Ok(value) => FfiResult::ok(FfiString::from(value)),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_to_pem_base64(csr: *mut FfiCsr) -> FfiResult<FfiString> {
    let csr = match unsafe { csr.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csr handle is null".to_string()),
    };
    let csr = match borrow_handle::<CertReq>(csr.ptr, "csr") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match csr.to_pem_base64_string() {
        Ok(value) => FfiResult::ok(FfiString::from(value)),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csr_free(csr: *mut FfiCsr) {
    if csr.is_null() {
        return;
    }
    let csr = unsafe { &mut *csr };
    if csr.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(csr.ptr as *mut CertReq)) };
    csr.ptr = std::ptr::null_mut();
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
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_client_free(client: *mut FfiZatcaClient) {
    if client.is_null() {
        return;
    }
    let client = unsafe { &mut *client };
    if client.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(client.ptr as *mut ZatcaClient)) };
    client.ptr = std::ptr::null_mut();
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
    let token = match required_string(token, "csid token") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let secret = match required_string(secret, "csid secret") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let token = match required_string(token, "csid token") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let secret = match required_string(secret, "csid secret") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let creds = match unsafe { creds.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let creds = match borrow_handle::<CsidCredentials<Compliance>>(creds.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match creds.request_id() {
        Some(value) => FfiResult::ok(value),
        None => FfiResult::err("missing request id".to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_production_request_id(creds: *mut FfiCsidProduction) -> FfiResult<u64> {
    let creds = match unsafe { creds.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let creds = match borrow_handle::<CsidCredentials<Production>>(creds.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match creds.request_id() {
        Some(value) => FfiResult::ok(value),
        None => FfiResult::err("missing request id".to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_compliance_token(creds: *mut FfiCsidCompliance) -> FfiResult<FfiString> {
    let creds = match unsafe { creds.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let creds = match borrow_handle::<CsidCredentials<Compliance>>(creds.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(creds.binary_security_token().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_compliance_secret(creds: *mut FfiCsidCompliance) -> FfiResult<FfiString> {
    let creds = match unsafe { creds.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let creds = match borrow_handle::<CsidCredentials<Compliance>>(creds.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(creds.secret().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_production_token(creds: *mut FfiCsidProduction) -> FfiResult<FfiString> {
    let creds = match unsafe { creds.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let creds = match borrow_handle::<CsidCredentials<Production>>(creds.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(creds.binary_security_token().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_production_secret(creds: *mut FfiCsidProduction) -> FfiResult<FfiString> {
    let creds = match unsafe { creds.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let creds = match borrow_handle::<CsidCredentials<Production>>(creds.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(creds.secret().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_compliance_free(creds: *mut FfiCsidCompliance) {
    if creds.is_null() {
        return;
    }
    let creds = unsafe { &mut *creds };
    if creds.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(creds.ptr as *mut CsidCredentials<Compliance>)) };
    creds.ptr = std::ptr::null_mut();
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_csid_production_free(creds: *mut FfiCsidProduction) {
    if creds.is_null() {
        return;
    }
    let creds = unsafe { &mut *creds };
    if creds.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(creds.ptr as *mut CsidCredentials<Production>)) };
    creds.ptr = std::ptr::null_mut();
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_post_csr_for_ccsid(
    client: *mut FfiZatcaClient,
    csr: *mut FfiCsr,
    otp: *const c_char,
) -> FfiResult<FfiCsidCompliance> {
    let client = match unsafe { client.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("client handle is null".to_string()),
    };
    let client = match borrow_handle::<ZatcaClient>(client.ptr, "client") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let csr = match unsafe { csr.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csr handle is null".to_string()),
    };
    let csr = match borrow_handle::<CertReq>(csr.ptr, "csr") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let otp = match required_string(otp, "otp") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let client = match unsafe { client.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("client handle is null".to_string()),
    };
    let client = match borrow_handle::<ZatcaClient>(client.ptr, "client") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let ccsid = match unsafe { ccsid.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let ccsid = match borrow_handle::<CsidCredentials<Compliance>>(ccsid.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let client = match unsafe { client.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("client handle is null".to_string()),
    };
    let client = match borrow_handle::<ZatcaClient>(client.ptr, "client") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let pcsid = match unsafe { pcsid.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let pcsid = match borrow_handle::<CsidCredentials<Production>>(pcsid.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let csr = match unsafe { csr.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csr handle is null".to_string()),
    };
    let csr = match borrow_handle::<CertReq>(csr.ptr, "csr") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let otp = match required_string(otp, "otp") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let language = optional_string(accept_language);
    match run_async(client.renew_csid(pcsid, csr, &otp, language.as_deref())) {
        Ok(creds) => FfiResult::ok(FfiCsidProduction {
            ptr: Box::into_raw(Box::new(creds)) as *mut std::os::raw::c_void,
        }),
        Err(message) => FfiResult::err(message),
    }
}

fn validation_response_to_json(response: &fatoora_core::api::ValidationResponse) -> Result<String, String> {
    serde_json::to_string(response).map_err(|err| err.to_string())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_zatca_check_compliance(
    client: *mut FfiZatcaClient,
    invoice: *mut FfiSignedInvoice,
    ccsid: *mut FfiCsidCompliance,
) -> FfiResult<FfiString> {
    let client = match unsafe { client.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("client handle is null".to_string()),
    };
    let client = match borrow_handle::<ZatcaClient>(client.ptr, "client") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<SignedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let ccsid = match unsafe { ccsid.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let ccsid = match borrow_handle::<CsidCredentials<Compliance>>(ccsid.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match run_async(client.check_invoice_compliance(invoice, ccsid)) {
        Ok(response) => match validation_response_to_json(&response) {
            Ok(json) => FfiResult::ok(FfiString::from(json)),
            Err(message) => FfiResult::err(message),
        },
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
) -> FfiResult<FfiString> {
    let client = match unsafe { client.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("client handle is null".to_string()),
    };
    let client = match borrow_handle::<ZatcaClient>(client.ptr, "client") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<SignedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let pcsid = match unsafe { pcsid.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let pcsid = match borrow_handle::<CsidCredentials<Production>>(pcsid.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let language = optional_string(accept_language);
    match run_async(client.report_simplified_invoice(
        invoice,
        pcsid,
        clearance_status,
        language.as_deref(),
    )) {
        Ok(response) => match validation_response_to_json(&response) {
            Ok(json) => FfiResult::ok(FfiString::from(json)),
            Err(message) => FfiResult::err(message),
        },
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
) -> FfiResult<FfiString> {
    let client = match unsafe { client.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("client handle is null".to_string()),
    };
    let client = match borrow_handle::<ZatcaClient>(client.ptr, "client") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<SignedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let pcsid = match unsafe { pcsid.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("csid handle is null".to_string()),
    };
    let pcsid = match borrow_handle::<CsidCredentials<Production>>(pcsid.ptr, "csid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let language = optional_string(accept_language);
    match run_async(client.clear_standard_invoice(
        invoice,
        pcsid,
        clearance_status,
        language.as_deref(),
    )) {
        Ok(response) => match validation_response_to_json(&response) {
            Ok(json) => FfiResult::ok(FfiString::from(json)),
            Err(message) => FfiResult::err(message),
        },
        Err(message) => FfiResult::err(message),
    }
}
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
    let xml = match required_string(xml, "xml") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match validate_xml_invoice_from_str(&xml, config) {
        Ok(()) => FfiResult::ok(true),
        Err(err) => FfiResult::err(err.to_string()),
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
    let path = match required_string(path, "xml path") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match validate_xml_invoice_from_file(std::path::Path::new(&path), config) {
        Ok(()) => FfiResult::ok(true),
        Err(err) => FfiResult::err(err.to_string()),
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
    let currency_code = match required_string(currency_code, "currency code") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let currency = match parse_currency(&currency_code) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let seller_country_code = match required_string(seller_country_code, "seller country code") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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

    let seller_city = match required_string(seller_city, "seller city") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let seller_street = match required_string(seller_street, "seller street") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let seller_building_number =
        match required_string(seller_building_number, "seller building number") {
            Ok(value) => value,
            Err(message) => return FfiResult::err(message),
        };
    let seller_postal_code = match required_string(seller_postal_code, "seller postal code") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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

    let seller_name = match required_string(seller_name, "seller name") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let seller_vat_id = match required_string(seller_vat_id, "seller vat id") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let seller = match Party::<SellerRole>::new(seller_name, seller_address, seller_vat_id, seller_other) {
        Ok(value) => value,
        Err(err) => return FfiResult::err(err.to_string()),
    };

    let id = match required_string(id, "invoice id") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let uuid = match required_string(uuid, "invoice uuid") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let previous_invoice_hash =
        match required_string(previous_invoice_hash, "previous invoice hash") {
            Ok(value) => value,
            Err(message) => return FfiResult::err(message),
        };
    let payment_means_code = match required_string(payment_means_code, "payment means code") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let builder = match unsafe { builder.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("builder handle is null".to_string()),
    };
    let builder = match borrow_handle_mut::<InvoiceBuilder>(builder.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let builder = match unsafe { builder.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("builder handle is null".to_string()),
    };
    let builder = match borrow_handle_mut::<InvoiceBuilder>(builder.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let builder = match unsafe { builder.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("builder handle is null".to_string()),
    };
    let builder = match borrow_handle_mut::<InvoiceBuilder>(builder.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let builder = match unsafe { builder.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("builder handle is null".to_string()),
    };
    let builder = match borrow_handle_mut::<InvoiceBuilder>(builder.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let description = match required_string(description, "line item description") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let unit_code = match required_string(unit_code, "line item unit code") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let builder = match unsafe { builder.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("builder handle is null".to_string()),
    };
    let builder = match borrow_handle_mut::<InvoiceBuilder>(builder.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let country_code = match required_string(country_code, "buyer country code") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let buyer_country = match parse_country(&country_code) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let city = match required_string(city, "buyer city") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let street = match required_string(street, "buyer street") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let building_number = match required_string(building_number, "buyer building number") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let postal_code = match required_string(postal_code, "buyer postal code") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let name = match required_string(name, "buyer name") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let buyer = match Party::<fatoora_core::invoice::BuyerRole>::new(name, address, optional_string(vat_id), other) {
        Ok(value) => value,
        Err(err) => return FfiResult::err(err.to_string()),
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
    let builder = match unsafe { builder.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("builder handle is null".to_string()),
    };
    let builder = match borrow_handle_mut::<InvoiceBuilder>(builder.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let language = match required_string(language, "note language") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let text = match required_string(text, "note text") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let builder = match unsafe { builder.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("builder handle is null".to_string()),
    };
    let builder = match borrow_handle_mut::<InvoiceBuilder>(builder.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let reason = match required_string(reason, "allowance reason") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    builder.set_allowance(&reason, amount);
    FfiResult::ok(true)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_free(builder: *mut FfiInvoiceBuilder) {
    if builder.is_null() {
        return;
    }
    let builder = unsafe { &mut *builder };
    if builder.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(builder.ptr as *mut InvoiceBuilder)) };
    builder.ptr = std::ptr::null_mut();
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_builder_build(builder: *mut FfiInvoiceBuilder) -> FfiResult<FfiFinalizedInvoice> {
    if builder.is_null() {
        return FfiResult::err("builder handle is null".to_string());
    }
    let handle = unsafe { &mut *builder };
    let builder = match take_handle::<InvoiceBuilder>(&mut handle.ptr, "builder") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    match builder.build() {
        Ok(invoice) => FfiResult::ok(FfiFinalizedInvoice {
            ptr: Box::into_raw(Box::new(invoice)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_parse_finalized_invoice_xml(
    xml: *const c_char,
) -> FfiResult<FfiFinalizedInvoice> {
    let xml = match required_string(xml, "xml") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml(&xml) {
        Ok(invoice) => FfiResult::ok(FfiFinalizedInvoice {
            ptr: Box::into_raw(Box::new(invoice)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_parse_signed_invoice_xml(
    xml: *const c_char,
) -> FfiResult<FfiSignedInvoice> {
    let xml = match required_string(xml, "xml") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match fatoora_core::invoice::xml::parse::parse_signed_invoice_xml(&xml) {
        Ok(invoice) => FfiResult::ok(FfiSignedInvoice {
            ptr: Box::into_raw(Box::new(invoice)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_count(invoice: *mut FfiFinalizedInvoice) -> FfiResult<u64> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(invoice.data().line_items().len() as u64)
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_line_item_count(signed: *mut FfiSignedInvoice) -> FfiResult<u64> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(signed.data().line_items().len() as u64)
}

fn line_item_from_invoice(invoice: &InvoiceData, index: u64) -> Result<&LineItem, String> {
    let idx = usize::try_from(index).map_err(|_| "index out of range".to_string())?;
    invoice
        .line_items()
        .get(idx)
        .ok_or_else(|| "index out of range".to_string())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_line_item_description(
    invoice: *mut FfiFinalizedInvoice,
    index: u64,
) -> FfiResult<FfiString> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
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
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match line_item_from_invoice(signed.data(), index) {
        Ok(item) => FfiResult::ok(item.vat_category() as u8),
        Err(message) => FfiResult::err(message),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_totals_tax_inclusive(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<f64> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(invoice.totals().tax_inclusive_amount())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_totals_tax_amount(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<f64> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(invoice.totals().tax_amount())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_totals_line_extension(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<f64> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(invoice.totals().line_extension())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_totals_allowance_total(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<f64> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(invoice.totals().allowance_total())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_totals_charge_total(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<f64> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(invoice.totals().charge_total())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_totals_taxable_amount(
    invoice: *mut FfiFinalizedInvoice,
) -> FfiResult<f64> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(invoice.totals().taxable_amount())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_totals_tax_inclusive(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<f64> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(signed.totals().tax_inclusive_amount())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_totals_tax_amount(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<f64> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(signed.totals().tax_amount())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_totals_line_extension(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<f64> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(signed.totals().line_extension())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_totals_allowance_total(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<f64> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(signed.totals().allowance_total())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_totals_charge_total(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<f64> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(signed.totals().charge_total())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_totals_taxable_amount(
    signed: *mut FfiSignedInvoice,
) -> FfiResult<f64> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(signed.totals().taxable_amount())
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_flags(invoice: *mut FfiFinalizedInvoice) -> FfiResult<u8> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(flags_to_bits(invoice.data().flags()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_flags(signed: *mut FfiSignedInvoice) -> FfiResult<u8> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(flags_to_bits(signed.data().flags()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_to_xml(invoice: *mut FfiFinalizedInvoice) -> FfiResult<FfiString> {
    let invoice = match unsafe { invoice.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("invoice handle is null".to_string()),
    };
    let invoice = match borrow_handle::<FinalizedInvoice>(invoice.ptr, "invoice") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match invoice.to_xml() {
        Ok(xml) => FfiResult::ok(FfiString::from(xml)),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_free(invoice: *mut FfiFinalizedInvoice) {
    if invoice.is_null() {
        return;
    }
    let invoice = unsafe { &mut *invoice };
    if invoice.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(invoice.ptr as *mut fatoora_core::invoice::FinalizedInvoice)) };
    invoice.ptr = std::ptr::null_mut();
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signer_from_pem(
    cert_pem: *const c_char,
    key_pem: *const c_char,
) -> FfiResult<FfiSigner> {
    let cert_pem = match required_string(cert_pem, "cert pem") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    let key_pem = match required_string(key_pem, "key pem") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    match InvoiceSigner::from_pem(&cert_pem, &key_pem) {
        Ok(signer) => FfiResult::ok(FfiSigner {
            ptr: Box::into_raw(Box::new(signer)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
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
        return FfiResult::err("null der pointers".to_string());
    }
    let cert = unsafe { std::slice::from_raw_parts(cert_der, cert_len) };
    let key = unsafe { std::slice::from_raw_parts(key_der, key_len) };
    match InvoiceSigner::from_der(cert, key) {
        Ok(signer) => FfiResult::ok(FfiSigner {
            ptr: Box::into_raw(Box::new(signer)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signer_free(signer: *mut FfiSigner) {
    if signer.is_null() {
        return;
    }
    let signer = unsafe { &mut *signer };
    if signer.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(signer.ptr as *mut InvoiceSigner)) };
    signer.ptr = std::ptr::null_mut();
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_invoice_sign(
    invoice: *mut FfiFinalizedInvoice,
    signer: *mut FfiSigner,
) -> FfiResult<FfiSignedInvoice> {
    if invoice.is_null() {
        return FfiResult::err("invoice handle is null".to_string());
    }
    let invoice_handle = unsafe { &mut *invoice };
    let invoice = match take_handle::<fatoora_core::invoice::FinalizedInvoice>(
        &mut invoice_handle.ptr,
        "invoice",
    ) {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    let signer = match unsafe { signer.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signer handle is null".to_string()),
    };
    let signer = match borrow_handle::<InvoiceSigner>(signer.ptr, "signer") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };

    match invoice.sign(signer) {
        Ok(signed) => FfiResult::ok(FfiSignedInvoice {
            ptr: Box::into_raw(Box::new(signed)) as *mut std::os::raw::c_void,
        }),
        Err(err) => FfiResult::err(err.to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_xml(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(signed.xml().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_qr(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(signed.qr_code().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_uuid(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(signed.uuid().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_hash(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(signed.invoice_hash().to_string()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_xml_base64(signed: *mut FfiSignedInvoice) -> FfiResult<FfiString> {
    let signed = match unsafe { signed.as_mut() } {
        Some(handle) => handle,
        None => return FfiResult::err("signed invoice handle is null".to_string()),
    };
    let signed = match borrow_handle::<SignedInvoice>(signed.ptr, "signed") {
        Ok(value) => value,
        Err(message) => return FfiResult::err(message),
    };
    FfiResult::ok(FfiString::from(signed.to_xml_base64()))
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_signed_invoice_free(signed: *mut FfiSignedInvoice) {
    if signed.is_null() {
        return;
    }
    let signed = unsafe { &mut *signed };
    if signed.ptr.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(signed.ptr as *mut SignedInvoice)) };
    signed.ptr = std::ptr::null_mut();
}
