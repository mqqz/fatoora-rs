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

pub use error::{FfiResult, fatoora_error_free};
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

            let report_result = fatoora_zatca_report_simplified_invoice(
                &mut ffi_client,
                &mut ffi_simplified,
                &mut pcsid,
                false,
                cstr("ar").as_ptr(),
            );
            assert!(report_result.ok);
            fatoora_string_free(report_result.value);

            let standard =
                build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Standard), &signer);
            let mut ffi_standard = FfiSignedInvoice {
                ptr: Box::into_raw(Box::new(standard)) as *mut c_void,
            };

            let clear_result = fatoora_zatca_clear_standard_invoice(
                &mut ffi_client,
                &mut ffi_standard,
                &mut pcsid,
                true,
                std::ptr::null(),
            );
            assert!(clear_result.ok);
            fatoora_string_free(clear_result.value);

            let ccsid_result = fatoora_csid_compliance_new(
                FfiEnvironment::NonProduction,
                false,
                0,
                cstr("token").as_ptr(),
                cstr("secret").as_ptr(),
            );
            assert!(ccsid_result.ok);
            let mut ccsid = ccsid_result.value;

            let compliance_result =
                fatoora_zatca_check_compliance(&mut ffi_client, &mut ffi_simplified, &mut ccsid);
            assert!(compliance_result.ok);
            fatoora_string_free(compliance_result.value);

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
