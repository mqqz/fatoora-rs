use std::ffi::CString;

use fatoora_ffi::*;

fn cstr(value: &str) -> CString {
    CString::new(value).expect("CString")
}

#[test]
fn config_validate_and_free() {
    unsafe {
        let config = fatoora_config_new(FfiEnvironment::NonProduction);
        assert!(!config.is_null());

        let xml = cstr("<Invoice></Invoice>");
        let result = fatoora_validate_xml_str(config, xml.as_ptr());
        assert!(!result.ok);
        if !result.error.is_null() {
            fatoora_error_free(result.error);
        }

        fatoora_config_free(config);
    }
}

#[test]
fn invoice_builder_roundtrip() {
    unsafe {
        let builder_result = fatoora_invoice_builder_new(
            FfiInvoiceTypeKind::Tax,
            FfiInvoiceSubType::Simplified,
            cstr("INV-1").as_ptr(),
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
            cstr("").as_ptr(),
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
        assert!(builder_result.ok, "builder error");
        let mut builder = builder_result.value;

        let flags_result = fatoora_invoice_builder_set_flags(&mut builder, 0b00001);
        assert!(flags_result.ok);
        let flags_result = fatoora_invoice_builder_enable_flags(&mut builder, 0b00100);
        assert!(flags_result.ok);
        let flags_result = fatoora_invoice_builder_disable_flags(&mut builder, 0b00001);
        assert!(flags_result.ok);

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
            cstr("Test note").as_ptr(),
        );
        assert!(note_result.ok);

        let allowance_result = fatoora_invoice_builder_set_allowance(
            &mut builder,
            cstr("Discount").as_ptr(),
            5.0,
        );
        assert!(allowance_result.ok);

        let add_result = fatoora_invoice_builder_add_line_item(
            &mut builder,
            cstr("Item").as_ptr(),
            1.0,
            cstr("PCE").as_ptr(),
            100.0,
            15.0,
            FfiVatCategory::Standard,
        );
        assert!(add_result.ok, "add line item failed");

        let invoice_result = fatoora_invoice_builder_build(&mut builder);
        assert!(invoice_result.ok, "build failed");
        let mut invoice = invoice_result.value;

        let xml_result = fatoora_invoice_to_xml(&mut invoice);
        assert!(xml_result.ok, "xml failed");
        let xml = std::ffi::CStr::from_ptr(xml_result.value.ptr)
            .to_string_lossy()
            .to_string();
        assert!(xml.contains("<Invoice"));
        fatoora_string_free(xml_result.value);

        let count = fatoora_invoice_line_item_count(&mut invoice);
        assert!(count.ok);
        assert_eq!(count.value, 1);

        let totals = fatoora_invoice_totals_tax_inclusive(&mut invoice);
        assert!(totals.ok);
        assert!(totals.value > 0.0);

        let flags = fatoora_invoice_flags(&mut invoice);
        assert!(flags.ok);

        fatoora_invoice_free(&mut invoice);
        fatoora_invoice_builder_free(&mut builder);
    }
}

#[test]
fn parse_finalized_invoice_xml() {
    unsafe {
        let builder_result = fatoora_invoice_builder_new(
            FfiInvoiceTypeKind::Tax,
            FfiInvoiceSubType::Simplified,
            cstr("INV-2").as_ptr(),
            cstr("123e4567-e89b-12d3-a456-426614174001").as_ptr(),
            1_700_000_000,
            0,
            cstr("SAR").as_ptr(),
            cstr("hash").as_ptr(),
            2,
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
        assert!(builder_result.ok);
        let mut builder = builder_result.value;

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

        let xml_result = fatoora_invoice_to_xml(&mut invoice);
        assert!(xml_result.ok);
        let xml = std::ffi::CStr::from_ptr(xml_result.value.ptr)
            .to_string_lossy()
            .to_string();
        fatoora_string_free(xml_result.value);
        fatoora_invoice_free(&mut invoice);

        let parsed_result = fatoora_parse_finalized_invoice_xml(cstr(&xml).as_ptr());
        assert!(parsed_result.ok);
        let mut parsed = parsed_result.value;

        let count = fatoora_invoice_line_item_count(&mut parsed);
        assert!(count.ok);
        assert_eq!(count.value, 1);

        fatoora_invoice_free(&mut parsed);
        fatoora_invoice_builder_free(&mut builder);
    }
}

#[test]
fn credit_note_requires_reference_and_reason() {
    unsafe {
        let result = fatoora_invoice_builder_new(
            FfiInvoiceTypeKind::CreditNote,
            FfiInvoiceSubType::Simplified,
            cstr("INV-3").as_ptr(),
            cstr("123e4567-e89b-12d3-a456-426614174002").as_ptr(),
            1_700_000_000,
            0,
            cstr("SAR").as_ptr(),
            cstr("hash").as_ptr(),
            3,
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
        assert!(!result.ok);
        if !result.error.is_null() {
            fatoora_error_free(result.error);
        }
    }
}

#[test]
fn credit_note_roundtrip() {
    unsafe {
        let result = fatoora_invoice_builder_new(
            FfiInvoiceTypeKind::CreditNote,
            FfiInvoiceSubType::Simplified,
            cstr("INV-4").as_ptr(),
            cstr("123e4567-e89b-12d3-a456-426614174003").as_ptr(),
            1_700_000_000,
            0,
            cstr("SAR").as_ptr(),
            cstr("hash").as_ptr(),
            4,
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
            cstr("INV-0").as_ptr(),
            cstr("123e4567-e89b-12d3-a456-426614174000").as_ptr(),
            cstr("2023-11-13").as_ptr(),
            cstr("Correction").as_ptr(),
        );
        assert!(result.ok);
        let mut builder = result.value;

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

        let xml_result = fatoora_invoice_to_xml(&mut invoice);
        assert!(xml_result.ok);
        fatoora_string_free(xml_result.value);

        fatoora_invoice_free(&mut invoice);
        fatoora_invoice_builder_free(&mut builder);
    }
}

#[test]
fn invalid_utf8_returns_error() {
    unsafe {
        let invalid = vec![0xff, 0x00];
        let ptr = invalid.as_ptr() as *const std::os::raw::c_char;
        let result = fatoora_csr_properties_parse(ptr);
        assert!(!result.ok);
        if !result.error.is_null() {
            fatoora_error_free(result.error);
        }
    }
}

#[test]
fn null_handles_return_error() {
    unsafe {
        let add_result = fatoora_invoice_builder_add_line_item(
            std::ptr::null_mut(),
            cstr("Item").as_ptr(),
            1.0,
            cstr("PCE").as_ptr(),
            100.0,
            15.0,
            FfiVatCategory::Standard,
        );
        assert!(!add_result.ok);
        if !add_result.error.is_null() {
            fatoora_error_free(add_result.error);
        }

        let validate_result = fatoora_validate_xml_str(std::ptr::null_mut(), cstr("<x/>").as_ptr());
        assert!(!validate_result.ok);
        if !validate_result.error.is_null() {
            fatoora_error_free(validate_result.error);
        }
    }
}

#[test]
fn config_with_xsd_null_uses_default() {
    unsafe {
        let config = fatoora_config_with_xsd(FfiEnvironment::NonProduction, std::ptr::null());
        assert!(!config.is_null());
        fatoora_config_free(config);
    }
}

#[test]
fn signer_errors_on_invalid_inputs() {
    unsafe {
        let bad_cert = cstr("not a cert");
        let bad_key = cstr("not a key");
        let result = fatoora_signer_from_pem(bad_cert.as_ptr(), bad_key.as_ptr());
        assert!(!result.ok);
        if !result.error.is_null() {
            fatoora_error_free(result.error);
        }

        let result = fatoora_signer_from_der(std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!result.ok);
        if !result.error.is_null() {
            fatoora_error_free(result.error);
        }
    }
}

#[test]
fn signing_key_from_der_null_errors() {
    unsafe {
        let result = fatoora_signing_key_from_der(std::ptr::null(), 0);
        assert!(!result.ok);
        if !result.error.is_null() {
            fatoora_error_free(result.error);
        }
    }
}

#[test]
fn parse_signed_invoice_xml_invalid() {
    unsafe {
        let result = fatoora_parse_signed_invoice_xml(cstr("<nope/>").as_ptr());
        assert!(!result.ok);
        if !result.error.is_null() {
            fatoora_error_free(result.error);
        }
    }
}
