from __future__ import annotations

import os
from pathlib import Path

from cffi import FFI

_CDEF_PREAMBLE = """
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long size_t;
typedef unsigned long uintptr_t;
typedef _Bool bool;
"""


_CDEF = """
typedef struct { void* ptr; } FfiConfig;
typedef struct { void* ptr; } FfiInvoiceBuilder;
typedef struct { void* ptr; } FfiFinalizedInvoice;
typedef struct { void* ptr; } FfiSignedInvoice;
typedef struct { void* ptr; } FfiSigner;
typedef struct { char* ptr; } FfiString;
typedef struct { void* ptr; } FfiCsrProperties;
typedef struct { void* ptr; } FfiCsr;
typedef struct { void* ptr; } FfiSigningKey;
typedef struct { FfiCsr csr; FfiSigningKey key; } FfiCsrBundle;
typedef struct { void* ptr; } FfiZatcaClient;
typedef struct { void* ptr; } FfiCsidCompliance;
typedef struct { void* ptr; } FfiCsidProduction;

typedef struct { _Bool ok; FfiInvoiceBuilder value; char* error; } FfiResult_FfiInvoiceBuilder;
typedef struct { _Bool ok; FfiFinalizedInvoice value; char* error; } FfiResult_FfiFinalizedInvoice;
typedef struct { _Bool ok; FfiSignedInvoice value; char* error; } FfiResult_FfiSignedInvoice;
typedef struct { _Bool ok; FfiSigner value; char* error; } FfiResult_FfiSigner;
typedef struct { _Bool ok; FfiString value; char* error; } FfiResult_FfiString;
typedef struct { _Bool ok; FfiCsrProperties value; char* error; } FfiResult_FfiCsrProperties;
typedef struct { _Bool ok; FfiCsr value; char* error; } FfiResult_FfiCsr;
typedef struct { _Bool ok; FfiSigningKey value; char* error; } FfiResult_FfiSigningKey;
typedef struct { _Bool ok; FfiCsrBundle value; char* error; } FfiResult_FfiCsrBundle;
typedef struct { _Bool ok; FfiZatcaClient value; char* error; } FfiResult_FfiZatcaClient;
typedef struct { _Bool ok; FfiCsidCompliance value; char* error; } FfiResult_FfiCsidCompliance;
typedef struct { _Bool ok; FfiCsidProduction value; char* error; } FfiResult_FfiCsidProduction;
typedef struct { _Bool ok; _Bool value; char* error; } FfiResult_bool;
typedef struct { _Bool ok; unsigned long long value; char* error; } FfiResult_u64;
typedef struct { _Bool ok; unsigned char value; char* error; } FfiResult_u8;
typedef struct { _Bool ok; double value; char* error; } FfiResult_f64;

void fatoora_error_free(char* error);
void fatoora_string_free(FfiString value);

FfiConfig* fatoora_config_new(int env);
FfiConfig* fatoora_config_with_xsd(int env, const char* path);
void fatoora_config_free(FfiConfig* cfg);

FfiResult_FfiCsrProperties fatoora_csr_properties_parse(const char* path);
void fatoora_csr_properties_free(FfiCsrProperties* props);

FfiResult_FfiSigningKey fatoora_signing_key_from_pem(const char* pem);
FfiResult_FfiSigningKey fatoora_signing_key_from_der(const unsigned char* der, uintptr_t len);
FfiResult_FfiString fatoora_signing_key_to_pem(FfiSigningKey* key);
void fatoora_signing_key_free(FfiSigningKey* key);

FfiResult_FfiCsrBundle fatoora_csr_build_with_rng(FfiCsrProperties* props, int env);
FfiResult_FfiCsr fatoora_csr_build(FfiCsrProperties* props, FfiSigningKey* key, int env);
FfiResult_FfiString fatoora_csr_to_base64(FfiCsr* csr);
FfiResult_FfiString fatoora_csr_to_pem_base64(FfiCsr* csr);
void fatoora_csr_free(FfiCsr* csr);

FfiResult_FfiZatcaClient fatoora_zatca_client_new(FfiConfig* cfg);
void fatoora_zatca_client_free(FfiZatcaClient* client);

FfiResult_FfiCsidCompliance fatoora_csid_compliance_new(
    int env,
    _Bool has_request_id,
    unsigned long long request_id,
    const char* token,
    const char* secret
);
FfiResult_FfiCsidProduction fatoora_csid_production_new(
    int env,
    _Bool has_request_id,
    unsigned long long request_id,
    const char* token,
    const char* secret
);
FfiResult_u64 fatoora_csid_compliance_request_id(FfiCsidCompliance* creds);
FfiResult_u64 fatoora_csid_production_request_id(FfiCsidProduction* creds);
FfiResult_FfiString fatoora_csid_compliance_token(FfiCsidCompliance* creds);
FfiResult_FfiString fatoora_csid_compliance_secret(FfiCsidCompliance* creds);
FfiResult_FfiString fatoora_csid_production_token(FfiCsidProduction* creds);
FfiResult_FfiString fatoora_csid_production_secret(FfiCsidProduction* creds);
void fatoora_csid_compliance_free(FfiCsidCompliance* creds);
void fatoora_csid_production_free(FfiCsidProduction* creds);

FfiResult_FfiCsidCompliance fatoora_zatca_post_csr_for_ccsid(
    FfiZatcaClient* client,
    FfiCsr* csr,
    const char* otp
);
FfiResult_FfiCsidProduction fatoora_zatca_post_ccsid_for_pcsid(
    FfiZatcaClient* client,
    FfiCsidCompliance* ccsid
);
FfiResult_FfiCsidProduction fatoora_zatca_renew_csid(
    FfiZatcaClient* client,
    FfiCsidProduction* pcsid,
    FfiCsr* csr,
    const char* otp,
    const char* accept_language
);
FfiResult_FfiString fatoora_zatca_check_compliance(
    FfiZatcaClient* client,
    FfiSignedInvoice* invoice,
    FfiCsidCompliance* ccsid
);
FfiResult_FfiString fatoora_zatca_report_simplified_invoice(
    FfiZatcaClient* client,
    FfiSignedInvoice* invoice,
    FfiCsidProduction* pcsid,
    _Bool clearance_status,
    const char* accept_language
);
FfiResult_FfiString fatoora_zatca_clear_standard_invoice(
    FfiZatcaClient* client,
    FfiSignedInvoice* invoice,
    FfiCsidProduction* pcsid,
    _Bool clearance_status,
    const char* accept_language
);

FfiResult_bool fatoora_validate_xml_str(FfiConfig* cfg, const char* xml);
FfiResult_bool fatoora_validate_xml_file(FfiConfig* cfg, const char* path);

FfiResult_FfiInvoiceBuilder fatoora_invoice_builder_new(
    int invoice_type_kind,
    int invoice_sub_type,
    const char* id,
    const char* uuid,
    long long issue_timestamp,
    unsigned int issue_nanos,
    const char* currency_code,
    const char* previous_invoice_hash,
    unsigned long long invoice_counter,
    const char* payment_means_code,
    int vat_category,
    const char* seller_name,
    const char* seller_country_code,
    const char* seller_city,
    const char* seller_street,
    const char* seller_additional_street,
    const char* seller_building_number,
    const char* seller_additional_number,
    const char* seller_postal_code,
    const char* seller_subdivision,
    const char* seller_district,
    const char* seller_vat_id,
    const char* seller_other_id,
    const char* seller_other_id_scheme,
    const char* original_invoice_id,
    const char* original_invoice_uuid,
    const char* original_invoice_issue_date,
    const char* original_invoice_reason
);

FfiResult_bool fatoora_invoice_builder_add_line_item(
    FfiInvoiceBuilder* builder,
    const char* description,
    double quantity,
    const char* unit_code,
    double unit_price,
    double vat_rate,
    int vat_category
);

FfiResult_bool fatoora_invoice_builder_set_buyer(
    FfiInvoiceBuilder* builder,
    const char* name,
    const char* country_code,
    const char* city,
    const char* street,
    const char* additional_street,
    const char* building_number,
    const char* additional_number,
    const char* postal_code,
    const char* subdivision,
    const char* district,
    const char* vat_id,
    const char* other_id_value,
    const char* other_id_scheme
);

FfiResult_bool fatoora_invoice_builder_set_note(
    FfiInvoiceBuilder* builder,
    const char* language,
    const char* text
);

FfiResult_bool fatoora_invoice_builder_set_allowance(
    FfiInvoiceBuilder* builder,
    const char* reason,
    double amount
);

FfiResult_bool fatoora_invoice_builder_set_flags(
    FfiInvoiceBuilder* builder,
    unsigned char flags
);
FfiResult_bool fatoora_invoice_builder_enable_flags(
    FfiInvoiceBuilder* builder,
    unsigned char flags
);
FfiResult_bool fatoora_invoice_builder_disable_flags(
    FfiInvoiceBuilder* builder,
    unsigned char flags
);

FfiResult_FfiFinalizedInvoice fatoora_invoice_builder_build(FfiInvoiceBuilder* builder);
void fatoora_invoice_builder_free(FfiInvoiceBuilder* builder);

FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml(const char* xml);
FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char* xml);

FfiResult_u64 fatoora_invoice_line_item_count(FfiFinalizedInvoice* invoice);
FfiResult_u64 fatoora_signed_invoice_line_item_count(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_invoice_line_item_description(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_FfiString fatoora_invoice_line_item_unit_code(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_quantity(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_unit_price(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_total_amount(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_vat_rate(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_vat_amount(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_u8 fatoora_invoice_line_item_vat_category(FfiFinalizedInvoice* invoice, unsigned long long index);

FfiResult_FfiString fatoora_signed_invoice_line_item_description(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_FfiString fatoora_signed_invoice_line_item_unit_code(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_quantity(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_unit_price(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_total_amount(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_vat_rate(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_vat_amount(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_u8 fatoora_signed_invoice_line_item_vat_category(FfiSignedInvoice* signed, unsigned long long index);

FfiResult_f64 fatoora_invoice_totals_tax_inclusive(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_tax_amount(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_line_extension(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_allowance_total(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_charge_total(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_taxable_amount(FfiFinalizedInvoice* invoice);

FfiResult_f64 fatoora_signed_invoice_totals_tax_inclusive(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_tax_amount(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_line_extension(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_allowance_total(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_charge_total(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_taxable_amount(FfiSignedInvoice* signed);

FfiResult_u8 fatoora_invoice_flags(FfiFinalizedInvoice* invoice);
FfiResult_u8 fatoora_signed_invoice_flags(FfiSignedInvoice* signed);

FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice* invoice);
void fatoora_invoice_free(FfiFinalizedInvoice* invoice);

FfiResult_FfiSigner fatoora_signer_from_pem(const char* cert_pem, const char* key_pem);
FfiResult_FfiSigner fatoora_signer_from_der(const unsigned char* cert_der, uintptr_t cert_len, const unsigned char* key_der, uintptr_t key_len);
void fatoora_signer_free(FfiSigner* signer);
FfiResult_FfiSignedInvoice fatoora_invoice_sign(FfiFinalizedInvoice* invoice, FfiSigner* signer);

FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_xml_base64(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_qr(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_uuid(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_hash(FfiSignedInvoice* signed);
void fatoora_signed_invoice_free(FfiSignedInvoice* signed);
"""


class FfiLibrary:
    def __init__(self, path: str | None = None) -> None:
        if path is None:
            path = self._default_library_path()
        self.ffi = FFI()
        self.ffi.cdef(_load_cdef())
        self.lib = self.ffi.dlopen(path)

    @staticmethod
    def _default_library_path() -> str:
        env_path = os.environ.get("FATOORA_FFI_PATH")
        if env_path:
            return env_path

        base = Path(__file__).resolve().parent
        names = ("libfatoora_ffi.so", "libfatoora_ffi.dylib", "fatoora_ffi.dll")
        for name in names:
            candidate = base / name
            if candidate.exists():
                return str(candidate)

        repo_root = base.parents[2]
        for name in names:
            for build in ("release", "debug"):
                candidate = repo_root / "target" / build / name
                if candidate.exists():
                    return str(candidate)

        raise FileNotFoundError(
            "fatoora-ffi shared library not found. Build with "
            "`cargo build -p fatoora-ffi --release` or set FATOORA_FFI_PATH."
        )


def _load_cdef() -> str:
    header = _find_header()
    if header is None:
        return _CDEF
    try:
        return _CDEF_PREAMBLE + _cdef_from_header(header)
    except OSError:
        return _CDEF


def _find_header() -> str | None:
    env_path = os.environ.get("FATOORA_FFI_HEADER")
    if env_path:
        return env_path

    base = Path(__file__).resolve().parent
    candidate = base / "fatoora_ffi.h"
    if candidate.exists():
        return str(candidate)

    repo_root = base.parents[2]
    candidate = repo_root / "fatoora-ffi" / "include" / "fatoora_ffi.h"
    if candidate.exists():
        return str(candidate)

    return None


def _cdef_from_header(path: str) -> str:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_extern = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("extern \"C\""):
            in_extern = True
            continue
        if in_extern and stripped.startswith("}"):
            in_extern = False
            continue
        if stripped.startswith("namespace "):
            continue
        if stripped.startswith("} // namespace"):
            continue
        out.append(line)
    return "\n".join(out)
