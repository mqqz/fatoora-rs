from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Optional

from ._lib import FfiLibrary
from .errors import FfiError


class Environment(IntEnum):
    NON_PRODUCTION = 0
    SIMULATION = 1
    PRODUCTION = 2


class InvoiceTypeKind(IntEnum):
    TAX = 0
    PREPAYMENT = 1
    CREDIT_NOTE = 2
    DEBIT_NOTE = 3


class InvoiceSubType(IntEnum):
    STANDARD = 0
    SIMPLIFIED = 1


class VatCategory(IntEnum):
    EXEMPT = 0
    STANDARD = 1
    ZERO = 2
    OUT_OF_SCOPE = 3


class InvoiceFlag(IntEnum):
    THIRD_PARTY = 0b00001
    NOMINAL = 0b00010
    EXPORT = 0b00100
    SUMMARY = 0b01000
    SELF_BILLED = 0b10000


@dataclass(frozen=True)
class InvoiceLineItem:
    description: str
    unit_code: str
    quantity: float
    unit_price: float
    total_amount: float
    vat_rate: float
    vat_amount: float
    vat_category: VatCategory


@dataclass(frozen=True)
class InvoiceTotals:
    tax_inclusive: float
    tax_amount: float
    line_extension: float
    allowance_total: float
    charge_total: float
    taxable_amount: float


def _opt_cstr(ffi, value: Optional[str]):
    if value is None:
        return ffi.NULL
    return value.encode("utf-8")


def _as_bytes(value: str) -> bytes:
    return value.encode("utf-8")


def _flags_from_bits(bits: int) -> set[InvoiceFlag]:
    return {flag for flag in InvoiceFlag if bits & flag.value}


def _json_or_raise(ffi, lib, result) -> dict:
    payload = _decode_string(ffi, lib, _result_or_raise(ffi, lib, result))
    return json.loads(payload)


def _decode_error(ffi, lib, err_ptr) -> str:
    if not err_ptr:
        return "unknown error"
    message = ffi.string(err_ptr)
    lib.fatoora_error_free(err_ptr)
    return message.decode("utf-8") if message else "unknown error"


def _decode_string(ffi, lib, value) -> str:
    raw = ffi.string(value.ptr)
    lib.fatoora_string_free(value)
    return raw.decode("utf-8") if raw else ""


def _result_or_raise(ffi, lib, result, value_attr: str = "value"):
    if not result.ok:
        raise FfiError(_decode_error(ffi, lib, result.error))
    return getattr(result, value_attr)


def _wrap_handle(ffi, ctype: str, value):
    return ffi.new(f"{ctype} *", value)


class _FfiBindings:
    _instance: Optional["_FfiBindings"] = None

    def __init__(self) -> None:
        self._ffi = FfiLibrary()
        self.ffi = self._ffi.ffi
        self.lib = self._ffi.lib

    @classmethod
    def instance(cls) -> "_FfiBindings":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


@dataclass
class Config:
    env: Environment = Environment.NON_PRODUCTION
    _handle: Optional[Any] = None

    def __post_init__(self) -> None:
        if self._handle is not None:
            return
        bindings = _FfiBindings.instance()
        self._handle = bindings.lib.fatoora_config_new(int(self.env))

    @classmethod
    def with_xsd_path(cls, env: Environment, path: str) -> "Config":
        bindings = _FfiBindings.instance()
        handle = bindings.lib.fatoora_config_with_xsd(int(env), _as_bytes(path))
        return cls(env=env, _handle=handle)

    def validate_xml(self, xml: str) -> bool:
        return validate_xml_str(self, xml)

    def validate_xml_file(self, path: str) -> bool:
        return validate_xml_file(self, path)

    def close(self) -> None:
        if self._handle:
            _FfiBindings.instance().lib.fatoora_config_free(self._handle)
            self._handle = None

    def __enter__(self) -> "Config":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


@dataclass
class Signer:
    _handle: Optional[Any] = None

    @classmethod
    def from_pem(cls, cert_pem: str, key_pem: str) -> "Signer":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signer_from_pem(
            _as_bytes(cert_pem), _as_bytes(key_pem)
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiSigner",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    @classmethod
    def from_der(cls, cert_der: bytes, key_der: bytes) -> "Signer":
        bindings = _FfiBindings.instance()
        cert_buf = bytes(cert_der)
        key_buf = bytes(key_der)
        result = bindings.lib.fatoora_signer_from_der(
            cert_buf,
            len(cert_buf),
            key_buf,
            len(key_buf),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiSigner",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_signer_free(self._handle)
            self._handle = None

    def __enter__(self) -> "Signer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class SigningKey:
    _handle: Optional[Any] = None

    @classmethod
    def from_pem(cls, pem: str) -> "SigningKey":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signing_key_from_pem(_as_bytes(pem))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiSigningKey",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    @classmethod
    def from_der(cls, der: bytes) -> "SigningKey":
        bindings = _FfiBindings.instance()
        der_buf = bytes(der)
        result = bindings.lib.fatoora_signing_key_from_der(der_buf, len(der_buf))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiSigningKey",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def to_pem(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signing_key_to_pem(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_signing_key_free(self._handle)
            self._handle = None

    def __enter__(self) -> "SigningKey":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class CsrProperties:
    _handle: Optional[Any] = None

    @classmethod
    def parse(cls, path: str) -> "CsrProperties":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_properties_parse(_as_bytes(path))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsrProperties",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def build_with_rng(self, env: Environment) -> "CsrBundle":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_build_with_rng(self._handle, int(env))
        bundle = _result_or_raise(bindings.ffi, bindings.lib, result)
        csr = Csr(_wrap_handle(bindings.ffi, "FfiCsr", bundle.csr))
        key = SigningKey(_wrap_handle(bindings.ffi, "FfiSigningKey", bundle.key))
        return CsrBundle(csr=csr, key=key)

    def build(self, key: SigningKey, env: Environment) -> "Csr":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_build(self._handle, key._handle, int(env))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsr",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return Csr(handle)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_csr_properties_free(self._handle)
            self._handle = None

    def __enter__(self) -> "CsrProperties":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class Csr:
    _handle: Any

    def to_base64(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_to_base64(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def to_pem_base64(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_to_pem_base64(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_csr_free(self._handle)
            self._handle = None

    def __enter__(self) -> "Csr":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass(frozen=True)
class CsrBundle:
    csr: Csr
    key: SigningKey


@dataclass
class CsidCompliance:
    _handle: Any

    @classmethod
    def new(
        cls,
        env: Environment,
        token: str,
        secret: str,
        request_id: Optional[int] = None,
    ) -> "CsidCompliance":
        bindings = _FfiBindings.instance()
        has_request_id = request_id is not None
        result = bindings.lib.fatoora_csid_compliance_new(
            int(env),
            bool(has_request_id),
            int(request_id or 0),
            _as_bytes(token),
            _as_bytes(secret),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsidCompliance",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def request_id(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_compliance_request_id(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def token(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_compliance_token(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def secret(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_compliance_secret(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_csid_compliance_free(self._handle)
            self._handle = None

    def __enter__(self) -> "CsidCompliance":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class CsidProduction:
    _handle: Any

    @classmethod
    def new(
        cls,
        env: Environment,
        token: str,
        secret: str,
        request_id: Optional[int] = None,
    ) -> "CsidProduction":
        bindings = _FfiBindings.instance()
        has_request_id = request_id is not None
        result = bindings.lib.fatoora_csid_production_new(
            int(env),
            bool(has_request_id),
            int(request_id or 0),
            _as_bytes(token),
            _as_bytes(secret),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsidProduction",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def request_id(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_production_request_id(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def token(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_production_token(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def secret(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_production_secret(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_csid_production_free(self._handle)
            self._handle = None

    def __enter__(self) -> "CsidProduction":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class ZatcaClient:
    def __init__(self, config: Config) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_client_new(config._handle)
        self._handle = _wrap_handle(
            bindings.ffi,
            "FfiZatcaClient",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )

    def post_csr_for_ccsid(self, csr: Csr, otp: str) -> CsidCompliance:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_post_csr_for_ccsid(
            self._handle, csr._handle, _as_bytes(otp)
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsidCompliance",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return CsidCompliance(handle)

    def post_ccsid_for_pcsid(self, ccsid: CsidCompliance) -> CsidProduction:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_post_ccsid_for_pcsid(self._handle, ccsid._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsidProduction",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return CsidProduction(handle)

    def renew_csid(
        self,
        pcsid: CsidProduction,
        csr: Csr,
        otp: str,
        accept_language: Optional[str] = None,
    ) -> CsidProduction:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_renew_csid(
            self._handle,
            pcsid._handle,
            csr._handle,
            _as_bytes(otp),
            _opt_cstr(bindings.ffi, accept_language),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsidProduction",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return CsidProduction(handle)

    def check_compliance(self, invoice: "SignedInvoice", ccsid: CsidCompliance) -> dict:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_check_compliance(
            self._handle, invoice._handle, ccsid._handle
        )
        return _json_or_raise(bindings.ffi, bindings.lib, result)

    def report_simplified_invoice(
        self,
        invoice: "SignedInvoice",
        pcsid: CsidProduction,
        clearance_status: bool,
        accept_language: Optional[str] = None,
    ) -> dict:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_report_simplified_invoice(
            self._handle,
            invoice._handle,
            pcsid._handle,
            bool(clearance_status),
            _opt_cstr(bindings.ffi, accept_language),
        )
        return _json_or_raise(bindings.ffi, bindings.lib, result)

    def clear_standard_invoice(
        self,
        invoice: "SignedInvoice",
        pcsid: CsidProduction,
        clearance_status: bool,
        accept_language: Optional[str] = None,
    ) -> dict:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_clear_standard_invoice(
            self._handle,
            invoice._handle,
            pcsid._handle,
            bool(clearance_status),
            _opt_cstr(bindings.ffi, accept_language),
        )
        return _json_or_raise(bindings.ffi, bindings.lib, result)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if getattr(self, "_handle", None) and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_zatca_client_free(self._handle)
            self._handle = None

    def __enter__(self) -> "ZatcaClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class SignedInvoice:
    _handle: Any

    def xml(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_xml(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def xml_base64(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_xml_base64(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def qr(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_qr(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def uuid(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_uuid(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def invoice_hash(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_hash(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def line_item_count(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_line_item_count(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def _line_item_string(self, func, index: int) -> str:
        bindings = _FfiBindings.instance()
        result = func(self._handle, int(index))
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def _line_item_f64(self, func, index: int) -> float:
        bindings = _FfiBindings.instance()
        result = func(self._handle, int(index))
        return float(_result_or_raise(bindings.ffi, bindings.lib, result))

    def _line_item_vat_category(self, func, index: int) -> VatCategory:
        bindings = _FfiBindings.instance()
        result = func(self._handle, int(index))
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return VatCategory(value)

    def line_item(self, index: int) -> InvoiceLineItem:
        bindings = _FfiBindings.instance()
        return InvoiceLineItem(
            description=self._line_item_string(
                bindings.lib.fatoora_signed_invoice_line_item_description, index
            ),
            unit_code=self._line_item_string(
                bindings.lib.fatoora_signed_invoice_line_item_unit_code, index
            ),
            quantity=self._line_item_f64(
                bindings.lib.fatoora_signed_invoice_line_item_quantity, index
            ),
            unit_price=self._line_item_f64(
                bindings.lib.fatoora_signed_invoice_line_item_unit_price, index
            ),
            total_amount=self._line_item_f64(
                bindings.lib.fatoora_signed_invoice_line_item_total_amount, index
            ),
            vat_rate=self._line_item_f64(
                bindings.lib.fatoora_signed_invoice_line_item_vat_rate, index
            ),
            vat_amount=self._line_item_f64(
                bindings.lib.fatoora_signed_invoice_line_item_vat_amount, index
            ),
            vat_category=self._line_item_vat_category(
                bindings.lib.fatoora_signed_invoice_line_item_vat_category, index
            ),
        )

    def line_items(self) -> list[InvoiceLineItem]:
        return [self.line_item(i) for i in range(self.line_item_count())]

    def totals(self) -> InvoiceTotals:
        bindings = _FfiBindings.instance()
        return InvoiceTotals(
            tax_inclusive=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_signed_invoice_totals_tax_inclusive(self._handle),
                )
            ),
            tax_amount=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_signed_invoice_totals_tax_amount(self._handle),
                )
            ),
            line_extension=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_signed_invoice_totals_line_extension(self._handle),
                )
            ),
            allowance_total=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_signed_invoice_totals_allowance_total(self._handle),
                )
            ),
            charge_total=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_signed_invoice_totals_charge_total(self._handle),
                )
            ),
            taxable_amount=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_signed_invoice_totals_taxable_amount(self._handle),
                )
            ),
        )

    def flags_raw(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_flags(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def flags(self) -> set[InvoiceFlag]:
        return _flags_from_bits(self.flags_raw())

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_signed_invoice_free(self._handle)
            self._handle = None

    @classmethod
    def from_xml(cls, xml: str) -> "SignedInvoice":
        return parse_signed_invoice_xml(xml)

    def __enter__(self) -> "SignedInvoice":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class Invoice:
    _handle: Any

    def xml(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_to_xml(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def sign(self, signer: Signer) -> SignedInvoice:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_sign(self._handle, signer._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiSignedInvoice",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return SignedInvoice(handle)

    def line_item_count(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_line_item_count(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def _line_item_string(self, func, index: int) -> str:
        bindings = _FfiBindings.instance()
        result = func(self._handle, int(index))
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def _line_item_f64(self, func, index: int) -> float:
        bindings = _FfiBindings.instance()
        result = func(self._handle, int(index))
        return float(_result_or_raise(bindings.ffi, bindings.lib, result))

    def _line_item_vat_category(self, func, index: int) -> VatCategory:
        bindings = _FfiBindings.instance()
        result = func(self._handle, int(index))
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return VatCategory(value)

    def line_item(self, index: int) -> InvoiceLineItem:
        bindings = _FfiBindings.instance()
        return InvoiceLineItem(
            description=self._line_item_string(
                bindings.lib.fatoora_invoice_line_item_description, index
            ),
            unit_code=self._line_item_string(
                bindings.lib.fatoora_invoice_line_item_unit_code, index
            ),
            quantity=self._line_item_f64(
                bindings.lib.fatoora_invoice_line_item_quantity, index
            ),
            unit_price=self._line_item_f64(
                bindings.lib.fatoora_invoice_line_item_unit_price, index
            ),
            total_amount=self._line_item_f64(
                bindings.lib.fatoora_invoice_line_item_total_amount, index
            ),
            vat_rate=self._line_item_f64(
                bindings.lib.fatoora_invoice_line_item_vat_rate, index
            ),
            vat_amount=self._line_item_f64(
                bindings.lib.fatoora_invoice_line_item_vat_amount, index
            ),
            vat_category=self._line_item_vat_category(
                bindings.lib.fatoora_invoice_line_item_vat_category, index
            ),
        )

    def line_items(self) -> list[InvoiceLineItem]:
        return [self.line_item(i) for i in range(self.line_item_count())]

    def totals(self) -> InvoiceTotals:
        bindings = _FfiBindings.instance()
        return InvoiceTotals(
            tax_inclusive=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_invoice_totals_tax_inclusive(self._handle),
                )
            ),
            tax_amount=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_invoice_totals_tax_amount(self._handle),
                )
            ),
            line_extension=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_invoice_totals_line_extension(self._handle),
                )
            ),
            allowance_total=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_invoice_totals_allowance_total(self._handle),
                )
            ),
            charge_total=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_invoice_totals_charge_total(self._handle),
                )
            ),
            taxable_amount=float(
                _result_or_raise(
                    bindings.ffi,
                    bindings.lib,
                    bindings.lib.fatoora_invoice_totals_taxable_amount(self._handle),
                )
            ),
        )

    def flags_raw(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_flags(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def flags(self) -> set[InvoiceFlag]:
        return _flags_from_bits(self.flags_raw())

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_invoice_free(self._handle)
            self._handle = None

    @classmethod
    def from_xml(cls, xml: str) -> "Invoice":
        return parse_invoice_xml(xml)

    def __enter__(self) -> "Invoice":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def parse_invoice_xml(xml: str) -> Invoice:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_parse_finalized_invoice_xml(_as_bytes(xml))
    handle = _wrap_handle(
        bindings.ffi,
        "FfiFinalizedInvoice",
        _result_or_raise(bindings.ffi, bindings.lib, result),
    )
    return Invoice(handle)


def parse_signed_invoice_xml(xml: str) -> SignedInvoice:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_parse_signed_invoice_xml(_as_bytes(xml))
    handle = _wrap_handle(
        bindings.ffi,
        "FfiSignedInvoice",
        _result_or_raise(bindings.ffi, bindings.lib, result),
    )
    return SignedInvoice(handle)


def validate_xml_str(config: Config, xml: str) -> bool:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_validate_xml_str(config._handle, _as_bytes(xml))
    return bool(_result_or_raise(bindings.ffi, bindings.lib, result))


def validate_xml_file(config: Config, path: str) -> bool:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_validate_xml_file(config._handle, _as_bytes(path))
    return bool(_result_or_raise(bindings.ffi, bindings.lib, result))


@dataclass
class InvoiceBuilder:
    _handle: Any

    @classmethod
    def new(
        cls,
        invoice_type: InvoiceTypeKind,
        invoice_subtype: InvoiceSubType,
        invoice_id: str,
        uuid: str,
        issue_datetime: datetime,
        currency_code: str,
        previous_invoice_hash: str,
        invoice_counter: int,
        payment_means_code: str,
        vat_category: VatCategory,
        seller_name: str,
        seller_country_code: str,
        seller_city: str,
        seller_street: str,
        seller_building_number: str,
        seller_postal_code: str,
        seller_vat_id: str,
        seller_additional_street: Optional[str] = None,
        seller_additional_number: Optional[str] = None,
        seller_subdivision: Optional[str] = None,
        seller_district: Optional[str] = None,
        seller_other_id: Optional[str] = None,
        seller_other_id_scheme: Optional[str] = None,
        original_invoice_id: Optional[str] = None,
        original_invoice_uuid: Optional[str] = None,
        original_invoice_issue_date: Optional[str] = None,
        original_invoice_reason: Optional[str] = None,
    ) -> "InvoiceBuilder":
        if issue_datetime.tzinfo is None:
            issue_datetime = issue_datetime.replace(tzinfo=timezone.utc)
        issue_datetime = issue_datetime.astimezone(timezone.utc)
        seconds = int(issue_datetime.timestamp())
        nanos = int(issue_datetime.microsecond * 1000)

        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_new(
            int(invoice_type),
            int(invoice_subtype),
            _as_bytes(invoice_id),
            _as_bytes(uuid),
            seconds,
            nanos,
            _as_bytes(currency_code),
            _as_bytes(previous_invoice_hash),
            int(invoice_counter),
            _as_bytes(payment_means_code),
            int(vat_category),
            _as_bytes(seller_name),
            _as_bytes(seller_country_code),
            _as_bytes(seller_city),
            _as_bytes(seller_street),
            _opt_cstr(bindings.ffi, seller_additional_street),
            _as_bytes(seller_building_number),
            _opt_cstr(bindings.ffi, seller_additional_number),
            _as_bytes(seller_postal_code),
            _opt_cstr(bindings.ffi, seller_subdivision),
            _opt_cstr(bindings.ffi, seller_district),
            _as_bytes(seller_vat_id),
            _opt_cstr(bindings.ffi, seller_other_id),
            _opt_cstr(bindings.ffi, seller_other_id_scheme),
            _opt_cstr(bindings.ffi, original_invoice_id),
            _opt_cstr(bindings.ffi, original_invoice_uuid),
            _opt_cstr(bindings.ffi, original_invoice_issue_date),
            _opt_cstr(bindings.ffi, original_invoice_reason),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiInvoiceBuilder",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def add_line_item(
        self,
        description: str,
        quantity: float,
        unit_code: str,
        unit_price: float,
        vat_rate: float,
        vat_category: VatCategory,
    ) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_add_line_item(
            self._handle,
            _as_bytes(description),
            float(quantity),
            _as_bytes(unit_code),
            float(unit_price),
            float(vat_rate),
            int(vat_category),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_buyer(
        self,
        name: str,
        country_code: str,
        city: str,
        street: str,
        building_number: str,
        postal_code: str,
        vat_id: Optional[str] = None,
        other_id: Optional[str] = None,
        other_id_scheme: Optional[str] = None,
        additional_street: Optional[str] = None,
        additional_number: Optional[str] = None,
        subdivision: Optional[str] = None,
        district: Optional[str] = None,
    ) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_buyer(
            self._handle,
            _as_bytes(name),
            _as_bytes(country_code),
            _as_bytes(city),
            _as_bytes(street),
            _opt_cstr(bindings.ffi, additional_street),
            _as_bytes(building_number),
            _opt_cstr(bindings.ffi, additional_number),
            _as_bytes(postal_code),
            _opt_cstr(bindings.ffi, subdivision),
            _opt_cstr(bindings.ffi, district),
            _opt_cstr(bindings.ffi, vat_id),
            _opt_cstr(bindings.ffi, other_id),
            _opt_cstr(bindings.ffi, other_id_scheme),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_note(self, language: str, text: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_note(
            self._handle,
            _as_bytes(language),
            _as_bytes(text),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_allowance(self, reason: str, amount: float) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_allowance(
            self._handle,
            _as_bytes(reason),
            float(amount),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_flags(self, flags: int) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_flags(
            self._handle, flags
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def enable_flags(self, flags: int) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_enable_flags(
            self._handle, flags
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def disable_flags(self, flags: int) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_disable_flags(
            self._handle, flags
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def build(self) -> Invoice:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_build(self._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiFinalizedInvoice",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return Invoice(handle)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_invoice_builder_free(self._handle)
            self._handle = None

    def __enter__(self) -> "InvoiceBuilder":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
