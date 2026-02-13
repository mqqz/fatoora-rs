from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional

from ._lib import FfiLibrary
from .errors import FfiError, error_class_for_code


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


def _decode_error(ffi, lib, err_ptr) -> tuple[str, int | None]:
    if not err_ptr:
        return "unknown error", None
    code = int(lib.fatoora_error_code(err_ptr))
    message = lib.fatoora_error_message(err_ptr)
    decoded = _decode_optional_string(ffi, lib, message)
    lib.fatoora_error_free(err_ptr)
    return decoded or "unknown error", code


def _decode_string(ffi, lib, value) -> str:
    if not value.ptr:
        lib.fatoora_string_free(value)
        return ""
    raw = ffi.string(value.ptr)
    lib.fatoora_string_free(value)
    return raw.decode("utf-8") if raw else ""


def _decode_optional_string(ffi, lib, value) -> Optional[str]:
    if not value.ptr:
        lib.fatoora_string_free(value)
        return None
    raw = ffi.string(value.ptr)
    lib.fatoora_string_free(value)
    return raw.decode("utf-8") if raw else None


def _decode_bytes(ffi, lib, value) -> bytes:
    if not value.ptr:
        lib.fatoora_bytes_free(value)
        return b""
    data = bytes(ffi.buffer(value.ptr, int(value.len)))
    lib.fatoora_bytes_free(value)
    return data


def _decode_bytes_list(ffi, lib, value) -> list[bytes]:
    if not value.ptr:
        lib.fatoora_bytes_list_free(value)
        return []
    items = ffi.cast("FfiBytes *", value.ptr)
    out: list[bytes] = []
    for idx in range(int(value.len)):
        item = items[idx]
        if not item.ptr:
            out.append(b"")
            continue
        out.append(bytes(ffi.buffer(item.ptr, int(item.len))))
    lib.fatoora_bytes_list_free(value)
    return out


def _result_or_raise(ffi, lib, result, value_attr: str = "value"):
    if not result.ok:
        message, code = _decode_error(ffi, lib, result.error)
        raise error_class_for_code(code)(message, code)
    return getattr(result, value_attr)


def _wrap_handle(ffi, ctype: str, value):
    return ffi.new(f"{ctype} *", value)


def _wrap_optional_handle(ffi, ctype: str, value):
    if not value.ptr:
        return None
    return _wrap_handle(ffi, ctype, value)


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


class Config:
    _handle: Optional[Any]

    def __init__(
        self,
        env: Environment = Environment.NON_PRODUCTION,
        _handle: Optional[Any] = None,
    ) -> None:
        self._handle = _handle
        if self._handle is not None:
            return
        bindings = _FfiBindings.instance()
        self._handle = bindings.lib.fatoora_config_new(int(env))

    def __post_init__(self) -> None:
        # Backward compatibility with any dataclass-style initialization paths.
        if self._handle is None:
            bindings = _FfiBindings.instance()
            self._handle = bindings.lib.fatoora_config_new(int(Environment.NON_PRODUCTION))

    def env(self) -> Environment:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_config_env(self._handle)
        return Environment(int(_result_or_raise(bindings.ffi, bindings.lib, result)))

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

    def certificate_der(self) -> bytes:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signer_certificate_der(self._handle)
        return _decode_bytes(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def certificate_pem(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signer_certificate_pem(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

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

    @classmethod
    def generate(cls) -> "SigningKey":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signing_key_generate()
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

    def to_der(self) -> bytes:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signing_key_to_der(self._handle)
        return _decode_bytes(
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
    def new(
        cls,
        common_name: str,
        serial_number: str,
        organization_identifier: str,
        organization_unit_name: str,
        organization_name: str,
        country_name: str,
        invoice_type: str,
        location_address: str,
        industry_business_category: str,
    ) -> "CsrProperties":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_properties_new(
            _as_bytes(common_name),
            _as_bytes(serial_number),
            _as_bytes(organization_identifier),
            _as_bytes(organization_unit_name),
            _as_bytes(organization_name),
            _as_bytes(country_name),
            _as_bytes(invoice_type),
            _as_bytes(location_address),
            _as_bytes(industry_business_category),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsrProperties",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    @classmethod
    def from_properties_str(cls, properties: str) -> "CsrProperties":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_properties_from_str(_as_bytes(properties))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsrProperties",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    @classmethod
    def parse_csr_config(cls, properties: str) -> "CsrProperties":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_properties_parse_csr_config(_as_bytes(properties))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsrProperties",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    @classmethod
    def parse_csr_config_file(cls, path: str) -> "CsrProperties":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_properties_parse_csr_config_file(_as_bytes(path))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsrProperties",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

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

    @classmethod
    def from_der(cls, der: bytes) -> "Csr":
        bindings = _FfiBindings.instance()
        buf = bytes(der)
        result = bindings.lib.fatoora_csr_from_der(buf, len(buf))
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsr",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

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

    def to_der(self) -> bytes:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_to_der(self._handle)
        return _decode_bytes(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def to_pem(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_to_pem(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def subject_string(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_subject_string(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def extension_values_der(self) -> list[bytes]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csr_extension_values_der(self._handle)
        return _decode_bytes_list(
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


@dataclass
class CsidCompliance:
    _handle: Any

    @classmethod
    def new(
        cls,
        env: Environment,
        token: str,
        secret: str,
        request_id: Optional[str] = None,
    ) -> "CsidCompliance":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_compliance_new(
            int(env),
            _opt_cstr(bindings.ffi, request_id),
            _as_bytes(token),
            _as_bytes(secret),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsidCompliance",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def request_id(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_compliance_request_id(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def env(self) -> Environment:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_compliance_env(self._handle)
        return Environment(int(_result_or_raise(bindings.ffi, bindings.lib, result)))

    def binary_security_token(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_compliance_binary_security_token(self._handle)
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
        request_id: Optional[str] = None,
    ) -> "CsidProduction":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_production_new(
            int(env),
            _opt_cstr(bindings.ffi, request_id),
            _as_bytes(token),
            _as_bytes(secret),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiCsidProduction",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def request_id(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_production_request_id(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def env(self) -> Environment:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_production_env(self._handle)
        return Environment(int(_result_or_raise(bindings.ffi, bindings.lib, result)))

    def binary_security_token(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_csid_production_binary_security_token(self._handle)
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


@dataclass
class ValidationMessage:
    _handle: Any

    def message_type(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_message_type(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def code(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_message_code(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def category(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_message_category(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def message(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_message_text(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def status(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_message_status(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_validation_message_free(self._handle)
            self._handle = None

    def __enter__(self) -> "ValidationMessage":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class ValidationResults:
    _handle: Any

    def status(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_results_status(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def _info_len(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_results_info_len(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def _warning_len(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_results_warning_len(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def _error_len(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_results_error_len(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def _info_message(self, index: int) -> ValidationMessage:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_results_info_message(
            self._handle, int(index)
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiValidationMessage",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return ValidationMessage(handle)

    def _warning_message(self, index: int) -> ValidationMessage:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_results_warning_message(
            self._handle, int(index)
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiValidationMessage",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return ValidationMessage(handle)

    def _error_message(self, index: int) -> ValidationMessage:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_results_error_message(
            self._handle, int(index)
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiValidationMessage",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return ValidationMessage(handle)

    def info_messages(self) -> list[ValidationMessage]:
        return [self._info_message(idx) for idx in range(self._info_len())]

    def warning_messages(self) -> list[ValidationMessage]:
        return [self._warning_message(idx) for idx in range(self._warning_len())]

    def error_messages(self) -> list[ValidationMessage]:
        return [self._error_message(idx) for idx in range(self._error_len())]

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_validation_results_free(self._handle)
            self._handle = None

    def __enter__(self) -> "ValidationResults":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class ValidationResponse:
    _handle: Any

    def reporting_status(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_response_reporting_status(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def clearance_status(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_response_clearance_status(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def qr_seller_status(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_response_qr_seller_status(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def qr_buyer_status(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_response_qr_buyer_status(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def validation_results(self) -> ValidationResults:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_validation_response_validation_results(self._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiValidationResults",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return ValidationResults(handle)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_validation_response_free(self._handle)
            self._handle = None

    def __enter__(self) -> "ValidationResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class VatId:
    _handle: Any

    def value(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_vat_id_value(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_vat_id_free(self._handle)
            self._handle = None

    def __enter__(self) -> "VatId":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class OtherId:
    _handle: Any

    def value(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_other_id_value(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def scheme(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_other_id_scheme(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_other_id_free(self._handle)
            self._handle = None

    def __enter__(self) -> "OtherId":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class Address:
    _handle: Any

    @classmethod
    def new(
        cls,
        country_code: str,
        city: str,
        street: str,
        building_number: str,
        postal_code: str,
        additional_street: Optional[str] = None,
        additional_number: Optional[str] = None,
        subdivision: Optional[str] = None,
        district: Optional[str] = None,
    ) -> "Address":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_new(
            _as_bytes(country_code),
            _as_bytes(city),
            _as_bytes(street),
            _opt_cstr(bindings.ffi, additional_street),
            _as_bytes(building_number),
            _opt_cstr(bindings.ffi, additional_number),
            _as_bytes(postal_code),
            _opt_cstr(bindings.ffi, subdivision),
            _opt_cstr(bindings.ffi, district),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiAddress",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return cls(handle)

    def country_code(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_country_code(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def city(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_city(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def street(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_street(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def additional_street(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_additional_street(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def building_number(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_building_number(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def additional_number(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_additional_number(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def postal_code(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_postal_code(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def subdivision(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_subdivision(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def district(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_address_district(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_address_free(self._handle)
            self._handle = None

    def __enter__(self) -> "Address":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class Party:
    _handle: Any

    def name(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_party_name(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def address(self) -> Address:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_party_address(self._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiAddress",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return Address(handle)

    def vat_id(self) -> Optional[VatId]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_party_vat_id(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiVatId",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return VatId(handle) if handle is not None else None

    def other_id(self) -> Optional[OtherId]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_party_other_id(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiOtherId",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return OtherId(handle) if handle is not None else None

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_party_free(self._handle)
            self._handle = None

    def __enter__(self) -> "Party":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class InvoiceNote:
    _handle: Any

    def language(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_note_language(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def text(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_note_text(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_invoice_note_free(self._handle)
            self._handle = None

    def __enter__(self) -> "InvoiceNote":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class OriginalInvoiceRef:
    _handle: Any

    def id(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_original_invoice_ref_id(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def uuid(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_original_invoice_ref_uuid(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def issue_date(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_original_invoice_ref_issue_date(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_original_invoice_ref_free(self._handle)
            self._handle = None

    def __enter__(self) -> "OriginalInvoiceRef":
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

    def check_invoice_compliance(self, invoice: "SignedInvoice", ccsid: CsidCompliance) -> "ValidationResponse":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_check_invoice_compliance(
            self._handle, invoice._handle, ccsid._handle
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiValidationResponse",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return ValidationResponse(handle)

    def report_simplified_invoice(
        self,
        invoice: "SignedInvoice",
        pcsid: CsidProduction,
        clearance_status: bool,
        accept_language: Optional[str] = None,
    ) -> "ValidationResponse":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_report_simplified_invoice(
            self._handle,
            invoice._handle,
            pcsid._handle,
            bool(clearance_status),
            _opt_cstr(bindings.ffi, accept_language),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiValidationResponse",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return ValidationResponse(handle)

    def clear_standard_invoice(
        self,
        invoice: "SignedInvoice",
        pcsid: CsidProduction,
        clearance_status: bool,
        accept_language: Optional[str] = None,
    ) -> "ValidationResponse":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_zatca_clear_standard_invoice(
            self._handle,
            invoice._handle,
            pcsid._handle,
            bool(clearance_status),
            _opt_cstr(bindings.ffi, accept_language),
        )
        handle = _wrap_handle(
            bindings.ffi,
            "FfiValidationResponse",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return ValidationResponse(handle)

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

    def id(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_id(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def xml(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_xml(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def to_xml_base64(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_to_xml_base64(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def qr_code(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_qr_code(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def uuid(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_uuid(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def issue_datetime(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_issue_datetime(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def currency(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_currency(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def previous_invoice_hash(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_previous_hash(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def invoice_counter(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_counter(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def payment_means_code(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_payment_means_code(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def vat_category(self) -> VatCategory:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_vat_category(self._handle)
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return VatCategory(value)

    def invoice_level_charge(self) -> float:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_level_charge(self._handle)
        return float(_result_or_raise(bindings.ffi, bindings.lib, result))

    def invoice_level_discount(self) -> float:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_level_discount(self._handle)
        return float(_result_or_raise(bindings.ffi, bindings.lib, result))

    def allowance_reason(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_allowance_reason(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def invoice_hash(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_hash(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def hash_base64(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_hash_base64(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def signature(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_signature(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def public_key(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_public_key(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def zatca_key_signature(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_zatca_key_signature(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def cert_hash(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_cert_hash(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def signed_props_hash(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_signed_props_hash(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def signing_time(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_signing_time(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def issuer(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_issuer(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def serial(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_serial(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def seller(self) -> Party:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_seller(self._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiParty",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return Party(handle)

    def buyer(self) -> Optional[Party]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_buyer(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiParty",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return Party(handle) if handle is not None else None

    def note(self) -> Optional[InvoiceNote]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_note(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiInvoiceNote",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return InvoiceNote(handle) if handle is not None else None

    def invoice_type_kind(self) -> InvoiceTypeKind:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_type_kind(self._handle)
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return InvoiceTypeKind(value)

    def invoice_sub_type(self) -> InvoiceSubType:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_sub_type(self._handle)
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return InvoiceSubType(value)

    def original_invoice_ref(self) -> Optional[OriginalInvoiceRef]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_original_ref(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiOriginalInvoiceRef",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return OriginalInvoiceRef(handle) if handle is not None else None

    def original_invoice_reason(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_original_reason(self._handle)
        return _decode_optional_string(
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

    def is_third_party(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_is_third_party(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_nominal(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_is_nominal(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_export(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_is_export(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_summary(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_is_summary(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_self_billed(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_is_self_billed(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_simplified(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_signed_invoice_is_simplified(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_signed_invoice_free(self._handle)
            self._handle = None

    def __enter__(self) -> "SignedInvoice":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class FinalizedInvoice:
    _handle: Any

    def id(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_id(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def uuid(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_uuid(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def issue_datetime(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_issue_datetime(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def currency(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_currency(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def previous_invoice_hash(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_previous_hash(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def invoice_counter(self) -> int:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_counter(self._handle)
        return int(_result_or_raise(bindings.ffi, bindings.lib, result))

    def payment_means_code(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_payment_means_code(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def vat_category(self) -> VatCategory:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_vat_category(self._handle)
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return VatCategory(value)

    def invoice_level_charge(self) -> float:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_level_charge(self._handle)
        return float(_result_or_raise(bindings.ffi, bindings.lib, result))

    def invoice_level_discount(self) -> float:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_level_discount(self._handle)
        return float(_result_or_raise(bindings.ffi, bindings.lib, result))

    def allowance_reason(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_allowance_reason(self._handle)
        return _decode_optional_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def xml(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_to_xml(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def hash_base64(self) -> str:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_hash_base64(self._handle)
        return _decode_string(
            bindings.ffi, bindings.lib, _result_or_raise(bindings.ffi, bindings.lib, result)
        )

    def seller(self) -> Party:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_seller(self._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiParty",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return Party(handle)

    def buyer(self) -> Optional[Party]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_buyer(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiParty",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return Party(handle) if handle is not None else None

    def note(self) -> Optional[InvoiceNote]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_note(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiInvoiceNote",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return InvoiceNote(handle) if handle is not None else None

    def invoice_type_kind(self) -> InvoiceTypeKind:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_type_kind(self._handle)
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return InvoiceTypeKind(value)

    def invoice_sub_type(self) -> InvoiceSubType:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_sub_type(self._handle)
        value = int(_result_or_raise(bindings.ffi, bindings.lib, result))
        return InvoiceSubType(value)

    def original_invoice_ref(self) -> Optional[OriginalInvoiceRef]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_original_ref(self._handle)
        handle = _wrap_optional_handle(
            bindings.ffi,
            "FfiOriginalInvoiceRef",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return OriginalInvoiceRef(handle) if handle is not None else None

    def original_invoice_reason(self) -> Optional[str]:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_original_reason(self._handle)
        return _decode_optional_string(
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

    def is_third_party(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_is_third_party(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_nominal(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_is_nominal(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_export(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_is_export(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_summary(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_is_summary(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_self_billed(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_is_self_billed(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def is_simplified(self) -> bool:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_is_simplified(self._handle)
        return bool(_result_or_raise(bindings.ffi, bindings.lib, result))

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._handle and self._handle.ptr:
            _FfiBindings.instance().lib.fatoora_invoice_free(self._handle)
            self._handle = None

    def __enter__(self) -> "FinalizedInvoice":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def parse_finalized_invoice_xml(xml: str) -> FinalizedInvoice:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_parse_finalized_invoice_xml(_as_bytes(xml))
    handle = _wrap_handle(
        bindings.ffi,
        "FfiFinalizedInvoice",
        _result_or_raise(bindings.ffi, bindings.lib, result),
    )
    return FinalizedInvoice(handle)


def parse_finalized_invoice_xml_file(path: str) -> FinalizedInvoice:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_parse_finalized_invoice_xml_file(_as_bytes(path))
    handle = _wrap_handle(
        bindings.ffi,
        "FfiFinalizedInvoice",
        _result_or_raise(bindings.ffi, bindings.lib, result),
    )
    return FinalizedInvoice(handle)


def parse_signed_invoice_xml(xml: str) -> SignedInvoice:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_parse_signed_invoice_xml(_as_bytes(xml))
    handle = _wrap_handle(
        bindings.ffi,
        "FfiSignedInvoice",
        _result_or_raise(bindings.ffi, bindings.lib, result),
    )
    return SignedInvoice(handle)


def parse_signed_invoice_xml_file(path: str) -> SignedInvoice:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_parse_signed_invoice_xml_file(_as_bytes(path))
    handle = _wrap_handle(
        bindings.ffi,
        "FfiSignedInvoice",
        _result_or_raise(bindings.ffi, bindings.lib, result),
    )
    return SignedInvoice(handle)


def validate_xml_invoice_from_str(config: Config, xml: str) -> bool:
    bindings = _FfiBindings.instance()
    result = bindings.lib.fatoora_validate_xml_invoice_from_str(config._handle, _as_bytes(xml))
    return bool(_result_or_raise(bindings.ffi, bindings.lib, result))



@dataclass
class InvoiceBuilder:
    _handle: Any

    @classmethod
    def new(
        cls,
        invoice_type: InvoiceTypeKind,
        invoice_subtype: InvoiceSubType,
        original_invoice_id: Optional[str] = None,
        original_invoice_uuid: Optional[str] = None,
        original_invoice_issue_date: Optional[str] = None,
        original_invoice_reason: Optional[str] = None,
    ) -> "InvoiceBuilder":
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_new(
            int(invoice_type),
            int(invoice_subtype),
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

    def set_id(self, invoice_id: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_id(
            self._handle, _as_bytes(invoice_id)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_uuid(self, uuid: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_uuid(
            self._handle, _as_bytes(uuid)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_issue_datetime(self, issue_datetime: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_issue_datetime(
            self._handle, _as_bytes(issue_datetime)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_currency(self, currency_code: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_currency(
            self._handle, _as_bytes(currency_code)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_previous_invoice_hash(self, previous_invoice_hash: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_previous_hash(
            self._handle, _as_bytes(previous_invoice_hash)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_invoice_counter(self, invoice_counter: int) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_invoice_counter(
            self._handle, int(invoice_counter)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_payment_means_code(self, payment_means_code: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_payment_means_code(
            self._handle, _as_bytes(payment_means_code)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_vat_category(self, vat_category: VatCategory) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_vat_category(
            self._handle, int(vat_category)
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def set_seller(
        self,
        name: str,
        country_code: str,
        city: str,
        street: str,
        building_number: str,
        postal_code: str,
        vat_id: str,
        additional_street: Optional[str] = None,
        additional_number: Optional[str] = None,
        subdivision: Optional[str] = None,
        district: Optional[str] = None,
        other_id: Optional[str] = None,
        other_id_scheme: Optional[str] = None,
    ) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_set_seller(
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
            _as_bytes(vat_id),
            _opt_cstr(bindings.ffi, other_id),
            _opt_cstr(bindings.ffi, other_id_scheme),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

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

    def invoice_level_charge(self, charge: float) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_invoice_level_charge(
            self._handle,
            float(charge),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def invoice_level_discount(self, discount: float) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_invoice_level_discount(
            self._handle,
            float(discount),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def allowance_reason(self, reason: str) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_allowance_reason(
            self._handle,
            _as_bytes(reason),
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def flags(self, flags: int) -> None:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_flags(
            self._handle, flags
        )
        _result_or_raise(bindings.ffi, bindings.lib, result)

    def build(self) -> FinalizedInvoice:
        bindings = _FfiBindings.instance()
        result = bindings.lib.fatoora_invoice_builder_build(self._handle)
        handle = _wrap_handle(
            bindings.ffi,
            "FfiFinalizedInvoice",
            _result_or_raise(bindings.ffi, bindings.lib, result),
        )
        return FinalizedInvoice(handle)

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
