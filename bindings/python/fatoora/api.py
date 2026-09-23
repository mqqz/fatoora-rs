from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from decimal import Decimal
from enum import IntEnum
import json
from threading import RLock
from typing import Optional

from . import _native
from .errors import InvalidInputError, error_class_for_code

class Environment(IntEnum):
    NON_PRODUCTION = 0
    SIMULATION = 1
    PRODUCTION = 2

class InvoiceOutcome(IntEnum):
    """Outcome of the invoked operation; compliance acceptance only means the check passed."""
    UNKNOWN = 0
    ACCEPTED = 1
    REJECTED = 2

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
    THIRD_PARTY = 1
    NOMINAL = 2
    EXPORT = 4
    SUMMARY = 8
    SELF_BILLED = 16

@dataclass(frozen=True)
class InvoiceLineItem:
    description: str
    unit_code: str
    quantity: Decimal
    unit_price: Decimal
    total_amount: Decimal
    vat_rate: Decimal
    vat_amount: Decimal
    vat_category: VatCategory

@dataclass(frozen=True)
class InvoiceTotals:
    tax_inclusive: Decimal
    tax_amount: Decimal
    line_extension: Decimal
    allowance_total: Decimal
    charge_total: Decimal
    taxable_amount: Decimal
    prepaid_amount: Decimal
    payable_rounding_amount: Decimal
    payable_amount: Decimal


class _Owned:
    """Own a generated object; serialize calls that could consume its state."""
    def __init__(self, handle):
        self._handle = handle
        self._lock = RLock()

    def close(self):
        with self._lock:
            self._handle = None

    def __enter__(self):
        with self._lock:
            self._require_open()
        return self

    def __exit__(self, *args):
        self.close()

    def _require_open(self):
        if self._handle is None:
            raise InvalidInputError("object is closed", 1, {"type": "binding_error"})
        return self._handle

    def _invoke(self, name, *args):
        return _call(lambda owner, *values: getattr(owner, name)(*values), self, *args)


def _call(function, *args):
    # Hold all argument owners through GIL-releasing calls. Stable ordering avoids
    # deadlocks when two callers use the same objects in a different order.
    owners = sorted({id(v): v for v in args if isinstance(v, _Owned)}.values(), key=id)
    with ExitStack() as locks:
        for owner in owners:
            locks.enter_context(owner._lock)
        values = [v._require_open() if isinstance(v, _Owned) else v for v in args]
        try:
            value = function(*values)
        except Exception as exc:
            if len(exc.args) != 1 or not isinstance(exc.args[0], _native.BindingError):
                raise
            error = exc.args[0]
            code = error.code()
            raise error_class_for_code(code)(error.message(), code, json.loads(error.details_json())) from None
        return _convert(value)


def _convert(value):
    if isinstance(value, _native.Text):
        return _call(value.value)
    if isinstance(value, _native.Bytes):
        return value._copy()
    if isinstance(value, _native.BytesList):
        return [_call(value.get, i) for i in range(value.len())]
    return value


def _decimal(value: Decimal | str | int) -> str:
    if isinstance(value, (float, bool)) or not isinstance(value, (Decimal, str, int)):
        raise TypeError("decimal values must be Decimal, str, or int")
    return format(value, "f") if isinstance(value, Decimal) else str(value)

def _optional(cls, value):
    return None if value is None else cls(value)

class Config(_Owned):
    def __init__(self, env: Environment = Environment.NON_PRODUCTION):
        super().__init__(_call(_native.Config.new, int(env)))

    def env(self) -> Environment:
        return Environment(self._invoke("env"))

class Signer(_Owned):
    def sign_xml(self, xml: str) -> str:
        return self._invoke("sign_xml", xml)

    @classmethod
    def from_pem(cls, cert_pem: str, key_pem: str) -> 'Signer':
        return Signer(_call(_native.Signer.from_pem, cert_pem, key_pem))

    @classmethod
    def from_der(cls, cert_der: bytes, key_der: bytes) -> 'Signer':
        return Signer(_call(_native.Signer.from_der, cert_der, key_der))

    def certificate_der(self) -> bytes:
        return self._invoke("certificate_der")

    def certificate_pem(self) -> str:
        return self._invoke("certificate_pem")

class SigningKey(_Owned):
    @classmethod
    def from_pem(cls, pem: str) -> 'SigningKey':
        return SigningKey(_call(_native.SigningKey.from_pem, pem))

    @classmethod
    def from_der(cls, der: bytes) -> 'SigningKey':
        return SigningKey(_call(_native.SigningKey.from_der, der))

    @classmethod
    def generate(cls) -> 'SigningKey':
        return SigningKey(_call(_native.SigningKey.generate))

    def to_pem(self) -> str:
        return self._invoke("to_pem")

    def to_der(self) -> bytes:
        return self._invoke("to_der")

class CsrProperties(_Owned):
    @classmethod
    def new(cls, common_name: str, serial_number: str, organization_identifier: str, organization_unit_name: str, organization_name: str, country_name: str, invoice_type: str, location_address: str, industry_business_category: str) -> 'CsrProperties':
        return CsrProperties(_call(_native.CsrProperties.new, common_name, serial_number, organization_identifier, organization_unit_name, organization_name, country_name, invoice_type, location_address, industry_business_category))

    @classmethod
    def from_properties_str(cls, properties: str) -> 'CsrProperties':
        return CsrProperties(_call(_native.CsrProperties.from_properties_str, properties))

    @classmethod
    def parse_csr_config(cls, properties: str) -> 'CsrProperties':
        return CsrProperties(_call(_native.CsrProperties.from_properties_str, properties))

    @classmethod
    def parse_csr_config_file(cls, path: str) -> 'CsrProperties':
        return CsrProperties(_call(_native.CsrProperties.parse_csr_config_file, path))

    def build(self, key: SigningKey, env: Environment) -> 'Csr':
        return Csr(self._invoke("build", key, int(env)))

class Csr(_Owned):
    @classmethod
    def from_der(cls, der: bytes) -> 'Csr':
        return Csr(_call(_native.Csr.from_der, der))

    def to_base64(self) -> str:
        return self._invoke("to_base64")

    def to_pem_base64(self) -> str:
        return self._invoke("to_pem_base64")

    def to_der(self) -> bytes:
        return self._invoke("to_der")

    def to_pem(self) -> str:
        return self._invoke("to_pem")

    def subject_string(self) -> str:
        return self._invoke("subject_string")

    def extension_values_der(self) -> list[bytes]:
        return self._invoke("extension_values_der")

class CsidCompliance(_Owned):
    @classmethod
    def new(cls, env: Environment, token: str, secret: str, request_id: Optional[str]=None) -> 'CsidCompliance':
        return CsidCompliance(_call(_native.CsidCompliance.create, int(env), request_id, token, secret))

    def request_id(self) -> str:
        return self._invoke("request_id") or ""

    def env(self) -> Environment:
        return Environment(self._invoke("env"))

    def binary_security_token(self) -> str:
        return self._invoke("binary_security_token")

    def secret(self) -> str:
        return self._invoke("secret")

class CsidProduction(_Owned):
    @classmethod
    def new(cls, env: Environment, token: str, secret: str, request_id: Optional[str]=None) -> 'CsidProduction':
        return CsidProduction(_call(_native.CsidProduction.create, int(env), request_id, token, secret))

    def request_id(self) -> str:
        return self._invoke("request_id") or ""

    def env(self) -> Environment:
        return Environment(self._invoke("env"))

    def binary_security_token(self) -> str:
        return self._invoke("binary_security_token")

    def secret(self) -> str:
        return self._invoke("secret")

class ValidationMessage(_Owned):
    def message_type(self) -> Optional[str]:
        return self._invoke("message_type")

    def code(self) -> Optional[str]:
        return self._invoke("code")

    def category(self) -> Optional[str]:
        return self._invoke("category")

    def message(self) -> Optional[str]:
        return self._invoke("message")

    def status(self) -> Optional[str]:
        return self._invoke("status")

class ValidationResults(_Owned):
    def status(self) -> Optional[str]:
        return self._invoke("status")

    def info_messages(self) -> list[ValidationMessage]:
        return [ValidationMessage(self._invoke("info_message", i)) for i in range(self._invoke("info_len"))]

    def warning_messages(self) -> list[ValidationMessage]:
        return [ValidationMessage(self._invoke("warning_message", i)) for i in range(self._invoke("warning_len"))]

    def error_messages(self) -> list[ValidationMessage]:
        return [ValidationMessage(self._invoke("error_message", i)) for i in range(self._invoke("error_len"))]

class ValidationResponse(_Owned):
    def http_status(self) -> Optional[int]:
        return self._invoke("http_status")

    def outcome(self) -> InvoiceOutcome:
        value = self._invoke("outcome")
        if value == _native.InvoiceOutcome.Accepted:
            return InvoiceOutcome.ACCEPTED
        if value == _native.InvoiceOutcome.Rejected:
            return InvoiceOutcome.REJECTED
        return InvoiceOutcome.UNKNOWN

    def ensure_accepted(self) -> None:
        return self._invoke("ensure_accepted")

    def cleared_invoice_base64(self) -> Optional[str]:
        return self._invoke("cleared_invoice_base64")

    def cleared_invoice_xml(self) -> Optional[str]:
        return self._invoke("cleared_invoice_xml")

    def reporting_status(self) -> Optional[str]:
        return self._invoke("reporting_status")

    def clearance_status(self) -> Optional[str]:
        return self._invoke("clearance_status")

    def qr_seller_status(self) -> Optional[str]:
        return self._invoke("qr_seller_status")

    def qr_buyer_status(self) -> Optional[str]:
        return self._invoke("qr_buyer_status")

    def validation_results(self) -> ValidationResults:
        return ValidationResults(self._invoke("validation_results"))

class VatId(_Owned):
    def value(self) -> str:
        return self._invoke("value")

class OtherId(_Owned):
    def value(self) -> str:
        return self._invoke("value")

    def scheme(self) -> Optional[str]:
        return self._invoke("scheme")

class Address(_Owned):
    @classmethod
    def new(cls, country_code: str, city: str, street: str, building_number: str, postal_code: str, additional_street: Optional[str]=None, additional_number: Optional[str]=None, district: Optional[str]=None) -> 'Address':
        return Address(_call(_native.Address.new, country_code, city, street, building_number, postal_code, additional_street, additional_number, district))

    def country_code(self) -> str:
        return self._invoke("country_code")

    def city(self) -> str:
        return self._invoke("city")

    def street(self) -> str:
        return self._invoke("street")

    def additional_street(self) -> Optional[str]:
        return self._invoke("additional_street")

    def building_number(self) -> str:
        return self._invoke("building_number")

    def additional_number(self) -> Optional[str]:
        return self._invoke("additional_number")

    def postal_code(self) -> str:
        return self._invoke("postal_code")

    def district(self) -> Optional[str]:
        return self._invoke("district")

class Party(_Owned):
    def name(self) -> str:
        return self._invoke("name")

    def address(self) -> Address:
        return Address(self._invoke("address"))

    def vat_id(self) -> Optional[VatId]:
        return _optional(VatId, self._invoke("vat_id"))

    def other_id(self) -> Optional[OtherId]:
        return _optional(OtherId, self._invoke("other_id"))

class InvoiceNote(_Owned):
    def language(self) -> str:
        return self._invoke("language")

    def text(self) -> str:
        return self._invoke("text")

class OriginalInvoiceRef(_Owned):
    def id(self) -> str:
        return self._invoke("id")

    def uuid(self) -> Optional[str]:
        return self._invoke("uuid")

    def issue_date(self) -> Optional[str]:
        return self._invoke("issue_date")

class ZatcaClient(_Owned):
    def __init__(self, config: Config):
        super().__init__(_call(_native.ZatcaClient.create, config))

    def post_csr_for_ccsid(self, csr: Csr, otp: str) -> CsidCompliance:
        return CsidCompliance(self._invoke("_blocking_post_csr_for_ccsid", csr, otp))

    def post_ccsid_for_pcsid(self, ccsid: CsidCompliance) -> CsidProduction:
        return CsidProduction(self._invoke("_blocking_post_ccsid_for_pcsid", ccsid))

    def renew_csid(self, pcsid: CsidProduction, csr: Csr, otp: str, accept_language: Optional[str]=None) -> CsidProduction:
        return CsidProduction(self._invoke("_blocking_renew_csid", pcsid, csr, otp, accept_language))

    def check_invoice_compliance(self, invoice: 'SignedInvoice', ccsid: CsidCompliance) -> 'ValidationResponse':
        return ValidationResponse(self._invoke("_blocking_check_invoice_compliance", invoice, ccsid))

    def report_simplified_invoice(self, invoice: 'SignedInvoice', pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]=None) -> 'ValidationResponse':
        return ValidationResponse(self._invoke("_blocking_report_simplified_invoice", invoice, pcsid, clearance_status, accept_language))

    def clear_standard_invoice(self, invoice: 'SignedInvoice', pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]=None) -> 'ValidationResponse':
        return ValidationResponse(self._invoke("_blocking_clear_standard_invoice", invoice, pcsid, clearance_status, accept_language))

class _Invoice(_Owned):
    def _data(self, name, *args):
        data = self._invoke("data")
        return _call(getattr(data, name), *args)

    def id(self) -> str:
        return self._data("id")

    def uuid(self) -> str:
        return self._data("uuid")

    def issue_datetime(self) -> str:
        return self._data("issue_datetime")

    def currency(self) -> str:
        return self._data("currency")

    def previous_invoice_hash(self) -> str:
        return self._data("previous_invoice_hash")

    def invoice_counter(self) -> int:
        return self._data("invoice_counter")

    def payment_means_code(self) -> str:
        return self._data("payment_means_code")

    def vat_category(self) -> VatCategory:
        return VatCategory(self._data("vat_category"))

    def invoice_level_charge(self) -> Decimal:
        return Decimal(self._data("invoice_level_charge"))

    def invoice_level_discount(self) -> Decimal:
        return Decimal(self._data("invoice_level_discount"))

    def allowance_reason(self) -> Optional[str]:
        return self._data("allowance_reason")

    def seller(self) -> Party:
        return Party(self._data("seller"))

    def buyer(self) -> Optional[Party]:
        return _optional(Party, self._data("buyer"))

    def note(self) -> Optional[InvoiceNote]:
        return _optional(InvoiceNote, self._data("note"))

    def invoice_type_kind(self) -> InvoiceTypeKind:
        return InvoiceTypeKind(self._data("invoice_type_kind"))

    def invoice_sub_type(self) -> InvoiceSubType:
        return InvoiceSubType(self._data("invoice_sub_type"))

    def original_invoice_ref(self) -> Optional[OriginalInvoiceRef]:
        return _optional(OriginalInvoiceRef, self._data("original_invoice_ref"))

    def original_invoice_reason(self) -> Optional[str]:
        return self._data("original_invoice_reason")

    def line_item_count(self) -> int:
        return self._data("line_items_len")

    def line_item(self, index: int) -> InvoiceLineItem:
        return self._line_item_value(self._data("line_item", index))

    @staticmethod
    def _line_item_value(item) -> InvoiceLineItem:
        return InvoiceLineItem(description=(_call(item.description)), unit_code=(_call(item.unit_code)), quantity=Decimal(_call(item.quantity)), unit_price=Decimal(_call(item.unit_price)), total_amount=Decimal(_call(item.total_amount)), vat_rate=Decimal(_call(item.vat_rate)), vat_amount=Decimal(_call(item.vat_amount)), vat_category=VatCategory(_call(item.vat_category)))

    def line_items(self) -> list[InvoiceLineItem]:
        data = self._invoke("data")
        return [self._line_item_value(_call(data.line_item, i))
                for i in range(_call(data.line_items_len))]

    def totals(self) -> InvoiceTotals:
        totals = self._invoke("totals")
        return InvoiceTotals(**{name: Decimal(_call(getattr(totals, name))) for name in InvoiceTotals.__dataclass_fields__})

    def flags_raw(self) -> int:
        return self._data("flags_raw")

    def flags(self) -> set[InvoiceFlag]:
        return {flag for flag in InvoiceFlag if self.flags_raw() & flag.value}

    def is_third_party(self) -> bool:
        return InvoiceFlag.THIRD_PARTY in self.flags()

    def is_nominal(self) -> bool:
        return InvoiceFlag.NOMINAL in self.flags()

    def is_export(self) -> bool:
        return InvoiceFlag.EXPORT in self.flags()

    def is_summary(self) -> bool:
        return InvoiceFlag.SUMMARY in self.flags()

    def is_self_billed(self) -> bool:
        return InvoiceFlag.SELF_BILLED in self.flags()

    def is_simplified(self) -> bool:
        return self.invoice_sub_type() == InvoiceSubType.SIMPLIFIED

    def xml(self) -> str:
        return self._invoke("xml")

    def to_xml(self) -> str:
        return self.xml()

    def hash_base64(self) -> str:
        return self._invoke("hash_base64")


class FinalizedInvoice(_Invoice):
    def sign(self, signer: Signer) -> SignedInvoice:
        return SignedInvoice(signer._invoke("sign", self))


class SignedInvoice(_Invoice):
    def into_xml(self) -> str:
        return self._invoke("into_xml")

    def to_xml_base64(self) -> str:
        return self._invoke("to_xml_base64")

    def qr_code(self) -> str:
        return self._invoke("qr_code")

    def invoice_hash(self) -> str:
        return self._invoke("invoice_hash")

    def signature(self) -> str:
        return self._invoke("signature")

    def public_key(self) -> str:
        return self._invoke("public_key")

    def zatca_key_signature(self) -> Optional[str]:
        return self._invoke("zatca_key_signature")

    def cert_hash(self) -> str:
        return self._invoke("cert_hash")

    def signed_props_hash(self) -> str:
        return self._invoke("signed_props_hash")

    def signing_time(self) -> str:
        return self._invoke("signing_time")

    def issuer(self) -> str:
        return self._invoke("issuer")

    def serial(self) -> str:
        return self._invoke("serial")

class InvoiceBuilder(_Owned):
    @classmethod
    def new(cls, invoice_type: InvoiceTypeKind, invoice_subtype: InvoiceSubType, original_invoice_id: Optional[str]=None, original_invoice_uuid: Optional[str]=None, original_invoice_issue_date: Optional[str]=None, original_invoice_reason: Optional[str]=None) -> 'InvoiceBuilder':
        return cls(_call(_native.InvoiceBuilder.new, int(invoice_type), int(invoice_subtype), original_invoice_id, original_invoice_uuid, original_invoice_issue_date, original_invoice_reason))

    def set_id(self, invoice_id: str) -> None:
        self._invoke("set_id", invoice_id)

    def set_uuid(self, uuid: str) -> None:
        self._invoke("set_uuid", uuid)

    def set_issue_datetime(self, issue_datetime: str) -> None:
        self._invoke("set_issue_datetime", issue_datetime)

    def set_currency(self, currency_code: str) -> None:
        self._invoke("set_currency", currency_code)

    def set_previous_invoice_hash(self, previous_invoice_hash: str) -> None:
        self._invoke("set_previous_invoice_hash", previous_invoice_hash)

    def set_invoice_counter(self, invoice_counter: int) -> None:
        self._invoke("set_invoice_counter", invoice_counter)

    def set_payment_means_code(self, payment_means_code: str) -> None:
        self._invoke("set_payment_means_code", payment_means_code)

    def set_vat_category(self, vat_category: VatCategory) -> None:
        self._invoke("set_vat_category", int(vat_category))

    def set_seller(self, name: str, country_code: str, city: str, street: str, building_number: str, postal_code: str, vat_id: str, additional_street: Optional[str]=None, additional_number: Optional[str]=None, district: Optional[str]=None, other_id: Optional[str]=None, other_id_scheme: Optional[str]=None) -> None:
        address = Address.new(country_code, city, street, building_number, postal_code, additional_street, additional_number, district)
        self._invoke("set_seller", name, address, vat_id, other_id, other_id_scheme)

    def add_line_item(self, description: str, quantity: Decimal | str | int, unit_code: str, unit_price: Decimal | str | int, vat_rate: Decimal | str | int, vat_category: VatCategory) -> None:
        self._invoke("add_line_item", description, _decimal(quantity), unit_code, _decimal(unit_price), _decimal(vat_rate), int(vat_category))

    def set_buyer(self, name: str, country_code: str, city: str, street: str, building_number: str, postal_code: str, vat_id: Optional[str]=None, other_id: Optional[str]=None, other_id_scheme: Optional[str]=None, additional_street: Optional[str]=None, additional_number: Optional[str]=None, district: Optional[str]=None) -> None:
        address = Address.new(country_code, city, street, building_number, postal_code, additional_street, additional_number, district)
        self._invoke("set_buyer", name, address, vat_id, other_id, other_id_scheme)

    def set_note(self, language: str, text: str) -> None:
        self._invoke("set_note", language, text)

    def set_allowance(self, reason: str, amount: Decimal | str | int) -> None:
        self._invoke("set_allowance", reason, _decimal(amount))

    def invoice_level_charge(self, charge: Decimal | str | int) -> None:
        self._invoke("invoice_level_charge", _decimal(charge))

    def invoice_level_discount(self, discount: Decimal | str | int) -> None:
        self._invoke("invoice_level_discount", _decimal(discount))

    def allowance_reason(self, reason: str) -> None:
        self._invoke("allowance_reason", reason)

    def flags(self, flags: int) -> None:
        self._invoke("flags", flags)

    def build(self) -> FinalizedInvoice:
        return FinalizedInvoice(self._invoke("build"))

def parse_finalized_invoice_xml(xml: str) -> FinalizedInvoice:
    return FinalizedInvoice(_call(_native.FinalizedInvoice.from_xml, xml))


def parse_finalized_invoice_xml_file(path: str) -> FinalizedInvoice:
    return FinalizedInvoice(_call(_native.FinalizedInvoice.from_file, str(path)))


def parse_signed_invoice_xml(xml: str) -> SignedInvoice:
    return SignedInvoice(_call(_native.SignedInvoice.from_xml, xml))


def parse_signed_invoice_xml_file(path: str) -> SignedInvoice:
    return SignedInvoice(_call(_native.SignedInvoice.from_file, str(path)))


def validate_xml_invoice_from_str(config: Config, xml: str) -> bool:
    return _call(_native.Xml.validate, config, xml)


def invoice_hash_base64_from_xml_str(xml: str) -> str:
    return _call(_native.Xml.hash, xml)
