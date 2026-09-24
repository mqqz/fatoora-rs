# Invoice Model

See [C and C++ bindings](bindings/c.md) for ownership rules and text output.
The declarations below come from the generated headers. C++ exposes the same types
in namespace `fatoora` through `fatoora/Type.hpp` headers.

Core data types for building and inspecting invoices. See [Decimal numbers and rounding](numbers.md) for numeric inputs, calculation rules and binding representations.

## InvoiceBuilder

Rust configuration methods consume and return the builder. Chain calls or assign
back to the builder for conditional configuration. `line_item` appends; other
configuration methods replace their corresponding values. `build(self)` moves
owned fields into the invoice and consumes the builder on success or error.

C and Python keep mutable builder handles and their existing setter names.
Setters validate their arguments before moving the builder; rejected arguments
leave it available for correction. Building consumes the handle on success or
validation failure.

```rust
let invoice = InvoiceBuilder::new(invoice_type)
    .id("INV-1")
    // Configure the remaining required fields.
    .build()?;
```

### `new`

???+ note "Create builder"
    Create a builder for a specific invoice type/subtype.

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::new(invoice_type: InvoiceType) -> InvoiceBuilder
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.new(invoice_type: InvoiceTypeKind, invoice_subtype: InvoiceSubType, original_invoice_id: Optional[str] = None, original_invoice_uuid: Optional[str] = None, original_invoice_issue_date: Optional[str] = None, original_invoice_reason: Optional[str] = None) -> InvoiceBuilder
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_new_result fatoora_InvoiceBuilder_new(uint8_t kind, uint8_t subtype, OptionStringView original_id, OptionStringView original_uuid, OptionStringView original_date, OptionStringView reason);
        ```

### `id`

???+ note "Set invoice ID"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::id(id: impl Into<String>) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_id(invoice_id: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_id_result fatoora_InvoiceBuilder_set_id(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `uuid`

???+ note "Set invoice UUID"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::uuid(uuid: impl Into<String>) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_uuid(uuid: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_uuid_result fatoora_InvoiceBuilder_set_uuid(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `issue_datetime`

???+ note "Set issue datetime"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::issue_datetime(value: impl Into<String>) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_issue_datetime(issue_datetime: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_issue_datetime_result fatoora_InvoiceBuilder_set_issue_datetime(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `currency`

???+ note "Set currency"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::currency(code: impl Into<String>) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_currency(currency_code: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_currency_result fatoora_InvoiceBuilder_set_currency(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `previous_invoice_hash`

???+ note "Set previous invoice hash"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::previous_invoice_hash(hash: impl Into<String>) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_previous_invoice_hash(hash: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_previous_invoice_hash_result fatoora_InvoiceBuilder_set_previous_invoice_hash(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `invoice_counter`

???+ note "Set invoice counter"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::invoice_counter(counter: u64) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_invoice_counter(counter: int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_invoice_counter_result fatoora_InvoiceBuilder_set_invoice_counter(InvoiceBuilder* self, uint64_t value);
        ```

### `payment_means_code`

???+ note "Set payment means code"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::payment_means_code(code: impl Into<String>) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_payment_means_code(code: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_payment_means_code_result fatoora_InvoiceBuilder_set_payment_means_code(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `vat_category`

???+ note "Set invoice VAT category"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::vat_category(category: VatCategory) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_vat_category(category: VatCategory) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_vat_category_result fatoora_InvoiceBuilder_set_vat_category(InvoiceBuilder* self, uint8_t value);
        ```

### `seller`

???+ note "Set seller party"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::seller(seller: Seller) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_seller(...) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_seller_result fatoora_InvoiceBuilder_set_seller(InvoiceBuilder* self, DiplomatStringView name, const Address* address, DiplomatStringView vat_id, OptionStringView other_id, OptionStringView scheme);
        ```

### `buyer`

???+ note "Set buyer party"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::buyer(buyer: Buyer) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_buyer(...) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_buyer_result fatoora_InvoiceBuilder_set_buyer(InvoiceBuilder* self, DiplomatStringView name, const Address* address, OptionStringView vat_id, OptionStringView other_id, OptionStringView scheme);
        ```

### `note`

???+ note "Set invoice note"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::note(note: InvoiceNote) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_note(language: str, text: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_note_result fatoora_InvoiceBuilder_set_note(InvoiceBuilder* self, DiplomatStringView language, DiplomatStringView value);
        ```

### `allowance`

???+ note "Set allowance reason and amount"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::allowance(reason: impl Into<String>, amount: Decimal) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_allowance(reason: str, amount: Decimal | str | int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_set_allowance_result fatoora_InvoiceBuilder_set_allowance(InvoiceBuilder* self, DiplomatStringView reason, DiplomatStringView amount);
        ```

### `invoice_level_charge`

???+ note "Set invoice-level charge"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::invoice_level_charge(charge: Decimal) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.invoice_level_charge(charge: Decimal | str | int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_invoice_level_charge_result fatoora_InvoiceBuilder_invoice_level_charge(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `invoice_level_discount`

???+ note "Set invoice-level discount"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::invoice_level_discount(discount: Decimal) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.invoice_level_discount(discount: Decimal | str | int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_invoice_level_discount_result fatoora_InvoiceBuilder_invoice_level_discount(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `allowance_reason`

???+ note "Set allowance reason"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::allowance_reason(reason: impl Into<String>) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.allowance_reason(reason: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_allowance_reason_result fatoora_InvoiceBuilder_allowance_reason(InvoiceBuilder* self, DiplomatStringView value);
        ```

### `flags`

???+ note "Set invoice flags"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::flags(flags: InvoiceFlags) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.flags(flags: int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_flags_result fatoora_InvoiceBuilder_flags(InvoiceBuilder* self, uint8_t value);
        ```

### `line_item`

???+ note "Add line item"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::line_item(item: LineItem) -> Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.add_line_item(description: str, quantity: Decimal | str | int, unit_code: str, unit_price: Decimal | str | int, vat_rate: Decimal | str | int, vat_category: VatCategory) -> None
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_add_line_item_result fatoora_InvoiceBuilder_add_line_item(InvoiceBuilder* self, DiplomatStringView description, DiplomatStringView quantity, DiplomatStringView unit_code, DiplomatStringView unit_price, DiplomatStringView vat_rate, uint8_t category);
        ```

### `build`

???+ note "Finalize invoice"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::build(self) -> Result<FinalizedInvoice, InvoiceError>
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.build() -> FinalizedInvoice
        ```

    === "{{ lang.c }}"
        ```c
        #include "InvoiceBuilder.h"

        fatoora_InvoiceBuilder_build_result fatoora_InvoiceBuilder_build(InvoiceBuilder* self);
        ```

## Field Groups

### `id`

- Setter: `InvoiceBuilder::id` / `InvoiceBuilder.set_id` / `fatoora_InvoiceBuilder_set_id`
- Getters: `FinalizedInvoice.id`, `SignedInvoice.id`, `fatoora_InvoiceData_id`, `fatoora_InvoiceData_id`

### `uuid`

- Setter: `InvoiceBuilder::uuid` / `InvoiceBuilder.set_uuid` / `fatoora_InvoiceBuilder_set_uuid`
- Getters: `FinalizedInvoice.uuid`, `SignedInvoice.uuid`, `fatoora_InvoiceData_uuid`, `fatoora_InvoiceData_uuid`

### `issue_datetime`

- Setter: `InvoiceBuilder::issue_datetime` / `InvoiceBuilder.set_issue_datetime` / `fatoora_InvoiceBuilder_set_issue_datetime`
- Getters: `FinalizedInvoice.issue_datetime`, `SignedInvoice.issue_datetime`, `fatoora_InvoiceData_issue_datetime`, `fatoora_InvoiceData_issue_datetime`

### `currency`

- Setter: `InvoiceBuilder::currency` / `InvoiceBuilder.set_currency` / `fatoora_InvoiceBuilder_set_currency`
- Getters: `FinalizedInvoice.currency`, `SignedInvoice.currency`, `fatoora_InvoiceData_currency`, `fatoora_InvoiceData_currency`

### `previous_invoice_hash`

- Setter: `InvoiceBuilder::previous_invoice_hash` / `InvoiceBuilder.set_previous_invoice_hash` / `fatoora_InvoiceBuilder_set_previous_invoice_hash`
- Getters: `FinalizedInvoice.previous_invoice_hash`, `SignedInvoice.previous_invoice_hash`, `fatoora_InvoiceData_previous_invoice_hash`, `fatoora_InvoiceData_previous_invoice_hash`

### `invoice_counter`

- Setter: `InvoiceBuilder::invoice_counter` / `InvoiceBuilder.set_invoice_counter` / `fatoora_InvoiceBuilder_set_invoice_counter`
- Getters: `FinalizedInvoice.invoice_counter`, `SignedInvoice.invoice_counter`, `fatoora_InvoiceData_invoice_counter`, `fatoora_InvoiceData_invoice_counter`

### `payment_means_code`

- Setter: `InvoiceBuilder::payment_means_code` / `InvoiceBuilder.set_payment_means_code` / `fatoora_InvoiceBuilder_set_payment_means_code`
- Getters: `FinalizedInvoice.payment_means_code`, `SignedInvoice.payment_means_code`, `fatoora_InvoiceData_payment_means_code`, `fatoora_InvoiceData_payment_means_code`

### `vat_category`

- Setter: `InvoiceBuilder::vat_category` / `InvoiceBuilder.set_vat_category` / `fatoora_InvoiceBuilder_set_vat_category`
- Getters: `FinalizedInvoice.vat_category`, `SignedInvoice.vat_category`, `fatoora_InvoiceData_vat_category`, `fatoora_InvoiceData_vat_category`

### Parties (`seller`, `buyer`)

- Setters: `InvoiceBuilder::seller`, `InvoiceBuilder::buyer` and matching Python/C builder methods.
- Getters: `FinalizedInvoice.seller`, `FinalizedInvoice.buyer`, `SignedInvoice.seller`, `SignedInvoice.buyer`, `fatoora_InvoiceData_seller`, `fatoora_InvoiceData_buyer`, `fatoora_InvoiceData_seller`, `fatoora_InvoiceData_buyer`

### Notes and Allowance (`note`, `allowance_reason`, charge/discount)

- Setters: `set_note`, `set_allowance`, `invoice_level_charge`, `invoice_level_discount`, `allowance_reason` and matching Python/C builder methods.
- Getters: `note`, `allowance_reason`, `invoice_level_charge`, `invoice_level_discount` on finalized/signed invoices and `fatoora_InvoiceData_*` getters on an owned snapshot.

### Flags and Type

- Setter: `InvoiceBuilder::flags` / `InvoiceBuilder.flags` / `fatoora_InvoiceBuilder_flags`
- Getters: `flags`, `is_third_party`, `is_nominal`, `is_export`, `is_summary`, `is_self_billed`, `is_simplified`, `invoice_type_kind`, `invoice_sub_type` on finalized/signed invoices and matching C getters.

### Line Items and Totals

- Setter: `InvoiceBuilder::line_item` / `InvoiceBuilder.add_line_item` / `fatoora_InvoiceBuilder_add_line_item`
- Getters: `line_items`, `totals` on finalized/signed invoices and C getters on owned `InvoiceData`, `InvoiceLineItem`, and `InvoiceTotals` snapshots.

C field getters operate on an owned `InvoiceData` snapshot obtained with
`fatoora_FinalizedInvoice_data` or `fatoora_SignedInvoice_data`. Check the result,
read the fields, then call `fatoora_InvoiceData_destroy`. Totals follow the same
pattern with `InvoiceTotals`. Snapshots survive destruction of their invoice.

## FinalizedInvoice

### `hash_base64`

???+ note "Get finalized invoice hash (Base64)"

    === "{{ lang.rust }}"
        ```rust
        FinalizedInvoice::hash_base64(&self) -> Result<String, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        FinalizedInvoice.hash_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "FinalizedInvoice.h"

        fatoora_FinalizedInvoice_hash_base64_result fatoora_FinalizedInvoice_hash_base64(const FinalizedInvoice* self, DiplomatWrite* write);
        ```

### `sign`

???+ note "Sign finalized invoice"

    === "{{ lang.rust }}"
        ```rust
        FinalizedInvoice::sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        FinalizedInvoice.sign(signer: Signer) -> SignedInvoice
        ```

    === "{{ lang.c }}"
        ```c
        #include "Signer.h"

        fatoora_Signer_sign_result fatoora_Signer_sign(const Signer* self, FinalizedInvoice* invoice);
        ```

### field accessors

???+ note "Read finalized invoice fields"
    Accessors for identity, parties, references, flags, line items, and totals are available per field in Python and C.

    === "{{ lang.python }}"
        ```python
        FinalizedInvoice.id() -> str
        FinalizedInvoice.uuid() -> str
        FinalizedInvoice.issue_datetime() -> str
        FinalizedInvoice.currency() -> str
        FinalizedInvoice.previous_invoice_hash() -> str
        FinalizedInvoice.invoice_counter() -> int
        FinalizedInvoice.payment_means_code() -> str
        FinalizedInvoice.vat_category() -> VatCategory
        FinalizedInvoice.invoice_level_charge() -> Decimal
        FinalizedInvoice.invoice_level_discount() -> Decimal
        FinalizedInvoice.allowance_reason() -> Optional[str]
        FinalizedInvoice.invoice_type_kind() -> InvoiceTypeKind
        FinalizedInvoice.invoice_sub_type() -> InvoiceSubType
        FinalizedInvoice.original_invoice_ref() -> Optional[OriginalInvoiceRef]
        FinalizedInvoice.original_invoice_reason() -> Optional[str]
        FinalizedInvoice.seller() -> Party
        FinalizedInvoice.buyer() -> Optional[Party]
        FinalizedInvoice.note() -> Optional[InvoiceNote]
        FinalizedInvoice.line_items() -> list[InvoiceLineItem]
        FinalizedInvoice.totals() -> InvoiceTotals
        FinalizedInvoice.flags() -> set[InvoiceFlag]
        FinalizedInvoice.is_third_party() -> bool
        FinalizedInvoice.is_nominal() -> bool
        FinalizedInvoice.is_export() -> bool
        FinalizedInvoice.is_summary() -> bool
        FinalizedInvoice.is_self_billed() -> bool
        FinalizedInvoice.is_simplified() -> bool
        FinalizedInvoice.xml() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "FinalizedInvoice.h"
        #include "InvoiceData.h"
        #include "InvoiceTotals.h"

        fatoora_FinalizedInvoice_data_result fatoora_FinalizedInvoice_data(const FinalizedInvoice* self);
        fatoora_InvoiceData_id_result fatoora_InvoiceData_id(const InvoiceData* self, DiplomatWrite* write);
        fatoora_InvoiceData_uuid_result fatoora_InvoiceData_uuid(const InvoiceData* self, DiplomatWrite* write);
        fatoora_FinalizedInvoice_xml_result fatoora_FinalizedInvoice_xml(const FinalizedInvoice* self, DiplomatWrite* write);
        size_t fatoora_InvoiceData_line_items_len(const InvoiceData* self);
        fatoora_FinalizedInvoice_totals_result fatoora_FinalizedInvoice_totals(const FinalizedInvoice* self);
        fatoora_InvoiceTotals_tax_inclusive_result fatoora_InvoiceTotals_tax_inclusive(const InvoiceTotals* self, DiplomatWrite* write);
        ```

## SignedInvoice

For exact XML preservation and consuming `into_xml()` access, see [XML ownership](xml.md#signedinvoice).

### `xml`

???+ note "Get signed invoice XML"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::xml(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.xml() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_xml_result fatoora_SignedInvoice_xml(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `to_xml_base64`

???+ note "Get signed XML as Base64"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::to_xml_base64(&self) -> String
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.to_xml_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_to_xml_base64_result fatoora_SignedInvoice_to_xml_base64(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `hash_base64`

???+ note "Get signed invoice hash (Base64)"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::hash_base64(&self) -> Result<String, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.hash_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_hash_base64_result fatoora_SignedInvoice_hash_base64(const SignedInvoice* self, DiplomatWrite* write);
        ```

### signature metadata accessors

???+ note "Read signature metadata"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::invoice_hash(&self) -> &str
        SignedInvoice::signature(&self) -> &str
        SignedInvoice::public_key(&self) -> &str
        SignedInvoice::zatca_key_signature(&self) -> Option<&str>
        SignedProperties::issuer(&self) -> &str
        SignedProperties::serial(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.invoice_hash() -> str
        SignedInvoice.signature() -> str
        SignedInvoice.public_key() -> str
        SignedInvoice.zatca_key_signature() -> Optional[str]
        SignedInvoice.cert_hash() -> str
        SignedInvoice.signed_props_hash() -> str
        SignedInvoice.signing_time() -> str
        SignedInvoice.issuer() -> str
        SignedInvoice.serial() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_invoice_hash_result fatoora_SignedInvoice_invoice_hash(const SignedInvoice* self, DiplomatWrite* write);
        fatoora_SignedInvoice_signature_result fatoora_SignedInvoice_signature(const SignedInvoice* self, DiplomatWrite* write);
        fatoora_SignedInvoice_public_key_result fatoora_SignedInvoice_public_key(const SignedInvoice* self, DiplomatWrite* write);
        fatoora_SignedInvoice_zatca_key_signature_result fatoora_SignedInvoice_zatca_key_signature(const SignedInvoice* self);
        fatoora_SignedInvoice_cert_hash_result fatoora_SignedInvoice_cert_hash(const SignedInvoice* self, DiplomatWrite* write);
        fatoora_SignedInvoice_signed_props_hash_result fatoora_SignedInvoice_signed_props_hash(const SignedInvoice* self, DiplomatWrite* write);
        fatoora_SignedInvoice_signing_time_result fatoora_SignedInvoice_signing_time(const SignedInvoice* self, DiplomatWrite* write);
        fatoora_SignedInvoice_issuer_result fatoora_SignedInvoice_issuer(const SignedInvoice* self, DiplomatWrite* write);
        fatoora_SignedInvoice_serial_result fatoora_SignedInvoice_serial(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `Address.new`

`district` is the single city-district field and maps to XML
`cbc:CitySubdivisionName`. Replace the removed `subdivision` field, accessor,
and constructor argument with `district`, including in serialized address JSON.
C callers must rebuild against the matching header and library.

???+ note "Create address value"

    === "{{ lang.python }}"
        ```python
        Address.new(
            country_code: str,
            city: str,
            street: str,
            building_number: str,
            postal_code: str,
            additional_street: Optional[str] = None,
            additional_number: Optional[str] = None,
            district: Optional[str] = None,
        ) -> Address
        ```

    === "{{ lang.c }}"
        ```c
        #include "Address.h"

        fatoora_Address_new_result fatoora_Address_new(DiplomatStringView country_code, DiplomatStringView city, DiplomatStringView street, DiplomatStringView building_number, DiplomatStringView postal_code, OptionStringView additional_street, OptionStringView additional_number, OptionStringView district);
        ```

### field accessors

???+ note "Read signed invoice data fields"
    Signed invoices expose the same business-field accessors as finalized invoices, plus signature metadata.

    === "{{ lang.python }}"
        ```python
        SignedInvoice.id() -> str
        SignedInvoice.uuid() -> str
        SignedInvoice.issue_datetime() -> str
        SignedInvoice.currency() -> str
        SignedInvoice.previous_invoice_hash() -> str
        SignedInvoice.invoice_counter() -> int
        SignedInvoice.payment_means_code() -> str
        SignedInvoice.vat_category() -> VatCategory
        SignedInvoice.invoice_level_charge() -> Decimal
        SignedInvoice.invoice_level_discount() -> Decimal
        SignedInvoice.allowance_reason() -> Optional[str]
        SignedInvoice.invoice_type_kind() -> InvoiceTypeKind
        SignedInvoice.invoice_sub_type() -> InvoiceSubType
        SignedInvoice.original_invoice_ref() -> Optional[OriginalInvoiceRef]
        SignedInvoice.original_invoice_reason() -> Optional[str]
        SignedInvoice.seller() -> Party
        SignedInvoice.buyer() -> Optional[Party]
        SignedInvoice.note() -> Optional[InvoiceNote]
        SignedInvoice.line_items() -> list[InvoiceLineItem]
        SignedInvoice.totals() -> InvoiceTotals
        SignedInvoice.flags() -> set[InvoiceFlag]
        SignedInvoice.is_third_party() -> bool
        SignedInvoice.is_nominal() -> bool
        SignedInvoice.is_export() -> bool
        SignedInvoice.is_summary() -> bool
        SignedInvoice.is_self_billed() -> bool
        SignedInvoice.is_simplified() -> bool
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"
        #include "InvoiceData.h"
        #include "InvoiceTotals.h"

        fatoora_SignedInvoice_data_result fatoora_SignedInvoice_data(const SignedInvoice* self);
        fatoora_InvoiceData_id_result fatoora_InvoiceData_id(const InvoiceData* self, DiplomatWrite* write);
        fatoora_InvoiceData_uuid_result fatoora_InvoiceData_uuid(const InvoiceData* self, DiplomatWrite* write);
        size_t fatoora_InvoiceData_line_items_len(const InvoiceData* self);
        fatoora_SignedInvoice_totals_result fatoora_SignedInvoice_totals(const SignedInvoice* self);
        fatoora_InvoiceTotals_tax_inclusive_result fatoora_InvoiceTotals_tax_inclusive(const InvoiceTotals* self, DiplomatWrite* write);
        ```

## Supporting Types

!!! note "Types"
    - `CountryCode`, `CurrencyCode`, `InvoiceTimestamp`, `InvoiceDate`, `VatId`, `OtherId`.
    - `InvoiceNote`, `OriginalInvoiceRef`, `LineItem`, `Party` (`Seller`/`Buyer` roles).

See also: [Invoice Signing Reference](invoice-signing.md)
