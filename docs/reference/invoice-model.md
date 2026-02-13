# Invoice Model

Core data types for building and inspecting invoices.

## InvoiceBuilder

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
        FfiResult_FfiInvoiceBuilder fatoora_invoice_builder_new(FfiInvoiceTypeKind type_kind, FfiInvoiceSubType subtype, const char* original_id, const char* original_uuid, const char* original_issue_date, const char* original_reason);
        ```

### `set_id`

???+ note "Set invoice ID"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_id(id: impl Into<String>) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_id(invoice_id: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_id(FfiInvoiceBuilder* builder, const char* id);
        ```

### `set_uuid`

???+ note "Set invoice UUID"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_uuid(uuid: impl Into<String>) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_uuid(uuid: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_uuid(FfiInvoiceBuilder* builder, const char* uuid);
        ```

### `set_issue_datetime`

???+ note "Set issue datetime"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_issue_datetime(value: impl Into<String>) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_issue_datetime(issue_datetime: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_issue_datetime(FfiInvoiceBuilder* builder, const char* value);
        ```

### `set_currency`

???+ note "Set currency"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_currency(code: impl Into<String>) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_currency(currency_code: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_currency(FfiInvoiceBuilder* builder, const char* code);
        ```

### `set_previous_invoice_hash`

???+ note "Set previous invoice hash"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_previous_invoice_hash(hash: impl Into<String>) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_previous_invoice_hash(hash: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_previous_hash(FfiInvoiceBuilder* builder, const char* hash);
        ```

### `set_invoice_counter`

???+ note "Set invoice counter"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_invoice_counter(counter: u64) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_invoice_counter(counter: int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_invoice_counter(FfiInvoiceBuilder* builder, uint64_t counter);
        ```

### `set_payment_means_code`

???+ note "Set payment means code"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_payment_means_code(code: impl Into<String>) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_payment_means_code(code: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_payment_means_code(FfiInvoiceBuilder* builder, const char* code);
        ```

### `set_vat_category`

???+ note "Set invoice VAT category"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_vat_category(category: VatCategory) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_vat_category(category: VatCategory) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_vat_category(FfiInvoiceBuilder* builder, FfiVatCategory cat);
        ```

### `set_seller`

???+ note "Set seller party"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_seller(seller: Seller) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_seller(...) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_seller(FfiInvoiceBuilder* builder, const char* name, const char* country, const char* city, const char* street, const char* additional_street, const char* building_number, const char* additional_number, const char* postal_code, const char* subdivision, const char* district, const char* vat_id, const char* other_id, const char* other_id_scheme);
        ```

### `set_buyer`

???+ note "Set buyer party"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_buyer(buyer: Buyer) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_buyer(...) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_buyer(FfiInvoiceBuilder* builder, const char* name, const char* country, const char* city, const char* street, const char* additional_street, const char* building_number, const char* additional_number, const char* postal_code, const char* subdivision, const char* district, const char* vat_id, const char* other_id, const char* other_id_scheme);
        ```

### `set_note`

???+ note "Set invoice note"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_note(note: InvoiceNote) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_note(language: str, text: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_note(FfiInvoiceBuilder* builder, const char* lang, const char* text);
        ```

### `set_allowance`

???+ note "Set allowance reason and amount"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_allowance(reason: impl Into<String>, amount: f64) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_allowance(reason: str, amount: float) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_allowance(FfiInvoiceBuilder* builder, const char* reason, double amount);
        ```

### `invoice_level_charge`

???+ note "Set invoice-level charge"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::invoice_level_charge(charge: f64) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.invoice_level_charge(charge: float) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_invoice_level_charge(FfiInvoiceBuilder* builder, double charge);
        ```

### `invoice_level_discount`

???+ note "Set invoice-level discount"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::invoice_level_discount(discount: f64) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.invoice_level_discount(discount: float) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_invoice_level_discount(FfiInvoiceBuilder* builder, double discount);
        ```

### `allowance_reason`

???+ note "Set allowance reason"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::allowance_reason(reason: impl Into<String>) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.allowance_reason(reason: str) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_allowance_reason(FfiInvoiceBuilder* builder, const char* reason);
        ```

### `flags`

???+ note "Set invoice flags"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::flags(flags: InvoiceFlags) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.flags(flags: int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_flags(FfiInvoiceBuilder* builder, uint8_t flags);
        ```

### `add_line_item`

???+ note "Add line item"

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::add_line_item(item: LineItem) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.add_line_item(description: str, quantity: float, unit_code: str, unit_price: float, vat_rate: float, vat_category: VatCategory) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_add_line_item(FfiInvoiceBuilder* builder, const char* description, double quantity, const char* unit_code, double unit_price, double vat_rate, FfiVatCategory vat_category);
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
        FfiResult_FfiFinalizedInvoice fatoora_invoice_builder_build(FfiInvoiceBuilder* builder);
        ```

## Field Groups

### `id`

- Setter: `InvoiceBuilder::set_id` / `InvoiceBuilder.set_id` / `fatoora_invoice_builder_set_id`
- Getters: `FinalizedInvoice.id`, `SignedInvoice.id`, `fatoora_invoice_id`, `fatoora_signed_invoice_id`

### `uuid`

- Setter: `InvoiceBuilder::set_uuid` / `InvoiceBuilder.set_uuid` / `fatoora_invoice_builder_set_uuid`
- Getters: `FinalizedInvoice.uuid`, `SignedInvoice.uuid`, `fatoora_invoice_uuid`, `fatoora_signed_invoice_uuid`

### `issue_datetime`

- Setter: `InvoiceBuilder::set_issue_datetime` / `InvoiceBuilder.set_issue_datetime` / `fatoora_invoice_builder_set_issue_datetime`
- Getters: `FinalizedInvoice.issue_datetime`, `SignedInvoice.issue_datetime`, `fatoora_invoice_issue_datetime`, `fatoora_signed_invoice_issue_datetime`

### `currency`

- Setter: `InvoiceBuilder::set_currency` / `InvoiceBuilder.set_currency` / `fatoora_invoice_builder_set_currency`
- Getters: `FinalizedInvoice.currency`, `SignedInvoice.currency`, `fatoora_invoice_currency`, `fatoora_signed_invoice_currency`

### `previous_invoice_hash`

- Setter: `InvoiceBuilder::set_previous_invoice_hash` / `InvoiceBuilder.set_previous_invoice_hash` / `fatoora_invoice_builder_set_previous_hash`
- Getters: `FinalizedInvoice.previous_invoice_hash`, `SignedInvoice.previous_invoice_hash`, `fatoora_invoice_previous_hash`, `fatoora_signed_invoice_previous_hash`

### `invoice_counter`

- Setter: `InvoiceBuilder::set_invoice_counter` / `InvoiceBuilder.set_invoice_counter` / `fatoora_invoice_builder_set_invoice_counter`
- Getters: `FinalizedInvoice.invoice_counter`, `SignedInvoice.invoice_counter`, `fatoora_invoice_counter`, `fatoora_signed_invoice_counter`

### `payment_means_code`

- Setter: `InvoiceBuilder::set_payment_means_code` / `InvoiceBuilder.set_payment_means_code` / `fatoora_invoice_builder_set_payment_means_code`
- Getters: `FinalizedInvoice.payment_means_code`, `SignedInvoice.payment_means_code`, `fatoora_invoice_payment_means_code`, `fatoora_signed_invoice_payment_means_code`

### `vat_category`

- Setter: `InvoiceBuilder::set_vat_category` / `InvoiceBuilder.set_vat_category` / `fatoora_invoice_builder_set_vat_category`
- Getters: `FinalizedInvoice.vat_category`, `SignedInvoice.vat_category`, `fatoora_invoice_vat_category`, `fatoora_signed_invoice_vat_category`

### Parties (`seller`, `buyer`)

- Setters: `InvoiceBuilder::set_seller`, `InvoiceBuilder::set_buyer` and matching Python/C builder methods.
- Getters: `FinalizedInvoice.seller`, `FinalizedInvoice.buyer`, `SignedInvoice.seller`, `SignedInvoice.buyer`, `fatoora_invoice_seller`, `fatoora_invoice_buyer`, `fatoora_signed_invoice_seller`, `fatoora_signed_invoice_buyer`

### Notes and Allowance (`note`, `allowance_reason`, charge/discount)

- Setters: `set_note`, `set_allowance`, `invoice_level_charge`, `invoice_level_discount`, `allowance_reason` and matching Python/C builder methods.
- Getters: `note`, `allowance_reason`, `invoice_level_charge`, `invoice_level_discount` on finalized/signed invoices and matching `fatoora_invoice_*` and `fatoora_signed_invoice_*` getters.

### Flags and Type

- Setter: `InvoiceBuilder::flags` / `InvoiceBuilder.flags` / `fatoora_invoice_builder_flags`
- Getters: `flags`, `is_third_party`, `is_nominal`, `is_export`, `is_summary`, `is_self_billed`, `is_simplified`, `invoice_type_kind`, `invoice_sub_type` on finalized/signed invoices and matching C getters.

### Line Items and Totals

- Setter: `InvoiceBuilder::add_line_item` / `InvoiceBuilder.add_line_item` / `fatoora_invoice_builder_add_line_item`
- Getters: `line_items`, `totals` on finalized/signed invoices and matching C line-item/totals getters (`fatoora_invoice_line_item_*`, `fatoora_invoice_totals_*`, `fatoora_signed_invoice_line_item_*`, `fatoora_signed_invoice_totals_*`).

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
        FfiResult_FfiString fatoora_invoice_hash_base64(FfiFinalizedInvoice* invoice);
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
        FfiResult_FfiSignedInvoice fatoora_invoice_sign(FfiFinalizedInvoice* invoice, FfiSigner* signer);
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
        FinalizedInvoice.invoice_level_charge() -> float
        FinalizedInvoice.invoice_level_discount() -> float
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
        /* field-level getters: fatoora_invoice_* */
        FfiResult_FfiString fatoora_invoice_id(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_uuid(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice* invoice);
        FfiResult_u64 fatoora_invoice_line_item_count(FfiFinalizedInvoice* invoice);
        FfiResult_f64 fatoora_invoice_totals_tax_inclusive(FfiFinalizedInvoice* invoice);
        /* plus remaining fatoora_invoice_* accessors */
        ```

## SignedInvoice

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
        FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
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
        FfiResult_FfiString fatoora_signed_invoice_to_xml_base64(FfiSignedInvoice* signed);
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
        FfiResult_FfiString fatoora_signed_invoice_hash_base64(FfiSignedInvoice* signed);
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
        FfiResult_FfiString fatoora_signed_invoice_hash(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_signature(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_public_key(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_zatca_key_signature(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_cert_hash(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_signed_props_hash(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_signing_time(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_issuer(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_serial(FfiSignedInvoice* signed);
        ```

### `Address.new`

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
            subdivision: Optional[str] = None,
            district: Optional[str] = None,
        ) -> Address
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiAddress fatoora_address_new(
            const char* country_code,
            const char* city,
            const char* street,
            const char* additional_street,
            const char* building_number,
            const char* additional_number,
            const char* postal_code,
            const char* subdivision,
            const char* district
        );
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
        SignedInvoice.invoice_level_charge() -> float
        SignedInvoice.invoice_level_discount() -> float
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
        /* field-level getters: fatoora_signed_invoice_* */
        FfiResult_FfiString fatoora_signed_invoice_id(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_uuid(FfiSignedInvoice* signed);
        FfiResult_u64 fatoora_signed_invoice_line_item_count(FfiSignedInvoice* signed);
        FfiResult_f64 fatoora_signed_invoice_totals_tax_inclusive(FfiSignedInvoice* signed);
        /* plus remaining fatoora_signed_invoice_* accessors */
        ```

## Supporting Types

!!! note "Types"
    - `CountryCode`, `CurrencyCode`, `InvoiceTimestamp`, `InvoiceDate`, `VatId`, `OtherId`.
    - `InvoiceNote`, `OriginalInvoiceRef`, `LineItem`, `Party` (`Seller`/`Buyer` roles).

See also: [Invoice Signing Reference](invoice-signing.md)
