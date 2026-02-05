# Invoice Model

Core data types for building and inspecting invoices.

## Invoice Builder

??? note "Create builder"
    Create a builder for a specific invoice type and subtype.

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

    !!! info "Args"
        - `invoice_type` / `invoice_subtype`: invoice classification.
        - `original_*`: original invoice references for credit/debit flows.

    !!! info "Returns"
        - `InvoiceBuilder`: mutable builder handle.

??? note "Set fields"
    Set header fields and parties on the builder.

    === "{{ lang.rust }}"
        ```rust
        InvoiceBuilder::set_id(id: impl Into<String>) -> &mut Self
        InvoiceBuilder::set_uuid(uuid: impl Into<String>) -> &mut Self
        InvoiceBuilder::set_issue_datetime(value: impl Into<String>) -> &mut Self
        InvoiceBuilder::set_currency(code: impl Into<String>) -> &mut Self
        InvoiceBuilder::set_previous_invoice_hash(hash: impl Into<String>) -> &mut Self
        InvoiceBuilder::set_invoice_counter(counter: u64) -> &mut Self
        InvoiceBuilder::set_payment_means_code(code: impl Into<String>) -> &mut Self
        InvoiceBuilder::set_vat_category(category: VatCategory) -> &mut Self
        InvoiceBuilder::set_seller(seller: Seller) -> &mut Self
        InvoiceBuilder::set_buyer(buyer: Buyer) -> &mut Self
        InvoiceBuilder::set_note(note: InvoiceNote) -> &mut Self
        InvoiceBuilder::set_allowance(reason: impl Into<String>, amount: f64) -> &mut Self
        InvoiceBuilder::invoice_level_charge(charge: f64) -> &mut Self
        InvoiceBuilder::invoice_level_discount(discount: f64) -> &mut Self
        InvoiceBuilder::allowance_reason(reason: impl Into<String>) -> &mut Self
        InvoiceBuilder::flags(flags: InvoiceFlags) -> &mut Self
        ```

    === "{{ lang.python }}"
        ```python
        InvoiceBuilder.set_id(invoice_id: str) -> None
        InvoiceBuilder.set_uuid(uuid: str) -> None
        InvoiceBuilder.set_issue_datetime(issue_datetime: str) -> None
        InvoiceBuilder.set_currency(currency_code: str) -> None
        InvoiceBuilder.set_previous_invoice_hash(hash: str) -> None
        InvoiceBuilder.set_invoice_counter(counter: int) -> None
        InvoiceBuilder.set_payment_means_code(code: str) -> None
        InvoiceBuilder.set_vat_category(category: VatCategory) -> None
        InvoiceBuilder.set_seller(...) -> None
        InvoiceBuilder.set_buyer(...) -> None
        InvoiceBuilder.set_note(language: str, text: str) -> None
        InvoiceBuilder.set_allowance(reason: str, amount: float) -> None
        InvoiceBuilder.set_flags(flags: int) -> None
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_invoice_builder_set_id(FfiInvoiceBuilder* builder, const char* id);
        FfiResult_bool fatoora_invoice_builder_set_uuid(FfiInvoiceBuilder* builder, const char* uuid);
        FfiResult_bool fatoora_invoice_builder_set_issue_datetime(FfiInvoiceBuilder* builder, const char* value);
        FfiResult_bool fatoora_invoice_builder_set_currency(FfiInvoiceBuilder* builder, const char* code);
        FfiResult_bool fatoora_invoice_builder_set_previous_hash(FfiInvoiceBuilder* builder, const char* hash);
        FfiResult_bool fatoora_invoice_builder_set_invoice_counter(FfiInvoiceBuilder* builder, uint64_t counter);
        FfiResult_bool fatoora_invoice_builder_set_payment_means_code(FfiInvoiceBuilder* builder, const char* code);
        FfiResult_bool fatoora_invoice_builder_set_vat_category(FfiInvoiceBuilder* builder, FfiVatCategory cat);
        FfiResult_bool fatoora_invoice_builder_set_seller(FfiInvoiceBuilder* builder, const char* name, const char* country, const char* city, const char* street, const char* additional_street, const char* building_number, const char* additional_number, const char* postal_code, const char* subdivision, const char* district, const char* vat_id, const char* other_id, const char* other_id_scheme);
        FfiResult_bool fatoora_invoice_builder_set_buyer(FfiInvoiceBuilder* builder, const char* name, const char* country, const char* city, const char* street, const char* additional_street, const char* building_number, const char* additional_number, const char* postal_code, const char* subdivision, const char* district, const char* vat_id, const char* other_id, const char* other_id_scheme);
        FfiResult_bool fatoora_invoice_builder_set_note(FfiInvoiceBuilder* builder, const char* lang, const char* text);
        FfiResult_bool fatoora_invoice_builder_set_allowance(FfiInvoiceBuilder* builder, const char* reason, double amount);
        FfiResult_bool fatoora_invoice_builder_set_flags(FfiInvoiceBuilder* builder, uint8_t flags);
        ```

    !!! info "Args"
        - Field values as shown in the signatures.

    !!! info "Returns"
        - Rust: builder for chaining.
        - Python: None (raises on error).
        - C: ok=true on success, error set on failure.

??? note "Line items"
    Add invoice line items.

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

    !!! info "Args"
        - Line item fields as shown in the signatures.

    !!! info "Returns"
        - Builder updated with the new line item.

??? note "Build"
    Finalize the builder into a finalized invoice.

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

    !!! info "Returns"
        - `FinalizedInvoice`: immutable invoice handle.

## Finalized Invoice

??? note "Accessors"
    Read finalized invoice fields.

    === "{{ lang.rust }}"
        ```rust
        FinalizedInvoice::data(&self) -> &InvoiceData
        FinalizedInvoice::totals(&self) -> &InvoiceTotalsData
        FinalizedInvoice::hash_base64(&self) -> Result<String, SigningError>
        FinalizedInvoice::sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>
        ```

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
        FinalizedInvoice.xml() -> str
        FinalizedInvoice.hash_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_invoice_id(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_uuid(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_issue_datetime(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_currency(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_previous_hash(FfiFinalizedInvoice* invoice);
        FfiResult_u64 fatoora_invoice_counter(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_payment_means_code(FfiFinalizedInvoice* invoice);
        FfiResult_FfiVatCategory fatoora_invoice_vat_category(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_allowance_reason(FfiFinalizedInvoice* invoice);
        FfiResult_f64 fatoora_invoice_level_charge(FfiFinalizedInvoice* invoice);
        FfiResult_f64 fatoora_invoice_level_discount(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_invoice_hash_base64(FfiFinalizedInvoice* invoice);
        FfiResult_FfiInvoiceTypeKind fatoora_invoice_type_kind(FfiFinalizedInvoice* invoice);
        FfiResult_FfiInvoiceSubType fatoora_invoice_sub_type(FfiFinalizedInvoice* invoice);
        FfiResult_FfiParty fatoora_invoice_seller(FfiFinalizedInvoice* invoice);
        FfiResult_FfiParty fatoora_invoice_buyer(FfiFinalizedInvoice* invoice);
        FfiResult_FfiInvoiceNote fatoora_invoice_note(FfiFinalizedInvoice* invoice);
        ```

    !!! info "Args"
        - `invoice`: finalized invoice handle.

    !!! info "Returns"
        - Field values for the finalized invoice.

## Signed Invoice

??? note "Accessors"
    Read signed invoice fields and metadata.

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::data(&self) -> &InvoiceData
        SignedInvoice::totals(&self) -> &InvoiceTotalsData
        SignedInvoice::signed_properties(&self) -> &SignedProperties
        SignedInvoice::qr_code(&self) -> &str
        SignedInvoice::xml(&self) -> &str
        SignedInvoice::uuid(&self) -> &str
        SignedInvoice::invoice_hash(&self) -> &str
        SignedInvoice::signature(&self) -> &str
        SignedInvoice::public_key(&self) -> &str
        SignedInvoice::zatca_key_signature(&self) -> Option<&str>
        SignedInvoice::to_xml_base64(&self) -> String
        SignedInvoice::hash_base64(&self) -> Result<String, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.xml() -> str
        SignedInvoice.xml_base64() -> str
        SignedInvoice.qr() -> str
        SignedInvoice.invoice_hash() -> str
        SignedInvoice.hash_base64() -> str
        SignedInvoice.signature() -> str
        SignedInvoice.public_key() -> str
        SignedInvoice.zatca_key_signature() -> Optional[str]
        SignedInvoice.cert_hash() -> str
        SignedInvoice.signed_props_hash() -> str
        SignedInvoice.signing_time() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_xml_base64(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_qr(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_hash(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_hash_base64(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_signature(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_public_key(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_zatca_key_signature(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_cert_hash(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_signed_props_hash(FfiSignedInvoice* signed);
        FfiResult_FfiString fatoora_signed_invoice_signing_time(FfiSignedInvoice* signed);
        ```

    !!! info "Args"
        - `signed`: signed invoice handle.

    !!! info "Returns"
        - Signed XML, hashes, and signature metadata.

## Supporting Types

!!! note "Types"
    - CountryCode, CurrencyCode, InvoiceTimestamp, InvoiceDate, VatId, OtherId.
    - InvoiceNote, OriginalInvoiceRef, LineItem, Party (Seller/Buyer roles).

See also: [Invoice Signing Reference](invoice-signing.md)
