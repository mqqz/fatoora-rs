# Invoice Model

Core data types for building and inspecting invoices.

## Symbols

=== "Rust"
    - `InvoiceBuilder::new(invoice_type: InvoiceType) -> InvoiceBuilder`
    - `InvoiceBuilder::set_id(id: impl Into<String>) -> &mut Self`
    - `InvoiceBuilder::set_uuid(uuid: impl Into<String>) -> &mut Self`
    - `InvoiceBuilder::set_issue_datetime(value: impl Into<String>) -> &mut Self` — `YYYY-MM-DDTHH:MM:SSZ`.
    - `InvoiceBuilder::set_currency(code: impl Into<String>) -> &mut Self` — ISO 4217 (e.g. `SAR`).
    - `InvoiceBuilder::set_previous_invoice_hash(hash: impl Into<String>) -> &mut Self`
    - `InvoiceBuilder::set_invoice_counter(counter: u64) -> &mut Self`
    - `InvoiceBuilder::set_payment_means_code(code: impl Into<String>) -> &mut Self`
    - `InvoiceBuilder::set_vat_category(category: VatCategory) -> &mut Self`
    - `InvoiceBuilder::set_seller(seller: Seller) -> &mut Self`
    - `InvoiceBuilder::set_buyer(buyer: Buyer) -> &mut Self`
    - `InvoiceBuilder::set_note(note: InvoiceNote) -> &mut Self`
    - `InvoiceBuilder::set_allowance(reason: impl Into<String>, amount: f64) -> &mut Self`
    - `InvoiceBuilder::invoice_level_charge(charge: f64) -> &mut Self`
    - `InvoiceBuilder::invoice_level_discount(discount: f64) -> &mut Self`
    - `InvoiceBuilder::allowance_reason(reason: impl Into<String>) -> &mut Self`
    - `InvoiceBuilder::add_line_item(item: LineItem) -> &mut Self`
    - `InvoiceBuilder::flags(flags: InvoiceFlags) -> &mut Self`
    - `InvoiceBuilder::build(self) -> Result<FinalizedInvoice, InvoiceError>`

    - `FinalizedInvoice::data(&self) -> &InvoiceData`
    - `FinalizedInvoice::totals(&self) -> &InvoiceTotalsData`
    - `FinalizedInvoice::hash_base64(&self) -> Result<String, SigningError>`
    - `FinalizedInvoice::sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>`

    - `SignedInvoice::data(&self) -> &InvoiceData`
    - `SignedInvoice::totals(&self) -> &InvoiceTotalsData`
    - `SignedInvoice::signed_properties(&self) -> &SignedProperties`
    - `SignedInvoice::qr_code(&self) -> &str`
    - `SignedInvoice::xml(&self) -> &str`
    - `SignedInvoice::uuid(&self) -> &str`
    - `SignedInvoice::invoice_hash(&self) -> &str`
    - `SignedInvoice::signature(&self) -> &str`
    - `SignedInvoice::public_key(&self) -> &str`
    - `SignedInvoice::zatca_key_signature(&self) -> Option<&str>`
    - `SignedInvoice::to_xml_base64(&self) -> String`
    - `SignedInvoice::hash_base64(&self) -> Result<String, SigningError>`

    - `CountryCode::parse(value: impl Into<String>) -> Result<CountryCode, InvoiceError>`
    - `CurrencyCode::parse(value: impl Into<String>) -> Result<CurrencyCode, InvoiceError>`
    - `InvoiceTimestamp::parse(value: impl Into<String>) -> Result<InvoiceTimestamp, InvoiceError>`
    - `InvoiceDate::parse(value: impl Into<String>) -> Result<InvoiceDate, InvoiceError>`
    - `VatId::parse(value: impl Into<String>) -> Result<VatId, InvoiceError>`
    - `OtherId::new(value: impl Into<String>) -> OtherId`
    - `OtherId::with_scheme(value: impl Into<String>, scheme: impl Into<String>) -> OtherId`
    - `InvoiceNote::new(language: impl Into<String>, text: impl Into<String>) -> InvoiceNote`
    - `OriginalInvoiceRef::new(id: impl Into<String>) -> OriginalInvoiceRef`
    - `OriginalInvoiceRef::with_uuid(self, uuid: impl Into<String>) -> OriginalInvoiceRef`
    - `OriginalInvoiceRef::with_issue_date(self, date: InvoiceDate) -> OriginalInvoiceRef`
    - `OriginalInvoiceRef::with_issue_date_str(self, date: impl Into<String>) -> Result<OriginalInvoiceRef, InvoiceError>`
    - `LineItem::new(description: impl Into<String>, quantity: f64, unit_code: impl Into<String>, unit_price: f64, vat_rate: f64, vat_category: VatCategory) -> LineItem`
    - `LineItem::from_totals(description: impl Into<String>, quantity: f64, unit_code: impl Into<String>, unit_price: f64, total_amount: f64, vat_rate: f64, vat_category: VatCategory) -> LineItem`
    - `LineItem::try_from_parts(description: impl Into<String>, quantity: f64, unit_code: impl Into<String>, unit_price: f64, total_amount: f64, vat_rate: f64, vat_amount: f64, vat_category: VatCategory) -> Result<LineItem, ValidationError>`
    - `Party<SellerRole>::new(name: String, address: Address, vat_id: impl Into<String>, other_id: Option<OtherId>) -> Result<Seller, InvoiceError>`
    - `Party<BuyerRole>::new(name: String, address: Address, vat_id: Option<String>, other_id: Option<OtherId>) -> Result<Buyer, InvoiceError>`

=== "Python"
    - `InvoiceBuilder.new(invoice_type: InvoiceTypeKind, invoice_subtype: InvoiceSubType, original_invoice_id: Optional[str] = None, original_invoice_uuid: Optional[str] = None, original_invoice_issue_date: Optional[str] = None, original_invoice_reason: Optional[str] = None) -> InvoiceBuilder`
    - `InvoiceBuilder.set_id(invoice_id: str) -> None`
    - `InvoiceBuilder.set_uuid(uuid: str) -> None`
    - `InvoiceBuilder.set_issue_datetime(issue_datetime: str) -> None`
    - `InvoiceBuilder.set_currency(currency_code: str) -> None`
    - `InvoiceBuilder.set_previous_invoice_hash(hash: str) -> None`
    - `InvoiceBuilder.set_invoice_counter(counter: int) -> None`
    - `InvoiceBuilder.set_payment_means_code(code: str) -> None`
    - `InvoiceBuilder.set_vat_category(category: VatCategory) -> None`
    - `InvoiceBuilder.set_seller(...) -> None` — seller fields + optional address extras.
    - `InvoiceBuilder.set_buyer(...) -> None` — buyer fields + optional IDs.
    - `InvoiceBuilder.set_note(language: str, text: str) -> None`
    - `InvoiceBuilder.set_allowance(reason: str, amount: float) -> None`
    - `InvoiceBuilder.set_flags(flags: int) -> None` — bitset of `InvoiceFlag`.
    - `InvoiceBuilder.add_line_item(description: str, quantity: float, unit_code: str, unit_price: float, vat_rate: float, vat_category: VatCategory) -> None`
    - `InvoiceBuilder.build() -> Invoice`

    - `Invoice.id() -> str`
    - `Invoice.uuid() -> str`
    - `Invoice.issue_datetime() -> str`
    - `Invoice.currency() -> str`
    - `Invoice.previous_invoice_hash() -> str`
    - `Invoice.invoice_counter() -> int`
    - `Invoice.payment_means_code() -> str`
    - `Invoice.vat_category() -> VatCategory`
    - `Invoice.invoice_level_charge() -> float`
    - `Invoice.invoice_level_discount() -> float`
    - `Invoice.allowance_reason() -> Optional[str]`
    - `Invoice.invoice_type_kind() -> InvoiceTypeKind`
    - `Invoice.invoice_sub_type() -> InvoiceSubType`
    - `Invoice.original_invoice_ref() -> Optional[OriginalInvoiceRef]`
    - `Invoice.original_invoice_reason() -> Optional[str]`
    - `Invoice.seller() -> Party`
    - `Invoice.buyer() -> Optional[Party]`
    - `Invoice.note() -> Optional[InvoiceNote]`
    - `Invoice.line_items() -> list[InvoiceLineItem]`
    - `Invoice.totals() -> InvoiceTotals`
    - `Invoice.flags() -> set[InvoiceFlag]`
    - `Invoice.xml() -> str`
    - `Invoice.hash_base64() -> str`

    - `SignedInvoice.xml() -> str`
    - `SignedInvoice.xml_base64() -> str`
    - `SignedInvoice.qr() -> str`
    - `SignedInvoice.invoice_hash() -> str`
    - `SignedInvoice.hash_base64() -> str`
    - `SignedInvoice.signature() -> str`
    - `SignedInvoice.public_key() -> str`
    - `SignedInvoice.zatca_key_signature() -> Optional[str]`
    - `SignedInvoice.cert_hash() -> str`
    - `SignedInvoice.signed_props_hash() -> str`
    - `SignedInvoice.signing_time() -> str`

=== "C (FFI)"
    - `fatoora_invoice_builder_new(type_kind: FfiInvoiceTypeKind, subtype: FfiInvoiceSubType, original_id: const char*, original_uuid: const char*, original_issue_date: const char*, original_reason: const char*) -> FfiResult_FfiInvoiceBuilder`
    - `fatoora_invoice_builder_set_id(builder: FfiInvoiceBuilder*, id: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_uuid(builder: FfiInvoiceBuilder*, uuid: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_issue_datetime(builder: FfiInvoiceBuilder*, value: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_currency(builder: FfiInvoiceBuilder*, code: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_previous_hash(builder: FfiInvoiceBuilder*, hash: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_invoice_counter(builder: FfiInvoiceBuilder*, counter: uint64_t) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_payment_means_code(builder: FfiInvoiceBuilder*, code: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_vat_category(builder: FfiInvoiceBuilder*, cat: FfiVatCategory) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_seller(builder: FfiInvoiceBuilder*, name: const char*, country: const char*, city: const char*, street: const char*, additional_street: const char*, building_number: const char*, additional_number: const char*, postal_code: const char*, subdivision: const char*, district: const char*, vat_id: const char*, other_id: const char*, other_id_scheme: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_buyer(builder: FfiInvoiceBuilder*, name: const char*, country: const char*, city: const char*, street: const char*, additional_street: const char*, building_number: const char*, additional_number: const char*, postal_code: const char*, subdivision: const char*, district: const char*, vat_id: const char*, other_id: const char*, other_id_scheme: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_note(builder: FfiInvoiceBuilder*, lang: const char*, text: const char*) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_allowance(builder: FfiInvoiceBuilder*, reason: const char*, amount: double) -> FfiResult_bool`
    - `fatoora_invoice_builder_add_line_item(builder: FfiInvoiceBuilder*, description: const char*, quantity: double, unit_code: const char*, unit_price: double, vat_rate: double, vat_category: FfiVatCategory) -> FfiResult_bool`
    - `fatoora_invoice_builder_set_flags(builder: FfiInvoiceBuilder*, flags: uint8_t) -> FfiResult_bool`
    - `fatoora_invoice_builder_build(builder: FfiInvoiceBuilder*) -> FfiResult_FfiFinalizedInvoice`

    - `fatoora_invoice_*` accessors for `FfiFinalizedInvoice` fields and line items.
    - `fatoora_signed_invoice_*` accessors for `FfiSignedInvoice` fields and line items.
    - `fatoora_*_invoice_totals_*` for totals accessors.

## Notes
- `InvoiceType` in Rust carries the subtype and (for credit/debit notes) the original reference + reason.
- `InvoiceFlags` are packed into a bitset; in Python you get a `set[InvoiceFlag]`.

See also: [CLI Guide](../guides/cli.md) and [Python Bindings Guide](../guides/python-bindings.md)
