---
title: Invoice Model Reference
description: Build and inspect ZATCA invoices with fatoority. Reference for required fields, amounts, invoice types, builder methods, return values, and object lifetimes.
---

# Invoice model

Use the invoice model to assemble invoice data, calculate totals, and inspect imported or signed invoices. For an existing XML document, start with [XML parsing](xml.md). For signatures and certificate inputs, see [invoice signing](invoice-signing.md).

## Building an invoice

Create a builder, set the required fields, append one or more line items, then build a finalized invoice. Building checks supported field formats and amounts and calculates totals. It does not run schema validation, all ZATCA business rules, or signature verification; use [validation](invoice-validation.md) for those checks.

Repeated configuration replaces the previous value. Adding a line item appends it in insertion order. An allowance sets the invoice-level discount and its reason; it does not add a second discount.

## Fields and expected values

| Field | Required | Expected value and behavior |
| --- | --- | --- |
| Invoice type and subtype | Yes | Tax invoice, prepayment, credit note, or debit note; standard or simplified subtype. Credit/debit notes also need an original invoice ID and reason. Original UUID and issue date are optional. |
| ID | Yes | Nonblank invoice identifier, such as `INV-1001`. |
| UUID | Yes | Invoice UUID text. The builder checks nonblank input, not UUID syntax. |
| Issue datetime | Yes | UTC `YYYY-MM-DDTHH:MM:SSZ`, for example `2026-10-15T09:30:00Z`. |
| Currency | Yes | Recognized ISO currency code, such as `SAR`. Trimmed and normalized to uppercase. |
| Previous invoice hash | Yes | Previous invoice hash text. The builder checks nonblank input; it does not verify the chain or decode the hash. |
| Invoice counter | Yes | Unsigned 64-bit integer. The model accepts zero; check applicable business rules separately. |
| Seller | Yes | Name, address, and VAT ID; optional other identification and scheme. |
| Buyer | No in builder | Name and address, plus VAT ID or other identification. A supplied buyer must have at least one identifier. Additional requirements depend on invoice business rules. |
| Payment means code | Yes | Nonblank code text, for example `10` for cash. The builder does not validate the complete payment code list. |
| VAT category | Yes | Standard, zero-rated, exempt, or out of scope. Each line also has its own category. |
| Line items | Yes | At least one. Nonblank description and unit code; nonnegative quantity and unit price. |
| VAT rate | Per line | Percentage from `0` to `100`, at most two decimal places. Categories other than standard require zero. |
| Invoice charge / discount | No | Nonnegative decimal amount, at most two decimal places. Defaults to zero. |
| Note | No | Language code and text. |
| Flags | No | Third party, nominal, export, summary, self-billed. Defaults to no flags. |

Address inputs are country code, city, street, building number, and postal code, with optional additional street, additional number, and district. Country accepts recognized ISO alpha-2 or alpha-3 values (`SA` or `SAU`) and is stored as alpha-3. A VAT ID wrapper checks only that trimmed text is nonempty; use ZATCA validation for country-specific requirements.

Credit/debit note original issue dates use `YYYY-MM-DD`. Optional values mean absence; an empty string is still a supplied value.

See [decimal numbers](numbers.md) for precision and rounding. Line totals are calculated from quantity and price. Explicitly supplied line totals must match the rounded calculation; imported amounts are not accepted merely because they parse.

## Returned data and totals

A finalized invoice contains invoice data and calculated totals. A signed invoice additionally contains signed XML, QR payload, and signature metadata. Importing a signed invoice does not prove its signature is valid.

| Result | Contents |
| --- | --- |
| Invoice data | Identity, type/subtype, parties, notes, original invoice reference, flags, line items, and invoice adjustments. |
| Line item | Description, quantity, unit code, unit price, line total, VAT rate, VAT amount, and category. Indexed access is zero-based and rejects out-of-range indexes. |
| Totals | Line extension, allowance total, charge total, taxable amount, tax amount, tax inclusive total, prepaid amount, payable rounding amount, and payable amount. |
| Model hash | Base64 hash calculated by serializing the finalized invoice model. On imported signed documents this can differ from the embedded invoice hash. |

## Language reference

Choose your language for method names, argument types, return values, and lifecycle rules. The tables list callable signatures; their argument names correspond to the fields above.

=== "Rust"

    **Create and configure**

    Import model types from `fatoora_core::invoice`. `InvoiceBuilder::new(invoice_type: InvoiceType) -> InvoiceBuilder` accepts `InvoiceType::Tax(subtype)`, `Prepayment(subtype)`, `CreditNote(subtype, original, reason)`, or `DebitNote(subtype, original, reason)`. Subtype is `InvoiceSubType::Standard` or `Simplified`; credit/debit notes use `OriginalInvoiceRef::new(id)` with optional `with_uuid(uuid)` and `with_issue_date_str(date)`.

    Every setter consumes and returns `Self`: chain calls or reassign the result.

    | Call | Returns |
    | --- | --- |
    | `id(value: impl Into<String>)` | `Self` |
    | `uuid(value: impl Into<String>)` | `Self` |
    | `issue_datetime(value: impl Into<String>)` | `Self` |
    | `currency(value: impl Into<String>)` | `Self` |
    | `previous_invoice_hash(value: impl Into<String>)` | `Self` |
    | `payment_means_code(value: impl Into<String>)` | `Self` |
    | `allowance_reason(value: impl Into<String>)` | `Self` |
    | `invoice_counter(value: u64)` | `Self` |
    | `seller(value: Seller)` | `Self` |
    | `buyer(value: Buyer)` | `Self` |
    | `vat_category(value: VatCategory)` | `Self` |
    | `flags(value: InvoiceFlags)` | `Self` |
    | `note(value: InvoiceNote)` | `Self` |
    | `invoice_level_charge(value: Decimal)` | `Self` |
    | `invoice_level_discount(value: Decimal)` | `Self` |
    | `line_item(value: LineItem)` | `Self` |
    | `allowance(reason: impl Into<String>, amount: Decimal)` | `Self` |
    | `build(self)` | `Result<FinalizedInvoice, InvoiceError>` |

    `build(self)` consumes the builder on success or failure. `VatCategory` variants are `Standard`, `Zero`, `Exempt`, and `OutOfScope`. Combine `InvoiceFlags::THIRD_PARTY`, `NOMINAL`, `EXPORT`, `SUMMARY`, and `SELF_BILLED` with `\|`.

    **Supporting values**

    `LineItem::new(description, quantity, unit_code, unit_price, vat_rate, vat_category)` takes text values for description/unit code, `Decimal` for quantities/amounts/rate, and `VatCategory`; it returns `Result<LineItem, InvoiceError>`. `LineItem::from_totals(...)` adds an explicit `total_amount` after unit price; `try_from_parts(...)` also adds `vat_amount` after VAT rate and checks both supplied amounts.

    Use `CountryCode::parse`, `CurrencyCode::parse`, `InvoiceTimestamp::parse`, `InvoiceDate::parse`, and `VatId::parse` for validated wrappers; each returns `Result<Wrapper, InvoiceError>`. `InvoiceNote::new(language, text)` returns a note. `OtherId::new(value)` creates an ID without a scheme; `OtherId::with_scheme(value, scheme_id)` supplies both.

    Construct `Address` with its public fields: `country_code: CountryCode`, `city: String`, `street: String`, `building_number: String`, `postal_code: String`, and optional `additional_street`, `additional_number`, `district` (`Option<String>`).

    `Seller::new(name: String, address: Address, vat_id: impl Into<String>, other_id: Option<OtherId>) -> Result<Seller, InvoiceError>` requires a VAT ID. `Buyer::new(name: String, address: Address, vat_id: Option<String>, other_id: Option<OtherId>) -> Result<Buyer, InvoiceError>` requires at least one identifier.

    **Read invoice data**

    Both invoice types provide `data() -> &InvoiceData`, `totals() -> &InvoiceTotalsData`, and `hash_base64() -> Result<String, SigningError>`. Read fields through the returned data's accessor methods, including `id()`, `uuid()`, `seller()`, `buyer()`, `line_items()`, `flags()`, and `invoice_type()`. Decimal accessors return `Decimal`; optional fields return `Option`.

    `FinalizedInvoice::sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>` consumes the finalized invoice even if signing fails. Signed metadata and XML access are described in [signing](invoice-signing.md) and [XML](xml.md).

=== "Python"

    **Create and configure**

    Import from `fatoora`. Enum values are `InvoiceTypeKind.TAX`, `PREPAYMENT`, `CREDIT_NOTE`, `DEBIT_NOTE`; `InvoiceSubType.STANDARD` / `SIMPLIFIED`; and `VatCategory.EXEMPT`, `STANDARD`, `ZERO`, `OUT_OF_SCOPE`. Decimal inputs accept `decimal.Decimal`, a decimal string, or an integer; binary floats are rejected.

    | Call | Returns |
    | --- | --- |
    | `new(invoice_type: InvoiceTypeKind, invoice_subtype: InvoiceSubType, original_invoice_id: Optional[str]=None, original_invoice_uuid: Optional[str]=None, original_invoice_issue_date: Optional[str]=None, original_invoice_reason: Optional[str]=None)` | `InvoiceBuilder` |
    | `set_id(invoice_id: str)` | `None` |
    | `set_uuid(uuid: str)` | `None` |
    | `set_issue_datetime(issue_datetime: str)` | `None` |
    | `set_currency(currency_code: str)` | `None` |
    | `set_previous_invoice_hash(previous_invoice_hash: str)` | `None` |
    | `set_invoice_counter(invoice_counter: int)` | `None` |
    | `set_payment_means_code(payment_means_code: str)` | `None` |
    | `set_vat_category(vat_category: VatCategory)` | `None` |
    | `set_seller(name: str, country_code: str, city: str, street: str, building_number: str, postal_code: str, vat_id: str, additional_street: Optional[str]=None, additional_number: Optional[str]=None, district: Optional[str]=None, other_id: Optional[str]=None, other_id_scheme: Optional[str]=None)` | `None` |
    | `add_line_item(description: str, quantity: Decimal \| str \| int, unit_code: str, unit_price: Decimal \| str \| int, vat_rate: Decimal \| str \| int, vat_category: VatCategory)` | `None` |
    | `set_buyer(name: str, country_code: str, city: str, street: str, building_number: str, postal_code: str, vat_id: Optional[str]=None, other_id: Optional[str]=None, other_id_scheme: Optional[str]=None, additional_street: Optional[str]=None, additional_number: Optional[str]=None, district: Optional[str]=None)` | `None` |
    | `set_note(language: str, text: str)` | `None` |
    | `set_allowance(reason: str, amount: Decimal \| str \| int)` | `None` |
    | `invoice_level_charge(charge: Decimal \| str \| int)` | `None` |
    | `invoice_level_discount(discount: Decimal \| str \| int)` | `None` |
    | `allowance_reason(reason: str)` | `None` |
    | `flags(flags: int)` | `None` |
    | `build()` | `FinalizedInvoice` |

    Setters mutate the builder and return `None`. `build()` consumes its state on success or failure. Rejected setter inputs leave it available for correction. Close owned objects with `close()` or use a `with` block; closing a consumed builder is safe.

    **Read invoice data**

    The following methods are available on both `FinalizedInvoice` and `SignedInvoice`:

    | Call | Returns |
    | --- | --- |
    | `id()` | `str` |
    | `uuid()` | `str` |
    | `issue_datetime()` | `str` |
    | `currency()` | `str` |
    | `previous_invoice_hash()` | `str` |
    | `invoice_counter()` | `int` |
    | `payment_means_code()` | `str` |
    | `vat_category()` | `VatCategory` |
    | `invoice_level_charge()` | `Decimal` |
    | `invoice_level_discount()` | `Decimal` |
    | `allowance_reason()` | `Optional[str]` |
    | `seller()` | `Party` |
    | `buyer()` | `Optional[Party]` |
    | `note()` | `Optional[InvoiceNote]` |
    | `invoice_type_kind()` | `InvoiceTypeKind` |
    | `invoice_sub_type()` | `InvoiceSubType` |
    | `original_invoice_ref()` | `Optional[OriginalInvoiceRef]` |
    | `original_invoice_reason()` | `Optional[str]` |
    | `line_item_count()` | `int` |
    | `line_item(index: int)` | `InvoiceLineItem` |
    | `line_items()` | `list[InvoiceLineItem]` |
    | `totals()` | `InvoiceTotals` |
    | `flags_raw()` | `int` |
    | `flags()` | `set[InvoiceFlag]` |
    | `is_third_party()` | `bool` |
    | `is_nominal()` | `bool` |
    | `is_export()` | `bool` |
    | `is_summary()` | `bool` |
    | `is_self_billed()` | `bool` |
    | `is_simplified()` | `bool` |
    | `xml()` | `str` |
    | `to_xml()` | `str` |
    | `hash_base64()` | `str` |

    `totals()` returns an `InvoiceTotals` value with decimal amount fields. `line_items()` returns a list of `InvoiceLineItem` values. Party and address accessors return owned objects; optional fields return `None` when absent. `Address.new(country_code, city, street, building_number, postal_code, additional_street=None, additional_number=None, district=None)` returns an `Address`.

    `FinalizedInvoice.sign(signer: Signer) -> SignedInvoice` consumes the finalized invoice on success or signing failure; the signer remains reusable. See [signing](invoice-signing.md) for metadata and [XML](xml.md) for serialization.

=== "JavaScript"

    Import from `fatoority`. All decimal arguments and amounts are strings; counters use `bigint`, indexes use `number`, and other numeric arguments use `number`. Pass `null` for absent optional arguments. Operations are synchronous and throw an `Error` with a `BindingError` cause on failure. Returned `Text` objects expose `.value()`.

    Invoice kind codes: `0` tax, `1` prepayment, `2` credit note, `3` debit note. Subtype: `0` standard, `1` simplified. VAT category: `0` exempt, `1` standard, `2` zero-rated, `3` out of scope. Flags are a bitmask: `1` third party, `2` nominal, `4` export, `8` summary, `16` self-billed. Use zero for no flags.

    **Create and configure**

    | Call | Returns |
    | --- | --- |
    | `new_(kind, subtype, originalId, originalUuid, originalDate, reason)` | `InvoiceBuilder` |
    | `setId(value)` | `void` |
    | `setUuid(value)` | `void` |
    | `setIssueDatetime(value)` | `void` |
    | `setCurrency(value)` | `void` |
    | `setPreviousInvoiceHash(value)` | `void` |
    | `setPaymentMeansCode(value)` | `void` |
    | `allowanceReason(value)` | `void` |
    | `invoiceLevelCharge(value)` | `void` |
    | `invoiceLevelDiscount(value)` | `void` |
    | `setInvoiceCounter(value)` | `void` |
    | `setVatCategory(value)` | `void` |
    | `flags(value)` | `void` |
    | `setNote(language, value)` | `void` |
    | `setAllowance(reason, amount)` | `void` |
    | `setSeller(name, address, vatId, otherId, scheme)` | `void` |
    | `setBuyer(name, address, vatId, otherId, scheme)` | `void` |
    | `addLineItem(description, quantity, unitCode, unitPrice, vatRate, category)` | `void` |
    | `build()` | `FinalizedInvoice` |

    **Address inputs**

    | Call | Returns |
    | --- | --- |
    | `new_(countryCode, city, street, buildingNumber, postalCode, additionalStreet, additionalNumber, district)` | `Address` |

    Setters replace values; line-item calls append. Building consumes builder state even on validation failure. Signing through the signer consumes finalized invoice state. Further calls on consumed state fail.

    **Read invoice data**

    `invoice.data()` returns an owned `InvoiceData` snapshot; `invoice.totals()` returns owned `InvoiceTotals`. Both are independent of invoice state.

    | Call | Returns |
    | --- | --- |
    | `id()` | `string` |
    | `uuid()` | `string` |
    | `previousInvoiceHash()` | `string` |
    | `paymentMeansCode()` | `string` |
    | `currency()` | `string` |
    | `issueDatetime()` | `string` |
    | `invoiceLevelCharge()` | `string` |
    | `invoiceLevelDiscount()` | `string` |
    | `allowanceReason()` | `Text \| null` |
    | `invoiceCounter()` | `bigint` |
    | `vatCategory()` | `number` |
    | `flagsRaw()` | `number` |
    | `invoiceTypeKind()` | `number` |
    | `invoiceSubType()` | `number` |
    | `seller()` | `Party` |
    | `buyer()` | `Party \| null` |
    | `note()` | `InvoiceNote \| null` |
    | `lineItemsLen()` | `number` |
    | `lineItem(index)` | `InvoiceLineItem` |
    | `originalInvoiceRef()` | `OriginalInvoiceRef \| null` |
    | `originalInvoiceReason()` | `Text \| null` |

    **Totals**

    | Call | Returns |
    | --- | --- |
    | `taxInclusive()` | `string` |
    | `taxAmount()` | `string` |
    | `lineExtension()` | `string` |
    | `allowanceTotal()` | `string` |
    | `chargeTotal()` | `string` |
    | `taxableAmount()` | `string` |
    | `prepaidAmount()` | `string` |
    | `payableRoundingAmount()` | `string` |
    | `payableAmount()` | `string` |

    Optional object accessors return null when absent. Line-item objects provide description, quantity, unit code, unit price, total amount, VAT rate, VAT amount, and category. See [XML](xml.md) and [signing](invoice-signing.md) for document and signature operations.

=== "C#"

    Use the `Fatoora` namespace. Decimal arguments and amounts are strings; counters use `ulong`, indexes use `nuint`, and enum codes/flags use `byte`. Pass `null` for absent optional arguments. Methods throw on failure. Dispose each owned object with `using`; returned `Text` exposes `Value()`.

    Invoice kind codes: `0` tax, `1` prepayment, `2` credit note, `3` debit note. Subtype: `0` standard, `1` simplified. VAT category: `0` exempt, `1` standard, `2` zero-rated, `3` out of scope. Flags are a bitmask: `1` third party, `2` nominal, `4` export, `8` summary, `16` self-billed. Use zero for no flags.

    **Create and configure**

    | Call | Returns |
    | --- | --- |
    | `New(byte kind, byte subtype, string? originalId, string? originalUuid, string? originalDate, string? reason)` | `InvoiceBuilder` |
    | `SetId(string value)` | `void` |
    | `SetUuid(string value)` | `void` |
    | `SetIssueDatetime(string value)` | `void` |
    | `SetCurrency(string value)` | `void` |
    | `SetPreviousInvoiceHash(string value)` | `void` |
    | `SetPaymentMeansCode(string value)` | `void` |
    | `AllowanceReason(string value)` | `void` |
    | `InvoiceLevelCharge(string value)` | `void` |
    | `InvoiceLevelDiscount(string value)` | `void` |
    | `SetInvoiceCounter(ulong value)` | `void` |
    | `SetVatCategory(byte value)` | `void` |
    | `Flags(byte value)` | `void` |
    | `SetNote(string language, string value)` | `void` |
    | `SetAllowance(string reason, string amount)` | `void` |
    | `SetSeller(string name, Address address, string vatId, string? otherId, string? scheme)` | `void` |
    | `SetBuyer(string name, Address address, string? vatId, string? otherId, string? scheme)` | `void` |
    | `AddLineItem(string description, string quantity, string unitCode, string unitPrice, string vatRate, byte category)` | `void` |
    | `Build()` | `FinalizedInvoice` |

    **Address inputs**

    | Call | Returns |
    | --- | --- |
    | `New(string countryCode, string city, string street, string buildingNumber, string postalCode, string? additionalStreet, string? additionalNumber, string? district)` | `Address` |

    Setters replace values; line-item calls append. Building consumes builder state even on validation failure. Signing through the signer consumes finalized invoice state. Further calls on consumed state fail.

    **Read invoice data**

    `invoice.Data()` returns an owned `InvoiceData` snapshot; `invoice.Totals()` returns owned `InvoiceTotals`. Both survive disposal of the invoice.

    | Call | Returns |
    | --- | --- |
    | `Id()` | `string` |
    | `Uuid()` | `string` |
    | `PreviousInvoiceHash()` | `string` |
    | `PaymentMeansCode()` | `string` |
    | `Currency()` | `string` |
    | `IssueDatetime()` | `string` |
    | `InvoiceLevelCharge()` | `string` |
    | `InvoiceLevelDiscount()` | `string` |
    | `AllowanceReason()` | `Text?` |
    | `InvoiceCounter()` | `ulong` |
    | `VatCategory()` | `byte` |
    | `FlagsRaw()` | `byte` |
    | `InvoiceTypeKind()` | `byte` |
    | `InvoiceSubType()` | `byte` |
    | `Seller()` | `Party` |
    | `Buyer()` | `Party?` |
    | `Note()` | `InvoiceNote?` |
    | `LineItemsLen()` | `nuint` |
    | `LineItem(nuint index)` | `InvoiceLineItem` |
    | `OriginalInvoiceRef()` | `OriginalInvoiceRef?` |
    | `OriginalInvoiceReason()` | `Text?` |

    **Totals**

    | Call | Returns |
    | --- | --- |
    | `TaxInclusive()` | `string` |
    | `TaxAmount()` | `string` |
    | `LineExtension()` | `string` |
    | `AllowanceTotal()` | `string` |
    | `ChargeTotal()` | `string` |
    | `TaxableAmount()` | `string` |
    | `PrepaidAmount()` | `string` |
    | `PayableRoundingAmount()` | `string` |
    | `PayableAmount()` | `string` |

    Optional object accessors return null when absent. Line-item objects provide description, quantity, unit code, unit price, total amount, VAT rate, VAT amount, and category. See [XML](xml.md) and [signing](invoice-signing.md) for document and signature operations.

=== "Kotlin"

    Use `com.fatoora`. Decimal arguments and amounts are strings; counters and indexes use `java.math.BigInteger`, enum codes/flags use `Int`. Optional values are nullable. Methods throw on failure. Close owned objects with `use`; returned `Text` exposes `value()`.

    Invoice kind codes: `0` tax, `1` prepayment, `2` credit note, `3` debit note. Subtype: `0` standard, `1` simplified. VAT category: `0` exempt, `1` standard, `2` zero-rated, `3` out of scope. Flags are a bitmask: `1` third party, `2` nominal, `4` export, `8` summary, `16` self-billed. Use zero for no flags.

    **Create and configure**

    | Call | Returns |
    | --- | --- |
    | `create(kind: Int, subtype: Int, originalId: String? = null, originalUuid: String? = null, originalDate: String? = null, reason: String? = null)` | `InvoiceBuilder` |
    | `setId(value: String)` | `Unit` |
    | `setUuid(value: String)` | `Unit` |
    | `setIssueDatetime(value: String)` | `Unit` |
    | `setCurrency(value: String)` | `Unit` |
    | `setPreviousInvoiceHash(value: String)` | `Unit` |
    | `setPaymentMeansCode(value: String)` | `Unit` |
    | `allowanceReason(value: String)` | `Unit` |
    | `invoiceLevelCharge(value: String)` | `Unit` |
    | `invoiceLevelDiscount(value: String)` | `Unit` |
    | `setInvoiceCounter(value: java.math.BigInteger)` | `Unit` |
    | `setVatCategory(value: Int)` | `Unit` |
    | `flags(value: Int)` | `Unit` |
    | `setNote(language: String, value: String)` | `Unit` |
    | `setAllowance(reason: String, amount: String)` | `Unit` |
    | `setSeller(name: String, address: Address, vatId: String, otherId: String? = null, scheme: String? = null)` | `Unit` |
    | `setBuyer(name: String, address: Address, vatId: String? = null, otherId: String? = null, scheme: String? = null)` | `Unit` |
    | `addLineItem(description: String, quantity: String, unitCode: String, unitPrice: String, vatRate: String, category: Int)` | `Unit` |
    | `build()` | `FinalizedInvoice` |

    **Address inputs**

    | Call | Returns |
    | --- | --- |
    | `create(countryCode: String, city: String, street: String, buildingNumber: String, postalCode: String, additionalStreet: String? = null, additionalNumber: String? = null, district: String? = null)` | `Address` |

    Setters replace values; line-item calls append. Building consumes builder state even on validation failure. Signing through the signer consumes finalized invoice state. Further calls on consumed state fail.

    **Read invoice data**

    `invoice.data()` returns an owned `InvoiceData` snapshot; `invoice.totals()` returns owned `InvoiceTotals`. Both are independent of invoice state.

    | Call | Returns |
    | --- | --- |
    | `id()` | `String` |
    | `uuid()` | `String` |
    | `previousInvoiceHash()` | `String` |
    | `paymentMeansCode()` | `String` |
    | `currency()` | `String` |
    | `issueDatetime()` | `String` |
    | `invoiceLevelCharge()` | `String` |
    | `invoiceLevelDiscount()` | `String` |
    | `allowanceReason()` | `Text?` |
    | `invoiceCounter()` | `java.math.BigInteger` |
    | `vatCategory()` | `Int` |
    | `flagsRaw()` | `Int` |
    | `invoiceTypeKind()` | `Int` |
    | `invoiceSubType()` | `Int` |
    | `seller()` | `Party` |
    | `buyer()` | `Party?` |
    | `note()` | `InvoiceNote?` |
    | `lineItemsLen()` | `java.math.BigInteger` |
    | `lineItem(index: java.math.BigInteger)` | `InvoiceLineItem` |
    | `originalInvoiceRef()` | `OriginalInvoiceRef?` |
    | `originalInvoiceReason()` | `Text?` |

    **Totals**

    | Call | Returns |
    | --- | --- |
    | `taxInclusive()` | `String` |
    | `taxAmount()` | `String` |
    | `lineExtension()` | `String` |
    | `allowanceTotal()` | `String` |
    | `chargeTotal()` | `String` |
    | `taxableAmount()` | `String` |
    | `prepaidAmount()` | `String` |
    | `payableRoundingAmount()` | `String` |
    | `payableAmount()` | `String` |

    Optional object accessors return null when absent. Line-item objects provide description, quantity, unit code, unit price, total amount, VAT rate, VAT amount, and category. See [XML](xml.md) and [signing](invoice-signing.md) for document and signature operations.

=== "Java"

    Import `com.fatoora.*`. Decimal arguments and amounts use `String`; counters and indexes use `BigInteger`, enum codes/flags use `int`. Optional values accept `null`. Call static `InvoiceBuilder.create(...)` and `Address.create(...)` with all arguments, including optional nulls. Close owned objects with try-with-resources. Returned `Text` exposes `value()`. The signatures below use Java parameter and return types.

    Invoice kind codes: `0` tax, `1` prepayment, `2` credit note, `3` debit note. Subtype: `0` standard, `1` simplified. VAT category: `0` exempt, `1` standard, `2` zero-rated, `3` out of scope. Flags are a bitmask: `1` third party, `2` nominal, `4` export, `8` summary, `16` self-billed. Use zero for no flags.

    **Create and configure**

    | Call | Returns |
    | --- | --- |
    | `create(int kind, int subtype, String originalId, String originalUuid, String originalDate, String reason)` | `InvoiceBuilder` |
    | `setId(String value)` | `void` |
    | `setUuid(String value)` | `void` |
    | `setIssueDatetime(String value)` | `void` |
    | `setCurrency(String value)` | `void` |
    | `setPreviousInvoiceHash(String value)` | `void` |
    | `setPaymentMeansCode(String value)` | `void` |
    | `allowanceReason(String value)` | `void` |
    | `invoiceLevelCharge(String value)` | `void` |
    | `invoiceLevelDiscount(String value)` | `void` |
    | `setInvoiceCounter(BigInteger value)` | `void` |
    | `setVatCategory(int value)` | `void` |
    | `flags(int value)` | `void` |
    | `setNote(String language, String value)` | `void` |
    | `setAllowance(String reason, String amount)` | `void` |
    | `setSeller(String name, Address address, String vatId, String otherId, String scheme)` | `void` |
    | `setBuyer(String name, Address address, String vatId, String otherId, String scheme)` | `void` |
    | `addLineItem(String description, String quantity, String unitCode, String unitPrice, String vatRate, int category)` | `void` |
    | `build()` | `FinalizedInvoice` |

    **Address inputs**

    | Call | Returns |
    | --- | --- |
    | `create(String countryCode, String city, String street, String buildingNumber, String postalCode, String additionalStreet, String additionalNumber, String district)` | `Address` |

    Setters replace values; line-item calls append. Building consumes builder state even on validation failure. Signing through the signer consumes finalized invoice state. Further calls on consumed state fail.

    **Read invoice data**

    `invoice.data()` returns an owned `InvoiceData` snapshot; `invoice.totals()` returns owned `InvoiceTotals`. Both are independent of invoice state.

    | Call | Returns |
    | --- | --- |
    | `id()` | `String` |
    | `uuid()` | `String` |
    | `previousInvoiceHash()` | `String` |
    | `paymentMeansCode()` | `String` |
    | `currency()` | `String` |
    | `issueDatetime()` | `String` |
    | `invoiceLevelCharge()` | `String` |
    | `invoiceLevelDiscount()` | `String` |
    | `allowanceReason()` | `Text` |
    | `invoiceCounter()` | `BigInteger` |
    | `vatCategory()` | `int` |
    | `flagsRaw()` | `int` |
    | `invoiceTypeKind()` | `int` |
    | `invoiceSubType()` | `int` |
    | `seller()` | `Party` |
    | `buyer()` | `Party` |
    | `note()` | `InvoiceNote` |
    | `lineItemsLen()` | `BigInteger` |
    | `lineItem(BigInteger index)` | `InvoiceLineItem` |
    | `originalInvoiceRef()` | `OriginalInvoiceRef` |
    | `originalInvoiceReason()` | `Text` |

    **Totals**

    | Call | Returns |
    | --- | --- |
    | `taxInclusive()` | `String` |
    | `taxAmount()` | `String` |
    | `lineExtension()` | `String` |
    | `allowanceTotal()` | `String` |
    | `chargeTotal()` | `String` |
    | `taxableAmount()` | `String` |
    | `prepaidAmount()` | `String` |
    | `payableRoundingAmount()` | `String` |
    | `payableAmount()` | `String` |

    Optional object accessors return null when absent. Line-item objects provide description, quantity, unit code, unit price, total amount, VAT rate, VAT amount, and category. See [XML](xml.md) and [signing](invoice-signing.md) for document and signature operations.

=== "C"

    Include `fatoora.h`. Functions return `FatooraStatus`; read output pointers only after success. On failure, inspect and free `FatooraError`. Release returned strings with `fatoora_string_free()` and objects with their matching `_free()` function. Optional input strings use `NULL`, not empty strings.

    Invoice kind codes: `0` tax, `1` prepayment, `2` credit note, `3` debit note. Subtype: `0` standard, `1` simplified. VAT category: `0` exempt, `1` standard, `2` zero-rated, `3` out of scope. Flags are a bitmask: `1` third party, `2` nominal, `4` export, `8` summary, `16` self-billed. Use zero for no flags.

    **Create and configure**

    ```c
    FatooraStatus fatoora_invoice_builder_new(
        const FatooraInvoiceOptions *options,
        FatooraInvoiceBuilder **out, FatooraError **error);
    FatooraStatus fatoora_invoice_builder_build(
        FatooraInvoiceBuilder *self,
        FatooraFinalizedInvoice **out, FatooraError **error);
    ```

    `FatooraInvoiceOptions` contains `int32_t kind`, `int32_t subtype`, and optional `const char *original_id`, `original_uuid`, `original_date`, `reason`. Credit/debit notes require original ID and reason. Set unused optional pointers to `NULL`.

    All setter functions take builder first and `FatooraError **error` last, return status, and have no output argument:

    | Function suffix after `fatoora_invoice_builder_` | Value arguments |
    | --- | --- |
    | `set_id`, `set_uuid`, `set_issue_datetime`, `set_currency`, `set_previous_invoice_hash`, `set_payment_means_code`, `allowance_reason` | `const char *value` |
    | `invoice_level_charge`, `invoice_level_discount` | `const char *value` containing decimal text |
    | `set_invoice_counter` | `uint64_t value` |
    | `set_vat_category`, `flags` | `int32_t value` |
    | `set_note` | `const char *language, const char *value` |
    | `set_allowance` | `const char *reason, const char *amount` |
    | `set_seller`, `set_buyer` | `const FatooraPartyOptions *options` |
    | `add_line_item` | `const FatooraLineItemOptions *options` |

    `FatooraPartyOptions` contains `name`, borrowed `const FatooraAddress *address`, `vat_id`, `other_id`, and `scheme`; text fields are `const char *`. Seller VAT is required; buyer needs VAT or an other ID. Create the address with `fatoora_address_new(&options, &address, &error)` using `FatooraAddressOptions`: country_code, city, street, building_number, postal_code, and optional additional_street/additional_number/district. Setters copy the address data.

    `FatooraLineItemOptions` contains text fields `description`, `quantity`, `unit_code`, `unit_price`, `vat_rate`, and `int32_t category`. Numbers are decimal strings.

    Building consumes builder state on success or failure. Rejected setter inputs leave the builder available for correction. Always call `fatoora_invoice_builder_free()` afterward, including after consumption.

    **Read invoice data**

    `fatoora_finalized_invoice_data(invoice, &data, &error)` and `fatoora_signed_invoice_data(invoice, &data, &error)` return an owned `FatooraInvoiceData` snapshot; free it with `fatoora_invoice_data_free`. Snapshots survive invoice destruction.

    Data getters take `const FatooraInvoiceData *self`, the output pointer below, and `FatooraError **error`, and return status:

    | Suffix after `fatoora_invoice_data_` | Output |
    | --- | --- |
    | `id`, `uuid`, `issue_datetime`, `currency`, `previous_invoice_hash`, `payment_means_code` | Owned `char **out` |
    | `invoice_level_charge`, `invoice_level_discount` | Owned decimal text through `char **out` |
    | `allowance_reason`, `original_invoice_reason` | Optional owned text through `char **out`; `NULL` when absent |
    | `invoice_counter` | `uint64_t *out` |
    | `vat_category`, `flags_raw`, `invoice_type_kind`, `invoice_sub_type` | `uint8_t *out` |
    | `seller`, `buyer` | Owned `FatooraParty **out`; buyer may be `NULL` |
    | `note` | Optional owned `FatooraInvoiceNote **out` |
    | `original_invoice_ref` | Optional owned `FatooraOriginalInvoiceRef **out` |
    | `line_items_len` | `size_t *out` |
    | `line_item` | Extra `size_t index` argument, then owned `FatooraInvoiceLineItem **out` |

    `fatoora_finalized_invoice_totals` and `fatoora_signed_invoice_totals` return owned `FatooraInvoiceTotals **out`. Its getters have prefix `fatoora_invoice_totals_` and suffix `tax_inclusive`, `tax_amount`, `line_extension`, `allowance_total`, `charge_total`, `taxable_amount`, `prepaid_amount`, `payable_rounding_amount`, or `payable_amount`. Each takes the totals handle, returns decimal text through `char **out`, and accepts `FatooraError **error`. Free the text and then the snapshot with `fatoora_invoice_totals_free()`.

    Use [XML](xml.md) for serialization and [signing](invoice-signing.md) for consuming signing operations and metadata.
