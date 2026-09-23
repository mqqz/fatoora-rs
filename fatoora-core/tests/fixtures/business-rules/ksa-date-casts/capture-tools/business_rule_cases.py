"""Independent rule-family mutations for the pinned SDK's public validator."""

import xml.etree.ElementTree as ET

NS = {
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
}


def identity_cases(base):
    cases = []

    def case(name, role, section, field, value, code, count=1, scheme=None):
        root = ET.fromstring(base)
        party = root.find(f"cac:Accounting{role}Party/cac:Party", NS)
        parent = party.find(f"cac:{section}", NS)
        if parent is None:
            parent = ET.Element(f"{{{NS['cac']}}}{section}")
            if section == "PartyIdentification":
                party.insert(0, parent)
            else:
                party.append(parent)
        element = parent.find(f"cbc:{field}", NS)
        if element is None:
            element = ET.Element(f"{{{NS['cbc']}}}{field}")
            if section == "PostalAddress" and field == "AdditionalStreetName":
                street = parent.find("cbc:StreetName", NS)
                parent.insert(list(parent).index(street) + 1, element)
            else:
                parent.append(element)
        if value is None:
            parent.remove(element)
        else:
            element.text = value
            if scheme is not None:
                element.set("schemeID", scheme)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": "error"
                        if code in ["BR-KSA-14", "BR-KSA-40", "BR-KSA-44"]
                        else "warning",
                        "count": count,
                    }
                ],
            }
        )

    for name, role, scheme, good, bad, code in [
        ("crn", "Supplier", "CRN", "7123456123", "712345612", "BR-KSA-F-08"),
        ("unified", "Supplier", "700", "7123456123", "6123456123", "BR-KSA-F-09"),
        ("tin", "Customer", "TIN", "3123456123", "4123456123", "BR-KSA-F-07"),
        ("national", "Customer", "NAT", "1123456123", "2123456123", "BR-KSA-F-10"),
        ("residence", "Customer", "IQA", "2123456123", "3123456123", "BR-KSA-F-11"),
    ]:
        for suffix, value, count in [
            ("valid", good, 0),
            ("invalid", bad, 1),
            ("space", f" {good}", 1),
        ]:
            case(
                f"{name}-{suffix}",
                role,
                "PartyIdentification",
                "ID",
                value,
                code,
                count,
                scheme,
            )
    for name, scheme, value, code, count in [
        ("scheme-spaces", " CRN ", "7123456123", "BR-KSA-F-12", 1),
        ("scheme-lowercase", "crn", "7123456123", "BR-KSA-F-12", 0),
        ("predictable", "CRN", "9912345678", "BR-KSA-F-13", 1),
        ("predictable-alpha", "CRN", "A12345678", "BR-KSA-F-13", 0),
    ]:
        case(name, "Supplier", "PartyIdentification", "ID", value, code, count, scheme)
    for scheme, count in [("TIN", 0), ("BAD", 1), ("TIN NAT", 0)]:
        case(
            "buyer-scheme-" + scheme.replace(" ", "-"),
            "Customer",
            "PartyIdentification",
            "ID",
            "3123456123",
            "BR-KSA-14",
            count,
            scheme,
        )
    for role, code in [("Supplier", "BR-KSA-40"), ("Customer", "BR-KSA-44")]:
        for suffix, value, count in [
            ("valid", "312345612300003", 0),
            ("invalid", "312345612300004", 1),
        ]:
            case(
                role.lower() + "-vat-" + suffix,
                role,
                "PartyTaxScheme",
                "CompanyID",
                value,
                code,
                count,
            )
    for name, role, field, value, code, count in [
        ("seller-address-missing-city", "Supplier", "CityName", None, "BR-KSA-09", 1),
        ("seller-street-empty", "Supplier", "StreetName", "", "BR-KSA-F-06-C4", 1),
        (
            "seller-street-boundary",
            "Supplier",
            "StreetName",
            "ع" * 1000,
            "BR-KSA-F-06-C4",
            0,
        ),
        (
            "seller-street-long",
            "Supplier",
            "StreetName",
            "ع" * 1001,
            "BR-KSA-F-06-C4",
            1,
        ),
        ("seller-city-long", "Supplier", "CityName", "x" * 128, "BR-KSA-F-06-C7", 1),
        (
            "seller-city-boundary",
            "Supplier",
            "CityName",
            "x" * 127,
            "BR-KSA-F-06-C7",
            0,
        ),
        (
            "seller-street2-long",
            "Supplier",
            "AdditionalStreetName",
            "x" * 128,
            "BR-KSA-F-06-C6",
            1,
        ),
        (
            "seller-street2-boundary",
            "Supplier",
            "AdditionalStreetName",
            "x" * 127,
            "BR-KSA-F-06-C6",
            0,
        ),
        (
            "buyer-street2-long",
            "Customer",
            "AdditionalStreetName",
            "x" * 128,
            "BR-KSA-F-06-C11",
            1,
        ),
        (
            "buyer-street2-boundary",
            "Customer",
            "AdditionalStreetName",
            "x" * 127,
            "BR-KSA-F-06-C11",
            0,
        ),
        ("seller-postcode-invalid", "Supplier", "PostalZone", "1234", "BR-KSA-66", 1),
        ("seller-postcode-valid", "Supplier", "PostalZone", "12345", "BR-KSA-66", 0),
        (
            "seller-building-invalid",
            "Supplier",
            "BuildingNumber",
            "123",
            "BR-KSA-37",
            1,
        ),
        ("seller-building-valid", "Supplier", "BuildingNumber", "1234", "BR-KSA-37", 0),
    ]:
        case(name, role, "PostalAddress", field, value, code, count)
    for field, value, code, count, suffix in [
        ("Telephone", "+1234", "BR-KSA-85", 0, "valid"),
        ("Telephone", "1234", "BR-KSA-85", 1, "invalid"),
        ("Name", "ع" * 1000, "BR-KSA-F-06-C37", 0, "boundary"),
        ("Name", "ع" * 1001, "BR-KSA-F-06-C37", 1, "long"),
        ("Note", "ع" * 1000, "BR-KSA-F-06-C38", 0, "boundary"),
        ("Note", "ع" * 1001, "BR-KSA-F-06-C38", 1, "long"),
    ]:
        case(
            "contact-" + field.lower() + "-" + suffix,
            "Customer",
            "Contact",
            field,
            value,
            code,
            count,
        )
    return cases


def structural_cases(base):
    """CEN expectations derived before invoking the reference SDK."""
    cases = []

    def case(
        name,
        path,
        value,
        code,
        severity="warning",
        xsd="passed",
        count=1,
        attribute=None,
    ):
        root = ET.fromstring(base)
        element = root.find(path, NS)
        if element is None:
            raise ValueError(f"Missing mutation target: {path}")
        if value is None:
            parent = next(p for p in root.iter() if element in list(p))
            parent.remove(element)
        elif attribute:
            element.set(attribute, value)
        else:
            element.text = value
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": xsd,
                "targets": [
                    {"source": "en", "code": code, "severity": severity, "count": count}
                ],
            }
        )

    for name, path, value, code, severity, xsd in [
        (
            "supporting-id-empty",
            "cac:AdditionalDocumentReference/cbc:ID",
            "",
            "BR-52",
            "warning",
            "passed",
        ),
        (
            "document-allowance-no-amount",
            "cac:AllowanceCharge[cbc:ChargeIndicator='false']/cbc:Amount",
            None,
            "BR-31",
            "error",
            "failed",
        ),
        (
            "document-allowance-no-category",
            "cac:AllowanceCharge[cbc:ChargeIndicator='false']/cac:TaxCategory/cbc:ID",
            None,
            "BR-32",
            "error",
            "passed",
        ),
        (
            "document-charge-no-amount",
            "cac:AllowanceCharge[cbc:ChargeIndicator='true']/cbc:Amount",
            None,
            "BR-36",
            "warning",
            "failed",
        ),
        (
            "document-charge-no-category",
            "cac:AllowanceCharge[cbc:ChargeIndicator='true']/cac:TaxCategory/cbc:ID",
            None,
            "BR-37",
            "warning",
            "passed",
        ),
        (
            "total-exclusive-missing",
            "cac:LegalMonetaryTotal/cbc:TaxExclusiveAmount",
            None,
            "BR-13",
            "warning",
            "passed",
        ),
        (
            "total-inclusive-missing",
            "cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount",
            None,
            "BR-14",
            "error",
            "passed",
        ),
        (
            "total-payable-missing",
            "cac:LegalMonetaryTotal/cbc:PayableAmount",
            None,
            "BR-15",
            "error",
            "failed",
        ),
        ("invoice-id-missing", "cbc:ID", None, "BR-02", "warning", "failed"),
        ("invoice-id-long", "cbc:ID", "x" * 128, "BR-KSA-F-06-C1", "warning", "passed"),
        ("issue-date-missing", "cbc:IssueDate", None, "BR-03", "error", "failed"),
        (
            "invoice-type-missing",
            "cbc:InvoiceTypeCode",
            None,
            "BR-04",
            "error",
            "passed",
        ),
        (
            "document-currency-missing",
            "cbc:DocumentCurrencyCode",
            None,
            "BR-05",
            "error",
            "passed",
        ),
        (
            "seller-name-empty",
            "cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName",
            "",
            "BR-06",
            "warning",
            "passed",
        ),
        (
            "seller-name-long",
            "cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName",
            "ع" * 1001,
            "BR-KSA-F-06-C10",
            "warning",
            "passed",
        ),
        (
            "seller-address-missing",
            "cac:AccountingSupplierParty/cac:Party/cac:PostalAddress",
            None,
            "BR-08",
            "warning",
            "passed",
        ),
        (
            "line-id-long",
            "cac:InvoiceLine/cbc:ID",
            "1234567",
            "BR-KSA-F-06-C17",
            "error",
            "passed",
        ),
        (
            "item-name-short",
            "cac:InvoiceLine/cac:Item/cbc:Name",
            "ab",
            "BR-KSA-F-06-C19",
            "warning",
            "passed",
        ),
        (
            "item-name-numeric",
            "cac:InvoiceLine/cac:Item/cbc:Name",
            "١٢٣",
            "BR-KSA-F-C-01",
            "warning",
            "passed",
        ),
        ("line-id-empty", "cac:InvoiceLine/cbc:ID", "", "BR-21", "warning", "passed"),
        (
            "line-quantity-zero",
            "cac:InvoiceLine/cbc:InvoicedQuantity",
            "0",
            "BR-22",
            "error",
            "passed",
        ),
        (
            "line-extension-missing",
            "cac:InvoiceLine/cbc:LineExtensionAmount",
            None,
            "BR-24",
            "error",
            "failed",
        ),
        (
            "line-price-missing",
            "cac:InvoiceLine/cac:Price/cbc:PriceAmount",
            None,
            "BR-26",
            "error",
            "failed",
        ),
        (
            "line-tax-category-missing",
            "cac:InvoiceLine/cac:Item/cac:ClassifiedTaxCategory/cbc:ID",
            None,
            "BR-CO-04",
            "error",
            "passed",
        ),
        (
            "payment-code-missing",
            "cac:PaymentMeans/cbc:PaymentMeansCode",
            None,
            "BR-49",
            "warning",
            "failed",
        ),
        (
            "seller-country-empty",
            "cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cac:Country/cbc:IdentificationCode",
            "",
            "BR-09",
            "warning",
            "passed",
        ),
        (
            "subtotal-taxable-missing",
            "cac:TaxTotal/cac:TaxSubtotal/cbc:TaxableAmount",
            None,
            "BR-45",
            "error",
            "passed",
        ),
        (
            "subtotal-tax-missing",
            "cac:TaxTotal/cac:TaxSubtotal/cbc:TaxAmount",
            None,
            "BR-46",
            "error",
            "failed",
        ),
        (
            "subtotal-category-missing",
            "cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cbc:ID",
            None,
            "BR-47",
            "error",
            "passed",
        ),
        (
            "subtotal-rate-missing",
            "cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cbc:Percent",
            None,
            "BR-48",
            "error",
            "passed",
        ),
    ]:
        case(name, path, value, code, severity, xsd)
    for name, path, code in [
        (
            "allowance",
            "cac:AllowanceCharge[cbc:ChargeIndicator='false']/cbc:Amount",
            "BR-DEC-01",
        ),
        (
            "charge",
            "cac:AllowanceCharge[cbc:ChargeIndicator='true']/cbc:Amount",
            "BR-DEC-05",
        ),
        ("line", "cac:InvoiceLine/cbc:LineExtensionAmount", "BR-DEC-23"),
        ("taxable", "cac:TaxTotal/cac:TaxSubtotal/cbc:TaxableAmount", "BR-DEC-19"),
        ("tax", "cac:TaxTotal/cac:TaxSubtotal/cbc:TaxAmount", "BR-DEC-20"),
    ]:
        original = ET.fromstring(base).find(path, NS).text
        case(name + "-scale", path, original + "0", code)
        case(name + "-scale-valid", path, original, code, count=0)

    case(
        "unit-code-long",
        "cac:InvoiceLine/cbc:InvoicedQuantity",
        "x" * 128,
        "BR-KSA-F-06-C18",
        attribute="unitCode",
    )
    case(
        "unit-code-boundary",
        "cac:InvoiceLine/cbc:InvoicedQuantity",
        "x" * 127,
        "BR-KSA-F-06-C18",
        count=0,
        attribute="unitCode",
    )
    case(
        "quantity-zero-decimal",
        "cac:InvoiceLine/cbc:InvoicedQuantity",
        "0.0",
        "BR-22",
        "error",
        count=0,
    )
    for name, path, good, bad, code, severity, attribute in [
        (
            "document-type",
            "cbc:InvoiceTypeCode",
            "388",
            "999",
            "BR-CL-01",
            "error",
            None,
        ),
        (
            "amount-currency",
            "cac:AllowanceCharge/cbc:Amount",
            "SAR",
            "BAD",
            "BR-CL-03",
            "error",
            "currencyID",
        ),
        (
            "document-currency",
            "cbc:DocumentCurrencyCode",
            "MRO",
            "MRU",
            "BR-CL-04",
            "error",
            None,
        ),
        (
            "tax-currency",
            "cbc:TaxCurrencyCode",
            "SAR",
            "BAD",
            "BR-CL-05",
            "error",
            None,
        ),
        (
            "country",
            "cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cac:Country/cbc:IdentificationCode",
            "1A",
            "BAD",
            "BR-CL-14",
            "warning",
            None,
        ),
        (
            "payment",
            "cac:PaymentMeans/cbc:PaymentMeansCode",
            "69",
            "999",
            "BR-CL-16",
            "warning",
            None,
        ),
        (
            "category",
            "cac:AllowanceCharge/cac:TaxCategory/cbc:ID",
            "AE",
            "BAD",
            "BR-CL-18",
            "error",
            None,
        ),
    ]:
        case(
            name + "-list-valid",
            path,
            good,
            code,
            severity,
            count=0,
            attribute=attribute,
        )
        case(name + "-list-invalid", path, bad, code, severity, attribute=attribute)
    return cases


def totals_cases(base):
    cases = []

    def case(name, fields, code, count=1, line=None, xsd="passed"):
        root = ET.fromstring(base)
        for field, value in fields.items():
            node = root.find("cac:LegalMonetaryTotal/cbc:" + field, NS)
            if value is None:
                root.find("cac:LegalMonetaryTotal", NS).remove(node)
            else:
                node.text = value
        if line is not None:
            for i, node in enumerate(
                root.findall("cac:InvoiceLine/cbc:LineExtensionAmount", NS)
            ):
                node.text = line if i == 0 else "0"
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": xsd,
                "targets": [
                    {
                        "source": "en",
                        "code": code,
                        "severity": "error"
                        if code in ["BR-CO-11", "BR-CO-12"]
                        else "warning",
                        "count": count,
                    }
                ],
            }
        )

    for field, value, wrong, code in [
        ("AllowanceTotalAmount", "20.00", "20.01", "BR-CO-11"),
        ("ChargeTotalAmount", "12.50", "12.51", "BR-CO-12"),
        ("TaxExclusiveAmount", "1392.50", "1392.51", "BR-CO-13"),
        ("PayableAmount", "1511.38", "1511.39", "BR-CO-16"),
    ]:
        case(field + "-valid", {field: value}, code, 0)
        case(field + "-invalid", {field: wrong}, code)
    case("charge-empty-sum", {"ChargeTotalAmount": ""}, "BR-CO-12", xsd="failed")
    case("charge-empty-exclusive", {"ChargeTotalAmount": " "}, "BR-CO-13", xsd="failed")
    for name, value, valid, invalid in [
        ("positive-half", "1.005", "1.00", "1.01"),
        ("negative-half", "-1.005", "-1.00", "-1.01"),
        ("two-sixty-seven", "2.675", "2.67", "2.68"),
        (
            "large-double",
            "1000000000000000100",
            "1000000000000000128",
            "1000000000000000100",
        ),
    ]:
        for suffix, total, count in [("binary", valid, 0), ("display", invalid, 1)]:
            case(
                name + "-" + suffix,
                {
                    "ChargeTotalAmount": "0",
                    "AllowanceTotalAmount": "0",
                    "TaxExclusiveAmount": total,
                },
                "BR-CO-13",
                count,
                value,
            )
    return cases


def ksa_field_cases(base):
    cases = []

    def case(name, change, code, count, severity="warning", xsd="passed"):
        root = ET.fromstring(base)
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": xsd,
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    for value, count in [("386", 0), ("380", 1), ("", 0)]:
        case(
            "type-" + (value or "empty"),
            lambda r, v=value: setattr(r.find("cbc:InvoiceTypeCode", NS), "text", v),
            "BR-KSA-05",
            count,
            "error",
        )
    for value, count in [("010000000", 0), ("0100200", 1), ("010000", 1)]:
        case(
            "transaction-" + value,
            lambda r, v=value: r.find("cbc:InvoiceTypeCode", NS).set("name", v),
            "BR-KSA-06",
            count,
            "error",
        )
    for value, count in [("010000000", 0), ("010000", 1)]:
        case(
            "transaction-length-" + value,
            lambda r, v=value: r.find("cbc:InvoiceTypeCode", NS).set("name", v),
            "BR-KSA-F-06-C40",
            count,
        )
    for value, count in [(" reporting:1.0 ", 0), ("Reporting:1.0", 1)]:
        case(
            "profile-" + str(count),
            lambda r, v=value: setattr(r.find("cbc:ProfileID", NS), "text", v),
            "BR-KSA-EN16931-01",
            count,
            "error",
        )

    def extra_tax(root):
        import copy

        node = next(
            n
            for n in root.findall("cac:TaxTotal", NS)
            if n.find("cac:TaxSubtotal", NS) is not None
        )
        root.insert(list(root).index(node), copy.deepcopy(node))

    case("subtotal-total-single", lambda r: None, "BR-KSA-EN16931-08", 0)
    case("subtotal-total-repeated", extra_tax, "BR-KSA-EN16931-08", 1)

    def allowance(root, base_amount, percentage):
        node = root.find("cac:AllowanceCharge", NS)
        amount = node.find("cbc:Amount", NS)
        if percentage:
            child = ET.Element(f"{{{NS['cbc']}}}MultiplierFactorNumeric")
            child.text = "10"
            node.insert(list(node).index(amount), child)
        if base_amount:
            child = ET.Element(f"{{{NS['cbc']}}}BaseAmount", {"currencyID": "SAR"})
            child.text = "200"
            node.insert(list(node).index(amount) + 1, child)

    for field, code in [
        ("base", "BR-KSA-EN16931-05"),
        ("percent", "BR-KSA-EN16931-04"),
    ]:
        for present, count in [(True, 0), (False, 1)]:
            case(
                f"{field}-pair-{present}",
                lambda r, f=field, p=present: allowance(
                    r, f == "base" or p, f == "percent" or p
                ),
                code,
                count,
            )

    def price_charge(root, value):
        price = root.find("cac:InvoiceLine/cac:Price", NS)
        charge = ET.SubElement(price, f"{{{NS['cac']}}}AllowanceCharge")
        ET.SubElement(charge, f"{{{NS['cbc']}}}ChargeIndicator").text = value
        ET.SubElement(
            charge, f"{{{NS['cbc']}}}Amount", {"currencyID": "SAR"}
        ).text = "0"

    for value, count in [("false", 0), ("true", 1)]:
        case(
            "price-charge-" + value,
            lambda r, v=value: price_charge(r, v),
            "BR-KSA-EN16931-06",
            count,
            "error",
        )

    def quantity(root, value, unit="PCE"):
        price = root.find("cac:InvoiceLine/cac:Price", NS)
        ET.SubElement(
            price, f"{{{NS['cbc']}}}BaseQuantity", {"unitCode": unit}
        ).text = value

    for value, count in [("1", 0), ("-1", 1)]:
        case(
            "base-quantity-" + value,
            lambda r, v=value: quantity(r, v),
            "BR-KSA-EN16931-12",
            count,
            "error",
        )
    for length, count in [(127, 0), (128, 1)]:
        case(
            "base-unit-" + str(length),
            lambda r, n=length: quantity(r, "1", "x" * n),
            "BR-KSA-F-06-C21",
            count,
        )
    return cases


def ksa_buyer_cases(base):
    cases = []

    def case(
        name,
        change,
        code,
        count,
        kind="0100000",
        invoice_type="388",
        severity="warning",
    ):
        root = ET.fromstring(base)
        type_node = root.find("cbc:InvoiceTypeCode", NS)
        type_node.set("name", kind)
        type_node.text = invoice_type
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    def set_text(root, path, value):
        root.find(path, NS).text = value

    address = "cac:AccountingCustomerParty/cac:Party/cac:PostalAddress/"
    for field, good, bad, code in [
        ("CitySubdivisionName", "District", "", "BR-KSA-F-06-C28"),
        ("CitySubdivisionName", "x" * 127, "x" * 128, "BR-KSA-F-06-C29"),
        ("PostalZone", "12345", "١٢٣٤٥", "BR-KSA-67"),
        ("StreetName", "Street", "", "BR-KSA-F-06-C23"),
        ("CityName", "City", "", "BR-KSA-F-06-C25"),
        ("CityName", "x" * 127, "x" * 128, "BR-KSA-F-06-C26"),
    ]:
        for value, count in [(good, 0), (bad, 1)]:
            case(
                code + "-" + str(count),
                lambda r, f=field, v=value: set_text(r, address + "cbc:" + f, v),
                code,
                count,
            )
    for kind, code in [("0100000", "BR-KSA-F-06-C12"), ("0200000", "BR-KSA-F-06-C32")]:
        for length, count in [(1000, 0), (1001, 1)]:
            case(
                code + "-" + str(length),
                lambda r, n=length: set_text(
                    r,
                    "cac:AccountingCustomerParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName",
                    "x" * n,
                ),
                code,
                count,
                kind,
            )
    for code, field in [("BR-KSA-52", "TaxAmount"), ("BR-KSA-53", "RoundingAmount")]:

        def remove_line_amount(root, f=field):
            tax = root.find("cac:InvoiceLine/cac:TaxTotal", NS)
            tax.remove(tax.find("cbc:" + f, NS))

        # TaxAmount is mandatory in UBL; use the optional rounding amount probe
        # here and cover TaxAmount directly in native tests.
        if field == "RoundingAmount":
            case(
                "line-inclusive-missing", remove_line_amount, code, 1, severity="error"
            )
    for value, count in [("68", 0), ("69", 1)]:
        case(
            "ksa-payment-" + value,
            lambda r, v=value: set_text(r, "cac:PaymentMeans/cbc:PaymentMeansCode", v),
            "BR-KSA-16",
            count,
        )

    def instruction(root, value):
        means = root.find("cac:PaymentMeans", NS)
        if value is None:
            root.remove(means)
        else:
            ET.SubElement(means, f"{{{NS['cbc']}}}InstructionNote").text = value

    for value, count, suffix in [
        (None, 1, "absent-payment"),
        ("", 0, "empty-reason"),
        ("Reason", 0, "reason"),
    ]:
        case(
            "note-" + suffix,
            lambda r, v=value: instruction(r, v),
            "BR-KSA-17",
            count,
            invoice_type="381",
            severity="error",
        )
    for value, count in [("", 1), ("x" * 1000, 0), ("x" * 1001, 1)]:
        case(
            "note-reason-length-" + str(len(value)),
            lambda r, v=value: instruction(r, v),
            "BR-KSA-F-06-C13",
            count,
            invoice_type="383",
        )

    def reference(root, value):
        node = ET.Element(f"{{{NS['cac']}}}BillingReference")
        invoice = ET.SubElement(node, f"{{{NS['cac']}}}InvoiceDocumentReference")
        ET.SubElement(invoice, f"{{{NS['cbc']}}}ID").text = value
        first = root.find("cac:AdditionalDocumentReference", NS)
        root.insert(list(root).index(first), node)

    for value, count in [("", 1), (" ", 0), ("Invoice", 0)]:
        case(
            "note-reference-" + str(len(value)),
            lambda r, v=value: reference(r, v),
            "BR-KSA-56",
            count,
            invoice_type="381",
        )
    for kind, count in [("0200000", 0), ("0200001", 1)]:
        case(
            "simple-flags-" + kind,
            lambda r: None,
            "BR-KSA-31",
            count,
            kind,
            severity="error",
        )
    for kind, count in [("0100100", 0), ("0100101", 1)]:
        case(
            "export-flags-" + kind,
            lambda r: None,
            "BR-KSA-07",
            count,
            kind,
            severity="error",
        )
    for value, count in [("310122393500003", 0), (" ", 1)]:
        case(
            "buyer-vat-empty-" + str(count),
            lambda r, v=value: set_text(
                r,
                "cac:AccountingCustomerParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID",
                v,
            ),
            "BR-KSA-99",
            count,
        )
    return cases


def ksa_common_cases(base):
    cases = []

    def case(name, change, code, count, severity="warning"):
        root = ET.fromstring(base)
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    for value, count, suffix in [
        ("A!anything", 0, "start-only"),
        ("_identifier", 1, "underscore"),
        ("😀", 0, "symbol"),
        ("", 1, "empty"),
    ]:
        case(
            "uuid-" + suffix,
            lambda r, v=value: setattr(r.find("cbc:UUID", NS), "text", v),
            "BR-KSA-03",
            count,
            "error",
        )
    for value, count, suffix in [
        ("007", 0, "digits"),
        ("7A", 1, "alpha"),
        ("", 0, "empty"),
    ]:
        case(
            "counter-" + suffix,
            lambda r, v=value: setattr(
                r.find("cac:AdditionalDocumentReference/cbc:UUID", NS), "text", v
            ),
            "BR-KSA-34",
            count,
            "error",
        )
    case(
        "counter-presence-empty",
        lambda r: setattr(
            r.find("cac:AdditionalDocumentReference/cbc:UUID", NS), "text", ""
        ),
        "BR-KSA-33",
        1,
        "error",
    )
    for value, count in [("310122393500003", 0), ("399999999900003", 1)]:
        case(
            "vat-equality-" + str(count),
            lambda r, v=value: setattr(
                r.find(
                    "cac:AccountingCustomerParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID",
                    NS,
                ),
                "text",
                v,
            ),
            "BR-CUSTOM-VALIDATION-01",
            count,
            "error",
        )
    for value, count in [("CRN", 0), ("CRN MOM", 0), ("BAD", 1)]:
        case(
            "seller-scheme-" + value.replace(" ", "-"),
            lambda r, v=value: r.find(
                "cac:AccountingSupplierParty/cac:Party/cac:PartyIdentification/cbc:ID",
                NS,
            ).set("schemeID", v),
            "BR-KSA-08",
            count,
        )
    for value, count in [("text/plain", 0), ("application/pdf", 1)]:
        for code in ["BR-KSA-61", "BR-KSA-26"]:
            case(
                "pih-mime-" + code + "-" + str(count),
                lambda r, v=value: r.find(
                    "cac:AdditionalDocumentReference/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
                    NS,
                ).set("mimeCode", v),
                code,
                count,
            )
    for value, count in [("SAR", 0), ("", 1)]:
        case(
            "tax-currency-presence-" + str(count),
            lambda r, v=value: setattr(r.find("cbc:TaxCurrencyCode", NS), "text", v),
            "BR-KSA-68",
            count,
            "error",
        )
    for value, count in [("Buyer", 0), ("", 1)]:
        case(
            "buyer-name-presence-" + str(count),
            lambda r, v=value: setattr(
                r.find(
                    "cac:AccountingCustomerParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName",
                    NS,
                ),
                "text",
                v,
            ),
            "BR-KSA-42",
            count,
        )
    return cases


def vat_cases(base):
    cases = []
    # format-number uses shortest-roundtrip decimal formatting, separately from
    # the exact binary-value casts tested by the monetary family.
    for taxable, lower, upper, rounded_up in [
        ("1.005", "0.99", "1.02", False),
        ("2.675", "2.66", "2.69", True),
        ("1.015", "1.00", "1.03", True),
        ("-1.005", "-1.02", "-0.99", True),
        ("-2.675", "-2.69", "-2.66", False),
        ("2.6749999999999994", "2.66", "2.69", False),
        ("2.6750000000000003", "2.66", "2.69", True),
        ("2.67499999999999", "2.66", "2.69", False),
        ("2.67500000000001", "2.66", "2.69", True),
        ("1.0149999999999997", "1.00", "1.03", False),
        ("1.0150000000000001", "1.00", "1.03", True),
    ]:
        for tax, count in [(lower, int(rounded_up)), (upper, int(not rounded_up))]:
            root = ET.fromstring(base)
            for line in root.findall("cac:InvoiceLine", NS)[1:]:
                root.remove(line)
            for total in root.findall("cac:TaxTotal", NS):
                for sub in total.findall("cac:TaxSubtotal", NS)[1:]:
                    total.remove(sub)
            sub = root.find("cac:TaxTotal/cac:TaxSubtotal", NS)
            sub.find("cbc:TaxableAmount", NS).text = taxable
            sub.find("cbc:TaxAmount", NS).text = tax
            sub.find("cac:TaxCategory/cbc:Percent", NS).text = "100"
            cases.append(
                {
                    "id": "round-" + taxable + "-" + tax,
                    "xml": ET.tostring(root, encoding="unicode"),
                    "expected_xsd": "passed",
                    "targets": [
                        {
                            "source": "en",
                            "code": code,
                            "severity": "warning",
                            "count": count,
                        }
                        for code in ["BR-CO-17", "BR-S-09"]
                    ],
                }
            )
    return cases


def ksa_adjustment_cases(base):
    cases = []

    def case(name, change, code, count, severity="warning"):
        root = ET.fromstring(base)
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    def adjustment(root, charge, line=False):
        parent = root.find("cac:InvoiceLine", NS) if line else root
        for node in parent.findall("cac:AllowanceCharge", NS):
            if node.find("cbc:ChargeIndicator", NS).text == charge:
                return node
        node = ET.Element(f"{{{NS['cac']}}}AllowanceCharge")
        ET.SubElement(node, f"{{{NS['cbc']}}}ChargeIndicator").text = charge
        ET.SubElement(node, f"{{{NS['cbc']}}}Amount", {"currencyID": "SAR"}).text = "0"
        index = next(
            i for i, n in enumerate(parent) if n.tag == f"{{{NS['cac']}}}TaxTotal"
        )
        parent.insert(index, node)
        return node

    def reason(root, field, value, line=False):
        node = adjustment(root, "true", line)
        child = node.find("cbc:" + field, NS)
        if child is None:
            child = ET.Element(f"{{{NS['cbc']}}}{field}")
            node.insert(1, child)
        child.text = value

    for line, code, field in [
        (False, "BR-KSA-19", "AllowanceChargeReasonCode"),
        (False, "BR-KSA-21", "AllowanceChargeReason"),
        (True, "BR-KSA-20", "AllowanceChargeReasonCode"),
        (True, "BR-KSA-22", "AllowanceChargeReason"),
    ]:
        for value, count in [("AA", 0), (" ", 1)]:
            case(
                code + "-" + str(count),
                lambda r, v=value, f=field, l=line: reason(r, f, v, l),
                code,
                count,
            )

    def percentage(root, value):
        node = adjustment(root, "false")
        child = ET.Element(f"{{{NS['cbc']}}}MultiplierFactorNumeric")
        child.text = value
        amount = node.find("cbc:Amount", NS)
        node.insert(list(node).index(amount), child)

    for value, count in [
        ("0", 0),
        ("100.00", 0),
        ("100.01", 1),
        ("0.000", 1),
        ("-1", 1),
    ]:
        case(
            "allowance-percent-" + value,
            lambda r, v=value: percentage(r, v),
            "BR-KSA-DEC-01",
            count,
            "error",
        )
    for value, count in [("15", 0), ("100.00", 0), ("100.01", 1), ("15.000", 1)]:
        case(
            "tax-percent-" + value,
            lambda r, v=value: setattr(
                r.find(
                    "cac:InvoiceLine/cac:Item/cac:ClassifiedTaxCategory/cbc:Percent", NS
                ),
                "text",
                v,
            ),
            "BR-KSA-DEC-02",
            count,
            "error",
        )
    for field, code in [
        ("TaxAmount", "BR-KSA-DEC-03"),
        ("RoundingAmount", "BR-KSA-DEC-04"),
    ]:
        for value, count in [("12.34", 0), ("12.345", 1)]:
            case(
                "line-" + field + "-" + str(count),
                lambda r, f=field, v=value: setattr(
                    r.find("cac:InvoiceLine/cac:TaxTotal/cbc:" + f, NS), "text", v
                ),
                code,
                count,
            )
    return cases


def ksa_exemption_cases(base):
    cases = []

    def case(name, change, code, count, severity="warning"):
        root = ET.fromstring(base)
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    def document_category(root, category, code=None, reason=None):
        sub = root.find("cac:TaxTotal/cac:TaxSubtotal", NS)
        tax = sub.find("cac:TaxCategory", NS)
        tax.find("cbc:ID", NS).text = category
        tax.find("cbc:Percent", NS).text = "0"
        sub.find("cbc:TaxAmount", NS).text = "0"
        for field, value in [
            ("TaxExemptionReasonCode", code),
            ("TaxExemptionReason", reason),
        ]:
            if value is not None:
                child = ET.Element(f"{{{NS['cbc']}}}{field}")
                child.text = value
                tax.insert(list(tax).index(tax.find("cac:TaxScheme", NS)), child)

    for category, code in [
        ("Z", "VATEX-SA-ROYALDECREE"),
        ("Z", "VATEX-SA-32(bis)"),
        ("E", "VATEX-SA-29-7"),
        ("O", "VATEX-SA-OOS"),
    ]:
        for value, count in [(code, 0), ("BAD", 1)]:
            case(
                "document-code-" + category + "-" + code + "-" + value,
                lambda r, c=category, v=value: document_category(r, c, v, "Reason"),
                "BR-KSA-CL-04",
                count,
            )
    for value, count in [("Reason", 0), (" ", 1)]:
        case(
            "document-reason-" + str(count),
            lambda r, v=value: document_category(r, "E", "VATEX-SA-29", v),
            "BR-KSA-83",
            count,
        )
    for value, count in [("15", 0), ("15.99", 0), ("5", 0), ("5.99", 1), ("16", 1)]:
        case(
            "standard-rate-" + value,
            lambda r, v=value: setattr(
                r.find(
                    "cac:InvoiceLine/cac:Item/cac:ClassifiedTaxCategory/cbc:Percent", NS
                ),
                "text",
                v,
            ),
            "BR-KSA-84",
            count,
            "error",
        )
    for value, count in [("text/plain", 0), ("image/png", 0), ("text/html", 1)]:
        case(
            "attachment-mime-" + value.replace("/", "-"),
            lambda r, v=value: r.find(
                "cac:AdditionalDocumentReference/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
                NS,
            ).set("mimeCode", v),
            "BR-KSA-CL-03",
            count,
            "error",
        )

    def prepayment(root, code, reason):
        total = root.find("cac:InvoiceLine/cac:TaxTotal", NS)
        sub = ET.SubElement(total, f"{{{NS['cac']}}}TaxSubtotal")
        for field in ["TaxableAmount", "TaxAmount"]:
            ET.SubElement(
                sub, f"{{{NS['cbc']}}}{field}", {"currencyID": "SAR"}
            ).text = "0"
        category = ET.SubElement(sub, f"{{{NS['cac']}}}TaxCategory")
        for field, value in [
            ("ID", "Z"),
            ("Percent", "0"),
            ("TaxExemptionReasonCode", code),
            ("TaxExemptionReason", reason),
        ]:
            if value is not None:
                ET.SubElement(category, f"{{{NS['cbc']}}}{field}").text = value
        scheme = ET.SubElement(category, f"{{{NS['cac']}}}TaxScheme")
        ET.SubElement(scheme, f"{{{NS['cbc']}}}ID").text = "VAT"

    for value, count in [
        ("VATEX-SA-32", 0),
        ("VATEX-SA-ROYALDECREE", 1),
        ("BAD", 1),
        (None, 0),
    ]:
        case(
            "prepayment-code-" + str(value),
            lambda r, v=value: prepayment(r, v, "Reason"),
            "BR-KSA-CL-07",
            count,
        )
    for value, count in [("Reason", 0), (" ", 1)]:
        case(
            "prepayment-reason-" + str(count),
            lambda r, v=value: prepayment(r, "VATEX-SA-32", v),
            "BR-KSA-96",
            count,
        )
    return cases


def ksa_currency_cases(base):
    cases = []

    def case(name, change, code, count, severity="error"):
        root = ET.fromstring(base)
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    patterns = [
        ("exact", "SAR", 0),
        ("substring", "S", 0),
        ("dot", "S.R", 0),
        ("class", "[A-Z]+", 0),
        ("block", r"^S\p{IsBasicLatin}{2}$", 0),
        ("xml-name", r"^\i\c*$", 0),
        ("word", r"^\w+$", 0),
        ("subtraction", "^[A-Z-[AEIOU]]+$", 1),
        ("backref", r"^(S)?\1AR$", 1),
        ("empty-capture", r"^(X)?\1SAR$", 0),
        ("noncapture", "^(?:S|U)AR$", 0),
        ("wrong", "USD", 1),
    ]
    for name, value, count in patterns:
        case(
            "amount-" + name,
            lambda r, v=value: r.find(
                "cac:InvoiceLine/cbc:LineExtensionAmount", NS
            ).set("currencyID", v),
            "BR-KSA-CL-02",
            count,
        )
    for name, value in [
        ("bracket", "["),
        ("possessive", "S++"),
        ("backref", r"(S)\2"),
        ("lookahead", "(?=SAR)"),
    ]:
        case(
            "invalid-pattern-" + name,
            lambda r, v=value: r.find(
                "cac:InvoiceLine/cbc:LineExtensionAmount", NS
            ).set("currencyID", v),
            "SaxonApiException",
            1,
        )

    def exchange(root, source, target, rate):
        node = ET.Element(f"{{{NS['cac']}}}TaxExchangeRate")
        for field, value in [
            ("SourceCurrencyCode", source),
            ("TargetCurrencyCode", target),
            ("CalculationRate", rate),
        ]:
            ET.SubElement(node, f"{{{NS['cbc']}}}{field}").text = value
        root.insert(list(root).index(root.find("cac:TaxTotal", NS)), node)

    for field, code in [("source", "BR-KSA-88"), ("target", "BR-KSA-89")]:
        for value, count in [("S", 0), ("USD", 1)]:
            case(
                "exchange-" + field + "-" + value,
                lambda r, v=value, f=field: exchange(
                    r, v if f == "source" else "SAR", v if f == "target" else "SAR", "1"
                ),
                code,
                count,
            )
    for value, count in [
        ("1.000000000000", 0),
        ("1.0000000000000", 1),
        ("1.00000000000000", 1),
    ]:
        case(
            "rate-" + str(len(value)),
            lambda r, v=value: exchange(r, "SAR", "SAR", v),
            "BR-KSA-90",
            count,
        )
    for value, count in [("0", 0), ("-0", 0), ("-1", 1)]:
        case(
            "price-sign-" + value,
            lambda r, v=value: setattr(
                r.find("cac:InvoiceLine/cac:Price/cbc:PriceAmount", NS), "text", v
            ),
            "BR-KSA-F-04",
            count,
        )
    return cases


def ksa_date_cases(base):
    cases = []

    def case(name, change, code, count, severity="error", xsd="passed"):
        root = ET.fromstring(base)
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": xsd,
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "severity": severity,
                        "count": count,
                    }
                ],
            }
        )

    for name, value, count in [
        ("local", "09:15:00", 0),
        ("utc", "09:15:00Z", 0),
        ("offset", "09:15:00+03:00", 1),
        ("fraction", "09:15:00.1", 1),
        ("midnight", "24:00:00", 1),
        ("whitespace", " 09:15:00 ", 1),
    ]:
        case(
            "issue-time-" + name,
            lambda r, v=value: setattr(r.find("cbc:IssueTime", NS), "text", v),
            "BR-KSA-70",
            count,
        )
    for name, value, count in [("past", "2024-02-10", 0), ("future", "2099-01-01", 1)]:
        case(
            "issue-date-" + name,
            lambda r, v=value: setattr(r.find("cbc:IssueDate", NS), "text", v),
            "BR-KSA-04",
            count,
        )

    def simplified(root, date):
        root.find("cbc:InvoiceTypeCode", NS).set("name", "0200000")
        root.find("cbc:IssueDate", NS).text = date

    for name, date, count in [("old", "2024-02-10", 1), ("future", "2099-01-01", 0)]:
        case(
            "simplified-" + name,
            lambda r, d=date: simplified(r, d),
            "BR-KSA-98",
            count,
            "warning",
        )

    def delivery(root, actual, latest):
        node = ET.Element(f"{{{NS['cac']}}}Delivery")
        ET.SubElement(node, f"{{{NS['cbc']}}}ActualDeliveryDate").text = actual
        ET.SubElement(node, f"{{{NS['cbc']}}}LatestDeliveryDate").text = latest
        root.insert(list(root).index(root.find("cac:PaymentMeans", NS)), node)

    for name, actual, latest, count in [
        ("equal", "2024-02-10", "2024-02-10", 0),
        ("ordered", "2024-02-10", "2024-02-11", 0),
        ("reversed", "2024-02-11", "2024-02-10", 1),
        ("outside-guard", "2100-02-11", "2100-02-10", 0),
    ]:
        case(
            "delivery-" + name,
            lambda r, a=actual, b=latest: delivery(r, a, b),
            "BR-KSA-36",
            count,
            "warning",
        )

    def reference(root, time):
        line = root.find("cac:InvoiceLine", NS)
        ref = ET.Element(f"{{{NS['cac']}}}DocumentReference")
        ET.SubElement(ref, f"{{{NS['cbc']}}}ID").text = "advance"
        ET.SubElement(ref, f"{{{NS['cbc']}}}IssueTime").text = time
        line.insert(list(line).index(line.find("cac:TaxTotal", NS)), ref)

    for name, time, count, xsd in [
        ("offset", "09:15:00+14:00", 0, "passed"),
        ("fraction", "09:15:00.123456789123", 0, "passed"),
        ("midnight", "24:00:00.000", 0, "passed"),
        ("offset-14-01", "09:15:00+14:01", 0, "failed"),
        ("offset-14-59", "09:15:00+14:59", 0, "failed"),
        ("offset-minus-14-59", "09:15:00-14:59", 0, "failed"),
        ("bad-offset", "09:15:00+15:00", 1, "failed"),
    ]:
        case(
            "prepayment-time-" + name,
            lambda r, t=time: reference(r, t),
            "BR-KSA-F-05",
            count,
            "warning",
            xsd,
        )
    return cases


def ksa_prepayment_cases(base):
    cases = []

    def prepare(
        root,
        prepaid="115.00",
        category="S",
        rate="15",
        taxable="100",
        tax="15",
        reference=True,
    ):
        root.find("cac:LegalMonetaryTotal/cbc:PrepaidAmount", NS).text = prepaid
        line = root.find("cac:InvoiceLine", NS)
        for path in [
            "cbc:LineExtensionAmount",
            "cac:TaxTotal/cbc:TaxAmount",
            "cac:TaxTotal/cbc:RoundingAmount",
            "cac:Price/cbc:PriceAmount",
        ]:
            line.find(path, NS).text = "0"
        if reference:
            ref = ET.Element(f"{{{NS['cac']}}}DocumentReference")
            for field, value in [
                ("ID", "advance"),
                ("IssueDate", "2024-02-01"),
                ("IssueTime", "09:00:00"),
                ("DocumentTypeCode", "386"),
            ]:
                ET.SubElement(ref, f"{{{NS['cbc']}}}{field}").text = value
            line.insert(list(line).index(line.find("cac:TaxTotal", NS)), ref)
        sub = ET.SubElement(
            line.find("cac:TaxTotal", NS), f"{{{NS['cac']}}}TaxSubtotal"
        )
        for field, value in [("TaxableAmount", taxable), ("TaxAmount", tax)]:
            ET.SubElement(
                sub, f"{{{NS['cbc']}}}{field}", {"currencyID": "SAR"}
            ).text = value
        cat = ET.SubElement(sub, f"{{{NS['cac']}}}TaxCategory")
        ET.SubElement(cat, f"{{{NS['cbc']}}}ID").text = category
        if rate is not None:
            ET.SubElement(cat, f"{{{NS['cbc']}}}Percent").text = rate
        scheme = ET.SubElement(cat, f"{{{NS['cac']}}}TaxScheme")
        ET.SubElement(scheme, f"{{{NS['cbc']}}}ID").text = "VAT"
        return line, sub

    def case(name, code, count, options=None, change=None, severity="warning"):
        root = ET.fromstring(base)
        line, sub = prepare(root, **(options or {}))
        if change:
            change(line, sub)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": "passed",
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "count": count,
                        "severity": severity,
                    }
                ],
            }
        )

    for value, count in [("115.00", 0), ("115.004", 0), ("115.006", 1), ("0", 1)]:
        case("total-" + value, "BR-KSA-80", count, {"prepaid": value})
    for prepaid in ["0", "115"]:
        for tax, count in [("14.99", 0), ("15.00", 0), ("15.01", 0), ("15.02", 1)]:
            case(
                "standard-" + prepaid + "-" + tax,
                "BR-KSA-79",
                count,
                {"prepaid": prepaid, "tax": tax},
            )
    for category in ["Z", "E", "O"]:
        for rate, count in [("0", 0), ("1", 1)]:
            case(
                "rate-" + category + "-" + rate,
                {"Z": "BR-KSA-76", "E": "BR-KSA-77", "O": "BR-KSA-78"}[category],
                count,
                {"category": category, "rate": rate, "tax": "0"},
            )
    for value, count in [("386", 0), (" 386 ", 0), ("388", 1)]:
        case(
            "document-type-" + value.strip() + "-" + str(len(value)),
            "BR-KSA-74",
            count,
            change=lambda line, sub, v=value: setattr(
                line.find("cac:DocumentReference/cbc:DocumentTypeCode", NS), "text", v
            ),
            severity="error",
        )
    for value, count in [("0", 0), ("1", 1)]:
        case(
            "zero-line-" + value,
            "BR-KSA-82",
            count,
            change=lambda line, sub, v=value: setattr(
                line.find("cbc:LineExtensionAmount", NS), "text", v
            ),
            severity="error",
        )
    case("missing-references", "BR-KSA-73", 1, {"reference": False})
    case(
        "missing-reference-time",
        "BR-KSA-73",
        1,
        change=lambda line, sub: line.find("cac:DocumentReference", NS).remove(
            line.find("cac:DocumentReference/cbc:IssueTime", NS)
        ),
    )
    case("missing-rate", "BR-KSA-75", 1, {"rate": None})
    for value, count in [("100.00", 0), ("100.000", 1)]:
        case("scale-" + value, "BR-KSA-DEC-06", count, {"taxable": value})
    return cases


def ksa_date_cast_cases(base):
    cases = []

    def case(name, change, code, count, severity="warning", xsd="failed"):
        root = ET.fromstring(base)
        change(root)
        cases.append(
            {
                "id": name,
                "xml": ET.tostring(root, encoding="unicode"),
                "expected_xsd": xsd,
                "targets": [
                    {
                        "source": "ksa",
                        "code": code,
                        "count": count,
                        "severity": severity,
                    }
                ],
            }
        )

    def issued(root, date, time="09:00:00"):
        root.find("cbc:InvoiceTypeCode", NS).set("name", "0200000")
        root.find("cbc:IssueDate", NS).text = date
        root.find("cbc:IssueTime", NS).text = time

    for date in ["0000-02-29", "-0000-02-29", "-0004-02-29"]:
        case(
            "year-" + date,
            lambda r, d=date: issued(r, d),
            "BR-KSA-98",
            1,
            xsd="passed" if date.startswith("-0004") else "failed",
        )
    case(
        "invalid-negative-leap-year",
        lambda r: issued(r, "-0001-02-29"),
        "SaxonApiException",
        1,
        "error",
    )
    for name, time, count in [
        ("subnanosecond", "24:00:00.000000000999", 1),
        ("nanosecond", "24:00:00.000000001", 0),
    ]:
        case(
            "datetime-" + name,
            lambda r, t=time: issued(r, "2024-02-10", t),
            "BR-KSA-98" if count else "SaxonApiException",
            1,
            "warning" if count else "error",
        )

    def reference(root, time):
        line = root.find("cac:InvoiceLine", NS)
        ref = ET.Element(f"{{{NS['cac']}}}DocumentReference")
        ET.SubElement(ref, f"{{{NS['cbc']}}}ID").text = "advance"
        ET.SubElement(ref, f"{{{NS['cbc']}}}IssueTime").text = time
        line.insert(list(line).index(line.find("cac:TaxTotal", NS)), ref)

    for time, count in [("24:00:00.000000000999", 0), ("24:00:00.0000000011", 1)]:
        case(
            "time-" + time.replace(":", "-"),
            lambda r, t=time: reference(r, t),
            "BR-KSA-F-05",
            count,
        )

    def duplicate_date_without_time(root):
        root.find("cbc:InvoiceTypeCode", NS).set("name", "0200000")
        root.remove(root.find("cbc:IssueTime", NS))
        pos = list(root).index(root.find("cbc:IssueDate", NS))
        node = ET.Element(f"{{{NS['cbc']}}}IssueDate")
        node.text = "2024-02-10"
        root.insert(pos, node)

    def empty_times(root):
        original = root.find("cbc:IssueTime", NS)
        original.text = ""
        root.insert(list(root).index(original), ET.Element(f"{{{NS['cbc']}}}IssueTime"))

    case("missing-time-guard", duplicate_date_without_time, "BR-KSA-70", 1, "error")
    case("empty-time-guard", empty_times, "BR-KSA-70", 1, "error")
    return cases
