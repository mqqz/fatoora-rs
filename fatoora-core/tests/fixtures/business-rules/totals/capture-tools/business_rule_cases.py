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
