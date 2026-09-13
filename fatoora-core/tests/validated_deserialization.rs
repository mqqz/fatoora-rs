use fatoora_core::invoice::{CountryCode, CurrencyCode, InvoiceDate, InvoiceTimestamp, VatId};
use serde::{Serialize, de::DeserializeOwned};

fn check<T: DeserializeOwned + Serialize>(invalid: &[&str], input: &str, normalized: &str) {
    let name = std::any::type_name::<T>().rsplit("::").next().unwrap();
    for value in invalid {
        let json = serde_json::to_string(value).unwrap();
        assert!(serde_json::from_str::<T>(&json).is_err(), "accepted {json}");
        let payload = ron::to_string(value).unwrap();
        for ron in [format!("({payload})"), format!("{name}({payload})")] {
            assert!(ron::from_str::<T>(&ron).is_err(), "accepted {ron}");
        }
    }
    let value: T = serde_json::from_value(serde_json::json!(input)).unwrap();
    let encoded = serde_json::to_value(&value).unwrap();
    assert_eq!(encoded, serde_json::json!(normalized));
    let decoded: T = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);

    // Unlike JSON, RON preserves the newtype boundary. Both historical spellings
    // must still normalize through the constructor and round-trip.
    let input = ron::to_string(input).unwrap();
    let expected = format!("({})", ron::to_string(normalized).unwrap());
    for ron in [format!("({input})"), format!("{name}({input})")] {
        let value: T = ron::from_str(&ron).unwrap();
        let serialized = ron::to_string(&value).unwrap();
        assert_eq!(serialized, expected);
        let decoded: T = ron::from_str(&serialized).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
        let named = ron::ser::to_string_pretty(
            &value,
            ron::ser::PrettyConfig::default().struct_names(true),
        )
        .unwrap();
        assert_eq!(named, format!("{name}{expected}"));
        let decoded: T = ron::from_str(&named).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
    }
}

#[test]
fn deserialization_enforces_constructor_validation_and_normalization() {
    check::<CountryCode>(&["", "ZZ", "bogus"], " sa ", "SAU");
    check::<CurrencyCode>(&["", "ZZZ", "bogus"], " sar ", "SAR");
    check::<InvoiceTimestamp>(
        &["", "x", "2026-02-30T12:00:00Z", "2026-09-13T25:00:00Z"],
        " 2026-09-13T12:00:00Z ",
        "2026-09-13T12:00:00Z",
    );
    check::<InvoiceDate>(&["", "x", "2026-02-30"], " 2026-09-13 ", "2026-09-13");
    // Preserve the constructor's current nonempty-only contract.
    check::<VatId>(&["", "   "], " example ", "example");
}

#[test]
fn nested_wrappers_are_validated_too() {
    #[derive(serde::Deserialize)]
    struct Payload {
        #[allow(dead_code)]
        country: CountryCode,
        #[allow(dead_code)]
        timestamp: InvoiceTimestamp,
    }
    for input in [
        serde_json::json!({"country": "ZZ", "timestamp": "2026-09-13T12:00:00Z"}),
        serde_json::json!({"country": "SAU", "timestamp": "x"}),
    ] {
        assert!(serde_json::from_value::<Payload>(input).is_err());
    }
}
