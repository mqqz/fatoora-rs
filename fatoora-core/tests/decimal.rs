use fatoora_core::Decimal;

#[test]
fn exact_string_contract() {
    for text in [
        "0",
        "-12.345",
        "0.0000000000000000000000000001",
        "79228162514264337593543950335",
    ] {
        assert_eq!(Decimal::parse(text).unwrap().to_string(), text);
    }
    assert_eq!(
        Decimal::parse("1.00").unwrap(),
        Decimal::parse("1").unwrap()
    );
    assert_eq!(Decimal::parse("-0.00").unwrap().to_string(), "0");
    for invalid in [
        "",
        " 1",
        "1 ",
        "1e2",
        "NaN",
        "inf",
        "1,23",
        ".5",
        "1.",
        "79228162514264337593543950336",
        "0.00000000000000000000000000001",
    ] {
        assert!(Decimal::parse(invalid).is_err(), "{invalid}");
    }
}
#[test]
fn serde_uses_strings_only() {
    let d = Decimal::parse("123.4500").unwrap();
    assert_eq!(serde_json::to_string(&d).unwrap(), "\"123.45\"");
    assert_eq!(serde_json::from_str::<Decimal>("\"123.450\"").unwrap(), d);
    assert!(serde_json::from_str::<Decimal>("123.45").is_err());
}
