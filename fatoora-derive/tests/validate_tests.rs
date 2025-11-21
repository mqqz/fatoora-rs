#[test]
fn validate_macro_tests() {
    let t = trybuild::TestCases::new();

    // Should compile
    t.pass("tests/ok/basic_valid.rs");
    t.pass("tests/ok/struct_rules.rs");
    t.pass("tests/ok/skip_field.rs");

    // Should fail compilation
    t.compile_fail("tests/fail/unknown_rule.rs");
    t.compile_fail("tests/fail/wrong_type.rs");
}
