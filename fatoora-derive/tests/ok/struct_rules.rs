use fatoora_derive::Validate;

#[derive(Validate)]
#[validate(non_empty, no_special_chars)]
pub struct Csr {
    pub common_name: String,
    pub serial_number: String,
}

fn main() {
    let c = Csr::new(
        "ACME".into(),
        "12345".into(),
    );

    assert!(c.is_ok());
}
