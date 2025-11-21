use fatoora_derive::Validate;

#[derive(Validate)]
pub struct Person {
    pub name: String,
    #[validate(is_country_code)]
    pub country: String,
}

fn main() {
    let p = Person::new(
        "Mohamad".into(),
        "SA".into(),
    );

    assert!(p.is_ok());
}
