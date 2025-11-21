use fatoora_derive::Validate;

#[derive(Validate)]
#[validate(non_empty)]
pub struct Sample {
    pub name: String,

    #[validate(skip)]
    pub internal: i32,
}

fn main() {
    let s = Sample::new("test".into(), 10);
    assert!(s.is_ok());
}
