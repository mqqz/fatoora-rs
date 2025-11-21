use fatoora_derive::Validate;

#[derive(Validate)]
#[validate(does_not_exist)]
pub struct Bad {
    pub name: String,
}

fn main() {}
