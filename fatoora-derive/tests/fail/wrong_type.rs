use fatoora_derive::Validate;

#[derive(Validate)]
#[validate(non_empty)]
pub struct Wrong {
    pub age: i32,  // not allowed
}

fn main() {}
