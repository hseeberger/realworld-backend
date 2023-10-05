use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

fn main() {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default().hash_password(b"password", &salt).unwrap();
    println!("{password_hash}");
}
