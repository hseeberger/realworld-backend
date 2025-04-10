//! A user.

use nutype::nutype;
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sqlx::prelude::FromRow;
use std::sync::LazyLock;
use thiserror::Error;
use uuid::Uuid;

static EMAIL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
        .expect("regex for email address is correct")
});

/// A user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow)]
pub struct User {
    pub id: Uuid,

    #[sqlx(try_from = "String")]
    pub username: Username,

    #[sqlx(try_from = "String")]
    pub email_address: EmailAddress,
}

/// A username, trimmed. Must neither be empty nor have more than 32 characters.
#[nutype(
    sanitize(trim),
    validate(not_empty, len_char_max = 32),
    derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Hash,
        Deref,
        FromStr,
        TryFrom,
        Serialize,
        Deserialize,
    )
)]
pub struct Username(String);

/// An email address, trimmed and lowercased. Must not have more than 256 characters and match the
/// regular expression `^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$`.
#[nutype(
    sanitize(trim, lowercase),
    validate(len_char_max = 256, regex = EMAIL_ADDRESS),
    derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Hash,
        Deref,
        FromStr,
        TryFrom,
        Serialize,
        Deserialize
    )
)]
pub struct EmailAddress(String);

/// A password. Must have eight to 256 characters.
#[nutype(
    validate(with = validate_password, error = PasswordError),
    derive(Clone, Debug, Deref, Deserialize)
)]
pub struct Password(SecretString);

fn validate_password(value: &SecretString) -> Result<(), PasswordError> {
    let len = value.expose_secret().chars().count();

    if len < 8 {
        Err(PasswordError::TooShort)
    } else if len > 256 {
        Err(PasswordError::TooLong)
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password too short, must not have less than eight characters")]
    TooShort,

    #[error("password too long, must not have more than 256 characters")]
    TooLong,
}

#[cfg(test)]
mod tests {
    use crate::domain::user::{
        EmailAddress, EmailAddressError, Password, PasswordError, Username, UsernameError,
    };
    use assert_matches::assert_matches;
    use proptest::{proptest, string::string_regex};
    use secrecy::ExposeSecret;

    #[test]
    fn test_username() {
        assert_matches!(Username::try_new(""), Err(UsernameError::NotEmptyViolated));

        let too_long_usernames = string_regex(r"\S[a-z]{31,100}\S").unwrap();
        proptest! {
            |(username in too_long_usernames)| {
                assert_matches!(
                    Username::try_new(&username),
                    Err(UsernameError::LenCharMaxViolated)
                );
            }
        }

        let valid_usernames = string_regex(r"\S|\S[a-z]{0,30}\S").unwrap();
        proptest! {
            |(username in valid_usernames)| {
                assert_matches!(
                    Username::try_new(&username),
                    Ok(u) if *u == username
                );
            }
        }
    }

    #[test]
    fn test_email_address() {
        assert_matches!(
            EmailAddress::try_new(""),
            Err(EmailAddressError::RegexViolated)
        );

        assert_matches!(
            EmailAddress::try_new("a"),
            Err(EmailAddressError::RegexViolated)
        );

        assert_matches!(
            EmailAddress::try_new("a@b"),
            Err(EmailAddressError::RegexViolated)
        );

        assert_matches!(
            EmailAddress::try_new("InFo@RealWorld.aPp"),
            Ok(e) if &*e == "info@realworld.app"
        );

        let valid_email_addresses =
            string_regex(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap();
        proptest! {
            |(email_address in valid_email_addresses)| {
                assert_matches!(
                    EmailAddress::try_new(&email_address),
                    Ok(e) if *e == email_address.to_lowercase()
                );
            }
        }
    }

    #[test]
    fn test_password() {
        let too_short_passwords = string_regex(r".{0,7}").unwrap();
        proptest! {
            |(password in too_short_passwords)| {
                assert_matches!(
                    Password::try_new(password.into()),
                    Err(PasswordError::TooShort)
                );
            }
        }

        let too_long_passwords = string_regex(r".{257,512}").unwrap();
        proptest! {
            |(password in too_long_passwords)| {
                assert_matches!(
                    Password::try_new(password.into()),
                    Err(PasswordError::TooLong)
                );
            }
        }

        let valid_passwords = string_regex(r".{8,256}").unwrap();
        proptest! {
            |(password in valid_passwords)| {
                assert_matches!(
                    Password::try_new(password.clone().into()),
                    Ok(p) if p.expose_secret() == password
                );
            }
        }
    }
}
