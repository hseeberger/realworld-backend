use crate::domain::SecretString;
use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_URL_SAFE, Engine};
use jwt_simple::prelude::{
    Claims, Duration, HS256Key, MACLike, NoCustomClaims, VerificationOptions,
};
use serde::Deserialize;
use std::{fmt::Debug, time::Duration as StdDuration};
use uuid::Uuid;

pub struct TokenFactory {
    key: HS256Key,
    token_expiry: Duration,
    verification_options: Option<VerificationOptions>,
}

impl TokenFactory {
    pub fn new(config: Config) -> Result<Self> {
        let Config {
            key,
            token_expiry,
            time_tolerance,
        } = config;

        let key = BASE64_URL_SAFE
            .decode(key.expose_secret())
            .context("decode key as Base64")?;
        let key = HS256Key::from_bytes(&key);

        let token_expiry = token_expiry.into();

        let verification_options = Some(VerificationOptions {
            time_tolerance: Some(time_tolerance.into()),
            ..Default::default()
        });

        Ok(Self {
            key,
            token_expiry,
            verification_options,
        })
    }

    pub fn create_token(&self, uuid: Uuid) -> Result<SecretString> {
        let claims = Claims::create(self.token_expiry).with_subject(uuid);
        self.key
            .authenticate(claims)
            .context("authenticate claims")
            .map(|token| token.into())
    }

    pub fn verify_token(&self, token: &SecretString) -> Result<Uuid> {
        self.key
            .verify_token::<NoCustomClaims>(
                token.expose_secret(),
                self.verification_options.clone(),
            )
            .context("verify token")
            .and_then(|claims| claims.subject.ok_or(anyhow!("JWT token has no subject")))
            .and_then(|subject| subject.parse().context("parse subject as Uuid"))
    }
}

impl Debug for TokenFactory {
    /// Don't expose secret!
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenFactory").finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    key: SecretString,

    #[serde(with = "humantime_serde")]
    token_expiry: StdDuration,

    #[serde(with = "humantime_serde")]
    time_tolerance: StdDuration,
}
