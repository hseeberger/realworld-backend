use anyhow::{Context, anyhow};
use derive_more::Debug;
use jwt_simple::prelude::{
    Claims, Duration, HS256Key, MACLike, NoCustomClaims, VerificationOptions,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use std::time::Duration as StdDuration;
use uuid::Uuid;

pub type Token = SecretString;

#[derive(Debug, Clone)]
pub struct Tokens {
    key: HS256Key,
    token_expiry: Duration,
    verification_options: VerificationOptions,
}

impl Tokens {
    pub fn new(config: Config) -> Self {
        let Config {
            key,
            token_expiry,
            time_tolerance,
        } = config;

        let key = HS256Key::from_bytes(&key);

        let token_expiry = token_expiry.into();

        let verification_options = VerificationOptions {
            time_tolerance: Some(time_tolerance.into()),
            ..Default::default()
        };

        Self {
            key,
            token_expiry,
            verification_options,
        }
    }

    pub fn create_token(&self, uuid: Uuid) -> anyhow::Result<Token> {
        let claims = Claims::create(self.token_expiry).with_subject(uuid);
        self.key
            .authenticate(claims)
            .context("create token")
            .map(|token| token.into())
    }

    pub fn verify_token(&self, token: &Token) -> anyhow::Result<Uuid> {
        self.key
            .verify_token::<NoCustomClaims>(
                token.expose_secret(),
                Some(self.verification_options.clone()),
            )
            .context("verify token")
            .and_then(|claims| claims.subject.ok_or(anyhow!("JWT token has no subject")))
            .and_then(|subject| subject.parse().context("parse subject as Uuid"))
    }
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[debug(skip)] // Skip is important, because this is a secret!
    #[serde_as(as = "Base64")]
    key: Vec<u8>,

    #[serde(with = "humantime_serde")]
    token_expiry: StdDuration,

    #[serde(with = "humantime_serde")]
    time_tolerance: StdDuration,
}
