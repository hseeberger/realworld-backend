pub mod user;

use secrecy::ExposeSecret;
use serde::Deserialize;

/// New type for `secrecy::SecretString`.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "axum", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "axum", schema(value_type = String, format = Password, example = "abcd567+"))]
pub struct SecretString(secrecy::SecretString);

impl SecretString {
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(secrecy::SecretString::new(s))
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        s.to_owned().into()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl Eq for SecretString {}

#[cfg(feature = "poem-openapi")]
impl poem_openapi::types::Type for SecretString {
    const IS_REQUIRED: bool = true;

    type RawValueType = Self;

    type RawElementValueType = Self;

    fn name() -> std::borrow::Cow<'static, str> {
        "secret-string".into()
    }

    fn schema_ref() -> poem_openapi::registry::MetaSchemaRef {
        let mut schema = poem_openapi::registry::MetaSchema::new_with_format("string", "secret");
        schema.example = Some(serde_json::Value::String("abcd567+".to_string()));
        poem_openapi::registry::MetaSchemaRef::Inline(Box::new(schema))
    }

    fn as_raw_value(&self) -> Option<&Self::RawValueType> {
        Some(self)
    }

    fn raw_element_iter<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = &'a Self::RawElementValueType> + 'a> {
        Box::new(self.as_raw_value().into_iter())
    }
}

#[cfg(feature = "poem-openapi")]
impl poem_openapi::types::ParseFromJSON for SecretString {
    fn parse_from_json(value: Option<serde_json::Value>) -> poem_openapi::types::ParseResult<Self> {
        String::parse_from_json(value)
            .map_err(|error| error.propagate())
            .map(|s| s.into())
    }
}

#[cfg(feature = "poem-openapi")]
impl poem_openapi::types::ToJSON for SecretString {
    fn to_json(&self) -> Option<serde_json::Value> {
        "***".to_json()
    }
}
