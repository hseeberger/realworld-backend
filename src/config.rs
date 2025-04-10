use crate::{infra, telemetry};
use figment::{
    Figment,
    providers::{Env, Format, Yaml},
};
use serde::Deserialize;
use std::env;

const CONFIG_FILE: &str = "CONFIG_FILE";

/// The main configuration.
///
/// It contains the flattened out application sepcific configuration and the tracing configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MainConfig {
    /// Application sepcific configuration.
    #[serde(flatten)]
    pub config: Config,

    /// Tracing configuration.
    #[serde(rename = "tracing", default)]
    pub tracing_config: telemetry::TracingConfig,
}

/// Application sepcific configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Infra configuration.
    #[serde(rename = "infra")]
    pub infra_config: infra::Config,
}

/// Extension methods for "configuration structs" which can be deserialized.
pub trait ConfigExt
where
    Self: for<'de> Deserialize<'de>,
{
    /// Load the configuration from the file at the value of the `CONFIG_FILE` environment variable
    /// or `config.yaml` by default, with an overlay provided by environment variables prefixed with
    /// `"APP__"` and split/nested via `"__"`.
    fn load() -> Result<Self, figment::Error> {
        let config_file = env::var(CONFIG_FILE)
            .map(Yaml::file_exact)
            .unwrap_or(Yaml::file_exact("config.yaml"));

        let config = Figment::new()
            .merge(config_file)
            .merge(Env::prefixed("APP__").split("__"))
            .extract()?;

        Ok(config)
    }
}

impl<T> ConfigExt for T where T: for<'de> Deserialize<'de> {}

#[cfg(test)]
mod tests {
    use crate::{
        config::{CONFIG_FILE, Config, ConfigExt, MainConfig},
        infra::{self, api},
    };
    use assert_matches::assert_matches;
    use std::env;

    #[test]
    fn test_load() {
        unsafe {
            env::set_var("APP__INFRA__API__PORT", "4242");
        }

        let config = MainConfig::load();
        assert_matches!(
            config,
            Ok(MainConfig {
                config: Config {
                    infra_config: infra::Config {
                        api_config: api::Config { port, .. },
                        ..
                    }
                }, tracing_config
            })
            if port == 4242 && tracing_config.otlp_exporter_endpoint == "http://localhost:4317"
        );

        unsafe {
            env::set_var(CONFIG_FILE, "nonexistent.yaml");
        }
        let config = Config::load();
        assert!(config.is_err());
    }
}
