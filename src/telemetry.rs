use fastrace_opentelemetry::OpenTelemetryReporter;
use logforth::{
    append::{FastraceEvent, Stdout},
    diagnostic::FastraceDiagnostic,
    filter::EnvFilter,
    layout::JsonLayout,
};
use opentelemetry::InstrumentationScope;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use serde::Deserialize;
use std::borrow::Cow;

/// Tracing configuration.
///
/// All fields have sensible deserialization defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct TracingConfig {
    /// Defaults to OTLP gRPC: "http://localhost:4317".
    #[serde(default = "otlp_exporter_endpoint_default")]
    pub otlp_exporter_endpoint: String,

    /// Defaults to the package name.
    #[serde(default = "package_name")]
    pub service_name: String,

    /// Defaults to the package name.
    #[serde(default = "package_name")]
    pub instrumentation_scope_name: String,

    /// Defaults to the package version.
    #[serde(default = "package_version")]
    pub instrumentation_scope_version: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            otlp_exporter_endpoint: otlp_exporter_endpoint_default(),
            service_name: package_name(),
            instrumentation_scope_name: package_name(),
            instrumentation_scope_version: package_version(),
        }
    }
}

/// Initialize logging with [Logforth](https://github.com/fast/logforth).
///
/// Log levels are filterd based on the `RUST_LOG` environment variable and log records are
/// formatted as JSON.
///
/// If logging happens in the context of a span, log records are added to the current span as events
/// and the trace ID of the current span is added to the log records, thus correlating logs and
/// traces.
///
/// # Panics
///
/// If logging has already been initialized.
pub fn init_logging() {
    logforth::builder()
        .dispatch(|dispatch| {
            dispatch
                .filter(EnvFilter::from_default_env())
                .diagnostic(FastraceDiagnostic::default())
                .append(Stdout::default().with_layout(JsonLayout::default()))
                .append(FastraceEvent::default())
        })
        .apply();
}

/// Initialize tracing with [fastrace](https://github.com/fast/fastrace).
///
/// Builds an OTLP exporter using gRPC from the given configuration.
///
/// # Panics
///
/// Panics if the OTLP exporter cannot be built.
pub fn init_tracing(config: TracingConfig) {
    let TracingConfig {
        otlp_exporter_endpoint,
        service_name,
        instrumentation_scope_name,
        instrumentation_scope_version,
    } = config;

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(otlp_exporter_endpoint)
        .build()
        .expect("OTLP exporter can be built");

    let resource = Resource::builder().with_service_name(service_name).build();

    let instrumentation_scope = InstrumentationScope::builder(instrumentation_scope_name)
        .with_version(instrumentation_scope_version)
        .build();

    let reporter =
        OpenTelemetryReporter::new(exporter, Cow::Owned(resource), instrumentation_scope);

    fastrace::set_reporter(reporter, fastrace::collector::Config::default());
}

fn otlp_exporter_endpoint_default() -> String {
    "http://localhost:4317".to_string()
}

fn package_name() -> String {
    env!("CARGO_PKG_NAME").to_owned()
}

fn package_version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}
