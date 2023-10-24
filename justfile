set shell := ["bash", "-uc"]

default_port := "8080"

check:
	cargo check --features axum --tests
	cargo check --features poem-openapi --tests

fmt:
	cargo +nightly fmt

fmt-check:
	cargo +nightly fmt --check

lint:
	cargo clippy --all-features --no-deps -- -D warnings

test:
	cargo test --all-features

fix:
	cargo fix --allow-dirty --allow-staged

all: fmt check lint test

run-axum port=default_port:
	RUST_LOG=realworld_backend=debug,info \
		CONFIG_ENVIRONMENT=dev \
		APP__API__PORT={{port}} \
		cargo run --features axum \
		| jq

run-poem-openapi port=default_port:
	RUST_LOG=realworld_backend=debug,info \
		CONFIG_ENVIRONMENT=dev \
		APP__API__PORT={{port}} \
		cargo run --features poem-openapi \
		| jq
