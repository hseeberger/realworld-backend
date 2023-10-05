set shell := ["bash", "-uc"]

check:
	cargo check --all-features --tests

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

run-axum:
	RUST_LOG=realworld_backend_axum=debug,info \
		CONFIG_ENVIRONMENT=dev \
		APP__API__PORT=8080 \
		cargo run --features axum \
		| jq

run-poem-openapi:
	RUST_LOG=realworld_backend_poem_openapi=debug,info \
		CONFIG_ENVIRONMENT=dev \
		APP__API__PORT=8081 \
		cargo run --features poem-openapi \
		| jq
