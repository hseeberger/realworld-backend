set shell := ["bash", "-uc"]

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

all: check fmt lint test

docker framework="axum" tag="latest":
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	docker build \
		--build-arg FRAMEWORK={{framework}} \
		-t hseeberger/realworld-backend:{{tag}}-{{framework}} \
		.

run framework="axum" port="8080":
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	RUST_LOG=realworld_backend=debug,info \
		CONFIG_OVERLAYS=dev \
		APP__API__PORT={{port}} \
		cargo run --features {{framework}} \
		| jq
