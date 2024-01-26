set shell := ["bash", "-uc"]

check:
	cargo check --features axum
	cargo check --features poem-openapi

fmt toolchain="+nightly":
	cargo {{toolchain}} fmt

fmt-check toolchain="+nightly":
	cargo {{toolchain}} fmt --check

lint:
	cargo clippy --all-features --no-deps -- -D warnings

test:
	cargo test --all-features

fix:
	cargo fix --allow-dirty --allow-staged

all: check fmt lint test

run framework="axum" port="8080":
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	RUST_LOG=realworld_backend=debug,info \
		CONFIG_OVERLAYS=dev \
		APP__API__PORT={{port}} \
		cargo run --features {{framework}}

docker framework="axum" tag="latest":
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	docker build \
		--build-arg FRAMEWORK={{framework}} \
		-t hseeberger/realworld-backend-{{framework}}:{{tag}} \
		.
