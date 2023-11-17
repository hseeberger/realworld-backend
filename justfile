set shell := ["bash", "-uc"]

check:
	@echo "RUSTUP_TOOLCHAIN is ${RUSTUP_TOOLCHAIN:-not set}"
	cargo check --features axum --tests
	cargo check --features poem-openapi --tests

fmt:
	@echo "RUSTUP_TOOLCHAIN is ${RUSTUP_TOOLCHAIN:-not set}"
	cargo fmt

fmt-check:
	@echo "RUSTUP_TOOLCHAIN is ${RUSTUP_TOOLCHAIN:-not set}"
	cargo fmt --check

lint:
	@echo "RUSTUP_TOOLCHAIN is ${RUSTUP_TOOLCHAIN:-not set}"
	cargo clippy --all-features --no-deps -- -D warnings

test:
	@echo "RUSTUP_TOOLCHAIN is ${RUSTUP_TOOLCHAIN:-not set}"
	cargo test --all-features

fix:
	@echo "RUSTUP_TOOLCHAIN is ${RUSTUP_TOOLCHAIN:-not set}"
	cargo fix --allow-dirty --allow-staged

all: check fmt lint test

run framework="axum" port="8080":
	@echo "RUSTUP_TOOLCHAIN is ${RUSTUP_TOOLCHAIN:-not set}"
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	RUST_LOG=realworld_backend=debug,info \
		CONFIG_OVERLAYS=dev \
		APP__API__PORT={{port}} \
		cargo run --features {{framework}} \
		| jq

docker framework="axum" tag="latest":
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	docker build \
		--build-arg FRAMEWORK={{framework}} \
		-t hseeberger/realworld-backend-{{framework}}:{{tag}} \
		.
