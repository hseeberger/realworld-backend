set shell := ["bash", "-uc"]

check:
	@echo "using toolchain ${RUSTUP_TOOLCHAIN:-NONE}"
	cargo check --features axum --tests
	cargo check --features poem-openapi --tests

fmt:
	@echo "using toolchain ${RUSTUP_TOOLCHAIN:-NONE}"
	cargo fmt

fmt-check:
	@echo "using toolchain ${RUSTUP_TOOLCHAIN:-NONE}"
	cargo fmt --check

lint:
	@echo "using toolchain ${RUSTUP_TOOLCHAIN:-NONE}"
	cargo clippy --all-features --no-deps -- -D warnings

test:
	@echo "using toolchain ${RUSTUP_TOOLCHAIN:-NONE}"
	cargo test --all-features

fix:
	@echo "using toolchain ${RUSTUP_TOOLCHAIN:-NONE}"
	cargo fix --allow-dirty --allow-staged

all: check fmt lint test

docker framework="axum" tag="latest":
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	docker build \
		--build-arg FRAMEWORK={{framework}} \
		-t hseeberger/realworld-backend-{{framework}}:{{tag}} \
		.

run framework="axum" port="8080":
	@echo "using toolchain ${RUSTUP_TOOLCHAIN:-NONE}"
	[ "{{framework}}" = "axum" ] || [ "{{framework}}" = "poem-openapi" ]
	RUST_LOG=realworld_backend=debug,info \
		CONFIG_OVERLAYS=dev \
		APP__API__PORT={{port}} \
		cargo run --features {{framework}} \
		| jq
