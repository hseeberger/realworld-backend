set shell := ["bash", "-uc"]

check:
	cargo check --tests

fmt toolchain="+nightly":
	cargo {{toolchain}} fmt

fmt-check toolchain="+nightly":
	cargo {{toolchain}} fmt --check

lint:
	cargo clippy --no-deps --tests -- -D warnings

test:
	cargo test

fix:
	cargo fix --allow-dirty --allow-staged

doc:
	cargo doc --no-deps

all: check fmt lint test doc

run:
	docker compose up -d postgres
	RUST_LOG=realworld_backend=debug,fastrace_opentelemetry=off,info \
		cargo run | tee ./target/a.log
