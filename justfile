set shell := ["bash", "-uc"]

check:
	cargo check

fmt toolchain="+nightly":
	cargo {{toolchain}} fmt

fmt-check toolchain="+nightly":
	cargo {{toolchain}} fmt --check

lint:
	cargo clippy --no-deps -- -D warnings

test:
	cargo test

fix:
	cargo fix --allow-dirty --allow-staged

all: check fmt lint test

run port="8080":
	RUST_LOG=realworld_backend=debug,info \
		CONFIG_OVERLAYS=dev \
		APP__API__PORT={{port}} \
		cargo run

docker tag="latest" profile="dev":
	docker build \
		--build-arg "PROFILE={{profile}}" \
		-t hseeberger/realworld-backend:{{tag}} \
		.
