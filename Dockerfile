ARG RUST_VERSION=1.73.0

FROM rust:${RUST_VERSION}-slim-bookworm AS builder
ARG FRAMEWORK
RUN [ "${FRAMEWORK}" = "axum" ] || [ "${FRAMEWORK}" = "poem-openapi" ]
WORKDIR /app
COPY . .
RUN \
  --mount=type=cache,target=/app/target/ \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  cargo build --locked --release --features ${FRAMEWORK} && \
  cp ./target/release/realworld-backend /app

FROM debian:bookworm-slim AS final
RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "10001" \
  appuser
COPY --from=builder /app/realworld-backend /usr/local/bin
RUN chown appuser /usr/local/bin/realworld-backend
COPY --from=builder /app/config /opt/realworld-backend/config
RUN chown -R appuser /opt/realworld-backend
USER appuser
WORKDIR /opt/realworld-backend
ENTRYPOINT ["realworld-backend"]
EXPOSE 80/tcp
