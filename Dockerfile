ARG RUST_VERSION=1.78.0

FROM rust:$RUST_VERSION-bookworm AS builder
ARG PROFILE=release
WORKDIR /build
COPY . .
RUN \
  --mount=type=cache,target=/build/target/ \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  cargo build --profile $PROFILE && \
  dir=release && if [ $PROFILE = dev ]; then dir=debug; fi && \
  cp ./target/$dir/realworld-backend /

FROM debian:bookworm-slim AS final
RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "10001" \
  appuser
COPY --from=builder /realworld-backend /usr/local/bin
RUN chown appuser /usr/local/bin/realworld-backend
COPY --from=builder /build /opt/realworld-backend/config
RUN chown -R appuser /opt/realworld-backend
USER appuser
ENV RUST_LOG="realworld_backend=debug,info"
WORKDIR /opt/realworld-backend
ENTRYPOINT ["realworld-backend"]
EXPOSE 8080/tcp
