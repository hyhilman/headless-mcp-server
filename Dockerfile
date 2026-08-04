# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /build

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin headless-mcp -p headless-mcp && \
    cp target/release/headless-mcp /build/headless-mcp

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin headless-mcp \
    && mkdir -p /data \
    && chown headless-mcp:headless-mcp /data

COPY --from=builder /build/headless-mcp /usr/local/bin/headless-mcp

USER headless-mcp
WORKDIR /home/headless-mcp
VOLUME ["/data"]

# HEADLESS_MCP_TOKEN: required for HTTP mode. Set at docker run time.
# HEADLESS_MCP_MASTER_KEY: optional, enables OAuth2 token persistence.
ENV HEADLESS_MCP_DATA_DIR=/data
ENV RUST_LOG=info

EXPOSE 9797

ENTRYPOINT ["headless-mcp"]
CMD ["serve", "--http"]
