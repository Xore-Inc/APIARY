# Build the sidecar, then ship only the binary and the signature database.
#
# Two stages because huginn-net pulls in a full Rust toolchain and ~200 crates
# to build, none of which belong on a VPS that also fronts every honeypot.
FROM rust:1-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8 AS build

# libpcap headers: huginn-net captures through libpcap, and the slim base has
# the runtime library but not the headers.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# libpcap0.8 for capture; ca-certificates is not needed -- this talks to
# nothing, it only reads packets and writes stdout.
# #3964: zlib1g CVE-2026-85091 (HIGH) is fixed in a Debian update that this
# trixie-slim digest predates. Upgrade it here rather than exempting the base.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 && \
    apt-get install -y --only-upgrade --no-install-recommends zlib1g && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home --shell /usr/sbin/nologin huginn

COPY --from=build /src/target/release/huginn-sidecar /usr/local/bin/huginn-sidecar

# Runs as root only because packet capture needs NET_RAW/NET_ADMIN, which the
# compose service grants explicitly while dropping every other capability.
ENTRYPOINT ["/usr/local/bin/huginn-sidecar"]
