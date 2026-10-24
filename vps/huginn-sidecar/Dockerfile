# Build the sidecar, then ship only the binary and the signature database.
#
# Two stages because huginn-net pulls in a full Rust toolchain and ~200 crates
# to build, none of which belong on a VPS that also fronts every honeypot.
FROM rust:1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS build

# libpcap headers: huginn-net captures through libpcap, and the slim base has
# the runtime library but not the headers.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

# libpcap0.8 for capture; ca-certificates is not needed -- this talks to
# nothing, it only reads packets and writes stdout.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home --shell /usr/sbin/nologin huginn

COPY --from=build /src/target/release/huginn-sidecar /usr/local/bin/huginn-sidecar

# Runs as root only because packet capture needs NET_RAW/NET_ADMIN, which the
# compose service grants explicitly while dropping every other capability.
ENTRYPOINT ["/usr/local/bin/huginn-sidecar"]
