# Build the sidecar, then ship only the binary and the signature database.
#
# Two stages because huginn-net pulls in a full Rust toolchain and ~200 crates
# to build, none of which belong on a VPS that also fronts every honeypot.
FROM rust:1-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0 AS build

# libpcap headers: huginn-net captures through libpcap, and the slim base has
# the runtime library but not the headers.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM docker.io/library/debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

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
