# DNS reflection bait (#238, #415). NOT a vendor of T-Pot's ddospot: its
# DNS pot (pots/dns/dns.py) forwards every new query to a real recursive
# resolver and relays that resolver's real -- unbounded -- response back
# verbatim, confirmed directly against its source before deciding not to
# build on it. This sensor never contacts a resolver at all; it only ever
# returns a small canned answer, and dns.go enforces (in code, covered by
# dns_test.go) that the response can never exceed the request's own byte
# length -- a UDP reflector that never returns more bytes than it received
# cannot be an amplification vector, by definition, independent of any
# particular request/response shape.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /dns-honeypot .

FROM scratch
COPY --from=build /dns-honeypot /dns-honeypot
EXPOSE 53/udp
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/dns-honeypot", "-healthcheck"]
ENTRYPOINT ["/dns-honeypot"]
