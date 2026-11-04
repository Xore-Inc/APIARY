# Cisco ASA WebVPN + IKE decoy (CVE-2018-0101), Go port of
# t3chn0m4g3/ciscoasa_honeypot (#238, #414) -- see main.go/ike.go's own
# doc comments for the real (not vendored-as-is) behavior this reproduces.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /cisco-asa-honeypot .

FROM scratch
COPY --from=build /cisco-asa-honeypot /cisco-asa-honeypot
EXPOSE 8443
EXPOSE 500/udp
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/cisco-asa-honeypot", "-healthcheck"]
ENTRYPOINT ["/cisco-asa-honeypot"]
