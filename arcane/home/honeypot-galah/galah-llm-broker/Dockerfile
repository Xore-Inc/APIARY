# galah-llm-broker -- #1420: the sole bridge between the attacker-facing
# galah sensor and the shared Ollama instance on the honeypot-llm network.
# See main.go's own doc comment for what it does and doesn't allow.
# Written from scratch (not vendored): this is this stack's own boundary
# enforcement, not third-party sensor logic.
FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /build
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /galah-llm-broker .

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache busybox-extras
COPY --from=build /galah-llm-broker /usr/local/bin/galah-llm-broker

EXPOSE 11434

USER 65534

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
  CMD nc -z 127.0.0.1 11434 || exit 1

ENTRYPOINT ["/usr/local/bin/galah-llm-broker"]
