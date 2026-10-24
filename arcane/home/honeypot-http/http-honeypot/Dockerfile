# Static Go binary in a scratch image (~8 MB, no shell/libc).
FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /honeypot .

FROM scratch
COPY --from=build /honeypot /honeypot

ENV LISTEN_ADDR=:8080
EXPOSE 8080

# Non-root (nobody). The log dir is a volume chowned in compose.
USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/honeypot", "-healthcheck"]

ENTRYPOINT ["/honeypot"]
