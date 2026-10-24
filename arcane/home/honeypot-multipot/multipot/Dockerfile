# Static Go binary in a scratch image (~8 MB, no shell/libc).
FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /multipot .

FROM scratch
COPY --from=build /multipot /multipot

EXPOSE 21 25 1433 3306 5432 5900 6379 9200 27017 2375

# Non-root (nobody). All emulated ports are unprivileged inside the container.
USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/multipot", "-healthcheck"]

ENTRYPOINT ["/multipot"]
