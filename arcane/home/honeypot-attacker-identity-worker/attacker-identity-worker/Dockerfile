# Static Go binary in a scratch image (~5 MB), same shape as ip-enrichment-worker/Dockerfile.
FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /attacker-identity-worker .

FROM scratch
COPY --from=build /attacker-identity-worker /attacker-identity-worker
ENTRYPOINT ["/attacker-identity-worker"]
