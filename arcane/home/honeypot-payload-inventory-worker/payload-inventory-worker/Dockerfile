# Static Go binary in a scratch image (~5 MB), same shape as ip-enrichment-worker/Dockerfile.
FROM golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /payload-inventory-worker .

FROM scratch
COPY --from=build /payload-inventory-worker /payload-inventory-worker
ENTRYPOINT ["/payload-inventory-worker"]
