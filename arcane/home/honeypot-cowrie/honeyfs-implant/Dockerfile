# honeyfs-implant -- #1487: see main.go's package doc for what this does
# and why. Matches canarytokens-adapter/Dockerfile's own scratch-based
# shape (this repo's own small internal-only service, nothing to vendor).

FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /honeyfs-implant .

FROM scratch
COPY --from=builder /honeyfs-implant /honeyfs-implant
EXPOSE 8091
# Same uid:gid as cowrie itself (2000:2000,
# arcane/home/honeypot-cowrie/cowrie/Dockerfile) -- both containers write
# into the same bind-mounted honeyfs/ host directory (compose.yml), so they
# need matching ownership to avoid the exact EPERM class of bug
# entrypoint.sh's own cp -a -> cp -r fix already ran into on the cowrie
# side. Not scratch's usual 65534:65534 (canarytokens-adapter's own
# convention) for that reason.
USER 2000:2000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/honeyfs-implant", "-healthcheck"]
ENTRYPOINT ["/honeyfs-implant"]
