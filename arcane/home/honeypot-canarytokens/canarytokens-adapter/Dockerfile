# canarytokens-adapter -- #1426: this repo's own small webhook receiver,
# not a vendored tool (nothing to vendor: translating an arbitrary JSON
# webhook into this repo's shared sensor-log shape is a few dozen lines,
# not a project). Matches rdp-honeypot/Dockerfile's own scratch-based shape.
FROM golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /canarytokens-adapter .

FROM scratch
COPY --from=build /canarytokens-adapter /canarytokens-adapter
EXPOSE 8090
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/canarytokens-adapter", "-healthcheck"]
ENTRYPOINT ["/canarytokens-adapter"]
