# canarytokens-adapter -- #1426: this repo's own small webhook receiver,
# not a vendored tool (nothing to vendor: translating an arbitrary JSON
# webhook into this repo's shared sensor-log shape is a few dozen lines,
# not a project). Matches rdp-honeypot/Dockerfile's own scratch-based shape.
FROM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
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
