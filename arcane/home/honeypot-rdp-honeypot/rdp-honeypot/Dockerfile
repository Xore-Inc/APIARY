# RDP (3389/tcp) decoy, Go port of CommunityHoneyNetwork/rdphoney (#238,
# #412) -- see main.go's own doc comment for why this is genuinely simple
# despite RDP's reputation, and why that reverses #238's original "vendor,
# don't port" call.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /rdp-honeypot .

FROM scratch
COPY --from=build /rdp-honeypot /rdp-honeypot
EXPOSE 3389
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/rdp-honeypot", "-healthcheck"]
ENTRYPOINT ["/rdp-honeypot"]
