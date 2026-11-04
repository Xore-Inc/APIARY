# SonicWall SMA1000 Work Place/AMC decoy for the CVE-2026-83548/83549
# SSRF+RCE chain (#3033) -- see main.go's own doc comment.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /sonicwall-sma-honeypot .

FROM scratch
COPY --from=build /sonicwall-sma-honeypot /sonicwall-sma-honeypot
EXPOSE 8443
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/sonicwall-sma-honeypot", "-healthcheck"]
ENTRYPOINT ["/sonicwall-sma-honeypot"]
