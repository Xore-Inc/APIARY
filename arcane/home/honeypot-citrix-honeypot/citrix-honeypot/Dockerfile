# Citrix ADC/NetScaler Gateway decoy (CVE-2019-19781), Go port of
# t3chn0m4g3/CitrixHoneypot (#238, #414) -- see main.go's own doc comment.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /citrix-honeypot .

FROM scratch
COPY --from=build /citrix-honeypot /citrix-honeypot
EXPOSE 443
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/citrix-honeypot", "-healthcheck"]
ENTRYPOINT ["/citrix-honeypot"]
