# Citrix ADC/NetScaler Gateway decoy (CVE-2019-19781), Go port of
# t3chn0m4g3/CitrixHoneypot (#238, #414) -- see main.go's own doc comment.
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
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
