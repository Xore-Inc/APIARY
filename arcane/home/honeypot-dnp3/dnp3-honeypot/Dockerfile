FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dnp3-honeypot .

FROM scratch
COPY --from=build /dnp3-honeypot /dnp3-honeypot
USER 65534:65534
EXPOSE 20000
ENTRYPOINT ["/dnp3-honeypot"]
