FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /endlessh-honeypot .

FROM scratch
COPY --from=build /endlessh-honeypot /endlessh-honeypot
USER 65534:65534
EXPOSE 2222
ENTRYPOINT ["/endlessh-honeypot"]
