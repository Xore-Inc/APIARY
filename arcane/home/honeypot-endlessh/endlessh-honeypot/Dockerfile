FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /endlessh-honeypot .

FROM scratch
COPY --from=build /endlessh-honeypot /endlessh-honeypot
USER 65534:65534
EXPOSE 2222
ENTRYPOINT ["/endlessh-honeypot"]
