FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tftp-relay .

FROM scratch
COPY --from=build /tftp-relay /tftp-relay
USER 65534:65534
EXPOSE 1069/udp
ENTRYPOINT ["/tftp-relay"]
