# Static Go binary in a scratch image (~5 MB).
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /portbridge .

FROM scratch
COPY --from=build /portbridge /portbridge
ENTRYPOINT ["/portbridge"]
