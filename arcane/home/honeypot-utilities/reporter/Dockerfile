# Static Go binary in a scratch image, same pattern as multipot/http-honeypot.
# modernc.org/sqlite is pure Go (no cgo), so CGO_ENABLED=0 still holds despite
# the SQLite dependency -- see dedup.go's import comment.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /reporter .

FROM scratch
COPY --from=build /reporter /reporter

# No USER pin here (defaults to root) -- deliberately, matching filebeat's
# situation in docker-compose.yml (#118's comment there has the full
# reasoning): this container reads every sensor's own JSON log, each owned
# by that sensor's own UID (0640, no "other" read bit -- confirmed against
# multipot/http-honeypot's own logger.go). A fixed non-root UID could read
# none of them; root only gets that read-bypass back via an explicit
# DAC_READ_SEARCH cap_add in compose, not by running as root alone.

ENTRYPOINT ["/reporter"]
