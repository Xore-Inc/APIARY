# Static Go binary in a scratch image (~5 MB).
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod .
# Every non-test .go file, not a hand-maintained list. The enumerated form
# silently omitted community_id.go when it was added: `go build ./...` locally
# compiles the whole directory and passed, while the image build failed on
# undefined symbols. A list that has to be updated in lockstep with the
# package is a list that will be wrong again.
COPY *.go ./
RUN rm -f ./*_test.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /portbridge .

FROM scratch
COPY --from=build /portbridge /portbridge
ENTRYPOINT ["/portbridge"]
