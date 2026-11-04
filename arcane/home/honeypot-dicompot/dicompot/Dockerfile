# nsmfoo/dicompot — DICOM (medical imaging) honeypot. Vendored rather than
# ported (#238, #413): the actual DICOM PDU/DIMSE state machine (association
# negotiation, C-FIND/C-STORE/C-GET), imported unmodified from
# github.com/nsmfoo/dicompot below, is built on GRAIL's go-dicom and isn't
# worth reimplementing from scratch for one honeypot.
#
# main.go in this directory replaces upstream's own server/dicompot.go
# entrypoint -- see its own doc comment for why: upstream's rotatefilehook
# file logging never actually writes (confirmed directly, not assumed --
# hook.Fire() discards lumberjack's Write() error silently), and
# ConnectionState carries no attacker address at all, so neither the
# protocol logic nor anything else in the vendored package needed to
# change, only the wiring around it.
#
# Pinned the same way tanner/tanner/Dockerfile pins TANNER_REF: building an
# unpinned master would change behavior whenever this image happens to
# rebuild. Fetched via `go get`, not `git clone` -- main.go is a normal
# dependent of the github.com/nsmfoo/dicompot module, not that module's own
# main package, so there is no local source tree to clone at all here. The
# pin itself lives in go.mod/go.sum (committed, like every other Go
# sensor's), not as a rebuild-time ARG -- that's what lets CI's `go test`
# and `go build` resolve the same pinned deps this image starts from.
#
# #3179: two DICOM fingerprint tells (2 and 5) can only be fixed inside the
# library's own DIMSE handling -- an A-ASSOCIATE-AC presentation-context
# result, and C-FIND/C-MOVE/C-GET response statuses -- so the wrapper in
# this directory cannot reach them. The dependency is therefore forked, in
# the same spirit as honeypot-cowrie's txtcmds_priority_patch.py: rather
# than committing a whole vendored copy of the module (which would turn a
# one-line `go get -u` pin bump into a hand-merged tree and hide the drift
# from `go mod` entirely), dimse_status_patch/ is a build-time patch
# program that rewrites a writable copy of the pinned module in the build
# stage, and `go mod edit -replace` points the build at that copy.
# go.mod/go.sum stay pristine, so `go test` and `go build` outside the
# image still resolve the unpatched pin -- which is exactly what makes the
# patch's test suite able to assert red-unpatched/green-patched
# (see dimse_status_patch/ax_status_test.go). The copy is discarded with
# the build stage; nothing patched is committed, and no upstream code is
# vendored in-tree.
#
# The patcher pins its anchors as exact byte matches against the revision
# above and hard-fails if any anchor stops matching exactly once, so a pin
# bump that moves the patched code fails the image build loudly instead of
# silently shipping an unpatched sensor.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go proxyproto.go aetitle.go ./
COPY dimse_status_patch/ ./dimse_status_patch/
# Patch the pinned dependency, then point this build at the patched copy.
# Scoped to the build stage: the `-replace` is written to the build stage's
# go.mod only, never to the committed one, and the patched copy is discarded
# with the stage. The closing `go list` re-check turns a silently
# ineffective `go mod edit` into a failed image build rather than a shipped
# but unpatched sensor.
RUN set -eu; \
    patched="$(go list -m -f '{{.Dir}}' github.com/nsmfoo/dicompot)"; \
    test -n "$patched"; \
    cp -R "$patched" /src/dicompot-patched; \
    chmod -R u+w /src/dicompot-patched; \
    go build -o /patch-dimse-status ./dimse_status_patch; \
    /patch-dimse-status /src/dicompot-patched; \
    go mod edit -replace github.com/nsmfoo/dicompot=/src/dicompot-patched; \
    test "$(go list -m -f '{{.Dir}}' github.com/nsmfoo/dicompot)" = /src/dicompot-patched
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /dicompot .

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache busybox-extras
COPY --from=build /dicompot /usr/local/bin/dicompot

# No sample DICOM files bundled: an attacker's C-FIND/C-GET/C-STORE attempts
# get logged regardless of whether any (fake) image data exists behind
# them -- that's the honeypot signal, not realistic image content, and it
# avoids bundling any medical-imaging-shaped sample data at all. /var/log/
# honeypot is deliberately not created here -- like every other sensor's
# image, it's a bind-mount point (docker-compose.dicompot.yml), so its
# permissions come from the host directory, not this image.
RUN mkdir -p /dicom-store

EXPOSE 11112

USER 65534

ENV LOG_FILE=/var/log/honeypot/dicompot.json

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD nc -z 127.0.0.1 11112 || exit 1

ENTRYPOINT ["/usr/local/bin/dicompot"]
