# github.com/yunginnanet/HellPot -- #1419: HTTP bot tarpit, vendored rather
# than reimplemented (the Markov-chain garbage generator and streaming
# response writer is real logic not worth rebuilding for one sensor). MIT
# licensed -- no copyleft concern at all, confirmed directly against the
# vendored LICENSE file.
#
# Pinned the same way beelzebub/Dockerfile pins BEELZEBUB_REF: building an
# unpinned master would change behavior whenever this image happens to
# rebuild. HELLPOT_REF is the commit tagged v0.5.4+build2 (latest at
# integration time, confirmed via `git ls-remote --tags`).
#
# router_patch.py removes getRealRemote()'s X-Real-IP trust -- see that
# file's own doc comment for why (confirmed live, not assumed: an
# unpatched build logs an attacker-supplied X-Real-IP header verbatim as
# REMOTE_ADDR with zero validation of which hop set it).
#
# On the raw-port path the real attacker IP is resolved by
# ip-enrichment-worker's via_port join against portbridge's connection log,
# the same trusted mechanism every other non-PROXY-protocol sensor uses.
#
# #1876: that path is no longer the only one. #1509 added a Traefik route
# for the bare/www/static hosts, which reaches HellPot through socat rather
# than portbridge -- so portbridge writes no record for those connections
# and the via_port join misses permanently. No header can fill that gap,
# because anything Traefik adds an attacker can send too: the #1511-era
# rule that trusted X-Forwarded-For from the tunnel peer was removed along
# that line (#1885 -> #1891, where the same indistinguishability was
# proven live against galah). xff_trust_patch.py therefore records rather
# than decides: REMOTE_ADDR keeps the true TCP peer, the raw header is
# logged alongside it as XFF, and since #1908 a second listener on
# HELLPOT_PROXIED_PORT gives the socat path a door of its own, so the
# arrival port in each log line says which way in. ip-enrichment-worker
# adjudicates -- portbridge's record on the raw path, the forwarded chain
# on the proxied one. It must run after router_patch.py, whose output it
# matches on.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
RUN apk add --no-cache python3 git
ARG HELLPOT_REF=0ba62c99ea4599ec32474e4982a8ea4d4105c471
WORKDIR /build
RUN git clone https://github.com/yunginnanet/HellPot /build \
 && git checkout "$HELLPOT_REF"
COPY router_patch.py /tmp/router_patch.py
RUN python3 /tmp/router_patch.py
COPY xff_trust_patch.py /tmp/xff_trust_patch.py
RUN python3 /tmp/xff_trust_patch.py
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=$HELLPOT_REF" \
    -o /hellpot cmd/HellPot/*.go

# alpine, not upstream's own distroless/static-debian11 choice: distroless
# has no shell/nc at all, which breaks this repo's established `nc -z`
# HEALTHCHECK pattern (beelzebub/Dockerfile, rdp-honeypot's Dockerfile,
# etc.) -- consistency with the rest of this stack wins over matching
# upstream's own base image exactly.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache busybox-extras
COPY --from=build /hellpot /usr/local/bin/hellpot
COPY config.toml /config.toml

EXPOSE 8080

USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 8080 || exit 1

ENTRYPOINT ["/usr/local/bin/hellpot", "-c", "/config.toml"]
