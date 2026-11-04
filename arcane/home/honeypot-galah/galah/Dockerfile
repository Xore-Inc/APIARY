# github.com/0x4d31/galah -- #1420: LLM-powered HTTP honeypot, vendored
# rather than reimplemented (the prompt construction, response caching,
# and multi-provider LLM plumbing is real logic not worth rebuilding for
# one sensor). Apache-2.0 -- no copyleft concern, confirmed against the
# vendored LICENSE file.
#
# Pinned the same way beelzebub/Dockerfile and hellpot/Dockerfile pin their
# own upstream ref: building an unpinned master would change behavior
# whenever this image happens to rebuild. GALAH_REF is the commit tagged
# v1.1.1 (latest at integration time, confirmed via `git ls-remote --tags`).
#
# #1891: there is deliberately no xff_trust_patch.py here any more, and
# adding one back would reopen a hole. galah's commonFields()
# (internal/logger/logger.go) resolves srcIP/srcPort from r.RemoteAddr and
# logs every request header in httpRequest.headers -- which is all the
# worker needs, so upstream is left alone.
#
# #1511 patched it to trust X-Forwarded-For whenever RemoteAddr was the
# WireGuard tunnel peer, because that release put a Traefik-routed
# subdomain in front of galah (Cloudflare won't proxy 8889 -- not on its
# allowed non-standard-port list) and such requests arrive from the tunnel,
# not the attacker. The rule was meant to fire only on that path.
#
# It could not tell that path apart. galah's raw port is portbridge rule
# `tcp:8889:10.8.0.2:8888`, with no `:pp`, so portbridge relays it and
# RemoteAddr is the tunnel peer there too -- both paths look identical to
# the sensor. Confirmed live rather than argued: a request to 8889 carrying
# `X-Forwarded-For: 198.51.100.77` was logged with `srcIP` 198.51.100.77.
# Any attacker could name their own source. Same defect as #1883, found in
# the code #1883 was copied from.
#
# The decision belongs to the enrichment worker, which holds portbridge's
# connection log -- the one piece of evidence that separates the two paths.
# See backend-service/src/ip_enrichment/sensors.rs::enrich_galah_line.
#
# timeout_patch.py DOES patch source (#1513): SetupServer()'s hardcoded
# WriteTimeout: 10 * time.Second -- not exposed via any CLI flag or `env:`
# binding -- silently 500'd every request that hit a cold Ollama model load
# (confirmed live: 15.1s load_duration alone for qwen2.5:7b-instruct-q4_K_M
# after its default 5-minute idle unload). See that patch's own docstring.
#
# json_log_rotation_patch.py DOES patch source (#2892): event_log.json had
# neither half of the #120 contract -- internal/logger/logger.go's New()
# os.OpenFile()s it once and hands the raw *os.File straight to cblog's
# EventLogger.SetOutput() with no size check and no rotation flag anywhere
# on galah's CLI. Same shape as dionaea/mailoney/conpot's own source
# patches: a close/rename/reopen writer inserted at build time, this one
# wrapping the file handle in a small io.Writer since Go has no
# string-replace-a-method-body shape as convenient as those three Python
# targets. See that patch's own docstring.
#
# LLM_PROVIDER/LLM_MODEL/LLM_SERVER_URL are set via environment (they carry
# `env:` tags in internal/app/args.go); everything else needs an explicit
# CLI flag below since ConfigFile/EventLogFile/CacheDBFile/RulesConfigFile
# have no env-var binding in that struct.
#
# CGO_ENABLED=1, glibc final stage, not this repo's usual static+alpine
# pattern: galah's response-cache DB (internal/cache/cache.go) opens
# "sqlite3" via mattn/go-sqlite3, a cgo binding with no pure-Go fallback,
# and galah.New() calls cache.InitializeCache() unconditionally at startup
# -- even with cache duration 0 the sqlite3 driver still has to load, so
# there's no config path around this. Confirmed live: a CGO_ENABLED=0
# build of the real pinned commit starts and fails immediately with
# "Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to
# work. This is a stub" -- not assumed from reading go.mod alone. Rather
# than gamble on alpine's gcompat shim actually satisfying a real
# dynamically-linked glibc cgo binary, the final stage reuses
# cowrie/Dockerfile's own pinned debian:bookworm-slim (same libc family as
# the golang:1.23 build stage, zero compatibility risk) plus
# netcat-openbsd for the same `nc -z` HEALTHCHECK convention alpine gives
# every other sensor here via busybox-extras.
FROM golang:1.27-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 git \
 && rm -rf /var/lib/apt/lists/*
ARG GALAH_REF=8f77b85e892731cf1402963d8121c79fef0e59c7
WORKDIR /build
RUN git clone https://github.com/0x4d31/galah /build \
 && git checkout "$GALAH_REF"
COPY timeout_patch.py /tmp/timeout_patch.py
RUN python3 /tmp/timeout_patch.py
COPY json_log_rotation_patch.py /tmp/json_log_rotation_patch.py
RUN python3 /tmp/json_log_rotation_patch.py
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=$GALAH_REF" \
    -o /galah ./cmd/galah

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /galah /usr/local/bin/galah
COPY config.yaml /config.yaml

EXPOSE 8888

USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 8888 || exit 1

ENTRYPOINT ["/usr/local/bin/galah", \
  "-c", "/config.yaml", \
  "-o", "/var/log/honeypot/event_log.json", \
  "-f", "/var/log/honeypot/cache.db"]
