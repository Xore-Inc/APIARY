# github.com/beelzebub-labs/beelzebub (formerly mariocandela/beelzebub) --
# #1418: multi-protocol deception runtime, vendored rather than reimplemented
# (SSH/HTTP/TCP/TELNET/MCP protocol handling + LLM-driven adaptive responses
# is a lot of real logic not worth rebuilding for one sensor). GPL-3.0 --
# same posture already taken for Dionaea's GPL-2.0-or-later: internal/
# private use only, never redistributed, so copyleft has no practical effect
# here. Confirmed directly against the vendored LICENSE file, not assumed.
#
# Pinned the same way tanner/tanner/Dockerfile pins TANNER_REF: building an
# unpinned master would change behavior whenever this image happens to
# rebuild. BEELZEBUB_REF is the commit tagged v3.9.0 (latest at integration
# time, confirmed via `git ls-remote --tags`).
#
# No plugins (configurations/plugins.yaml ships empty in upstream and stays
# that way here) -- every service this stack uses is upstream's own built-in
# SSH/HTTP/TCP/MCP strategy, configured via YAML, not custom Go code.
#
# json_log_rotation_patch.py DOES patch source (#2892): beelzebub.json
# (core.yaml's logsPath) had neither half of the #120 contract --
# internal/builder/builder.go's buildLogger() os.OpenFile()s it once and
# hands the raw *os.File to logrus through io.MultiWriter with no size
# check and no rotation knob in core.yaml's Logging block. Same shape as
# galah/json_log_rotation_patch.py (the other vendored Go sensor): a
# close/rename/reopen io.Writer wrapper inserted at build time, keeping
# Builder.logsFile (which Builder.Close() closes) pointed at the live
# generation. See that patch's own docstring.
FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
# python3 only runs json_log_rotation_patch.py (#2892) below; the runtime
# stage never sees it.
RUN apk add --no-cache git python3
ARG BEELZEBUB_REF=39242822af79a59a6b8d0139adc4a8ccf2edec0c
WORKDIR /build
RUN git clone https://github.com/mariocandela/beelzebub /build \
 && git checkout "$BEELZEBUB_REF"
COPY json_log_rotation_patch.py /tmp/json_log_rotation_patch.py
RUN python3 /tmp/json_log_rotation_patch.py
RUN go mod download
# go run . plugin install --no-build is upstream's own Dockerfile step for
# compiling declared plugins in -- skipped here, plugins.yaml is empty.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /beelzebub .

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates busybox-extras
COPY --from=build /beelzebub /usr/local/bin/beelzebub
COPY configurations /etc/beelzebub/configurations

# /var/log/honeypot is a bind-mount point (docker-compose.beelzebub.yml),
# same convention as every other sensor's image -- not created here.
# core.yaml's logsPath points at a file under it.

EXPOSE 2200 389 8000 8880

USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 8880 || exit 1

ENTRYPOINT ["/usr/local/bin/beelzebub", "run", "-c", "/etc/beelzebub/configurations/core.yaml", "-s", "/etc/beelzebub/configurations/services/"]
