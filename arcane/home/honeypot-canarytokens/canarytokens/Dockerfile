# github.com/thinkst/canarytokens (self-hosted via the thinkst/canarytokens-docker
# deployment shape) -- #1426: honeytoken platform, vendored rather than
# reimplemented (token generation/validation for ~28 token types, webhook
# alerting, DNS/SMTP/MySQL/etc listener channels is a lot of real logic not
# worth rebuilding). Distributed under a modified GPLv3 (see the vendored
# LICENSE file) -- same internal/private-use posture already taken for
# Dionaea/Beelzebub/HellPot: the added "derivative work" language only
# matters if this code is embedded into a redistributed product, which it
# isn't here.
#
# Pinned to a specific commit (this repo's usual convention) instead of
# upstream's own Dockerfile, which defaults to floating `master`.
# CANARYTOKENS_REF is HEAD as of the #1415 epic's integration pass.
#
# Two build-time patches (vendor + extend, matching dionaea/log_rotation_patch.py
# and hellpot/router_patch.py):
#   - webhook_ssrf_allowlist_patch.py: advocate's default SSRF protection
#     blocks webhook_url targets on any RFC1918 address, which would
#     silently blackhole every alert to our own adapter (a private-network-only
#     service, see docker-compose.canarytokens.yml). Every token this stack
#     creates sets its own fixed, non-attacker-controlled webhook_url, so
#     the SSRF threat model the check protects against doesn't apply here.

ARG ARCH=amd64
# the build pins its target platform on purpose (ARCH above)
# hadolint ignore=DL3029
FROM --platform=linux/${ARCH} python:3.13.16-slim@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.24 /uv /uvx /usr/local/bin/
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV UV_LINK_MODE=copy

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates dnsutils gcc iproute2 jq \
        libffi-dev libssl-dev libxml2-dev libxslt-dev \
        libz-dev locales lsof net-tools unzip wget zlib1g && \
    rm -rf /var/lib/apt/lists/*

ARG CANARYTOKENS_REF=dd92bf29bd0f6d1b446fb41e3b8114c6fc7a6205
RUN wget -O archive.zip "https://github.com/thinkst/canarytokens/archive/${CANARYTOKENS_REF}.zip" && \
    unzip -q archive.zip && \
    mv /canarytokens-*/* /srv && \
    rm -rf /canarytokens-* archive.zip && \
    echo "${CANARYTOKENS_REF}" > /COMMIT_SHA

FROM node:22@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7 AS frontend-builder
WORKDIR /build
COPY --from=builder /srv/frontend_vue /build/frontend
WORKDIR /build/frontend
RUN npm ci && touch .env && npm run build

FROM builder AS canary-tokens
COPY --from=frontend-builder /build/dist /srv/dist
COPY webhook_ssrf_allowlist_patch.py /srv/apply_patches.py
RUN cd /srv && python3 apply_patches.py && rm apply_patches.py
WORKDIR /srv
RUN uv sync --no-default-groups --frozen

# /logs is a bind-mount point for the adapter's own output, not written to
# by canarytokens itself (frontend/switchboard log to stdout/stderr, picked
# up via docker's own json-file logging driver -- operator-facing only,
# not shipped to Elasticsearch, since the actual token-fired events arrive
# via the webhook adapter, not these process logs).
#
# Runs as root (upstream's own default, unchanged here) -- switchboard's
# privileged-looking ports (25/53/etc, see common-services.yml upstream)
# are bound at non-privileged numbers inside the container and remapped by
# Docker's own port-publish, so root isn't actually load-bearing for that;
# left as-is rather than fighting upstream's own runtime assumptions for a
# webapp that also writes to /uploads and manages its own log rotation.

EXPOSE 8082 8083
# docker-compose.canarytokens.yml overrides `command:` per-service (frontend
# vs switchboard), matching upstream's own canarytokens-docker shape exactly.
CMD ["echo", "specify a command: in docker-compose.canarytokens.yml (frontend or switchboard)"]
