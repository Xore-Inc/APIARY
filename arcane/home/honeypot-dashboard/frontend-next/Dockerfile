# apiary-dashboard-next — the TanStack Start SSR/BFF tier (#1608).
# Nitro's node-server output is self-contained (.output holds server +
# client assets + public/static, including the vendored theme.css copy).
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build
# #3315: which revision of the repository this image is built from, stamped
# into the served /build.json below. Unset is normal, not an error: the
# generated file then says "unknown" rather than the build failing or the
# value being invented. Arcane passes it from the synced checkout via the
# stack's own `build.args`; CI passes ${{ github.sha }}.
ARG GIT_SHA
ARG GIT_SOURCE=https://github.com/Xore/APIARY
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Written after the source copy (it needs scripts/write-build-info.mjs) and
# before the build (vite copies public/ into .output/public, so a file added
# afterwards would never be served). Two consecutive RUNs because the stamp
# must exist even if `npm run build` is what fails: an image with no
# /build.json at all is a silent regression of this feature, and the error
# says nothing about which step dropped it.
# hadolint ignore=DL3059
RUN node scripts/write-build-info.mjs --out public/build.json
RUN npm run build

FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
# Redeclared per stage: Docker scopes an ARG to the stage that declares it, so
# the value the build stage wrote into public/build.json is not in scope here
# on its own.
ARG GIT_SHA
# Static, so it is written here rather than taken from a build arg: the
# repository URL is the same for every build of this image and there is no
# reason to let a caller point the label somewhere else.
ARG GIT_SOURCE=https://github.com/Xore/APIARY
# Build time is the one label a build cannot honestly invent. So it stays
# "unknown" unless the builder supplies it, and CI does (containers.yml passes
# metadata-action's labels, which carry a real created/source pair and take
# precedence over these). An "unknown" here reads as "nobody told us", which
# is true; a plausible-looking wrong timestamp would not be.
ARG BUILD_DATE
# #3315: `docker images` showed `Labels: null` for this image, so nothing said
# which commit a running dashboard was built from. Same labels as
# backend-service/Dockerfile, and they are read the same way:
# docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}'
LABEL org.opencontainers.image.revision="${GIT_SHA:-unknown}" \
      org.opencontainers.image.source="${GIT_SOURCE}" \
      org.opencontainers.image.created="${BUILD_DATE:-unknown}" \
      org.opencontainers.image.title="apiary-dashboard-next" \
      org.opencontainers.image.description="APIARY dashboard frontend/BFF (TanStack Start, Nitro)"

WORKDIR /app
COPY --from=build /app/.output ./.output
COPY server ./server
ENV PORT=8080 NODE_ENV=production
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=20s \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/static/theme.css || exit 1
USER node
# #1616: cluster.mjs forks WEB_CONCURRENCY copies of index.mjs (default
# min(4, host cpus) — see the file for why) instead of running the one
# process index.mjs used to be invoked as directly.
CMD ["node", "server/cluster.mjs"]
