# mushorg/redis — built from source (no published Docker Hub image)
# Mirrors the upstream docker/redis/Dockerfile from mushorg/tanner.
# #3720: redis 7 -> 8. This instance is a pure LRU cache (redis.conf:
# save "", appendonly no), so there is no on-disk data to migrate. Redis 8
# is RSALv2/SSPLv1/AGPLv3; private use only, never redistributed. The 8.x
# image bundles modules (search, json, bloom, timeseries) that load at
# start; tanner uses none of them and sets no ACLs.
FROM redis:8.10.3-alpine@sha256:21090af93f8324db2f0f0f4f38a7c60369d47d917e000c3423d89d2ae2883537

LABEL maintainer="honeypot-stack"

# Upstream tanner redis uses a minimal read-only config.
COPY redis.conf /usr/local/etc/redis/redis.conf

USER redis
EXPOSE 6379
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
