# mushorg/redis — built from source (no published Docker Hub image)
# Mirrors the upstream docker/redis/Dockerfile from mushorg/tanner.
# #3720: redis 7 -> 8. This instance is a pure LRU cache (redis.conf:
# save "", appendonly no), so there is no on-disk data to migrate. Redis 8
# is RSALv2/SSPLv1/AGPLv3; private use only, never redistributed. The 8.x
# image bundles modules (search, json, bloom, timeseries) that load at
# start; tanner uses none of them and sets no ACLs.
FROM redis:8.10.2-alpine@sha256:0bf6577d7774e592b29d093e3ac9390eb91e13d72c21e506afce736de5e0eeb0

LABEL maintainer="honeypot-stack"

# Upstream tanner redis uses a minimal read-only config.
COPY redis.conf /usr/local/etc/redis/redis.conf

USER redis
EXPOSE 6379
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
