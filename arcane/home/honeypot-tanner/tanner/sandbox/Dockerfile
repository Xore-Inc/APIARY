FROM busybox:1.38@sha256:dc2d74b28e4cf8984fa52af1f39bc7c3d9c73760b41a74d629f5d11b1ab28616 AS command_rootfs

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS template_rootfs
RUN apk add --no-cache python3 py3-jinja2 py3-mako py3-tornado

FROM docker:29.9.1-dind@sha256:3e5756e2b6dad6a5f1f5deacf0a19f9eaa2581b76ae092b2d4a118162e1d4d4e

# Seed both emulator images without giving the nested daemon internet access.
COPY --from=command_rootfs / /seed/command-rootfs/
COPY --from=template_rootfs / /seed/template-rootfs/
COPY entrypoint.sh /usr/local/bin/tanner-sandbox-entrypoint
RUN chmod 755 /usr/local/bin/tanner-sandbox-entrypoint

ENTRYPOINT ["/usr/local/bin/tanner-sandbox-entrypoint"]
