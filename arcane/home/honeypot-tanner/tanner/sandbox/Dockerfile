FROM busybox:1.38@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e AS command_rootfs

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS template_rootfs
RUN apk add --no-cache python3 py3-jinja2 py3-mako py3-tornado

FROM docker:29.9.3-dind@sha256:08a98015fce594af7c382883bea080ea206de74402a95da9dc52b6428c8cd121

# Seed both emulator images without giving the nested daemon internet access.
COPY --from=command_rootfs / /seed/command-rootfs/
COPY --from=template_rootfs / /seed/template-rootfs/
COPY entrypoint.sh /usr/local/bin/tanner-sandbox-entrypoint
RUN chmod 755 /usr/local/bin/tanner-sandbox-entrypoint

ENTRYPOINT ["/usr/local/bin/tanner-sandbox-entrypoint"]
