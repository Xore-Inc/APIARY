# mushorg/phpox — PHP sandbox for tanner (no published Docker Hub image)
# Provides the PHP eval sandbox tanner uses for template-injection emulation.
FROM php:8.5-cli-alpine@sha256:93684051146ec037620855feb77f278090bde45ddc030801cd3f2a7685bc4deb

LABEL maintainer="honeypot-stack"

# Pin the audited source revision, the same way tanner/Dockerfile pins
# TANNER_REF and sentrypeer/Dockerfile pins SENTRYPEER_REF: building an
# unpinned master would change eval-sandbox behaviour whenever Dockge
# happened to rebuild the image (#2434) -- phpox is the sandbox that
# actually executes the php_code_injection/php_object_injection/
# template_injection payloads tanner routes to it, so a silent swap of its
# source is a silent swap of those evaluations. No tagged release exists to
# pin instead: `git ls-remote` (2026-08-27) shows a single HEAD ref and
# zero refs/tags/*, so a commit pin is the only form available -- exactly
# the case SENTRYPEER_REF already handles ("no tagged release newer than
# this exists at the time of writing"). 55a6cbdc is upstream HEAD as of
# 2026-08-27 and is the revision the deployed image (built 2026-08-26) was
# already shipping, verified read-only inside the running hp-tanner-phpox
# container. Taking a newer upstream commit must stay a deliberate bump of
# this ARG, never a side effect of a rebuild.
ARG PHPOX_REF=55a6cbdc2c62f08eb45acffaf84f23f06a1d4703
RUN apk add --no-cache git \
 && git clone https://github.com/mushorg/phpox /opt/phpox \
 && git -C /opt/phpox checkout "$PHPOX_REF" \
 && rm -rf /opt/phpox/.git

# #877: this is the PHP eval sandbox that actually executes
# attacker-influenced php_code_injection/php_object_injection/
# template_injection payloads tanner routes to it -- it ran as root (uid 0)
# by default, with nothing in this file or docker-compose.tanner.yml's
# service definition dropping to a real unprivileged user (cap_drop: ALL,
# no-new-privileges, and read_only: true there are all real, complementary
# hardening, but none of them make the process's own uid non-root). `php -S`
# only ever needs to read /opt/phpox and write to the /tmp tmpfs the compose
# file already provides -- no reason for the eval sandbox to hold uid 0.
RUN addgroup -S phpox && adduser -S -G phpox phpox \
 && chown -R phpox:phpox /opt/phpox
USER phpox

WORKDIR /opt/phpox
EXPOSE 8088
CMD ["php", "-S", "0.0.0.0:8088", "index.php"]
