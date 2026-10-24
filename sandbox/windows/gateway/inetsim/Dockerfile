# INetSim — the fake internet the detonation guest talks to.
#
# Built from Kali rather than Debian because `inetsim` is packaged there and
# not in Debian proper. The alternative — fetching the upstream tarball from
# inetsim.org — means carrying a version and a checksum in this repository and
# re-pinning them by hand; the distribution package is the maintained path.
#
# Build on a host WITH internet. The container runs with none: it is attached
# to an internal macvlan on the isolated sandbox bridge, which has no route off
# the box. See docker-compose.sandbox.yml.
FROM kalilinux/kali-rolling:latest@sha256:4be87f78671419c13dcf4f207ead1cfc0de178ea281b3f69c0f49b69ba4e79b1

# procps for the entrypoint's process check; ca-certificates so the build step
# itself can talk to the Kali mirror over TLS.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        inetsim procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# INetSim writes reports and captured second-stage downloads here. The compose
# file bind-mounts a per-detonation directory over it so each sample's network
# evidence stays separate.
RUN mkdir -p /var/log/inetsim/report /var/lib/inetsim/http/fakefiles

# Runs as root because it binds 21/25/53/80/443 — all privileged. The container
# has no network path off the sandbox bridge, so the blast radius is the fake
# internet it is pretending to be.
ENTRYPOINT ["/usr/bin/inetsim", "--conf", "/etc/inetsim/inetsim.conf"]
