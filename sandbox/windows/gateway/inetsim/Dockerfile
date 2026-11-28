# INetSim — the fake internet the detonation guest talks to.
#
# Built from Debian trixie rather than Kali. #4005: Kali removed
# inetsim 1.3.2+dfsg.1-8 from kali-rolling on 2026-11-26, and the rolling
# repositories no longer carry the package at all, so a Kali digest pin cannot
# build this image any more. Debian trixie packages inetsim 1.3.2+dfsg.1-1,
# which is upstream's current 1.3.2 release, from the same Debian source
# package, with the same /usr/bin/inetsim entrypoint and /etc/inetsim config
# path the rest of this directory and docker-compose.sandbox.yml expect.
#
# Build on a host WITH internet. The container runs with none: it is attached
# to an internal macvlan on the isolated sandbox bridge, which has no route off
# the box. See docker-compose.sandbox.yml.
FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

# procps for the entrypoint's process check; ca-certificates so the build step
# itself can talk to the Debian mirror over TLS. The upgrade applies the
# trixie security fix for libzstd1 (CVE-2026-124851) that this digest predates,
# the same handling as the other trixie-slim images in this repository (#3964).
# libnet-dns-perl is pinned to the exact trixie build the DNS patch below was
# tested against (1.57-0+deb13u1). A newer build could rename the private
# _TCP_server/_UDP_server methods the patch calls; the assertion below catches
# that at build time, and the pin keeps an apt upgrade from changing it silently.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        inetsim procps ca-certificates libnet-dns-perl=1.57-0+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

# INetSim's DNS service calls Net::DNS::Nameserver->main_loop, which the libnet-dns-perl
# 1.57 in trixie no longer has (the DNS service died at startup). The patch serves the
# listeners directly; see inetsim-dns-trixie.patch. patch refuses to apply to a file it
# does not recognise, so a package update that changes DNS.pm fails the build instead
# of silently shipping a DNS service that does not run.
COPY inetsim-dns-trixie.patch /tmp/inetsim-dns-trixie.patch
# Build-time assertion: the patch calls these two private Net::DNS::Nameserver
# methods, so fail the build if the installed library no longer has them.
RUN perl -MNet::DNS::Nameserver -e 'for my $m (qw(_TCP_server _UDP_server)) { Net::DNS::Nameserver->can($m) or die "Net::DNS::Nameserver has no $m: inetsim-dns-trixie.patch is stale, revise it before rebuilding\n" } print "Net::DNS::Nameserver: _TCP_server and _UDP_server present\n"' \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends patch \
    && patch -p1 -d / --forward --batch -i /tmp/inetsim-dns-trixie.patch \
    && apt-get purge -y --auto-remove patch \
    && rm -rf /var/lib/apt/lists/* /tmp/inetsim-dns-trixie.patch

# INetSim writes reports and captured second-stage downloads here. The compose
# file bind-mounts a per-detonation directory over it so each sample's network
# evidence stays separate.
# Root-owned: the services run as root (service_run_as_user in the config), and
# the package's inetsim-owned 0700 log directory would refuse root's writes.
RUN mkdir -p /var/log/inetsim/report /var/lib/inetsim/http/fakefiles \
    && chown -R root:root /var/log/inetsim /var/lib/inetsim

# Runs as root because it binds 21/25/53/80/443 — all privileged. The container
# has no network path off the sandbox bridge, so the blast radius is the fake
# internet it is pretending to be.
ENTRYPOINT ["/usr/bin/inetsim", "--conf", "/etc/inetsim/inetsim.conf"]

# docker stop sends SIGTERM by default, and INetSim's service processes answer TERM
# by waiting for their children to close: a stop took the full 10 s timeout and ended
# in SIGKILL (exit 137). SIGQUIT takes the server_close path and exits in under a second.
STOPSIGNAL SIGQUIT
