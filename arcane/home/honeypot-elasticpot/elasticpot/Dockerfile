# github.com/bontchev/elasticpot -- #1423: Elasticsearch decoy, vendored
# rather than reimplemented. GPL-3.0 licensed, confirmed directly against
# the vendored LICENSE file (same posture as Dionaea's GPL-2.0-or-later,
# already vendored here for equivalent internal/private use).
#
# NOT schmalle/ElasticpotPY (T-Pot's own historical choice, and the tool
# named in issue #1423): checked directly via `gh api repos/.../license` --
# it ships no LICENSE file at all and GitHub's own detector reports
# license: null, meaning no explicit permission is granted for use even
# internally. bontchev/elasticpot is a from-scratch rewrite crediting
# ElasticpotPY as one of its influences, is GPL-3.0, and has a real plugin
# architecture (output_plugins/jsonlog.py) with native JSON logging --
# no logging-format patch needed, unlike hellpot/router_patch.py or
# dionaea's own patches. It DOES need no_egress_patch.py -- see that
# file's own doc comment: elasticpot.py unconditionally calls out to
# https://ident.me at startup, uncaught-exception-crashing the whole
# process if outbound internet isn't reachable, which this stack's
# sensors deliberately don't have by default.
#
# Pinned to the `develop` branch's HEAD, the actual latest real commit --
# despite GitHub reporting a 2025 "updated_at", the newest code commit on
# either branch is from 2020 (confirmed via `git log`); "actively
# maintained" doesn't hold up, but it's complete, licensed, and working,
# which is what matters for vendoring.
#
# Everything in etc/honeypot.cfg.base's [output_*] plugins defaults to
# `enabled = false`, including output_hpfeed (community threat-intel
# sharing) -- honeypot.cfg below only turns on output_jsonlog, matching
# this repo's declined-third-party-sharing stance
# (docs/community-threat-intel-sharing.md).
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG ELASTICPOT_REF=619df91b96881cea5bb3c7923784910f6ee19e6d
WORKDIR /build
RUN git clone https://gitlab.com/bontchev/elasticpot /build \
 && git checkout "$ELASTICPOT_REF"
COPY no_egress_patch.py /tmp/no_egress_patch.py
RUN python3 /tmp/no_egress_patch.py
# Only output_jsonlog is enabled (honeypot.cfg below) -- requirements.txt
# also pulls in deps for every other output plugin (mysqlclient, psycopg2,
# pymongo, couchdb, rethinkdb, hpfeeds, ...) we never turn on, including
# mysqlclient which needs a native pkg-config'd libmysqlclient this base
# image doesn't have. Install only what core + jsonlog actually use.
RUN python3 -m venv /elasticpot-env \
 && /elasticpot-env/bin/pip install --no-cache-dir --upgrade pip \
 && /elasticpot-env/bin/pip install --no-cache-dir \
      "configparser>=3.5.0" "service_identity>=18.1.0" "setuptools<45.0.0" \
      "Twisted>=18.9.0" "geoip2>=2.7.0" "maxminddb>=1.3.0"

FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d
RUN apt-get update && apt-get install -y --no-install-recommends netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /elasticpot-env /elasticpot-env
COPY --from=build /build /elasticpot
COPY honeypot.cfg /elasticpot/honeypot.cfg
WORKDIR /elasticpot

EXPOSE 9200

USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 9200 || exit 1

ENTRYPOINT ["/elasticpot-env/bin/python", "/elasticpot/elasticpot.py"]
