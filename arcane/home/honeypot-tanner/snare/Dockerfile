# Build mushorg/snare from source with a deterministic fictional portal.
#
# python:3.11-slim, NOT 3.14 -- found live during #787's actual homeserver
# reinstall (2026-08-09), on a genuinely fresh build with no Docker layer
# cache to hide it behind: aiohttp==3.8.6 (below) is pinned deliberately, a
# considered bump past upstream mushorg/snare's own requirements.txt
# (aiohttp==3.7.4), not accidental drift -- so the fix is making that exact
# pin installable again, not jumping to a modern aiohttp untested against
# this file's compatibility_patch.py. aiohttp 3.8.6 has no prebuilt wheel
# past cp311 (confirmed against the real PyPI file list), and its Cython-
# generated _websocket.c directly reads CPython-internal PyLongObject
# struct fields (ob_digit) that later CPython versions restructured --
# this is a genuine C-ABI incompatibility, not a missing build dependency;
# confirmed live that even installing every header package still fails
# identically against 3.12, let alone 3.14. 3.11 is the newest version
# with a real prebuilt wheel -- verified live: installs cleanly from a
# wheel against this exact digest, no compilation at all (3.12 was tried
# first, since ml-worker/Dockerfile and auth-events-worker/Dockerfile
# already pin that version elsewhere in this repo; it fails identically to
# 3.14, no cp312 wheel exists either -- 3.11 is the newest that actually
# has one).
FROM python:3.11-slim@sha256:6f31d6e9ba2b0a787a3f81c37b004155b87b9efa1b771182bd550c1615745be5

RUN apt-get update && apt-get install -y --no-install-recommends \
        git wget libxml2-dev libxslt-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/snare

ARG SNARE_REF=b17fdfe7c2ba3ac540548763d73fc475cfc185c4
RUN git clone https://github.com/mushorg/snare.git . \
 && git checkout "$SNARE_REF" \
 && rm -rf .git

COPY compatibility_patch.py /tmp/snare-compatibility-patch.py
RUN python /tmp/snare-compatibility-patch.py \
 && rm /tmp/snare-compatibility-patch.py

RUN pip install --no-cache-dir -U pip setuptools wheel \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir 'aiohttp==3.8.6' \
 && python setup.py install

ARG PAGE_URL=portal.meridian.example
ARG TANNER=tanner
ARG PORT=8080
ENV PAGE_URL=${PAGE_URL} TANNER=${TANNER} PORT=${PORT}

# Emit SNARE's content-addressed page layout without cloning a real company.
COPY persona /tmp/persona
COPY build_persona.py /tmp/build-persona.py
RUN python /tmp/build-persona.py \
 && mkdir -p /opt/snare/pages \
 && cp -a /opt/persona-pages/. /opt/snare/pages/ \
 && rm -rf /tmp/persona /tmp/build-persona.py

COPY entrypoint.sh /usr/local/bin/snare-entry.sh
RUN chmod +x /usr/local/bin/snare-entry.sh

VOLUME ["/opt/snare/pages"]
EXPOSE ${PORT}
CMD ["/usr/local/bin/snare-entry.sh"]
