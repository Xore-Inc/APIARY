# statictools — ssdeep/tlsh fuzzy hashing, lief structural parsing, capa
# capability tagging, and floss obfuscated-string extraction, as an isolated
# sidecar rather than a host pip install.
# See server.py's module docstring for why: worker/ghidra-worker.py is
# deliberately stdlib-only on the host, and these are exactly the compiled/
# C-extension dependencies that rule exists to keep off it.
FROM python:3.14-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libfuzzy-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ssdeep's own packaging (last touched years ago) needs all four of these
# pinned/present before it will build at all, verified against a clean
# python:3.12-slim image (2026-08-01):
#   - setuptools<81: its setup.py does `import pkg_resources` at build time,
#     which setuptools removed in 81 (deprecated since 2025-11-30). Newer
#     setuptools installed and still failing is this, not a stale cache.
#   - --no-build-isolation: pip's isolated build env ignores the pin above
#     and fetches current setuptools regardless unless the build shares the
#     outer environment.
#   - six, cffi: imported directly by ssdeep/binding.py at build time; not
#     declared as build requirements, so pip's dependency resolution never
#     installs them on its own.
# flare-floss's own binary2strings dependency needs a C++11 compiler at
# build time (build-essential above already covers it, verified against
# this same base image, 2026-08-01 -- no separate package needed).

# lief is pinned like every other tool here (#2072): an unpinned install is
# exactly the "one version drift from breaking" risk this container exists to
# prevent -- lief crossed its 1.0 major boundary, and server.py talks to its
# API surface directly (machine_type/machine/cpu_type per format). CI reads
# this pin back out of this file when it exercises lief_parse(), so the
# version under test and the version shipped cannot drift apart.
RUN pip install --no-cache-dir -U pip 'setuptools<81' wheel six cffi \
    && pip install --no-cache-dir --no-build-isolation ssdeep \
    && pip install --no-cache-dir py-tlsh lief==1.0.0 flare-capa==9.4.0 flare-floss==3.1.1

# capa-rules must match capa's own version exactly (Mandiant's own
# requirement -- rule schema drifts between releases). Pinned by tag and
# verified by digest, same convention as GhidrAssist's release zip in
# ghidrassist/README.md: a third-party artifact pulled at build time gets a
# checksum, not just a URL.
ARG CAPA_RULES_VERSION=v9.4.0
ARG CAPA_RULES_SHA256=273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669
# the pipe ends in `sha256sum -c -`, whose exit status already decides this step
# hadolint ignore=DL4006
RUN curl -fsSL -o /tmp/capa-rules.tar.gz \
      "https://github.com/mandiant/capa-rules/archive/refs/tags/${CAPA_RULES_VERSION}.tar.gz" \
    && echo "${CAPA_RULES_SHA256}  /tmp/capa-rules.tar.gz" | sha256sum -c - \
    && mkdir -p /app/capa-rules \
    && tar -xzf /tmp/capa-rules.tar.gz -C /app/capa-rules --strip-components=1 \
    && rm /tmp/capa-rules.tar.gz

# capa's own library-function signatures (.sig files, used to recognise
# statically-linked library code so it isn't misidentified as sample logic)
# -- separate from capa-rules above, and NOT bundled into the flare-capa pip
# package the way capa's own CLI docs imply ("use embedded signatures by
# default"). Found live (#498): every capa call failed with "Using default
# signature path, but it doesn't exist" because nothing had ever fetched
# them. They live in the main capa repo (not capa-rules), same
# version-pinned-by-tag-and-digest convention as the rules above.
ARG CAPA_SIGS_VERSION=v9.4.0
ARG CAPA_SIGS_SHA256=562edd9617b23286e74d06f0115d99217a4df178e43925375af0c35d5cae8d66
# the pipe ends in `sha256sum -c -`, whose exit status already decides this step
# hadolint ignore=DL4006
RUN curl -fsSL -o /tmp/capa.tar.gz \
      "https://github.com/mandiant/capa/archive/refs/tags/${CAPA_SIGS_VERSION}.tar.gz" \
    && echo "${CAPA_SIGS_SHA256}  /tmp/capa.tar.gz" | sha256sum -c - \
    && mkdir -p /app/capa-sigs \
    && tar -xzf /tmp/capa.tar.gz -C /app/capa-sigs --strip-components=2 "capa-${CAPA_SIGS_VERSION#v}/sigs" \
    && rm /tmp/capa.tar.gz

COPY server.py /app/server.py

# py-tlsh's compiled extension calls into libstdc++ (C++ exception-handling
# symbols like __gxx_personality_v0) but its own build doesn't declare
# libstdc++ as a needed shared library -- ldd on the built .so shows only
# libgcc_s/libc/ld-linux, no libstdc++.so.6, even though build-essential
# (providing it) is installed above. This is the well-known "a C++ Python
# extension got linked via the C compiler frontend, which doesn't
# auto-add -lstdc++ the way g++ does" packaging gap: the shared-object
# link step doesn't error on the unresolved symbol (most toolchains don't
# reject undefined symbols in a `-shared` build by default), so it only
# surfaces at import time. Found live during #787's homeserver reinstall
# (2026-08-09): every statictools container crash-looped on `import tlsh`
# with `undefined symbol: __gxx_personality_v0`. LD_PRELOAD-ing the
# library that's already installed on this same image (just never linked
# against) is the standard fix for this exact, well-known failure mode.
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libstdc++.so.6

# Non-root. capa needs the sample on disk (it has no stdin mode), so this
# service writes one file per request under $TMPDIR -- /tmp is world-writable
# by default, so 65534 can do that without owning anything else. It reads
# capa-rules/capa-sigs and its own code, and reads sample bytes into memory
# otherwise; it has no reason to write anywhere outside of that.
RUN chown -R 65534:65534 /app/capa-rules /app/capa-sigs
USER 65534:65534
EXPOSE 9091

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9091/v1/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["python3", "/app/server.py"]
