# Replacement for the third-party biniamfd/ghidra-headless-rest image (#245):
# that image is a single, unofficial maintainer's packaging with no public
# source repo to check health/bus-factor on, stuck on Ghidra 11.3.2 with no
# newer tag in over a year. The actual hard part -- decompilation and
# function/string/import extraction -- turned out to already be a
# self-contained script using only Ghidra's own public scripting API
# (confirmed live against the running third-party image's own
# /opt/ghidra_*/ghidra_scripts/export_json.py before writing this); the only
# thing genuinely worth replacing was the thin HTTP/queue wrapper around it,
# which server.py/export_json.py in this directory do independently (not
# copied -- that file carried no license).
#
# Ghidra itself is fetched from its own official GitHub releases (the NSA's
# own repository, not a third party) and checksum-verified, the same
# pin-by-digest convention statictools/Dockerfile already uses for its own
# third-party artifacts (capa-rules/capa-sigs).
FROM eclipse-temurin:21-jdk@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 unzip curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG GHIDRA_VERSION=11.3.2
ARG GHIDRA_BUILD_DATE=20250415
ARG GHIDRA_SHA256=99d45035bdcc3d6627e7b1232b7b379905a9fad76c772c920602e2b5d8b2dac2
# the pipe ends in `sha256sum -c -`, whose exit status already decides this step
# hadolint ignore=DL4006
RUN curl -fsSL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && chmod +x /opt/ghidra/support/analyzeHeadless

COPY server.py /opt/service/server.py
COPY security_index.py /opt/service/security_index.py
COPY export_json.py /opt/service/export_json.py

RUN mkdir -p /data/ghidra_projects \
    && useradd -u 65532 -m -d /home/ghidra -s /usr/sbin/nologin ghidra \
    && chown -R ghidra:ghidra /data/ghidra_projects /opt/service /home/ghidra

USER ghidra:ghidra
WORKDIR /opt/service

ENV GHIDRA_ANALYZE_HEADLESS=/opt/ghidra/support/analyzeHeadless
ENV GHIDRA_SCRIPT_DIR=/opt/service
ENV GHIDRA_DATA_DIR=/data/ghidra_projects
ENV ANALYSIS_TIMEOUT=3600
ENV PORT=9090

EXPOSE 9090

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=10 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9090/v1/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["python3", "/opt/service/server.py"]
