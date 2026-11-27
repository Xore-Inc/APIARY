FROM python:3.15-slim@sha256:63bb298d2b7b88f176f51b5189f54ce6535c997682ea70885d2132f5d473a8a5

LABEL maintainer="honeypot-stack"
LABEL description="Ships Ghidra/sandbox/GitHub-analysis/workbench-run results into Elasticsearch (#378)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY importer.py .

# No USER here -- runs as the uid the compose service sets (root, via
# cap_add: DAC_READ_SEARCH, same as the dashboard and yara-scanner services:
# the Ghidra/GitHub-analysis result directories are root-owned host bind
# mounts this container otherwise can't read).
VOLUME ["/state-importer"]

CMD ["python", "-u", "importer.py"]
