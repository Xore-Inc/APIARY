FROM python:3.14-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

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
