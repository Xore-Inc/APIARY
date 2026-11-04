FROM python:3.14-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

LABEL maintainer="honeypot-stack"
LABEL description="Knowledge-store vault-ingest worker (#1634 stage 2)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin vaultworker \
    && mkdir -p /vault && chown vaultworker:vaultworker /vault

COPY sanitize.py worker.py ./

USER 10002:10002

CMD ["python", "-u", "worker.py"]
