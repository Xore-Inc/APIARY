FROM python:3.15-slim@sha256:63bb298d2b7b88f176f51b5189f54ce6535c997682ea70885d2132f5d473a8a5

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
