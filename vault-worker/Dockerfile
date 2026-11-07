FROM python:3.15-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51

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
