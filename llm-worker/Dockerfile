FROM python:3.14-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

LABEL maintainer="honeypot-stack"
LABEL description="Guarded local LLM analysis worker"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin llmworker

COPY contracts.py injection_suite.py injection_corpus.jsonl worker.py ./

USER 10001:10001

CMD ["python", "-u", "worker.py"]
