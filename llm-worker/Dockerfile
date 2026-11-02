FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913

LABEL maintainer="honeypot-stack"
LABEL description="Guarded local LLM analysis worker"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin llmworker

COPY contracts.py injection_suite.py injection_corpus.jsonl worker.py ./

USER 10001:10001

CMD ["python", "-u", "worker.py"]
