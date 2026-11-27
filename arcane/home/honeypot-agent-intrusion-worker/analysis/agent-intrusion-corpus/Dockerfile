FROM python:3.15-slim@sha256:63bb298d2b7b88f176f51b5189f54ce6535c997682ea70885d2132f5d473a8a5

LABEL maintainer="honeypot-stack"
LABEL description="#154 phase 5: correlates real sensor events into campaigns and scores them against deterministic criticality rules"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# decode_correlate.py/campaign_correlator.py/criticality_rules.py are the
# same, unmodified modules already proven against corpus.jsonl in CI (see
# tests/) -- this container runs the exact code that testing already
# covers, not a copy or a reimplementation.
COPY decode_correlate.py campaign_correlator.py criticality_rules.py worker.py ./

CMD ["python", "-u", "worker.py"]
