FROM python:3.14-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

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
