FROM python:3.15-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51

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
