FROM python:3.14-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

LABEL maintainer="honeypot-stack"
LABEL description="ML anomaly detection worker for the honeypot stack"

WORKDIR /app

# System deps for PyTorch (CPU-only) and scipy
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user
RUN useradd -r -s /bin/false mlworker

# Model persistence volume -- created and chowned to mlworker BEFORE the
# volume mount happens, so a *fresh* named volume inherits writable
# ownership from the image instead of defaulting to root:root (a fresh
# volume on first mount copies in whatever the image already has at that
# path). Without this, the container's own cap_drop: [ALL] means not even
# `docker exec --user root` can chown it after the fact -- discovered when
# save_buffers() (#170) hit this on every cycle; retrain()'s _save() would
# have hit the identical error the first time a retrain fired (#65).
RUN mkdir -p /models && chown mlworker:mlworker /models
VOLUME ["/models"]

USER mlworker

CMD ["python", "-u", "worker.py"]
