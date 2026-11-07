FROM python:3.15-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51

LABEL maintainer="honeypot-stack"
LABEL description="Narrow, allowlisted Docker control adapter for the dashboard's Services pane (#197)"

WORKDIR /app
COPY services-adapter.py .

# Zero third-party dependencies (stdlib only) -- nothing to install.
# Runs as root: /var/run/docker.sock is root:docker-owned on the host, and
# this is the one component in the stack meant to hold that access (see the
# module docstring). cap_drop/no-new-privileges/read_only in
# docker-compose.yml bound what the *process itself* can do independent of
# what it can ask the daemon to do via the socket.
CMD ["python3", "-u", "services-adapter.py"]
