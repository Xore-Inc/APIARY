FROM python:3.15-slim@sha256:63bb298d2b7b88f176f51b5189f54ce6535c997682ea70885d2132f5d473a8a5

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
# Health: the adapter is healthy when its control socket answers a real
# /v1/services request with 200. That route calls the Docker Engine through
# docker.sock, so it also proves the adapter can still reach the daemon it
# exists to proxy. Stdlib only, exec form, no shell, no writes (read_only).
HEALTHCHECK --interval=30s --timeout=6s --start-period=10s --retries=3 \
  CMD ["python3", "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5); s.connect('/run/services-adapter/control.sock'); s.sendall(b'GET /v1/services HTTP/1.0\\r\\nHost: services-adapter\\r\\n\\r\\n'); sys.exit(0 if s.recv(12).startswith(b'HTTP/1.0 200') else 1)"]

CMD ["python3", "-u", "services-adapter.py"]
