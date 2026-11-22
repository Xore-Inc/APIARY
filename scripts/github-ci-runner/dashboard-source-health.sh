#!/usr/bin/env bash
# Installed root:root 0755 at /opt/github-ci-runner-helpers/ by
# install-deploy-runner.sh and run via its NOPASSWD sudoers grant (#3312).
#
# Diagnostics' pipeline section needs backend-service's source-health, which
# requires the dashboard's service token. That token lives in the dashboard
# stack's .env (root:root 0600 inside a 0700 dir), which github-deploy-runner
# cannot read -- and should not: the token authenticates as the service tier.
# This helper reads it as root and returns only the source-health JSON; the
# token never reaches the runner's environment, argv or logs. It takes no
# arguments on purpose, so the grant cannot aim the token at another host.
set -euo pipefail

# #3749: this used to go through dashboard-next's /bff passthrough on 19090.
# That frontend is gone, so the helper asks the backend itself: the token comes
# from the backend stack's own .env, and the request runs inside the backend
# container (it publishes no port), with the header on curl's stdin.
env_file=/var/dockge/stacks/honeypot-dashboard-backend/.env
container=hp-apiary-backend
token=$(sed -n 's/^DASHBOARD_SERVICE_TOKEN=//p' "$env_file" 2>/dev/null | head -1)
if [ -z "$token" ]; then
  echo "no DASHBOARD_SERVICE_TOKEN in $env_file" >&2
  exit 2
fi

# Header via curl's stdin config, not -H, so the token is not visible in
# the process list (host or container) while the request runs.
printf 'header = "X-Service-Token: %s"\n' "$token" \
  | docker exec -i "$container" sh -c \
      'curl -fsS --max-time 15 -K - "http://127.0.0.1:${LISTEN_ADDR##*:}/api/v1/source-health"'
