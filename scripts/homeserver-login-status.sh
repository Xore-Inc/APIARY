#!/usr/bin/env bash
set -uo pipefail

# Interactive homeserver status overview. Individual checks are deliberately
# bounded so a failed remote mount or service cannot stall shell login.

if [[ ! -t 1 ]]; then
  exit 0
fi

disable_file=${HOME}/.config/homeserver-login-menu.disabled
if [[ -e "$disable_file" ]]; then
  exit 0
fi

if [[ -t 1 ]]; then
  bold=$'\e[1m'
  green=$'\e[32m'
  yellow=$'\e[33m'
  red=$'\e[31m'
  reset=$'\e[0m'
else
  bold=
  green=
  yellow=
  red=
  reset=
fi

section() {
  printf '\n%s%s== %s ==%s\n' "$bold" "$green" "$1" "$reset"
}

unit_status() {
  local unit=$1
  local state
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  case "$state" in
    active) printf '%-52s %s%s%s\n' "$unit" "$green" "$state" "$reset" ;;
    activating) printf '%-52s %s%s%s\n' "$unit" "$yellow" "$state" "$reset" ;;
    *) printf '%-52s %s%s%s\n' "$unit" "$red" "${state:-unknown}" "$reset" ;;
  esac
}

http_status() {
  local name=$1
  local url=$2
  local result
  result=$(timeout 6 curl --silent --show-error --output /dev/null \
    --write-out '%{http_code} %{time_total}s' "$url" 2>/dev/null || true)
  if [[ "$result" =~ ^(200|204|301|302|401|403)[[:space:]] ]]; then
    printf '%-18s %s%-14s%s %s\n' "$name" "$green" "$result" "$reset" "$url"
  else
    printf '%-18s %s%-14s%s %s\n' "$name" "$red" "${result:-unreachable}" \
      "$reset" "$url"
  fi
}

clear
if command -v fastfetch >/dev/null 2>&1; then
  fastfetch
else
  printf '%sfastfetch is not installed%s\n' "$yellow" "$reset"
fi

section "Host resources"
uptime
free --human
df --human-readable --output=source,size,used,avail,pcent,target / /var \
  2>/dev/null | awk '!seen[$0]++'

section "GPU"
if command -v nvidia-smi >/dev/null 2>&1; then
  timeout 8 nvidia-smi \
    --query-gpu=name,driver_version,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw \
    --format=csv,noheader
else
  printf '%sNVIDIA utilities unavailable%s\n' "$yellow" "$reset"
fi

section "Network and boot-critical services"
ip -brief -4 address show ens9f0 2>/dev/null || true
ip -brief -4 address show eno2 2>/dev/null || true
ip -brief -4 address show wg0 2>/dev/null || true
ip -4 route show default
unit_status systemd-networkd-wait-online.service
unit_status wg-quick@wg0.service
unit_status docker.service
unit_status honeypot-log-mounts.service
unit_status 'var-dockge-stacks-honeypot\x2dstack-logs-suricata.mount'
unit_status 'var-dockge-stacks-honeypot\x2dstack-logs-portbridge.mount'
if timeout 4 ping -c 1 -W 2 10.8.0.1 >/dev/null 2>&1; then
  printf '%-52s %sreachable%s\n' 'WireGuard peer 10.8.0.1' "$green" "$reset"
else
  printf '%-52s %sunreachable%s\n' 'WireGuard peer 10.8.0.1' "$red" "$reset"
fi

section "Docker containers"
if timeout 6 docker info >/dev/null 2>&1; then
  docker ps --all \
    --format 'table {{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}'
else
  printf '%sDocker daemon unavailable or permission denied%s\n' "$red" "$reset"
fi

section "Web service health"
http_status Dockge http://127.0.0.1:5001/
http_status Dashboard http://10.8.0.2:19092/healthz
http_status EveBox http://10.8.0.2:19636/
http_status Kibana http://10.8.0.2:19601/api/status
http_status Arkime http://10.8.0.2:19080/

section "Ingestion freshness"
for source_file in \
  /opt/stacks/apiary/logs/suricata/eve.json \
  /opt/stacks/apiary/logs/portbridge/portbridge.json; do
  if [[ -e "$source_file" ]]; then
    stat --format='%y  %s bytes  %n' "$source_file"
  else
    printf '%sMISSING%s %s\n' "$red" "$reset" "$source_file"
  fi
done

section "Failed systemd units"
failed_units=$(systemctl --failed --no-legend --plain 2>/dev/null || true)
if [[ -n "$failed_units" ]]; then
  printf '%s%s%s\n' "$red" "$failed_units" "$reset"
else
  printf '%snone%s\n' "$green" "$reset"
fi

printf '\n'

confirm() {
  local prompt=$1
  local answer
  read -r -p "$prompt [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

compose_stack() {
  docker compose \
    --project-directory /opt/stacks/apiary \
    --file /opt/stacks/apiary/compose.yml \
    "$@"
}

deploy_latest_main() {
  local deploy_dir

  printf '%s\n' \
    'This downloads the latest origin/main, synchronizes repository-owned' \
    'files into the Dockge stack, preserves runtime data and .env, validates' \
    'Compose, and rebuilds/recreates changed services.'
  confirm 'Deploy latest main to the homeserver?' || return 0

  deploy_dir=$(mktemp -d /tmp/honeypot-deploy.XXXXXXXX)
  if [[ ! -d "$deploy_dir" || "$deploy_dir" != /tmp/honeypot-deploy.* ]]; then
    printf '%sRefusing unsafe temporary directory: %s%s\n' \
      "$red" "$deploy_dir" "$reset" >&2
    return 1
  fi

  if ! git clone --quiet --depth 1 --branch main \
    https://github.com/Xore/APIARY.git "$deploy_dir"; then
    rm -rf -- "$deploy_dir"
    return 1
  fi

  if ! rsync -a --delete-delay \
    --exclude '.git/' --exclude '.github/' --exclude '.env' \
    --exclude 'logs/' --exclude 'state/' --exclude 'dashboard-state/' \
    --exclude 'analysis/geoip/*.mmdb' --exclude 'sandbox/results/' \
    "$deploy_dir/" /opt/stacks/apiary/; then
    printf '%srsync failed, not touching compose.yml or recreating containers%s\n' "$red" "$reset" >&2
    rm -rf -- "$deploy_dir"
    return 1
  fi
  rm -rf -- "$deploy_dir"

  cp /opt/stacks/apiary/docker-compose.yml \
    /opt/stacks/apiary/compose.yml &&
  compose_stack config --quiet &&
  compose_stack up --detach --build --remove-orphans
}

show_admin_menu() {
  local choice

  while true; do
    printf '%s%s== Admin menu ==%s\n' "$bold" "$green" "$reset"
    cat <<'EOF'
  1) Refresh this health dashboard
  2) Deploy latest GitHub main and recreate changed containers
  3) Rebuild and recreate the current home stack
  4) Pull upstream images and recreate the current home stack
  5) Restart EveBox and Filebeat
  6) Recover WireGuard log mounts
  7) Show recent home-stack logs
  8) Show failed and unhealthy containers
  9) Reboot the homeserver
  d) Disable this dashboard/menu on future logins
  q) Close menu and return to the normal shell
EOF
    read -r -p 'Select an action [q]: ' choice
    case "${choice:-q}" in
      1)
        exec "$0"
        ;;
      2)
        deploy_latest_main
        ;;
      3)
        if confirm 'Rebuild and recreate the current home stack?'; then
          compose_stack config --quiet &&
            compose_stack up --detach --build --force-recreate
        fi
        ;;
      4)
        if confirm 'Pull images and recreate the current home stack?'; then
          compose_stack pull --ignore-buildable &&
            compose_stack config --quiet &&
            compose_stack up --detach --build
        fi
        ;;
      5)
        if confirm 'Restart EveBox and Filebeat?'; then
          docker restart hp-evebox hp-filebeat
        fi
        ;;
      6)
        if confirm 'Restart the privileged log-mount recovery service?'; then
          sudo systemctl restart honeypot-log-mounts.service &&
            systemctl --no-pager --full status honeypot-log-mounts.service
        fi
        ;;
      7)
        compose_stack logs --tail 100
        ;;
      8)
        printf '%sUnhealthy running containers%s\n' "$bold" "$reset"
        docker ps --filter health=unhealthy \
          --format 'table {{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}'
        printf '\n%sStopped containers%s\n' "$bold" "$reset"
        docker ps --all --filter status=dead --filter status=exited \
          --format 'table {{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}'
        ;;
      9)
        if confirm 'Reboot the homeserver now?'; then
          sudo systemctl reboot
          return
        fi
        ;;
      d|D)
        if confirm 'Disable the automatic login dashboard and menu?'; then
          install -d -m 0755 "${HOME}/.config"
          touch "$disable_file"
          printf 'Disabled. Re-enable with:\n  rm %q\n' "$disable_file"
          return
        fi
        ;;
      q|Q)
        printf 'Menu closed. Normal shell is ready.\n'
        return
        ;;
      *)
        printf '%sUnknown selection: %s%s\n' "$yellow" "$choice" "$reset"
        ;;
    esac
    printf '\n'
  done
}

show_admin_menu
