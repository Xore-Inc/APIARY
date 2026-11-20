#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
stack_dir="${KEYCLOAK_STACK_DIR:-$(cd -- "${script_dir}/.." && pwd)}"
env_file="${KEYCLOAK_ENV_FILE:-${stack_dir}/.env}"
compose_file="${KEYCLOAK_COMPOSE_FILE:-${stack_dir}/compose.yml}"
snapshot="${1:-latest}"

if [[ "${KEYCLOAK_RESTORE_CONFIRM:-}" != "restore-keycloak-database" ]]; then
  printf '%s\n' 'Refusing destructive restore.' >&2
  printf '%s\n' 'Set KEYCLOAK_RESTORE_CONFIRM=restore-keycloak-database and retry.' >&2
  exit 1
fi

[[ -f "${env_file}" ]] || { printf 'Missing environment file: %s\n' "${env_file}" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

: "${RESTIC_REPOSITORY:?set RESTIC_REPOSITORY in the Dockge environment file}"
: "${RESTIC_PASSWORD_FILE:?set RESTIC_PASSWORD_FILE in the Dockge environment file}"
command -v docker >/dev/null || { printf 'docker is required\n' >&2; exit 1; }
command -v restic >/dev/null || { printf 'restic is required\n' >&2; exit 1; }

export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE

# Keycloak may be the swarm service keycloak_keycloak or the Compose
# container (#3596). Stop whichever one runs, restore into whichever
# Postgres runs (task_container), then start the same Keycloak again.
# The helper lives in the repo's scripts/lib: found from a checkout, or from
# the homeserver's repo tree when this runs from the deployed stack copy.
task_container_lib="${TASK_CONTAINER_LIB:-}"
for candidate in "${script_dir}/../../../../scripts/lib/task-container.sh" /opt/stacks/apiary/scripts/lib/task-container.sh; do
  [[ -n "${task_container_lib}" ]] && break
  [[ -r "${candidate}" ]] && task_container_lib="${candidate}"
done
[[ -r "${task_container_lib}" ]] || { printf 'scripts/lib/task-container.sh not found; set TASK_CONTAINER_LIB\n' >&2; exit 1; }
# shellcheck disable=SC1090
source "${task_container_lib}"
pg_ctr="$(task_container keycloak_postgres hp-keycloak-postgres)"

if docker service inspect keycloak_keycloak >/dev/null 2>&1; then
  kc_replicas="$(docker service inspect keycloak_keycloak --format '{{.Spec.Mode.Replicated.Replicas}}')"
  docker service scale --detach=false keycloak_keycloak=0
  start_keycloak() { docker service scale --detach=false "keycloak_keycloak=${kc_replicas:-1}"; }
else
  docker compose --env-file "${env_file}" -f "${compose_file}" stop keycloak
  start_keycloak() { docker compose --env-file "${env_file}" -f "${compose_file}" start keycloak; }
fi
restic dump "${snapshot}" keycloak.dump \
  | docker exec -i "${pg_ctr}" \
      pg_restore --username=keycloak --dbname=keycloak --clean --if-exists \
        --no-owner --single-transaction
start_keycloak
