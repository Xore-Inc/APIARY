#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
stack_dir="${KEYCLOAK_STACK_DIR:-$(cd -- "${script_dir}/.." && pwd)}"
env_file="${KEYCLOAK_ENV_FILE:-${stack_dir}/.env}"

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
export RESTIC_HOST="${RESTIC_HOST:-apiary-homeserver}"

# The Postgres container is resolved, not taken from compose (#3596): the
# swarm task of keycloak_postgres first, the Compose hp-keycloak-postgres
# second. Neither running is an error, not an empty dump.
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

docker exec -i "${pg_ctr}" \
  pg_dump --username=keycloak --dbname=keycloak --format=custom --no-owner \
  | restic backup --stdin --stdin-filename keycloak.dump \
      --host "${RESTIC_HOST}" --tag keycloak-postgres

restic forget --tag keycloak-postgres \
  --keep-daily "${BACKUP_KEEP_DAILY:-7}" \
  --keep-weekly "${BACKUP_KEEP_WEEKLY:-4}" --prune
restic check --read-data-subset="${RESTIC_CHECK_SUBSET:-5%}"
