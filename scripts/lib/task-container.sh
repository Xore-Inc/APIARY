# task-container.sh: find the running container of a service that may be a
# swarm task or a Compose container (#3596, swarm phase 9).
#
# A Compose service keeps its `container_name:` (hp-keycloak-postgres). After
# it moves to a swarm stack, its container is a task named
# <stack>_<service>.<slot>.<task id>, and the Compose container is kept,
# stopped, as the rollback. Host tools that `docker exec` a fixed name then
# miss the running service, and until this helper the backup scripts logged
# "not running" and carried on without the identity dump.
#
# POSIX sh (backup-honeypot.sh runs under dash), no bashisms. Source it, then:
#
#   task_container SWARM_SERVICE COMPOSE_NAME
#
# prints the name of the one running container and returns 0. The swarm task
# (label com.docker.swarm.service.name=SWARM_SERVICE) is looked up first, the
# Compose container_name second, so a rollback to Compose keeps working with
# no change here. It prints a reason on stderr and returns
#   1 when neither is running,
#   2 when more than one is (two writers on one data directory, or a task
#     still being replaced: a caller must not pick one).
# Only this node's containers are seen (`docker ps`), which is where the
# homeserver-pinned stacks run.

task_container() {
    if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
        echo "task_container: usage: task_container SWARM_SERVICE COMPOSE_NAME" >&2
        return 2
    fi
    _tc_names=$(
        docker ps --filter "label=com.docker.swarm.service.name=$1" --filter status=running \
            --format '{{.Names}}' 2>/dev/null
        docker ps --filter "name=^$2\$" --filter status=running --format '{{.Names}}' 2>/dev/null
    ) || true
    _tc_count=$(printf '%s\n' "$_tc_names" | grep -c . || true)
    case $_tc_count in
        1)
            printf '%s\n' "$_tc_names" | grep .
            return 0
            ;;
        0)
            echo "task_container: neither swarm service $1 nor container $2 is running on this node" >&2
            return 1
            ;;
        *)
            echo "task_container: $_tc_count running containers for $1/$2 ($(printf '%s' "$_tc_names" | tr '\n' ' ')); refusing to pick one" >&2
            return 2
            ;;
    esac
}
