#!/usr/bin/env bash
# verify-deploy.sh -- #3315: prove mechanically that what is deployed is the
# code we think is deployed.
#
# The problem this closes, in the issue's own words: deploy verification was
# "manual inference -- compare `docker images` creation time with the merge
# time, or grep a string out of the shipped binary". docs/ARCANE-GIT-SYNC.md
# documents what that inference costs: apiary-backend:latest on the homeserver
# carried `Labels: null` and a creation time of 2026-09-08, every merge since
# was undeployed, and nothing surfaced it. "Green, healthy, running the old
# code" is indistinguishable from a good deploy by every signal the stack
# reports.
#
# Since #3315 there are three stamps, all from the same build arg (GIT_SHA):
#
#   backend-service  the revision is compiled into the binary by build.rs and
#                    answered by /healthz as {"revision": ...}
#   dashboard-next   the revision was baked into public/build.json (that
#                    image left with frontend-next in #3749; the production
#                    dashboard, Xore-Inc/apiary-dashboard, is pinned by
#                    digest in its own project)
#   the image        org.opencontainers.image.revision on the image config
#
# This script reads them and compares them against a git ref, so the question
# becomes "is the deployed revision the one I asked for?" instead of a reading
# of two timestamps. It also measures the lag -- commits behind, and the age of
# the deployed commit -- which is the number that says "this is fine, it is just
# three weeks old" or "this is not fine".
#
# Every comparison is a pure function over values already in hand (compare_
# revision, evaluate_lag) so the decisions can be tested without a live host,
# the same split scripts/arcane-verify-recreate.sh uses.
#
# Usage:
#   verify-deploy.sh [options] [<expected-sha>]
#
#   <expected-sha>       the revision that should be deployed. Defaults to
#                        origin/main in --repo-root.
#   --healthz-url URL    HTTP endpoint whose JSON body carries `revision`.
#   --healthz-exec CMD   command whose stdout is that same JSON. Needed for
#                        backend-service, whose /healthz is internal-only: the
#                        image publishes no port, so from the host it is only
#                        reachable with `docker exec`. Example:
#
#                          --healthz-exec 'docker exec hp-apiary-backend sh -c
#                            "curl -sf http://127.0.0.1:${LISTEN_ADDR##*:}/healthz"'
#
#                        (The `${LISTEN_ADDR##*:}` is the image's own HEALTHCHECK
#                        trick: the port is derived at check time, not
#                        hardcoded, because several stacks mount this image on
#                        a non-default LISTEN_ADDR.)
#   --image REF          also read REF's org.opencontainers.image.revision
#                        label, and compare it to the same expected revision.
#                        The image carrying one revision while the container
#                        running from it reports another is its own finding.
#   --repo-root DIR      clone to read origin/main from (default: cwd).
#   --behind-days N      report lag once the deployed commit is more than N
#                        days old (default 3; 0 disables the lag check).
#   --warn-only          print every finding, exit 0 anyway. For callers that
#                        report rather than gate (diagnostics.yml).
#   -h, --help           this header.
#
# Exit codes:
#   0  every stamp agrees with the expected revision, or --warn-only.
#   1  a stamp is missing, unstamped, disagrees, or is stale past --behind-days.
#   2  the check could not be run at all: bad usage, no origin/main to compare
#      against, or the healthz endpoint did not answer. Distinct from 1 on
#      purpose -- "we could not tell" must never be read as "it is fine".
#
# Environment overrides (also what scripts/tests stubs, mirroring the
# SYFT_BIN/TRIVY_BIN convention in generate-image-sbom.sh):
#   CURL_BIN, DOCKER_BIN, PYTHON_BIN, GIT_BIN
set -euo pipefail

readonly UNKNOWN="unknown"
readonly DEFAULT_BEHIND_DAYS=3

die() {
  echo "verify-deploy: $*" >&2
  exit 2
}

usage() {
  # Print this file's own leading comment block, minus the shebang: a help
  # text that drifts out of date with the code below it is worse than none.
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
}

# ---------------------------------------------------------------- pure ----

# Lowercase, and tolerate the two spellings the same object arrives in:
# `git rev-parse`'s bare name and the OCI spec's `sha256:`-prefixed one.
# A short name is kept short -- compare_revision decides prefix equivalence,
# which it can only do if the short form stays recognisable.
normalize_sha() {
  local raw=${1:-}
  raw=${raw#sha256:}
  printf '%s' "${raw,,}"
}

# Is this string a plausible git object name at all? Same 7-64 hex rule the
# two tiers apply to the value they stamp (backend-service's
# normalize_revision, frontend-next's normalizeRevision) -- one rule in three
# places is a smell, but a value that is not an object name must never be
# compared as if it were, and this is the place that decides.
is_object_name() {
  local candidate
  candidate=$(normalize_sha "${1:-}")
  [ ${#candidate} -ge 7 ] && [ ${#candidate} -le 64 ] &&
    [[ $candidate =~ ^[0-9a-f]+$ ]]
}

# compare_revision <observed> <expected> -- prints one verdict line, returns 0
# when the two agree.
#
# The prefix case is the common one and must not be a finding: `git rev-parse
# --short HEAD` and a full `github.sha` are the same commit, and an operator
# who set GIT_SHA from the short form would otherwise be told their deploy is
# wrong on every run.
compare_revision() {
  local observed expected short_len
  observed=$(normalize_sha "${1:-}")
  expected=$(normalize_sha "${2:-}")

  if [ -z "$observed" ] || [ "$observed" = "$UNKNOWN" ]; then
    echo "FAIL  not stamped: this build carries no revision, so nothing here can say which code is deployed"
    return 1
  fi
  if ! is_object_name "$observed"; then
    echo "FAIL  '$observed' is not a git object name -- the stamp is malformed, not merely stale"
    return 1
  fi
  if [ "$observed" = "$expected" ]; then
    echo "PASS  $observed matches the expected revision"
    return 0
  fi
  if is_object_name "$expected"; then
    # A short deployed name against a longer expected one. The length guards
    # are what keep this from accepting a truncated *prefix* of a different
    # commit: both names are already >= 7 hex chars, which is the shortest
    # unambiguous abbreviation, and 7 of 40 shared hex characters is a real
    # possibility, not a theoretical one.
    if [ ${#observed} -le ${#expected} ] && [ "${expected:0:${#observed}}" = "$observed" ]; then
      echo "PASS  $observed is an abbreviation of $expected"
      return 0
    fi
    if [ ${#expected} -le ${#observed} ] && [ "${observed:0:${#expected}}" = "$expected" ]; then
      echo "PASS  $expected is an abbreviation of $observed"
      return 0
    fi
  fi
  echo "FAIL  deployed $observed, expected $expected"
  return 1
}

# evaluate_lag <behind-count> <age-days> <behind-days-threshold> [subject]
#
# Only ever called once the deployed revision has been resolved to a real
# commit in the repo, so both numbers are measured rather than estimated. The
# age is of the *commit*, not of the container: an image rebuilt yesterday from
# a month-old revision is a month-old deploy, and reading its container creation
# time is the very inference this script exists to replace.
evaluate_lag() {
  local behind=$1 age=$2 threshold=$3 subject=${4:-deploy}
  [ "$threshold" -gt 0 ] || return 0
  if [ "$behind" -le 0 ]; then
    echo "PASS  $subject is at or ahead of the compared ref (0 commits behind)"
    return 0
  fi
  if [ "$age" -gt "$threshold" ]; then
    echo "FAIL  $subject is $behind commits behind and its commit is ${age}d old (threshold ${threshold}d) -- a merge has been sitting undeployed"
    return 1
  fi
  echo "WARN  $subject is $behind commits behind, commit ${age}d old (threshold ${threshold}d)"
  return 0
}

# ------------------------------------------------------------------ io ----

CURL_BIN=${CURL_BIN:-curl}
DOCKER_BIN=${DOCKER_BIN:-docker}
PYTHON_BIN=${PYTHON_BIN:-python3}
GIT_BIN=${GIT_BIN:-git}

# `safe.directory` on every git call rather than trusting the caller's config:
# the clone this is meant to read is usually owned by another user (the deploy
# runner's), and git refuses to operate on it otherwise -- the same reason
# diagnostics.yml passes it explicitly.
git_at() {
  local root=$1
  shift
  "$GIT_BIN" -c safe.directory="$root" -C "$root" "$@"
}

# Pull `revision` out of a JSON body. python3 rather than jq because every
# other script in this directory that needs JSON parsing (generate-image-sbom.sh)
# already depends on python3, while jq is not installed on the hosts these run
# on. Non-JSON and a missing key are both errors, not silent empties: this
# script's entire value is that its answer came from the field it names.
extract_revision() {
  "$PYTHON_BIN" -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except ValueError as error:
    sys.exit(f"not JSON ({error})")
if not isinstance(doc, dict) or "revision" not in doc:
    sys.exit("no 'revision' field in the response (keys: %s)" % (sorted(doc) if isinstance(doc, dict) else type(doc).__name__))
print(doc["revision"])
'
}

read_healthz_revision() {
  local url=$1 exec_cmd=$2 body
  if [ -n "$url" ]; then
    # -f so an HTTP error page cannot be parsed as a stamp; --max-time so an
    # endpoint behind a wedged network fails the check instead of hanging it.
    body=$("$CURL_BIN" -sf --max-time 10 "$url") ||
      die "could not read $url -- is the service up?"
  else
    # A command, deliberately, not a container name: reaching an internal-only
    # /healthz needs `docker exec` with the port derived from the container's own
    # LISTEN_ADDR, and hardcoding either half here would be wrong for every
    # stack that is not the default.
    # shellcheck disable=SC2086 # the caller's own quoting, passed through verbatim
    body=$(eval "$exec_cmd") ||
      die "the --healthz-exec command failed: $exec_cmd"
  fi
  [ -n "$body" ] || die "the healthz endpoint answered with an empty body"
  # A body that is not the JSON this script was promised is "we could not
  # tell", not "it disagrees" -- exit 2, never 1. Conflating them would make a
  # rewired or auth-gated endpoint look like a stale deploy.
  if ! printf '%s' "$body" | extract_revision; then
    die "could not read a 'revision' out of the healthz body (see the message above)"
  fi
}

read_image_revision() {
  local ref=$1
  "$DOCKER_BIN" image inspect --format \
    '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$ref" 2>/dev/null |
    head -1
}

# ---------------------------------------------------------------- main ----

main() {
  local healthz_url="" healthz_exec="" image="" repo_root="$PWD"
  local behind_days=$DEFAULT_BEHIND_DAYS warn_only=0 expected=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --healthz-url)
        healthz_url=${2:?--healthz-url needs a value}
        shift 2
        ;;
      --healthz-exec)
        healthz_exec=${2:?--healthz-exec needs a value}
        shift 2
        ;;
      --image)
        image=${2:?--image needs a value}
        shift 2
        ;;
      --repo-root)
        repo_root=${2:?--repo-root needs a value}
        shift 2
        ;;
      --behind-days)
        behind_days=${2:?--behind-days needs a value}
        shift 2
        ;;
      --warn-only)
        warn_only=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      -*) die "unknown option: $1 (try --help)" ;;
      *)
        [ -z "$expected" ] || die "only one expected revision may be given (got '$expected' and '$1')"
        expected=$1
        shift
        ;;
    esac
  done

  [ -n "$healthz_url" ] || [ -n "$healthz_exec" ] ||
    die "nothing to check: pass --healthz-url, --healthz-exec, or both (try --help)"
  [[ $behind_days =~ ^[0-9]+$ ]] || die "--behind-days wants a whole number of days, got '$behind_days'"
  [ -d "$repo_root" ] || die "--repo-root $repo_root is not a directory"
  command -v "$GIT_BIN" >/dev/null || die "git is required to resolve origin/main"
  command -v "$PYTHON_BIN" >/dev/null || die "python3 is required to read the JSON body"

  local failures=0 observed=""

  # What the deploy should be. An explicit argument wins; otherwise main. Either
  # way it has to resolve to a commit in *this* clone, because that is the only
  # thing the lag check can measure against.
  if [ -z "$expected" ]; then
    expected=$(git_at "$repo_root" rev-parse --verify --quiet origin/main) ||
      die "no origin/main in $repo_root -- run 'git -C $repo_root fetch origin main', or pass the expected revision explicitly"
  fi
  if ! is_object_name "$expected"; then
    die "'$expected' is not a git object name -- pass a revision, not a branch or a tag"
  fi
  local main_revision
  main_revision=$(git_at "$repo_root" rev-parse --verify --quiet origin/main 2>/dev/null || echo "")
  echo "INFO  expecting $expected${main_revision:+ (origin/main is $main_revision)}"

  # Read once. A second fetch could land after a redeploy and make the two
  # halves of this report describe different deploys, which is the one thing a
  # verification script must not do. `|| exit 2` rather than relying on
  # set -e: read_healthz_revision's die() runs in this command substitution's
  # subshell, and the "we could not tell" code has to survive that hop.
  observed=$(read_healthz_revision "$healthz_url" "$healthz_exec") || exit 2
  compare_revision "$observed" "$expected" || failures=$((failures + 1))

  if [ -n "$image" ]; then
    command -v "$DOCKER_BIN" >/dev/null ||
      die "docker is required for --image (or drop the flag to check only the endpoint)"
    local label
    label=$(read_image_revision "$image" || true)
    if [ -z "$label" ]; then
      # A missing image and an image with no labels are different facts, and
      # the second is the one this issue is about. Say which one this is.
      if "$DOCKER_BIN" image inspect "$image" >/dev/null 2>&1; then
        echo "FAIL  $image carries no org.opencontainers.image.revision label -- built without --build-arg GIT_SHA"
        failures=$((failures + 1))
      else
        die "no such image: $image"
      fi
    else
      compare_revision "$label" "$expected" || failures=$((failures + 1))
    fi
  fi

  # Lag, measured from the endpoint's revision. This is the number the issue
  # asks diagnostics to warn on, and it is the one an operator can act on
  # without a rollback: a deploy three weeks behind main is a scheduling fact,
  # not a broken image.
  if [ "$behind_days" -gt 0 ]; then
    local deployed_commit behind age_days commit_epoch now_epoch
    if deployed_commit=$(git_at "$repo_root" rev-parse --verify --quiet "${observed}^{commit}" 2>/dev/null); then
      behind=$(git_at "$repo_root" rev-list --count "${deployed_commit}..origin/main" 2>/dev/null || echo "")
      commit_epoch=$(git_at "$repo_root" log -1 --format=%ct "$deployed_commit" 2>/dev/null || echo "")
      now_epoch=$(date -u +%s)
      if [ -n "$behind" ] && [ -n "$commit_epoch" ]; then
        age_days=$(( (now_epoch - commit_epoch) / 86400 ))
        # A negative age means the deployed commit is dated in the future, which
        # is a clock problem, not a stale deploy. Report it as 0 rather than
        # letting a -3d read as "very stale".
        [ "$age_days" -ge 0 ] || age_days=0
        evaluate_lag "$behind" "$age_days" "$behind_days" "deployed revision" || failures=$((failures + 1))
      else
        echo "INFO  could not measure how far behind the deployed revision is (no rev-list/log for it in $repo_root)"
      fi
    else
      echo "WARN  deployed revision $observed is not in this clone -- cannot measure lag; fetch it, or compare by hand"
    fi
  fi

  if [ "$failures" -gt 0 ]; then
    if [ "$warn_only" -eq 1 ]; then
      echo "INFO  $failures finding(s) reported; --warn-only, so not failing the run"
      exit 0
    fi
    echo "FAIL  $failures finding(s): the deploy is not verifiably the expected revision"
    exit 1
  fi
  echo "PASS  every stamp checked agrees with $expected"
}

main "$@"
