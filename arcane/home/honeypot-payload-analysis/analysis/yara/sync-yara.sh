#!/usr/bin/env bash
# sync-yara.sh — vendor the upstream YARA corpus into this scanner.
#
# Fetches yara-rules/*.yar and yara-rules/auto/*.yar from Xore/Honeypot,
# compiles them before adopting them, and pins the upstream commit in
# rules/upstream.lock: vendor, pin, and let CI enforce that the tree still
# matches the pin.
#
# WHY VENDOR INSTEAD OF PULLING ON A TIMER
#
# The scanner sidecar runs network_mode: none, read_only: true, with rules
# baked in at image build (analysis/yara/Dockerfile COPYs this directory). It
# cannot fetch anything, and giving a container that reads live malware a
# network so it can download rule files is a much worse trade than syncing at
# the repository level. So the sync happens here, in a checkout, by an operator
# or a scheduled job — and the corpus that reaches the scanner is the one
# recorded in the lock file.
#
# WHY COMPILATION IS THE GATE
#
# yara(1) loads a rule set or refuses to start. A corpus with one broken rule
# does not degrade to "everything except that rule" — it disables scanning
# entirely, and the scanner's own startup probe is the only thing that would
# ever notice. Validating here means a bad upstream commit is a failed sync
# with a message, instead of a sidecar that has quietly stopped detecting.
#
# Note: the plan text says `yara --compile`, which is not a real flag. yarac(1)
# is the compiler; `yara <rules> <file>` compiles and then scans. Either proves
# the corpus compiles, and both are accepted below.
#
# Usage:
#   analysis/yara/sync-yara.sh [--ref <git-ref>] [--dry-run]
#
# Env:
#   YARA_UPSTREAM_REPO  default https://github.com/Xore/Honeypot
#   YARA_UPSTREAM_REF   default main

set -euo pipefail

REPO_URL="${YARA_UPSTREAM_REPO:-https://github.com/Xore/Honeypot}"
REF="${YARA_UPSTREAM_REF:-main}"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rules="$root/analysis/yara/rules"
local_rules="$rules/honeypot.yar"
dest="$rules/upstream"
index="$rules/index.yar"
lock="$rules/upstream.lock"

[ -f "$local_rules" ] || { echo "missing $local_rules" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

# Pick a compiler. Without one there is no validation, and a sync that cannot
# validate is exactly the thing this script exists to prevent.
compile() {
  if command -v yarac >/dev/null 2>&1; then
    yarac -w "$1" /dev/null
  else
    # Compiles the rules, then scans an empty file: a compile error is a
    # non-zero exit, a scan that matches nothing is exit 0.
    yara -w "$1" /dev/null >/dev/null
  fi
}
if ! command -v yarac >/dev/null 2>&1 && ! command -v yara >/dev/null 2>&1; then
  echo "neither yarac nor yara is installed - cannot validate, refusing to sync" >&2
  echo "  Debian/Ubuntu: sudo apt-get install -y yara" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ── 1. Fetch a pinned commit ─────────────────────────────────────────────────
echo "fetching $REPO_URL @ $REF"
git clone --quiet --depth 1 --branch "$REF" "$REPO_URL" "$tmp/src" 2>/dev/null ||
  git clone --quiet --depth 1 "$REPO_URL" "$tmp/src"
commit="$(git -C "$tmp/src" rev-parse HEAD)"
commit_date="$(git -C "$tmp/src" log -1 --format=%cI)"
src="$tmp/src/yara-rules"
[ -d "$src" ] || { echo "$REPO_URL@$REF has no yara-rules/ directory" >&2; exit 1; }

# ── 2. Stage a complete rules tree ───────────────────────────────────────────
# The staged tree has the same layout as the live one so the combined compile
# below exercises the include paths the scanner will actually use. Nothing
# under $rules is touched until every check has passed.
stage="$tmp/rules"
mkdir -p "$stage/upstream/auto"
cp "$local_rules" "$stage/honeypot.yar"

staged=()
for file in "$src"/*.yar; do
  [ -e "$file" ] || continue
  cp "$file" "$stage/upstream/$(basename "$file")"
  staged+=("upstream/$(basename "$file")")
done
for file in "$src"/auto/*.yar; do
  [ -e "$file" ] || continue
  cp "$file" "$stage/upstream/auto/$(basename "$file")"
  staged+=("upstream/auto/$(basename "$file")")
done
[ ${#staged[@]} -gt 0 ] || { echo "upstream has no .yar files - refusing to wipe the corpus" >&2; exit 1; }

# Deterministic order: what gets dropped on a name collision must not depend on
# the order the filesystem happened to return.
mapfile -t staged < <(printf '%s\n' "${staged[@]}" | sort)

rule_names() {
  grep -hoE '^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)*rule[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$1" |
    awk '{print $NF}'
}

# ── 3. Validate each file, and resolve rule-name collisions ──────────────────
# Two independent ways an upstream file can poison the whole corpus: it fails to
# compile on its own, or it redefines a rule identifier another file already
# used. YARA treats a duplicate identifier as a hard error, so upstream/auto/
# colliding with a curated rule would take the entire scanner down.
declare -A seen=()
while read -r name; do seen["$name"]=honeypot.yar; done < <(rule_names "$stage/honeypot.yar")

accepted=()
dropped=()
for rel in "${staged[@]}"; do
  path="$stage/$rel"
  # Carry yara's own message through. "does not compile" alone leaves an
  # operator with nothing to send upstream; the first error line names the rule
  # and the line number.
  if ! error="$(compile "$path" 2>&1 >/dev/null)"; then
    reason="$(printf '%s\n' "$error" | grep -m1 . | sed -e 's/^error: //' -e "s|$stage/||")"
    dropped+=("$rel (does not compile: ${reason:-unknown error})")
    rm -f "$path"
    continue
  fi
  collision=""
  while read -r name; do
    [ -n "$name" ] || continue
    if [ -n "${seen[$name]:-}" ]; then collision="$name (already in ${seen[$name]})"; break; fi
  done < <(rule_names "$path")
  if [ -n "$collision" ]; then
    dropped+=("$rel (duplicate rule $collision)")
    rm -f "$path"
    continue
  fi
  while read -r name; do [ -n "$name" ] && seen["$name"]="$rel"; done < <(rule_names "$path")
  accepted+=("$rel")
done

[ ${#accepted[@]} -gt 0 ] || { echo "every upstream file was rejected - not adopting" >&2; exit 1; }

# ── 4. Generate the include index ────────────────────────────────────────────
# The scanner loads one file. Local rules come first so a reader of index.yar
# can see that upstream is additive and never replaces them.
{
  echo "// Generated by analysis/yara/sync-yara.sh - do not edit."
  echo "// Local rules first; upstream/ is vendored and pinned in upstream.lock."
  echo 'include "honeypot.yar"'
  for rel in "${accepted[@]}"; do echo "include \"$rel\""; done
} > "$stage/index.yar"

# ── 5. Compile the corpus as the scanner will load it ────────────────────────
# Per-file compilation above does not prove the combination compiles, which is
# the only thing the scanner cares about.
if ! compile "$stage/index.yar"; then
  echo "the combined corpus does not compile - not adopting" >&2
  exit 1
fi
echo "combined corpus compiles: 1 local + ${#accepted[@]} upstream file(s)"

# Rule names defined under upstream/auto/. Auto-generated rules are broad by
# construction and an operator must be able to tell an auto hit from a curated
# detection; this list is what lets a consumer do that without re-parsing the
# corpus.
: > "$stage/upstream/AUTO_RULES"
for rel in "${accepted[@]}"; do
  case "$rel" in upstream/auto/*) rule_names "$stage/$rel" >> "$stage/upstream/AUTO_RULES" ;; esac
done
sort -o "$stage/upstream/AUTO_RULES" "$stage/upstream/AUTO_RULES"

# What upstream ships that this corpus does not, and why. Kept in the tree
# rather than only on the terminal of whoever last ran the sync: a rule file
# that silently stopped being vendored is otherwise invisible in review, and
# the gap between files= and upstream_files= in the lock says how many but not
# which. Empty when the whole upstream corpus was adopted.
: > "$stage/upstream/DROPPED"
if [ ${#dropped[@]} -gt 0 ]; then
  printf '%s\n' "${dropped[@]}" | sort > "$stage/upstream/DROPPED"
fi

if [ "$DRY_RUN" = 1 ]; then
  echo "dry run: not writing $dest"
  [ ${#dropped[@]} -eq 0 ] || printf 'would drop: %s\n' "${dropped[@]}"
  exit 0
fi

# ── 6. Adopt ─────────────────────────────────────────────────────────────────
rm -rf "$dest"
mv "$stage/upstream" "$dest"
mv "$stage/index.yar" "$index"

# Built outside $dest and moved in: redirecting into $dest/MANIFEST would create
# the file before find(1) walked the tree, so the manifest would list itself
# with the hash of the empty file it was at that instant.
( cd "$rules" && find upstream -type f ! -name MANIFEST | sort | xargs -r sha256sum ) > "$tmp/MANIFEST"
mv "$tmp/MANIFEST" "$dest/MANIFEST"
manifest_sha="$(sha256sum "$dest/MANIFEST" | cut -d' ' -f1)"

cat > "$lock" <<EOF
# Vendored upstream YARA corpus. Written by analysis/yara/sync-yara.sh,
# enforced by scripts/check-yara-corpus.sh. analysis/yara/rules/upstream/ must
# stay byte-identical to yara-rules/ at this commit, minus any file dropped for
# failing to compile or redefining a rule name (see files= vs upstream_files=).
repository=$REPO_URL
ref=$REF
commit=$commit
commit_date=$commit_date
files=${#accepted[@]}
upstream_files=${#staged[@]}
manifest_sha256=$manifest_sha
EOF

echo "vendored ${#accepted[@]} file(s) into ${dest#"$root"/} @ ${commit:0:7}"
if [ ${#dropped[@]} -gt 0 ]; then
  printf 'dropped: %s\n' "${dropped[@]}"
  echo "Dropped files are recorded only here. Re-run after upstream fixes them." >&2
fi
echo "rebuild the sidecar to load it: docker compose build yara-scanner && docker compose up -d yara-scanner"
