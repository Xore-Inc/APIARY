#!/usr/bin/env bash
# generate-image-sbom.sh -- write a CycloneDX SBOM for one digest-pinned
# image, and optionally leave a copy on the homeserver next to the image.
# #3321.
#
# The problem this closes: there was no inventory of what is inside
# apiary-backend, so answering "are we affected?" when a
# CVE lands meant rebuilding the image or exec-ing into the running
# container. The build already produces the answer and then throws it away;
# this keeps it.
#
# "Keyed by image digest" is enforced, not decorative:
#
#   * the reference must already carry an `@sha256:` pin. An SBOM generated
#     from a tag is a description of whatever that tag pointed at when syft
#     ran, which is not the thing the scan is about;
#   * the digest is stamped into the document itself (CycloneDX properties on
#     metadata.component). syft records only name + tag there -- verified
#     against syft 1.52.0's own cyclonedx-json output -- so a bare syft file
#     cannot be traced back to the image it describes;
#   * the copy kept on the homeserver is named for its digest.
#
# One generator for both callers, deliberately: the CI path and the
# homeserver path must not be able to disagree about what an SBOM in
# /var/image-sbom claims to be. Provenance attestation (cosign / buildx
# --provenance) is deliberately out of scope; the issue tracks it as a
# follow-up and an SBOM is not a signature.
#
# Usage:
#   generate-image-sbom.sh --image <repo[:tag]@sha256:...> --out <file.json>
#                          [--name <image-name>] [--publish-dir <dir>]
#
#   --publish-dir   when given, also write
#                   <dir>/<name>/<hex-digest>.sbom.json   (the record)
#                   <dir>/<name>/latest.sbom.json         (what ops reads)
#                   Directory is created if absent; an unwritable one is a
#                   warning, not a failure, so an unprovisioned homeserver
#                   degrades to "CI artifact only" instead of redding the
#                   required Containers gate.
#
# Emits sbom_path / sbom_ref / sbom_digest / sbom_digest_hex to
# $GITHUB_OUTPUT when running under Actions.
#
# Overrides: SYFT_BIN (use this syft instead of installing one -- the
# scripts/tests stub relies on it), SYFT_VERSION, SYFT_SHA256, SYFT_BIN_DIR.
set -euo pipefail

# The pin, same discipline as scripts/install-trivy.sh and every other
# tool fetch in this repo (actionlint, zizmor, hadolint, rustup): versioned
# archive, sha256 verified before extraction, never curl|sh.
# syft_1.52.0_linux_amd64.tar.gz, sha256 taken from the release artefact.
readonly PINNED_SYFT_VERSION=1.52.0
readonly PINNED_SYFT_SHA256=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d

die() {
  echo "generate-image-sbom: $*" >&2
  exit 1
}

image=""
out=""
name=""
publish_dir=""

while [ $# -gt 0 ]; do
  case "$1" in
    --image)
      image=${2:?--image needs a value}
      shift 2
      ;;
    --out)
      out=${2:?--out needs a value}
      shift 2
      ;;
    --name)
      name=${2:?--name needs a value}
      shift 2
      ;;
    --publish-dir)
      publish_dir=${2:?--publish-dir needs a value}
      shift 2
      ;;
    -h | --help)
      # Print this file's own leading comment block: a help text that drifts
      # out of date with the code above it is worse than no help text.
      awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$image" ] || die "--image is required"
[ -n "$out" ] || die "--out is required"

# Digest pinning is the contract. Fail before doing any work rather than
# writing an inventory nobody can tie back to an image.
case "$image" in
  *@sha256:*) ;;
  *) die "--image must be pinned by digest (repo[:tag]@sha256:...), got: $image" ;;
esac
digest=${image##*@}
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "--image carries a malformed digest: $digest"
digest_hex=${digest#sha256:}

# ---------------------------------------------------------------- syft ----

syft_version=${SYFT_VERSION:-$PINNED_SYFT_VERSION}
syft_checksum=${SYFT_SHA256:-}
if [ -z "$syft_checksum" ]; then
  if [ "$syft_version" != "$PINNED_SYFT_VERSION" ]; then
    die "SYFT_VERSION=$syft_version has no pinned sha256 in this script; set SYFT_SHA256 or update the pin"
  fi
  syft_checksum=$PINNED_SYFT_SHA256
fi
syft_asset="syft_${syft_version}_linux_amd64.tar.gz"

# Resolve the syft to use, into SYFT_RESOLVED. Not a command substitution on
# purpose: a `die` inside `$(...)` would exit the subshell and leave the
# parent with an empty tool path instead of stopping.
#
# An explicit SYFT_BIN wins outright and is trusted as given -- a caller that
# supplies one (the scripts/tests stub, an operator with an internal mirror)
# has already decided which build inventories the image. The version check
# below guards the *download*; there is nothing to police in an explicit
# choice.
SYFT_PINNED=0
resolve_syft() {
  if [ -n "${SYFT_BIN:-}" ]; then
    [ -x "$SYFT_BIN" ] || die "SYFT_BIN=$SYFT_BIN is not executable"
    SYFT_RESOLVED=$SYFT_BIN
    return 0
  fi

  SYFT_PINNED=1
  bindir=${SYFT_BIN_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/syft-bin}
  bin=$bindir/syft
  if [ -x "$bin" ] && "$bin" --version 2>/dev/null | grep -qx "syft $syft_version"; then
    SYFT_RESOLVED=$bin
    return 0
  fi
  work=$(mktemp -d)
  curl -sfL -o "$work/$syft_asset" \
    "https://github.com/anchore/syft/releases/download/v${syft_version}/${syft_asset}"
  echo "${syft_checksum}  ${work}/${syft_asset}" | sha256sum -c -
  rm -rf -- "$bindir"
  mkdir -p -- "$bindir"
  tar -xzf "$work/$syft_asset" -C "$bindir" syft
  chmod +x "$bin"
  rm -rf -- "$work"
  SYFT_RESOLVED=$bin
}

resolve_syft
syft_bin=$SYFT_RESOLVED
# The `|| true` covers the whole pipeline, not just head: under pipefail a
# syft that cannot report its version would otherwise abort the step with a
# bare pipeline error, which says nothing about which check failed.
got=$("$syft_bin" --version 2>/dev/null | head -1 || true)
if [ "$SYFT_PINNED" -eq 1 ] && [ "$got" != "syft $syft_version" ]; then
  # Fail loudly here rather than three steps later as an empty SBOM, which
  # reads like a scan problem instead of a bad download.
  die "installed syft reports '$got', expected 'syft $syft_version'"
fi
echo "generate-image-sbom: using $syft_bin (${got:-unknown version})"

# ------------------------------------------------------------- generate ----

mkdir -p -- "$(dirname -- "$out")"
rm -f -- "$out"

echo "generate-image-sbom: scanning $image"
# -q keeps the cataloguer chatter out of the job log; the scan is the slow
# part and its progress bar is the only thing it would have printed.
if ! "$syft_bin" "$image" -o "cyclonedx-json=$out" -q; then
  die "syft could not inventory $image (is it pushed, and are these credentials in scope?)"
fi
[ -s "$out" ] || die "syft produced no output at $out"

# Stamp the digest binding into the document. CycloneDX properties are the
# spec's own extension point for this and trivy ignores unknown names, so
# `trivy sbom` on the stamped file behaves identically to one on the raw
# syft output (checked, not assumed -- see the tests).
python3 - "$out" "$image" "$digest" "${name}" <<'PY' || die "could not stamp the digest into $out"
import json
import sys

path, ref, digest, name = sys.argv[1:5]
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)

if doc.get("bomFormat") != "CycloneDX":
    sys.exit(f"{path}: bomFormat is {doc.get('bomFormat')!r}, not CycloneDX")

component = doc.setdefault("metadata", {}).setdefault("component", {})
# syft fills `version` with the tag ("1.52.0", "latest", whatever the caller
# passed). The digest is the thing this file is keyed by, and a viewer that
# shows only name/version should show it.
component["version"] = digest

props = {
    p.get("name"): p.get("value")
    for p in component.get("properties", [])
    if isinstance(p, dict)
}
props["apiary:image-reference"] = ref
props["apiary:image-digest"] = digest
if name:
    props["apiary:image-name"] = name
component["properties"] = [{"name": k, "value": v} for k, v in sorted(props.items())]

with open(path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

# Re-read rather than trust the write: the stamp is the guarantee this whole
# step exists for, so it is verified on disk instead of assumed from the exit
# code of the process that wrote it.
python3 - "$out" "$digest" <<'PY' || die "$out does not record $digest after stamping"
import json
import sys

path, digest = sys.argv[1:3]
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)
props = {
    p.get("name"): p.get("value")
    for p in doc.get("metadata", {}).get("component", {}).get("properties", [])
    if isinstance(p, dict)
}
if props.get("apiary:image-digest") != digest:
    sys.exit(f"{path}: apiary:image-digest is {props.get('apiary:image-digest')!r}, expected {digest!r}")
PY

echo "generate-image-sbom: wrote $out ($(wc -c <"$out") bytes) for $digest"

# -------------------------------------------------------------- publish ----

if [ -n "$publish_dir" ]; then
  if [ -z "$name" ]; then
    echo "::warning::--publish-dir needs --name to lay the store out per image; skipping the homeserver copy"
  else
    publish_target=$publish_dir/$name
    # mkdir may fail because /var is root-owned (that is exactly why
    # install-homeserver.sh has a provision-image-sbom step), so probe
    # before reporting rather than letting `set -e` abort the build. An
    # unprovisioned homeserver should cost the local copy, not the row.
    if mkdir -p -- "$publish_target" 2>/dev/null && [ -w "$publish_target" ]; then
      # Two files, deliberately. <hex>.sbom.json is the record:
      # content-addressed, so re-running the same build overwrites in place
      # instead of piling up copies. latest.sbom.json is what a human or
      # Arcane reads without having to know which digest is current -- and
      # prune-image-sbom.sh keeps it pointing at the newest survivor.
      cp -f -- "$out" "$publish_target/$digest_hex.sbom.json"
      cp -f -- "$out" "$publish_target/latest.sbom.json"
      # Seven runner users share this tree and any of them can take any
      # matrix row (measured 2026-09-06, #2822's own note), so the last
      # writer must not own the result exclusively. The install step sets a
      # default ACL; an inherited entry is still ANDed with the writer's
      # umask, so re-grant rather than trusting it.
      chmod g+rw "$publish_target/$digest_hex.sbom.json" "$publish_target/latest.sbom.json" 2>/dev/null || true
      echo "generate-image-sbom: published to $publish_target ($digest_hex.sbom.json, latest.sbom.json)"
    else
      echo "::warning title=SBOM not published to the homeserver::$publish_target is not writable by $(id -un). Run scripts/install-homeserver.sh's provision-image-sbom step (#3321). The CI artifact still has it."
    fi
  fi
fi

# ------------------------------------------------------- Actions outputs ----

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    # Underscored keys, not hyphenated ones: GitHub's expression grammar
    # treats '-' as an operator, so steps.<id>.outputs.sbom-digest-hex is not
    # a property lookup. (Job ids get away with it; output names are read
    # back by an expression and should not depend on that.)
    printf 'sbom_path=%s\n' "$out"
    printf 'sbom_ref=%s\n' "$image"
    printf 'sbom_digest=%s\n' "$digest"
    printf 'sbom_digest_hex=%s\n' "$digest_hex"
  } >>"$GITHUB_OUTPUT"
fi
