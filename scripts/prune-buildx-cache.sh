#!/usr/bin/env bash
# prune-buildx-cache.sh -- bound the size of one image's type=local buildx
# cache directory (#2822). type=local has no eviction of any kind: every
# `cache-to` export leaves old, no-longer-referenced blobs behind in
# blobs/sha256/, and the directory grows without bound otherwise. This is
# the local-disk equivalent of the GHA-quota incident this issue exists to
# fix, just slower -- an unbounded cache on /var eventually starves
# whatever else is on that filesystem (including /var/benchmarks).
#
# Never delete individual blobs by age: an old blob may still be referenced
# by the current index. Reset the whole cache only when it exceeds the cap.
#
# Usage: prune-buildx-cache.sh <cache-dir>
set -euo pipefail

dir=${1:?usage: prune-buildx-cache.sh <cache-dir>}
MAX_BYTES=${MAX_BYTES:-$((2 * 1024 * 1024 * 1024))}  # 2 GiB per image

[ -d "$dir" ] || { echo "prune-buildx-cache: $dir does not exist, nothing to do"; exit 0; }

before=$(du -sb "$dir" 2>/dev/null | cut -f1)
echo "prune-buildx-cache: $dir before: ${before:-0} bytes"

# Hard-ceiling pass: whole-directory reset, not oldest-blob-at-a-time.
#
# Two reasons this beats trimming. (1) Correctness: since one missing blob
# voids the entire import (above), trimming to just under the ceiling most
# likely leaves a directory that is simultaneously useless AND ~MAX_BYTES
# large -- the worst of both. A reset gives up the cache honestly and the
# next build re-exports a clean, complete one. (2) Cost: the previous form
# re-ran `du -sb` over the whole tree after every single `rm`, which is
# O(n^2) over a directory of thousands of small blobs.
total=$(du -sb "$dir" 2>/dev/null | cut -f1)
[ -n "$total" ] || total=0
if [ "$total" -gt "$MAX_BYTES" ]; then
  echo "prune-buildx-cache: $dir is ${total} bytes, over the ${MAX_BYTES} ceiling -- resetting"
  # Remove the cache contents, not the directory itself: the runner owns
  # what is inside but may not be able to recreate the directory under a
  # root-owned /var (#2822's own blocker).
  find "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi

after=$(du -sb "$dir" 2>/dev/null | cut -f1)
echo "prune-buildx-cache: $dir after: ${after:-0} bytes"

# BuildKit may narrow group permissions despite the workflow's umask 002;
# retain group access for cache repair and a replacement runner account.
chmod -R g+rwX "$dir" 2>/dev/null || true
find "$dir" -type d -exec chmod g+s {} + 2>/dev/null || true
