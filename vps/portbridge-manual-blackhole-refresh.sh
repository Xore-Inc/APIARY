#!/bin/sh
set -eu

# #914: keeps portbridge's manual (operator-triggered) blackhole list current
# -- the dashboard-side companion to portbridge-blackhole-refresh.sh's own
# maltrail feed. Same shape as that script (poll on a timer, download to a
# temp file, atomic rename), pointed at the dashboard's own export endpoint
# instead of GitHub. See docs/dashboard-manual-ip-block-design.md decision 4
# for the full reasoning: the VPS PULLS this list, on a timer, over the
# WireGuard tunnel that already exists (home is reachable at 10.8.0.2,
# docs/CGNAT-DEPLOYMENT.md) -- no new inbound channel to the VPS, which is
# deliberately the more exposed, internet-facing box.
#
# Opt-in via the same "blackhole" compose profile portbridge-blackhole-
# refresh.sh already uses -- a deployment that doesn't run that profile is
# unaffected, exactly as before this addition.
#
# Downloads atomically (temp file + rename) so portbridge's own mtime-based
# reload (blackhole.go's readOne, which reads a source file only after Stat
# shows its mtime moved) never observes a partially-written file.
#
# #3403: this default URL was a path the dashboard does not serve, and the
# failure was invisible. The frontend answers an unknown path with an auth
# redirect, so `curl -fsSL` exited 0 on a 200 whose body was a login page
# rather than a list: every 300 seconds this loop replaced a working
# blocklist with nothing, logged a cheerful "updated (0 addresses)", and
# operator IP blocks never reached portbridge. Three things changed:
#
#   * the default is the route that actually serves the export. #3403 pointed
#     it at /api/v1/ip-block-export through the old dashboard's /bff proxy;
#     #3578 moves it to the rewrite dashboard's own
#     /export/portbridge-manual-blackhole.txt (apiary-dashboard#246), which
#     accepts the export token below. Redirects are deliberately NOT followed,
#     so a 307 is visible as a 307 instead of quietly fetching whatever it
#     pointed at.
#   * that route is auth-gated, so the request carries an export-only
#     credential -- BLACKHOLE_EXPORT_TOKEN -- in an X-Export-Token header,
#     handed to curl through its stdin config (-K -) so the secret is never in
#     argv, never in the container's process list, and never in this script's
#     log. Unset is a loud refusal, not an unauthenticated attempt: the
#     unauthenticated answer IS the bug.
#
# #3578 / apiary-dashboard#246: the token is NOT the dashboard's service token.
# That secret reaches the whole backend API, including service actions, so a
# VPS holding it could do far more than read a blocklist. The export-only token
# opens one read-only route and nothing else, and it is a different value from
# SERVICE_TOKEN (the dashboard refuses to boot if the two are equal). The
# default URL is therefore the dashboard's own export route, the only place
# that accepts it; SERVICE_TOKEN there is answered 401 and, like any other
# refusal below, leaves the last good list untouched.
#
#   * a download is written only after it is proven to be a blocklist: HTTP
#     200, a non-empty body, a text/plain content type, and every
#     non-comment line an address. Anything else -- a 404, the
#     307-to-/auth/login, a 0-byte 200, an HTML login page -- is refused
#     with a named [E-*] marker and $dest is left exactly as it was.
#
# That last point deliberately REVERSES this script's original "no
# minimum-count sanity floor" rule. An empty manual list (no IP has ever
# been manually blocked) used to be written as a legitimate empty file;
# after #3403 it is indistinguishable, over the wire, from a broken fetch,
# and that ambiguity is where the bug lived. The safe direction is the one
# this script already took for a download failure: keep the last known-good
# list and say so, loudly, on every interval. A genuinely empty list is
# still harmless -- blackhole.go treats a missing file as "no blocklist yet"
# -- and the first non-empty export replaces the stale one anyway.
#
# A refusal is loud but never fatal: this is a 5-minute loop, so a homeserver
# that is briefly down (or restarting) must cost one skipped refresh, not a
# sidecar that never runs again.

url="${MANUAL_BLACKHOLE_URL:-http://10.8.0.2:19092/export/portbridge-manual-blackhole.txt}"
dest="${BLACKHOLE_MANUAL_LIST:-/blackhole/manual.txt}"
interval="${MANUAL_REFRESH_INTERVAL_SECONDS:-300}"  # 5m -- an operator block should take effect quickly, unlike the mostly-static maltrail feed
token="${BLACKHOLE_EXPORT_TOKEN:-}"

# A line blackhole.go's readOne would actually consume: blank, a '#'
# comment, or an address as its first field (mass_scanner.txt's "<ip> #
# host" annotation shape, the format readOne documents). Used to prove a
# body is a list at all -- the first line of an HTML login page fails it on
# the '<' -- and to count what got written, so the number in the log can
# never disagree with what the file contains.
#
# The address field is hex digits, dots and colons rather than a dotted quad
# on purpose: readOne's gate is net.ParseIP, which also accepts IPv6, and
# ip_block::set_block parses an IpAddr and the export emits the stored string
# verbatim. An IPv4-only check here would refuse the WHOLE export over one
# IPv6 entry, which stops every operator block being delivered -- #3403 again,
# wearing a fix's clothes. The classes are POSIX ones only, and no bounded
# repetition is used: this runs on busybox grep inside curlimages/curl.
valid_line_re='^[[:space:]]*(#.*)?$|^[[:space:]]*[0-9A-Fa-f:.]+([[:space:]]|#|$)'
address_re='^[[:space:]]*[0-9A-Fa-f:.]+([[:space:]]|#|$)'

mkdir -p "$(dirname "$dest")"

# Every refusal path funnels through here: drop the temp file, then say what
# was wrong and that the existing list was kept. $dest is written in exactly
# one place in this script -- the mv at the bottom of the loop, reachable only
# once a body has passed all four checks -- so a failed fetch cannot truncate
# or clear a working list no matter which check it failed. $1 is the stable
# [E-*] marker to grep for, $2 the reason.
#
# The cleanup is deliberately first: these two lines are this script's
# "settled" signal for anything reading its output (a log scraper, a test),
# and nothing may still be in flight by the time they are printed.
refuse() {
  rm -f "$tmp"
  echo "portbridge-manual-blackhole-refresh: [$1] $2" >&2
  echo "portbridge-manual-blackhole-refresh: keeping existing $dest; will retry in ${interval}s" >&2
}

while true; do
  tmp="${dest}.tmp.$$"
  if [ -z "$token" ]; then
    refuse E-NO-EXPORT-TOKEN "BLACKHOLE_EXPORT_TOKEN is unset or empty, and $url is auth-gated: an unauthenticated request answers 401 or 307 to /auth/login, not the export. Set it in vps/.env to the dashboard stack's EXPORT_TOKEN (not SERVICE_TOKEN)."
  elif meta=$(printf 'header = "X-Export-Token: %s"\n' "$token" \
      | curl -sS --max-time 30 -o "$tmp" -w '%{http_code} %{content_type}' -K - "$url"); then
    code="${meta%% *}"
    ctype="${meta#* }"
    if [ "$code" != "200" ]; then
      refuse E-EXPORT-STATUS "$url answered HTTP $code, not 200. 401 or 307 means the token was refused or missing (a login page, or SERVICE_TOKEN sent by mistake); 404 means the route is not served here any more. Neither is a blocklist."
    elif [ ! -s "$tmp" ]; then
      refuse E-EMPTY-BODY "$url answered 200 with a 0-byte body. A genuinely empty export is 0 bytes too, which is exactly the ambiguity that hid #3403, so it is not written -- see this script's header."
    elif [ "${ctype%%;*}" != "text/plain" ]; then
      refuse E-NOT-TEXT-PLAIN "$url answered 200 with content type '${ctype:-<none>}', not text/plain. The export sets text/plain; charset=utf-8 (ip_block::export), so anything else is an intercepting page rather than a list."
    elif grep -qvE "$valid_line_re" "$tmp"; then
      # grep -qv is the whole decision -- its exit status, not a parsed
      # field, so no response line can talk this check into passing. The
      # line NUMBER below is decoration for the log; deliberately never the
      # line itself, since in the case this change exists for the offending
      # line is a login page.
      refuse E-NOT-A-BLOCKLIST "$url answered 200 with text/plain, but line $(grep -nvE "$valid_line_re" "$tmp" | head -n 1 | cut -d: -f1) of the body is neither blank, a '#' comment, nor an address. That is not the format blackhole.go reads."
    else
      # grep -c exits 1 on a body that is valid but all comments; the body
      # is already proven to be a list, so a zero count is a fact to log,
      # not a failure to trip over.
      count=$(grep -cE "$address_re" "$tmp" || true)
      mv -f "$tmp" "$dest"
      echo "portbridge-manual-blackhole-refresh: updated $dest ($count addresses)" >&2
    fi
  else
    refuse E-DOWNLOAD-FAILED "could not fetch $url (curl exit $?). The tunnel is down or the homeserver is restarting -- not a reason to empty the list."
  fi
  sleep "$interval"
done
