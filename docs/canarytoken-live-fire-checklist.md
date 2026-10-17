# Canarytoken live-fire checklist

Catalogued in [`docs/DECEPTION-EXTENSIONS.md`](DECEPTION-EXTENSIONS.md)'s
Canarytokens row, alongside [`docs/SENSORS.md`](SENSORS.md)'s description of the
stack this exercises.

**Why this file exists.** Every token type this stack offers has, at some point,
been confirmed to fire end to end — but that confirmation lives only in closed
issue threads (#1586, #1587, #1595). There is no artefact in the repo that says
which types have been observed firing, when, or how to repeat the observation.
That is how #1586 came to be closed with the PDF type's fired-status admittedly
unverified, and how #2136 had to be filed to notice.

This checklist is the structural thing that was missing. It is a **manual**
procedure: firing a canarytoken requires a real client (a document reader, a
browser, a phone camera, Explorer) doing the thing an attacker would do. Nothing
here is automatable in CI, which is precisely why it needs writing down.

**Run it:** after any change to the vendored canarytokens source
(`CANARYTOKENS_REF` in `arcane/home/honeypot-canarytokens/canarytokens/`), after
any change to `backend-service/src/canarytokens.rs` or
`canarytokens-adapter/main.go`, and once after the #1609 reinstall.

---

## Preconditions

- [ ] `hp-canarytokens-frontend`, `hp-canarytokens-switchboard`,
      `hp-canarytokens-redis` and `hp-apiary-backend` are up.
- [ ] The stack's `CANARY_PUBLIC_HOSTNAME` is **not** a placeholder. The backend
      refuses to create tokens under `.example` / `.example.com` / `.example.net`
      / `.example.org` / `.invalid` (`canarytokens.rs`,
      `RESERVED_PLACEHOLDER_SUFFIXES`) — because a token minted under the shipped
      placeholder can never resolve, and the resulting silence is
      indistinguishable from "nobody took the bait".
- [ ] The token's random hostname resolves publicly. Each token is a random label
      subdomained under `CANARY_PUBLIC_HOSTNAME`, matched by the VPS Traefik
      wildcard `HostRegexp` rule — see `docs/SENSORS.md` and
      `docs/CGNAT-DEPLOYMENT.md`.
- [ ] Note the vendored commit under test:
      `docker exec hp-canarytokens-frontend cat /COMMIT_SHA`. Record it in the
      results table below.

## Per-token procedure

For each type: create → plant/open → observe the fire → confirm it lands.

1. **Create** through the dashboard's *Settings → Canarytokens* pane (not by
   calling the API by hand). Use a memo that names this checklist run, e.g.
   `live-fire 2026-09-01 <type>`.
   - If you do need to drive the API directly, the create path is
     `${CANARYTOKENS_API_URL}${CANARYTOKENS_API_ROOT}/generate`. The API root is
     **deliberately non-guessable** upstream anti-scraping — it is not `/api`,
     and `POST /generate` against the bare origin correctly returns
     `405 Allow: GET`. The value the backend uses is `DEFAULT_API_ROOT` in
     `arcane/home/honeypot-dashboard/backend-service/src/canarytokens.rs`. Guessing
     paths from outside is the trap that cost #2136 a whole session.
2. **Trigger** it the way the per-type notes below describe, from a host that is
   *not* on the honeypot network (so the source IP is meaningful).
3. **Observe the fire.** The switchboard posts to `canarytokens-adapter` on the
   internal `canarytokens-adapter.internal` network; the public HTTP entry point
   is `canarytokens-http-router` (`hp-canarytokens-http-router`, host port
   19427), which is the service that actually holds `ADAPTER_URL`
   (compose.yml:311) and forwards to the adapter. The switchboard itself
   publishes no host port. The adapter then
   appends one sensor JSON line to `/var/log/honeypot/canarytokens.json`
   (`canarytokens-adapter/main.go`), which Filebeat tails into the honeypot index
   like any other sensor.
   - Tail it live while triggering:
     `docker exec hp-canarytokens-adapter tail -f /var/log/honeypot/canarytokens.json`
   - Then confirm it reached Elasticsearch. Query on `event.sensor: canarytokens`
     — the adapter writes a bare `sensor` key and Filebeat nests sensor-line
     fields under `honeypot.*`, so expect the payload at `honeypot.token_type`,
     `honeypot.token`, `honeypot.memo`. **Confirm the actual field paths on a
     document indexed after your fire** rather than trusting this line; a query
     against a field the data does not use silently returns nothing, which reads
     exactly like "it never fired".
4. **Confirm the dashboard shows it** on the canarytokens page.
5. **Record the result** in the table, with the alert timestamp.

## Types to cover

The authoritative list is `TYPES` in
`arcane/home/honeypot-dashboard/backend-service/src/canarytokens.rs`. As of
2026-09-01 it is six:

| id | what fires it | notes |
|---|---|---|
| `adobe_pdf` | opening the PDF in a reader that performs the embedded outbound request | **The known-weak one.** Many viewers — including Chrome's built-in PDF viewer — do not execute the active-content path this technique relies on, so a negative result in one reader is *not* evidence the token is broken. Record which reader was used. An `adobe_pdf` token did fire from an external client on 2026-08-17 (callback → sensor log → ES → dashboard, all re-verified 2026-09-03), but **what opened it is unknown** — do not treat a PDF row as passing until someone fills it in from a real reader. See #2136. |
| `ms_word` | opening the `.docx` in Word with external content allowed | |
| `ms_excel` | opening the `.xlsx` in Excel with external content allowed | |
| `web_image` | loading the image from a page or client that fetches it | requires an upload at creation time |
| `windows_dir` | opening the extracted folder in Windows Explorer | `desktop.ini` + icon bundle; needs a real Explorer, not a file manager |
| `qr_code` | scanning the PNG and following the URL | |

## Results

Copy this block per run; keep previous runs.

```
run date:            YYYY-MM-DD
CANARYTOKENS_REF:    <commit from /COMMIT_SHA>
run by:              <who>
reason:              <vendored bump / reinstall / adapter change / routine>

| type         | created | fired | ES doc | dashboard | client used            | alert ts |
|--------------|---------|-------|--------|-----------|------------------------|----------|
| adobe_pdf    |         |       |        |           |                        |          |
| ms_word      |         |       |        |           |                        |          |
| ms_excel     |         |       |        |           |                        |          |
| web_image    |         |       |        |           |                        |          |
| windows_dir  |         |       |        |           |                        |          |
| qr_code      |         |       |        |           |                        |          |
```

```
run date:            2026-09-03
CANARYTOKENS_REF:    dd92bf29bd0f6d1b446fb41e3b8114c6fc7a6205
run by:              Xore (via #2136)
reason:              #2136 -- resolve adobe_pdf's fired-status once and for all

| type         | created | fired | ES doc | dashboard | client used            | alert ts |
|--------------|---------|-------|--------|-----------|------------------------|----------|
| adobe_pdf    | yes     | no*   | n/a    | n/a       | Chrome (Playwright)    |          |
| ms_word      |         |       |        |           |                        |          |
| ms_excel     |         |       |        |           |                        |          |
| web_image    |         |       |        |           |                        |          |
| windows_dir  |         |       |        |           |                        |          |
| qr_code      |         |       |        |           |                        |          |
```

\* Created a real token via the documented API fallback (see step 1 above --
this resolved the exact `/generate` routing dead-end that cost a previous
attempt its whole session budget), downloaded the artifact through
`/download?...&fmt=pdf`, and confirmed with `qpdf --qdf` that it carries a
well-formed page-open `/AA` action (`/S /URI`, `/URI
(http://<token>.<hostname>/<path>)`) matching the token's own hostname --
the mechanism is correctly baked into the artifact. Navigating Chrome
(driven via Playwright, no interactive human-attached session available in
this environment) to the artifact's public download URL did **not** fire it
-- the server responded with an attachment disposition, so Chrome routed it
to a native "Save File" dialog instead of rendering it inline, and the
page-open action that would trigger the callback never had a chance to run.
This is **not a negative live-fire result** for the technique itself; it is
"no PDF reader ever opened the file" -- Chrome's PDF viewer, which is
explicitly documented above as one of the weak ones, never even got that far.
No ES doc, no dashboard entry, because nothing fired.

**However:** while establishing today's baseline, a genuine historical
`adobe_pdf` fire was found, and the four pipeline links after the callback
were verified against it -- see the next section. That closes everything
except the link this issue is named for: which client opened the document.
This checklist's own honesty rule still applies to *today's* attempt
(blank/negative stays blank/negative), and it applies to the historical event
too -- its client-used column stays blank.

### `adobe_pdf`: a historical fire, triggering client unknown (2026-08-17 event, re-verified 2026-09-03)

**An `adobe_pdf` token was observed firing from an external client — the four
pipeline links below are now verified, the reader link is not.** Found while
investigating this issue, not manufactured for it -- a real fire event already sat in
`/opt/stacks/apiary/logs/canarytokens/canarytokens.json` on the homeserver,
undetected because nothing had ever looked for it (which is the whole reason
this checklist exists):

```
token:      <redacted -- see #2136's comments for handling>
memo:       "Xore verification token (working)"
timestamp:  2026-08-17T15:48:20Z / :22Z (two hits, 2s apart)
src_ip:     94.31.93.171 (Germany, ASN 8899 / inexio Informationstechnologie)
useragent:  Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/151.0.0.0 ... Edg/151.0.0.0
```

Full path confirmed today, independently, at each link:

1. **ES doc** -- `GET honeypot-v2*/_search` on `event.sensor: canarytokens` +
   `honeypot.token: <token>` returns 2 hits at the field paths this checklist
   documents (`honeypot.token_type`, `honeypot.memo`, `honeypot.src_ip`).
2. **Dashboard** -- `GET /api/v1/events?sensor=canarytokens&size=50&since=365d`
   (the exact query `frontend-next/src/routes/canarytokens.tsx`'s "Fired
   tokens" tab issues — `since=365d`, chosen there because tokens fire rarely
   and the events endpoint's own default is 10d; the trailing `0` in an older
   revision of this checklist was a transcription slip, not a wider window) returns this event as row `detail: "token fired: Xore
   verification token (working) (HTTP)"`, geo-enriched (country DE, ASN 8899)
   -- confirmed surfaced, not just indexed.

The memo and a genuine non-loopback, non-testing-range source IP with a
plausible desktop browser UA establish that this is a **real fire from a real
external client**, not a synthetic test (the "Congrats! The newly saved webhook
works" entries elsewhere in the same log, by contrast, are visibly canned --
`1.1.1.1`, `example.com`, generic `Mozilla/5.0...` -- and are
webhook-configuration self-tests, not fires).

**What it does not establish is the one link #2136 was opened about.**
`src_data.referer` is empty and the user agent is a desktop browser, which is
exactly what you would see *either* if a PDF reader handed the embedded
`/S /URI` action to the default browser *or* if someone pasted the URL into
that browser directly. Nothing in the record distinguishes those two, so the
client-used column for this historical event is left blank rather than
guessed, and the real-reader test this checklist asks for has still not been
run. Whoever recognises this token's memo can close that gap with one
sentence -- which client opened it -- and nothing else can.

### Known state (updated 2026-09-03)

- `web_image`, `qr_code`, `windows_dir` and the fired-status/download fixes:
  confirmed live in #1586 / #1587 / #1595.
- `adobe_pdf`: an external client fired one on 2026-08-17, and callback →
  sensor log → ES → dashboard was re-verified on 2026-09-03 from that event
  (above). The **triggering client is unknown**, so the real-reader test #2136
  asks for has still not been run: do not treat a PDF row as passing until
  someone fills it in from a real reader.
- `ms_word` / `ms_excel`: still no live-fire record found either way -- this
  run did not attempt them (out of scope for #2136).

A blank row means "not observed", never "works". That distinction is the entire
point of this file.

### Two traps when re-running this checklist

- **Check the cluster is ingesting before you trust an empty "ES doc" column.**
  A fire that never reaches Elasticsearch looks identical to a token that never
  fired. On 2026-09-03 nothing had been indexed since `2026-08-31T23:59:59Z`
  (#2820 / #2905 / #2906), so a run that day would have produced a false
  negative in that column while the callback itself was fine. Query for *any*
  recent document first; if there are none, the instrument is blind and the
  column is "unknown", not "no".
- **`@timestamp` is ingest time, not event time.** The 2026-08-17 hits carry
  `@timestamp: 15:48:28Z` while the sensor line says `15:48:20Z` / `:22Z` --
  six to eight seconds apart. Query a window, not an instant, or search on the
  token/memo rather than the time.

