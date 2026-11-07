# Tunnel attribution: the portbridge join

How a honeypot event that arrived through the VPS portbridge gets the real
client address, why it stopped working (#3573), and how to deploy the fix and
backfill the history.

## The path

```
attacker ──► VPS portbridge (public port) ──WireGuard──► homeserver sensor
                 │ logs one JSON line per connection:
                 │ src_ip (the client), via_port (the tunnel-side
                 │ source port it dialled from), target, proto, time
                 ▼
     /opt/stacks/apiary/logs/portbridge/portbridge.json (VPS)
                 │ sshfs, read-only, on the homeserver
                 ▼
 backend-worker-enrichment (hp-apiary-worker-enrichment, uid 65534)
   tails each sensor log, replaces the tunnel peer with the client,
   writes logs/enriched/*.json ──► Filebeat ──► geoip-honeypot ──► honeypot-v2
```

A sensor that does not parse PROXY protocol sees the WireGuard peer
(`10.8.0.1`) as its client and the portbridge `via_port` as the client's
source port (iptables DNAT preserves it). That port and the time are the join
key. The same log also reaches Elasticsearch as `portbridge-v2-*`, which is
what the backfill joins against.

## What went wrong (#3573)

Observed on 2026-10-09:

- About 6.3M of 10.1M `honeypot-v2` documents had no `source.ip`. Their only
  address was the tunnel peer (4.86M) or loopback (305k).
- `cowrie`, `conpot`, `dionaea` documents with `source.ip`: about 1,000 out of
  6.0M since 2026-09-17, i.e. the join had attributed essentially nothing
  since the data begins.
- The worker's own stats showed `timed_out` equal to `attempted` for cowrie,
  and nothing else.
- `docker exec hp-apiary-worker-enrichment head -c1 /logs/portbridge/portbridge.json`
  failed with `Permission denied`. The file is `root:root 0640` on the VPS; the
  worker runs as `nobody`.
- `/etc/fstab` mounted the portbridge directory with `default_permissions`,
  which makes the kernel enforce those modes locally. #1677 had removed that
  option from the live fstab once, but `scripts/install-homeserver.sh` still
  wrote it, and the 2026-09 Rocky 10 rebuild put it back.
- The worker's `ViaMapBuilder` dropped the read error, so the map stayed empty
  and every tunnel line timed out unattributed, with no error logged.
- The join itself was fine on a live sample. A cowrie line on source port
  48132 at 23:31:45 and the portbridge dial on `via_port` 48132 at 23:31:44 to
  `10.8.0.2:19023` match.

Conclusion: it was a permissions regression with a silent failure, and the
join logic was not at fault. Separately, the join's rule (newest dial within
six hours) could name the wrong client, so it was tightened in the same
change. See below.

## Why not PROXY protocol for these sensors

portbridge already sends PROXY v1 wherever the sensor can parse it (the `:pp`
rules). The rest can't:

- **cowrie**: Twisted's `haproxy:` endpoint parsed the header but did not apply
  the address, and threw per connection (see `cowrie/cowrie.cfg`). It also
  rejects header-less connections, which would break the healthcheck.
- **dionaea** has no PROXY support.
- **UDP** (conpot SNMP/BACnet/IPMI, SIP, DNS, IKE) has no PROXY v1 form.
- **History**: PROXY only helps new connections. The backfill needs the join
  anyway.

So the join is the mechanism, and #3573 makes it work and makes it safe.

## The join rule

Implemented in `backend-service/src/ip_enrichment/viamap.rs` (`resolve`) and
mirrored constant for constant in `scripts/backfill-tunnel-attribution.py`.

| Input | Source |
|---|---|
| via_port | the sensor's source port (`src_port`, hellpot `REMOTE_ADDR`, sentrypeer `source_ip`, galah `srcPort`, beelzebub `event.SourcePort`, dionaea incident `remote_port`) |
| connection start | the earliest line of the session for cowrie (`session`), conpot (`id`) and dionaea incidents (connection `id`); otherwise the line's own time |
| target port | where the sensor's port equals portbridge's target: dionaea, elasticpot, mailoney, dns-honeypot, cisco-asa, hellpot (8080), galah (8888), conpot TCP; cowrie mapped 2222→19022, 2223→19023 |
| transport | the sensor's own field, or known per sensor; TCP and UDP ports are separate namespaces |

A dial matches when it was stamped from `DIAL_LEAD_SECONDS` (4) before the
connection start to `CLOCK_SKEW_SECONDS` (2) after it, on a compatible
transport and target. That window was measured. On 10,000 cowrie connects, the
sensor stamp minus the dial stamp was 0 s for 27%, 1 s for 69% and 2 s for 4%.
Everything else was unrelated reuse of the port.

| Case | Result |
|---|---|
| TCP, one client in the window | attributed |
| TCP, two different clients in the window | **ambiguous** |
| TCP without a known target, another client on the port in the 600 s before | **ambiguous** (a late line could otherwise meet an unrelated reuse) |
| UDP | the newest dial up to 3600 s back is the session (one socket per session, exclusive while it lives); ambiguous only if a rival is too close to the line to order |
| no dial | **unmatched** (live: retried for `PENDING_TIMEOUT`, then flushed) |
| no usable sensor time | never joined against a timed dial |

A wrong target-port mapping can only cost a match. While a connection is
open, no other connection can dial the same target from the same source port.

Live only: an attribution is held back until the map has read past the end of
its window, so a rival dial that is still in flight can't be missed. Backfill
only: a window that overlaps a gap in `portbridge-v2` (no dial at all for more
than 300 s) is `no_coverage` and never attributed.

## What a document carries

| Field | Meaning |
|---|---|
| `source.ip` | the client, promoted by `geoip-honeypot` from the rewritten sensor field |
| `honeypot.fleet_peer` | the tunnel address the sensor saw (`10.8.0.1`). Same field #3560's promotion writes |
| `honeypot.tunnel_attribution` | `portbridge`, `ambiguous` or `unmatched`. Absent on events that never went through the tunnel |

Count the outcomes:

```sh
docker exec hp-elasticsearch curl -s 'http://localhost:9200/honeypot-v2-*/_search?size=0' \
  -H content-type:application/json -d '{"query":{"range":{"@timestamp":{"gte":"now-1h"}}},
  "aggs":{"s":{"terms":{"field":"event.sensor"},"aggs":{"a":{"terms":{"field":"honeypot.tunnel_attribution"}}}}}}'
```

The worker logs the same counts every 30 s, per source, along with whether it
can read the log:

```
ip-enrichment: tunnel-peer join stats source=cowrie ... attributed=.. ambiguous=.. unmatched=.. portbridge_readable=true
```

If it can't read the log, it also logs one error line naming the path and the
`errno` (`cannot read the portbridge log`).

## Runbook

Nothing here has been applied. Run these steps in this order.

### 1. Make the log readable (homeserver host)

```sh
ssh homeserver
sudo cp /etc/fstab /etc/fstab.bak-3573
# drop default_permissions from the read-only VPS log mounts
sudo sed -i -E '/[[:space:]]fuse\.sshfs[[:space:]]/ { s/,default_permissions//; s/default_permissions,// }' /etc/fstab
grep fuse.sshfs /etc/fstab            # no default_permissions left
sudo systemctl daemon-reload
for d in portbridge suricata zeek zeek-extract huginn traefik; do
  sudo umount /var/dockge/stacks/apiary/logs/$d && sudo mount /var/dockge/stacks/apiary/logs/$d
done
sudo setpriv --reuid=65534 --regid=65534 --clear-groups head -c1 \
  /opt/stacks/apiary/logs/portbridge/portbridge.json && echo readable
```

`install-homeserver.sh` (step `sshfs-mounts`) now writes the entries without
the option, rewrites old entries, and fails if uid 65534 can't read the log.
A rebuild can't bring the regression back unnoticed.

Containers that bind-mount `/opt/stacks/apiary/logs` keep the old mount
underneath them until they are recreated. Step 2 recreates the enrichment
worker. Filebeat and pcap-sync also read these mounts, so redeploy
`honeypot-elk` too (or restart `hp-filebeat`).

### 2. Deploy the worker (Arcane)

This is a backend change, so use the documented order. Sync `honeypot-dashboard`
first, then build and redeploy `honeypot-dashboard-backend`, then build and
redeploy `honeypot-dashboard`. The last step recreates
`hp-apiary-worker-enrichment` on the new image. The endpoints are in
[ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md).

Verify:

```sh
docker exec hp-apiary-worker-enrichment head -c1 /logs/portbridge/portbridge.json && echo
docker logs --since 2m hp-apiary-worker-enrichment 2>&1 | grep 'join stats' | tail
# attributed > 0 for cowrie/dionaea, portbridge_readable=true
```

Then check in Elasticsearch, on documents indexed after the deploy, that
`source.ip` is present and `honeypot.tunnel_attribution` is `portbridge`. Use
the aggregation above with `now-15m`.

The worker starts each source at its persisted offset. Lines written while
the log was unreadable were already shipped unattributed, so the backfill
covers them.

### 3. Backfill (after step 2 is verified)

Elasticsearch is reachable only from the `honeynet` network:

```sh
cd /opt/stacks/apiary   # repo checkout on the homeserver
docker run --rm --network honeynet -v "$PWD/scripts:/s:ro" python:3-alpine \
  python /s/backfill-tunnel-attribution.py                # dry run, read-only
docker run --rm --network honeynet -v "$PWD/scripts:/s:ro" python:3-alpine \
  python /s/backfill-tunnel-attribution.py --apply --mark-unattributed
```

The dry run prints one row per sensor with every outcome. `--apply` writes in
batches of 500 through `_update_by_query` on each document's backing index,
with `pipeline=geoip-honeypot`. Each field is written only while it still holds
the tunnel value and only while `source.ip` is absent, so a re-run is a no-op.
`--since` and `--until` restrict by `@timestamp`, and `--sensor` restricts by
sensor. Expect two full scans of the unattributed documents plus one of
`portbridge-v2`. At this size it takes tens of minutes, plus the writes.

Verify afterwards:

```sh
docker exec hp-elasticsearch curl -s 'http://localhost:9200/honeypot-v2-*/_count' \
  -H content-type:application/json -d '{"query":{"bool":{"must_not":[{"exists":{"field":"source.ip"}}]}}}'
```

The remainder should be about the dry run's non-attributed total. It breaks
down by `honeypot.tunnel_attribution` (ambiguous / unmatched) plus loopback
healthchecks and `other`.

Geo/ASN on dionaea incident documents follows `source.ip` once #3560's
pipeline change (`geoip` on the promoted address) is deployed. Until then those
documents get `source.ip` but no geo, the same as at ingest today.

### Rollback

The worker change is additive. Redeploying the previous image restores the old
join, and the fstab backup restores the mount options. The backfill only adds
fields and fills `source.ip`. To find what it wrote, query
`honeypot.tunnel_attribution: portbridge` on documents indexed before the
deploy.

## What cannot be recovered

- Documents from before `portbridge-v2` begins (its first dial is 2026-09-24
  22:16 UTC). portbridge's own rotated logs on the VPS are pruned after about 3
  days, so nothing older exists anywhere. They come out as `no_coverage`.
- Windows where `portbridge-v2` has gaps (Filebeat outages). These also come
  out as `no_coverage`.
- Loopback documents. These are the sensors' own healthchecks (#1677), not
  attackers, and stay that way.
