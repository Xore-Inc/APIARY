# sensor-dionaea (#3593, phase 6)

The decoy `hp-dionaea` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing its 14 host ports in `mode: host`:
tcp 21, 135, 445, 1433, 1723, 1883, 3306, 5060, 9100, 11211, 27017 and udp 69,
1900, 5060. The image is the GHCR build of `arcane/home/honeypot-dionaea/dionaea`,
pinned by digest from the `image-digests` manifest of Containers run
42490632043 (`main` b38894a3).

Privilege gate (#3593 audit, 2026-11-08): the image keeps Ubuntu's stock
setuid/setgid tools (`su`, `passwd`, `mount`, `pam_extrausers_chkpwd`, `wall`,
...) and has no file capability (`getcap -r` on the exported image). Dionaea
drops to its own user by `setuid()`/`setgid()` and never execs them; the live
Compose container already runs with `no-new-privileges`. The stack sets
`security_opt: [no-new-privileges:true]` per service, `read_only`,
`cap_drop: ALL` and adds back only the five capabilities the Compose service
measured (NET_BIND_SERVICE, CHOWN, SETUID, SETGID, DAC_OVERRIDE): the
entrypoint chowns the data dirs and binds privileged ports as root.

## TFTP and hp-tftp-relay (option 1, Xore 2026-11-08)

`hp-tftp-relay` stays a Compose service in `arcane/home/honeypot-dionaea`
(portbridge `udp:69` → `10.8.0.2:1069`). This stack owns the attachable
overlay `sensor-dionaea_decoy` (`10.200.28.0/24`); the relay joins it as an
external network and keeps `TFTP_TARGET=dionaea:69`. The service runs in
`endpoint_mode: dnsrr`:

- Through the default VIP the request reaches dionaea, but dionaea answers
  from a new port (the TFTP TID) and the transfer times out (smoke,
  2026-11-08). With dnsrr `dionaea` resolves to the task address and the
  reply comes straight from it (RRQ through the relay: rc 0, same bytes).
- A replaced task gets a new address. The relay re-resolves `TFTP_TARGET`
  for each new session (cached `TFTP_RESOLVE_SECONDS`, default 5 s; a
  failed lookup keeps the last good address), so it follows the task without
  a restart (smoke: `service update --force`, relay logged the new address,
  next RRQ rc 0).
- Dionaea logs the relay's overlay address and the relay's upstream port,
  which is the `relay_port` in `sessions.json` (the #747 join is unchanged).

The service files are configs (`configs/*.yaml` are copies of
`arcane/home/honeypot-dionaea/dionaea/services/*.yaml`; bump the `_vN` names
when they change). `dionaea-lib` is the same external volume the Compose
service used; honeypot-init seeds the persona files into it, so `/persona` is
not mounted (nothing in the image reads it).

## Cutover

1. `home-swarm-host-guard` (DNAT-scoped since #3769) is active with the 14
   rows above in `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. The Arcane sync of `honeypot-dionaea` has `autoSync: false`. Stop the
   Compose service and keep the container as the rollback:
   `docker stop hp-dionaea`.
3. `ops/swarm/stackctl.py ensure sensor-dionaea` (creation deploys and
   creates the overlay).
4. Join the relay: apply this change's `honeypot-dionaea/compose.yml` and
   `tftp-relay/` diff to the live project directory (backups alongside), then
   rebuild and recreate only the relay (`docker compose up -d --no-deps
   --build tftp-relay` in the project dir; a project redeploy would start the
   rollback container into the stack's ports).
5. Prove:
   - the task runs on `supermicro`, `healthy`, `NoNewPrivs: 1`;
   - a TCP probe through the VPS (e.g. public 445) appears in `honeypot-v2`
     with the prober's public `honeypot.src_ip` (portbridge join);
   - a TFTP RRQ through public udp 69 returns the file, and dionaea's
     `TftpServerHandler` doc is indexed as before;
   - from the LAN, `nmap -Pn` shows the ports `filtered` and the guard's
     LOG/DROP counters rise.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-dionaea   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-dionaea
```

The relay finds the Compose dionaea again on `dionaea_net` within one resolve
interval. `stackctl.py remove sensor-dionaea --yes` deletes the stack and its
sync once the Compose service is serving; disconnect `hp-tftp-relay` from
`sensor-dionaea_decoy` first, or the attachable network survives.
