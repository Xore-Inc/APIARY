# honeypot-backend-workers (#3575)

The four sensor-bound Rust workers (`backend-worker`, `-importer`,
`-enrichment`, `-payload-inventory`) and `services-adapter`, as one
homeserver project. It does not depend on the old `honeypot-dashboard`
project or on a local image build.

- **Placement:** homeserver (.250) only. These services read sensor logs,
  analyzer spools and named volumes that live on that host, and the adapter
  drives that host's Docker daemon (#3582, #3592 decisions 1, 2 and 6).
- **Image:** `ghcr.io/xore-inc/honeypot-backend-service` and
  `ghcr.io/xore-inc/honeypot-services-adapter`, built by
  `.github/workflows/containers.yml`, pinned by tag and digest in the
  host-local `.env`. Use the backend release the HTTP tier runs. Arcane pulls
  them with its `ghcr` registry credential.
- **Names:** container and volume names match the old project, so
  monitoring, `scripts/honeypot-pause.sh` and the existing data keep working.
  `es-importer-state` is the old project's volume
  (`honeypot-dashboard_es-importer-state`), declared external. It must exist
  before the first `up`.

## Arcane

GitOps sync `honeypot-backend-workers` on environment 0 (homeserver), path
`arcane/home/honeypot-backend-workers/compose.yml`, branch `main`,
`syncDirectory: true`, auto-sync off. The host-local `.env` holds the image
pins plus every worker value copied unchanged from the old project's `.env`
(`.env.example` lists them).

## Cutover from honeypot-dashboard, one service at a time

The fixed container names make the two copies mutually exclusive, which is
what #1628 requires (no dual-running workers). For each service, in the
order `backend-worker-payload-inventory`, `backend-worker-importer`,
`backend-worker`, `backend-worker-enrichment`, `services-adapter`:

1. Record the old container's ID, image and start time, and the service's
   current output: the ES index it writes, its last log lines, or for
   `services-adapter` a services list through the backend.
2. `docker stop -t 60 <container> && docker rm <container>` (the old project's
   copy). Its volumes are named and survive.
3. `docker compose -p honeypot-backend-workers up -d --no-deps <service>` in
   the synced project directory, or Arcane `up` for that service.
4. Verify the replacement: healthy, the GHCR image digest, the same mounts
   (`docker inspect`), and fresh output written after the start (parity per
   loop). Only then go to the next service.

Rollback per service: stop and remove this project's container, then
`docker compose -p honeypot-dashboard up -d --no-deps <service>` in
`/var/dockge/stacks/honeypot-dashboard`, which restarts the old definition
on the same volumes.

After all five run here, a follow-up removes them from
`arcane/home/honeypot-dashboard/compose.yml`. Until then, a redeploy of the
old project fails on the container-name conflict for these services instead
of starting a second copy.
