# Galah broker migration (#3591)

This stack moves the existing stateless `galah-llm-broker` process from the
homeserver Compose project into Arcane GitOps Swarm. It deliberately has no
published port or host mount. The front overlay contains Galah and the broker;
the back overlay contains the broker and Ollama. Galah never joins the Ollama
network. Both overlays are attachable (for the remaining Compose containers),
encrypted, and use the fleet's 1310 overlay MTU.

The image is pinned to the `galah-llm-broker` entry of the successful
`image-digests` artifact from [Containers run 38159221962](https://github.com/Xore-Inc/APIARY/actions/runs/38159221962),
commit `81a8d5741359a23fdb4a56f1dbb7f2cdcbea96c3`. The broker build context
has not changed since that commit.

## Live state (2026-10-12)

The first credential supplied was a fine-grained `github_pat_...` token. It
passed Arcane's registry authentication test but a real GHCR image pull failed
with `permission_denied`; its Arcane registry entry was removed. GitHub
Packages requires a classic PAT with `read:packages` for external package
pulls. The workstation's existing GitHub CLI OAuth token was then granted
`read:packages` and saved as an **interim** Arcane `ghcr.io` registry credential.
It has broader `repo`/`workflow` scopes and should be replaced with a classic
read-only package token after the migration. Both managers pulled the exact
pinned image through Arcane. Do not make the package public to bypass auth.

`ops/swarm/stackctl.py ensure galah-broker --branch feat/3591-swarm-canary`
created the Arcane GitOps sync and converged at 2/2 on precision. The two
encrypted, attachable overlays have MTU 1310. A temporary Swarm task on the
normally Paused homeserver was needed to materialize each overlay before
attaching standalone Compose containers. The task was removed and homeserver
returned to Pause.

Galah is now attached to `galah-broker_front`, and Ollama is attached to
`galah-broker_back`; neither container was moved out of Compose. A direct
request from Galah through the Swarm broker returned HTTP 200, then an actual
Galah decoy request returned HTTP 200 with the legacy broker stopped. A later
Arcane Galah sync initially failed while recreating its container because no
Swarm task held the front overlay on homeserver. A temporary task materialized
the overlay again; the Galah sync then succeeded and another decoy request
returned HTTP 200. The temporary task was removed. Galah and Ollama are
healthy, the legacy Compose broker is stopped, and the Swarm broker is 2/2.

An earlier decoy probe timed out while Ollama was busy. A separate full model
benchmark is running on homeserver, so do not send further model probes or
restart Ollama during that run. The Ollama container has kept its original
start time, `2026-10-11T22:37:09Z`; its model roster, runtime settings, and
model volume were not changed by this cutover. The live Ollama Compose file
has only the back-overlay attachment added and retains its existing image and
KV-cache settings; this differs from the older file in this PR checkout.

With homeserver temporarily Active, scaling the broker to zero and back
placed one task on each manager. Draining precision moved both broker tasks
to homeserver; draining homeserver moved them back to precision. Homeserver
was restored to Pause, and both the broker and existing canary returned to
2/2 on precision. An Arcane GitOps rolling update of the broker completed
with 2/2 replicas and no Ollama restart. An intentionally unhealthy broker
update and automatic rollback remain untested.

## Remaining work before closing #3591

1. After the model benchmark finishes, exercise an intentionally unhealthy
   broker update and verify automatic rollback without touching Ollama.
2. Replace the interim Arcane GHCR credential with a classic PAT limited to
   `read:packages`, then prove pulls on both managers.
3. Merge this PR, point the canary and broker Arcane syncs at `main`, deploy,
   and verify both stacks at 2/2. Keep homeserver at `Pause` in normal service.
4. Confirm the updated Galah and Ollama Compose definitions are the source of
   truth, including the live Ollama image and runtime settings. Test that a
   later Galah recreation can reattach to the front overlay without a
   temporary task on homeserver; otherwise implement a durable
   network-materialization mechanism before treating the migration as stable.

The old **Compose service** stays stopped. The old `honeypot-galah` **project**
cannot stay stopped: it also owns the live Galah sensor. This is a literal
exception to the wording of #3591 and must be resolved explicitly before
closing the issue; splitting the sensor into a new project would add another
cutover and is not part of this change.

## Rollback

If broker tasks fail, restore the previous Galah Compose definition and start
its legacy broker, then remove the sensor's front-overlay attachment. Restore
the previous Ollama Compose definition only after Galah uses the legacy
broker. Keep the stack and overlays until no Compose container references
them.

Never use `docker compose down -v` here: the Ollama model volume and Galah
logs/state must survive this migration.
