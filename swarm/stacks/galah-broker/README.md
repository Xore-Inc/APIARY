# Galah broker migration (#3591)

This stack moves the existing stateless `galah-llm-broker` process from the
homeserver Compose project into Arcane GitOps Swarm. It deliberately has no
published port or host mount. The front overlay contains Galah and the broker;
the back overlay contains the broker and Ollama. Galah never joins the Ollama
network. Both overlays are attachable (for the remaining Compose containers),
encrypted, and use the fleet's 1310 overlay MTU.

The image is pinned to
`sha256:e7f48b58804f3c19766190eba95c33aa96df5a83cb7e5e17d091a107cc032886`,
the `main`/`sha-8e71cee` build of `main` commit
`8e71cee4fb0453ddedac32571d7421f625cbab2b`, pushed by the `galah-llm-broker`
job of [Containers run 39155280488](https://github.com/Xore-Inc/APIARY/actions/runs/39155280488).
That job succeeded. The run as a whole is red only because of the unrelated
`tanner-phpox` row, so it published no `image-digests` artifact. The digest
is taken from the job's push log and the GHCR tag instead. Its BuildKit
provenance records `vcs:revision` `8e71cee4…` and build context
`arcane/home/honeypot-galah/galah-llm-broker`. That commit contains
#3688 (`60a03cb6`): fail fast when Ollama is unavailable, plus the #3666
`MAX_INFLIGHT` cap that this stack sets. The broker build context has not
changed since `60a03cb6`. The previous pin (`sha256:5f6ce56a…`, built from
`81a8d574`) predates #3688 and has no in-flight cap. With that image,
`MAX_INFLIGHT` below would be silently ignored.

## Compose coupling: Swarm must exist before Ollama and Galah start

Two Compose files outside this stack now attach to its overlays as
`external: true` networks:

| Compose file | service | overlay | alias |
|---|---|---|---|
| `analysis/ghidra/docker-compose.ghidra.yml` | `ollama` | `galah-broker_back` | `ollama` |
| `arcane/home/honeypot-galah/compose.yml` | `galah` | `galah-broker_front` | (broker answers as `galah-llm-broker`) |

Compose refuses to start a service whose external network is missing.
**Ollama in the Ghidra stack will not start until this stack has been
deployed**, which also leaves every other Ollama consumer (llm-worker,
ml-worker, rex86-eval) without a model backend. Galah will not start either. So on a rebuild:

1. The homeserver must be a Swarm manager (`docker info --format
   '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}'` → `active true`)
   with availability **`active`** (`docker node inspect self --format
   '{{.Spec.Availability}}'`).
2. `galah-broker` must be deployed (through its Arcane GitOps sync), so that
   `docker network ls --filter name=galah-broker_` shows both overlays as
   `overlay`/`swarm`.
3. Only then start the Ghidra/Ollama stack, then `honeypot-galah`.

**Why `active` (#3722).** A standalone (Compose) container that joins an
attachable overlay asks the swarm for a network-attachment task on its node,
and the scheduler only places tasks on `active` nodes. On a `pause` node the
attach fails with `attaching to network failed ... context deadline
exceeded`, **even when the overlay is already materialized there** (proved
2026-10-31: the probe failed while `hp-galah` sat on `galah-broker_front`, and
succeeded after a 1 s `active` window with no throwaway task). The old
workaround (active, throwaway task, start, remove, pause) only worked because
of its `active` window. Since #3722 the homeserver stays `active`, and every
stack's placement decides explicitly whether it may run there
(`scripts/check-swarm-stacks.py`), so `pause` is no longer needed to keep
generic services off the sensor host.

If an attach still fails, check the availability first; `pause` and `drain`
both reject it. [`docs/STACK-REBUILD.md`](../../../docs/STACK-REBUILD.md)
carries the same ordering for a full reset.

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
then Paused homeserver was used to attach standalone Compose containers (the
`active` window is what mattered, see #3722 above). The task was removed and homeserver
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
3. Done 2026-10-24 (#3639): canary and broker syncs on `main`, both 2/2.
4. Done (#3722): the homeserver is `active` and placement keeps generic
   services off it, so Galah and Ollama recreate without a temporary task.
   The broker carries `apiary.homeserver: allow`, so after a resume its two
   replicas spread over the homeserver and precision.

The old **Compose service** stays stopped. The old `honeypot-galah` **project**
cannot stay stopped: it also owns the live Galah sensor. This is a literal
exception to the wording of #3591 and must be resolved explicitly before
closing the issue; splitting the sensor into a new project would add another
cutover and is not part of this change.

## Rollback

The old Compose broker is still defined in
`arcane/home/honeypot-galah/compose.yml`. It sits behind the `legacy`
profile, so a default `up` does not start it. It joins `galah_net` (which
Galah shares) and `honeypot-llm` (which Ollama still joins), so it needs
neither overlay.

**Broker-only rollback (Swarm healthy, broker tasks bad):**

```bash
# on the homeserver, in the deployed honeypot-galah project dir
docker compose --profile legacy up -d galah-llm-broker
# wait for hp-galah-llm-broker to be (healthy), then take the Swarm broker
# out of the name `galah-llm-broker`, so Galah resolves only the legacy one:
docker service scale galah-broker_broker=0      # from any manager
```

Galah keeps its `broker_front` attachment. With no broker task left on the
overlay, the alias resolves only through `galah_net`. Verify with a decoy
request. To return to the Swarm broker, scale `galah-broker_broker` back to
2, wait for 2/2 healthy, then run
`docker compose --profile legacy stop galah-llm-broker`.

**Full rollback (Swarm or the overlays unavailable):** the profile alone is
not enough, because Galah and Ollama still declare the external overlays and
will not be recreated without them. Revert the `broker_front` network on
`galah` and the `broker_back` network on `ollama` in both Compose files to
their pre-#3591 state. For Galah, that also restores
`depends_on: galah-llm-broker`, so the legacy broker becomes the default
again. Redeploy Galah and start its legacy broker with
`--profile legacy`, then redeploy Ollama. Restore the Ollama definition
only after Galah is using the legacy broker. Keep the stack and overlays until
no Compose container references them.

Never use `docker compose down -v` here: the Ollama model volume and Galah
logs/state must survive this migration.
