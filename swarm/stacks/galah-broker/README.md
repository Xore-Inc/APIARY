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

## Deployment gate

**Do not deploy this stack yet.** GHCR currently returns 403 for the pinned
private image with the workstation's `gh` credential (`repo` scope but no
`read:packages`), Arcane currently has zero saved container registries, and
neither manager has a GHCR pull credential. Docker
Swarm requires registry credentials propagated to each node for a private
image; `docker stack deploy --with-registry-auth` is the Docker CLI mechanism.
GitHub Packages currently requires a **personal access token (classic)** with
`read:packages`; the fine-grained `github_pat_...` credential tested on
2026-10-12 authenticated to Arcane but failed an actual GHCR image pull with
`permission_denied`. That registry entry was removed after the test. Before
the live cutover, provision a classic, least-privilege `read:packages`
credential through Arcane's registry integration (including its send-registry-
authentication deploy option) or an equivalent approved Swarm deploy path,
then prove a pinned-image pull and task start on **both**
managers. Do not make the package public merely to bypass the credential gap.

The PR also changes the Compose definitions for Galah and Ollama. They must
not be synced independently before this gate: each references an overlay that
the new stack creates. No Ollama model, runtime setting, or model volume is
changed.

## Ordered cutover after the gate

1. Check Galah, Ollama, and the legacy broker are healthy. Record their
   Compose config and current image IDs. Confirm the pinned GHCR image is
   pullable on homeserver and precision.
2. Deploy this stack with `ops/swarm/stackctl.py ensure galah-broker --branch
   <merged-branch>` (or `deploy` for an existing sync). Confirm two healthy
   broker tasks and both encrypted, attachable overlays.
3. Attach Ollama to `galah-broker_back` with its updated Compose definition.
   Verify `ollama:11434` from each broker task before changing Galah. Keep the
   existing `honeypot-llm` bridge and Ollama model volume untouched.
4. Stop only the legacy `hp-galah-llm-broker` container. Apply the updated
   Galah Compose definition, which puts `hp-galah` on `galah-broker_front`
   and keeps the old broker behind the `legacy` profile. Verify Galah DNS
   resolves `galah-llm-broker` to the Swarm VIP, and test a bounded request
   through Galah. Confirm Galah cannot resolve or reach `ollama` directly.
5. Temporarily set homeserver Active, force one broker task onto each manager,
   and verify Galah-to-broker-to-Ollama from each placement. Drain each
   manager in turn; restore precision Active and homeserver Pause when done.
   Exercise a rolling update and an intentionally unhealthy update to prove
   automatic rollback, as done for the synthetic canary. Leave the legacy
   broker stopped and defined for rollback.

The old **Compose service** stays stopped. The old `honeypot-galah` **project**
cannot stay stopped: it also owns the live Galah sensor. This is a literal
exception to the wording of #3591 and must be resolved explicitly before
closing the issue; splitting the sensor into a new project would add another
cutover and is not part of this change.

## Rollback

If broker tasks fail before Galah cutover, leave Galah and Ollama Compose
untouched and roll back or remove this stack through `stackctl.py`. After
cutover, restore the previous Galah Compose definition and start its legacy
broker, then remove the sensor's front-overlay attachment. Restore the
previous Ollama Compose definition only after Galah uses the legacy broker.
Keep the stack and overlays until no Compose container references them.

Never use `docker compose down -v` here: the Ollama model volume and Galah
logs/state must survive this migration.
