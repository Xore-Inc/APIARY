# llm: Ollama on the homeserver GPU (#3594)

Phase 7 step 3 of [`docs/SWARM-GPU.md`](../../../docs/SWARM-GPU.md). One
replica of Ollama, pinned to `node.labels.gpu == true`, reserving the whole
card (`NVIDIA-GPU: 1`). It replaces the Compose `ollama` in
`analysis/ghidra/docker-compose.ghidra.yml`, which stays behind the `legacy`
profile as the rollback.

## How the card reaches the task

The reservation is the scheduler's accounting. The device itself comes from
a `/dev/null` bind at `/var/run/nvidia-container-devices/<uuid>`, which the
NVIDIA runtime honours because the homeserver's
`/etc/nvidia-container-runtime/config.toml` sets
`accept-nvidia-visible-devices-as-volume-mounts = true`. The swarm variable
`DOCKER_RESOURCE_NVIDIA-GPU` alone does not work: the toolkit treats it as an
environment request, and `accept-nvidia-visible-devices-envvar-when-unprivileged
= false` ignores those for every unprivileged container (see the design doc).

## Model volume

The stack uses the local volume `llm_ollama_models`, **not**
`ghidra_ollama_models`. That one belongs to the legacy Ollama and the #3706
benchmark, both on Ollama 0.34.4. Ollama 0.40 migrates the store on start (it
writes `models/manifests-v2`), so sharing the volume would rewrite the
benchmark's models under it.

`llm_ollama_models` is created once on the homeserver and seeded with
reflink (copy-on-write) copies of the models the consumers use:
`qwen3:14b` (backend, Ghidra triage, Rev-Deck), `nomic-embed-text:latest`
(backend embeddings) and `qwen2.5:7b-instruct-q4_K_M` (Galah). The source is
only read. To add a model, pull it through the running service
(`docker exec <task> ollama pull <model>`) on an overlay with egress, or
seed it the same way.

## Consumers

All of them reach `ollama:11434` on the attachable overlay `llm_ollama`:

| Consumer | How it joins |
|---|---|
| `galah-broker` stack | stack network `llm` (external) |
| `hp-apiary-backend` (Compose) | `connect` line in `ops/swarm/hosts/homeserver-overlay-attach.txt` |
| host units (`honeypot-ghidra-worker`, `gpu-queue-drain`, `model-drift`, `llm-injection-suite`) | `127.0.0.1:11434` -> Compose `ollama-loopback` (socat) in `analysis/ghidra` |
| Rev-Deck (profile `revdeck`) | `llm` network in `analysis/ghidra` |

## One GPU owner at a time

Swarm does not see Compose or `docker run` device requests. While the #3706
benchmark (or the legacy Ollama) holds the card, this stack is paused and the
forwarder is stopped:

```sh
ops/swarm/stackctl.py pause llm          # 1 -> 0, closes the sync gate
docker stop ghidra-ollama-loopback-1     # frees 127.0.0.1:11434
# ... other owner runs ...
docker start ghidra-ollama-loopback-1
ops/swarm/stackctl.py resume
```

## Rollback

```sh
ops/swarm/stackctl.py pause llm
docker stop ghidra-ollama-loopback-1
cd analysis/ghidra   # the live checkout on the homeserver
docker compose -f docker-compose.ghidra.yml -f docker-compose.ghidra.gpu.yml up -d ollama
```

`ghidra-ollama-1` joins `honeypot-llm` and `galah-broker_back` with the alias
`ollama`, so the backend (still on `honeypot-llm`) and the broker (still on
`back`) find it again without a config change.
