# Swarm GPU: the homeserver GPU as a generic resource (phase 7)

[← back to README](../README.md) · [Swarm network](SWARM-NETWORK.md) · [ops/swarm runbook](../ops/swarm/README.md) · [GPU passthrough](gpu-docker-passthrough.md)

Design for [#3594](https://github.com/Xore-Inc/APIARY/issues/3594) (epic
[#3587](https://github.com/Xore-Inc/APIARY/issues/3587), decision 4: "swarm
with generic resources, NVIDIA on the homeserver, GPU services pinned by
constraint and reservation").

**Status (2026-10-31): design and lint only. Nothing is applied.** The model
benchmark ([#3706](https://github.com/Xore-Inc/APIARY/issues/3706)) owns the
GPU until it finishes. Every live step below waits for it, and step 1 needs a
dockerd restart on the homeserver, which restarts every container there.

## What is on the host today

Read on the homeserver on 2026-10-31 (`nvidia-smi -L`, `docker info`,
`nvidia-ctk config default`):

| Item | Value |
|---|---|
| GPU | one NVIDIA RTX 4000 Ada Generation, 20475 MiB, UUID `GPU-18a00c7e-670a-c305-a2aa-20e3a71917a3` |
| Docker | 29.9.2, default runtime `runc`, `nvidia` runtime registered, CDI spec in `/var/run/cdi/nvidia.yaml` |
| NVIDIA Container Toolkit | 1.20.1; `swarm-resource` present but commented out (`#swarm-resource = "DOCKER_RESOURCE_GPU"`) |
| Swarm node | `supermicro`, labels `gpu=true sensor=true`; availability `active` since #3722 |

GPU consumers, all Compose, all reserving the card by UUID through
`deploy.resources.reservations.devices`:

| Compose file | Service | Swarm blockers besides the GPU |
|---|---|---|
| `analysis/ghidra/docker-compose.ghidra.gpu.yml` | `ollama` | consumers on the bridge `honeypot-llm` and the overlay `galah-broker_back` |
| `ml-worker/docker-compose.ml-worker.gpu.yml` | `ml-worker` | overlay only reserves the device; nothing on the GPU path yet |
| `arcane/home/unsloth/compose.yml` | `unsloth-studio` | `ipc: host`, `security_opt`, `cap_add`, `memlock` ulimit |
| `analysis/ghidra/training/compose.yaml` | `train` | `ipc: host`, `memlock` ulimit; a run-to-completion job |
| `arcane/home/rex86-eval/compose.yml` | `rex86-eval` | `shm_size: 16gb`; a run-to-completion job |
| `docker-compose.arcane.gpu.yml` | `arcane` | the control plane (GPU panel only); never a stack |

## Mechanism

Swarm does not support device requests: `docker stack deploy` ignores
`deploy.resources.reservations.devices`. A GPU is scheduled as a **node
generic resource** instead.

1. **Advertise the GPU** in the homeserver's `/etc/docker/daemon.json`
   (dockerd restart):
   ```json
   {
     "node-generic-resources": ["NVIDIA-GPU=GPU-18a00c7e-670a-c305-a2aa-20e3a71917a3"],
     "default-runtime": "nvidia"
   }
   ```
   merged surgically into the existing file (keep `builder`,
   `default-address-pools`, `dns`, `log-driver`, `log-opts`, `runtimes`).
   A service cannot choose its runtime, so `nvidia` has to be the default
   for a swarm task to get the device.
2. **Let the runtime read swarm's assignment.** For each reserved unit swarm
   sets `DOCKER_RESOURCE_<KIND>` (the kind upper-cased) in the task's
   environment to the assigned IDs. In `/etc/nvidia-container-runtime/config.toml`:
   ```toml
   swarm-resource = "DOCKER_RESOURCE_NVIDIA-GPU"
   accept-nvidia-visible-devices-envvar-when-unprivileged = false
   ```
   The second line matters because `default-runtime: nvidia` applies to
   **every** container on the host. Images such as `ollama/ollama` and
   `nvidia/cuda` set `NVIDIA_VISIBLE_DEVICES=all` in their own environment.
   With the default `true`, any of them, started anywhere on the host, would
   take the GPU without a reservation. With `false`, only a device request (the
   Compose services above) or a swarm reservation hands out the card.
   Confirm both variable names inside the proof task (rollout step 2),
   because the toolkit's handling of `swarm-resource` under that setting is
   not documented.
3. **Reserve it in a stack** (enforced by `scripts/check-swarm-stacks.py`):
   ```yaml
   deploy:
     placement:
       constraints:
         - node.labels.gpu == true
     resources:
       reservations:
         generic_resources:
           - discrete_resource_spec:
               kind: NVIDIA-GPU
               value: 1
     update_config:
       order: stop-first      # one GPU: start-first would wait forever
       failure_action: rollback
     rollback_config:
       order: stop-first
       failure_action: pause
   ```
   The lint refuses `reservations.devices` in a stack, a `NVIDIA-GPU`
   reservation without `node.labels.gpu == true`, and either order not
   `stop-first`.

### Accounting gap: Compose and swarm do not see each other

Swarm counts generic resources only for swarm tasks. A Compose container
holding the card through a device request is invisible to the scheduler, so a
swarm GPU task can start next to it and both share VRAM. That is today's
behaviour between Compose services too (see [gpu-docker-passthrough.md
§8](gpu-docker-passthrough.md#8-sharing-one-gpu-across-multiple-containers)).
The rule stays: **one owner of the GPU at a time**, arbitrated by the GPU job
queue and the operator, not by the scheduler. Move a GPU service to swarm
only together with every other always-on GPU holder, or the reservation
proves nothing.

### What swarm cannot express

- `ipc: host`: not supported. `unsloth-studio` and the training job use it
  for PyTorch shared memory. A `tmpfs` mount at `/dev/shm` with an explicit
  size works in a stack (`type: tmpfs`, `tmpfs.size`), which also replaces
  `shm_size` for `rex86-eval`. It is not the same as the host IPC namespace;
  measure before switching.
- `security_opt`: not supported. `unsloth-studio` stays Compose until it can
  run without it (documented exception).
- `cap_add` and `ulimits` (`memlock: -1`) are supported (Docker 20.10 and 23.0).
- Run-to-completion jobs (`train`, `rex86-eval`) fit `mode: replicated-job`,
  but they are operator-started experiments. They stay Compose; nothing is
  gained by scheduling them.

## Proposal: what becomes a stack

| Workload | Proposal | Why |
|---|---|---|
| `ollama` | stack `llm`, one replica, `NVIDIA-GPU: 1`, pinned to `gpu == true`; model volume stays the existing named volume on the homeserver | the only always-on GPU holder and the dependency of Galah, the backend and the workers |
| `ml-worker` GPU overlay | stays Compose; drop the device reservation until ml-worker really uses the GPU | it reserves the card for nothing (its own header says so) |
| `unsloth-studio`, `train`, `rex86-eval` | stay Compose, documented exceptions | `security_opt` / `ipc: host` / operator-run jobs |
| `arcane` GPU panel | stays Compose | the control plane is never a stack |

Moving Ollama is coupled to its consumers. Today they reach it as `ollama` on
the bridge `honeypot-llm`, and the Galah broker reaches it on
`galah-broker_back`. A stack cannot join a Compose bridge, so the `llm` stack
owns an **attachable, encrypted overlay** (MTU 1310) with the alias `ollama`.
The Compose consumers (backend, workers, Ghidra worker, revdeck) attach to it
as an external network; the homeserver must be `active` for that (#3722).
Until a consumer moves, it keeps `honeypot-llm`, so Ollama joins both during
the transition.

## Rollout after the benchmark (one step at a time)

Each step has its own rollback. Stop and report before step 1, because it
restarts dockerd on the homeserver.

1. **Daemon and runtime config.** Back up `daemon.json` and `config.toml`
   (`.bak-3594-<ts>` next to them). Make the two surgical edits above. Restart
   dockerd at a quiet time. All homeserver containers restart: the sensors are
   down for about a minute (no `live-restore`), and Galah needs the overlay
   attach, which works because the node is `active`. Verify: `docker node
   inspect self --format '{{json .Description.Resources.GenericResources}}'`
   lists `NVIDIA-GPU`. Every GPU Compose service still sees the card, and
   `docker run --rm ollama/ollama:<pin> nvidia-smi` without `--gpus` must
   **fail** to see it (the `accept-...=false` guard).
   *Rollback:* restore both backups and restart dockerd.
2. **Proof stack** `gpu-canary` (not merged under `swarm/stacks/` until it
   passes locally): `nvidia/cuda` base digest, `nvidia-smi -L` as the
   healthcheck, one replica, `NVIDIA-GPU: 1`. Expect the task on the
   homeserver with `DOCKER_RESOURCE_NVIDIA-GPU=GPU-18a00c7e-…` in its
   environment, the UUID in `nvidia-smi -L`, and a second replica `pending`
   with "insufficient resources". Then remove it.
3. **`llm` stack** with Ollama, following the proposal above. The
   Compose Ollama stays defined behind a `legacy` profile for rollback. Cut
   over the way the Galah broker did: start the stack, move one consumer at a
   time, and verify with a real request through each consumer.
   *Rollback:* scale the stack to 0, `docker compose up -d ollama` from the
   Ghidra project.
4. **ml-worker overlay:** drop its device reservation (code), after Xore
   agrees that nothing uses it.

## Open questions for Xore

- `default-runtime: nvidia` is a host-wide change on the sensor host: it
  touches every container (it behaves like `runc` when no GPU is requested).
  Step 1 needs a planned dockerd restart window.
- Whether Ollama should ever share the card with a second always-on swarm GPU
  task. With one 20 GB card the answer today is no: `value: 1` is the whole
  GPU.
