# PentAGI on the homeserver — the stack as it runs

Record of the [PentAGI](https://github.com/vxcontrol/pentagi) autonomous-pentest
stack on the `homeserver` (SSH alias; `supermicro`, NVIDIA RTX 4000 Ada), kept
current as of **2026-09-27**. Reference: #3277.

**Status: RUNNING, and wanted in service.** Niklas decided 2026-09-27 that
PentAGI is *not wanted in the fleet* and had it torn down; that decision was
**reversed the same day** and the stack was brought back with
`docker compose up -d` in `/var/pentagi`. It is serving now
(`https://<host LAN address>:8443/` → HTTP 200). An earlier version of this
doc recorded the shutdown as final; that framing was wrong and is corrected
here. Nothing was deleted — volumes, compose files and `.env` are all intact, so
this is a running stack with a recorded inventory, not a tombstone.

## What it does

PentAGI is an autonomous-pentest stack, and it is **out of band from the
honeypot fleet**: it consumes no honeypot event, writes to no honeypot index,
and shares no network with any `hp-*` container. The `hp-galah-llm-broker` and
`ghidra-ollama-1` Ollama listeners on the host are separate services in
separate compose projects; neither is reachable from this stack, and both are
out of scope here.

End to end, as captured 2026-09-27:

- **Web UI on the host LAN, port 8443.** The only non-loopback binding in the
  stack — every other service is either in-network or on 127.0.0.1.
- **Drives its own agent sandboxes.** `pentagi-terminal-1..3` are Kali
  containers it creates and reaps itself as agent execution environments; they
  carry no compose labels and no `docker compose` invocation can manage them.
  Each keeps a `/work` volume and binds the **host Docker socket**, so an agent
  inside one can act on the host's containers.
- **Self-hosts its model and embeddings.** `pentagi-ollama-embedding` serves
  both `OLLAMA_SERVER_URL` and `EMBEDDING_URL` on 11434 inside
  `pentagi-network`; `pentagi-vllm` is profile-gated and contributes nothing.
- **Configures an external OpenAI-compatible endpoint alongside it.** Both
  `LLM_SERVER_URL` and `OPEN_AI_SERVER_URL` are set, so which backend a given
  request actually used is not recorded here.
- **No search backend, no tracing, no SSO, no licence.** See "Set and unset"
  below for the full set-vs-unset shape.
- **Not stably up.** See "Observed instability": the stack is cycled by an
  unidentified external actor more than once during the capture window, and
  each cycle destroys in-flight terminal work. "PentAGI is up" is a sampled
  observation, not a guarantee.

What it detects: nothing in the honeypot's telemetry. This doc records the
stack's operation and state; it makes no claim about what PentAGI found, which
is not this repo's record to keep. #3504.

Two things this doc deliberately does **not** carry, and why:

- **No configuration values, for any key, and no lengths.** The record is *set
  or unset* and nothing else. Set-vs-unset is the operationally useful part; the
  values are credentials, endpoints and salts and they live only in
  `/var/pentagi/.env` on the host. A character count is a length-derived hint
  about a secret, so it is not recorded either.
- **No compose files.** `/var/pentagi/docker-compose*.yml` and
  `/var/pentagi/.env` are not committed here. The repo describes the stack; it
  does not carry it. `scripts/check-public-leaks.py` is what keeps it that way —
  it fails the build on a deployment `.env`, on a literal credential
  assignment, and on the homeserver's own address, among other things.

## How it runs

Compose project `pentagi`, working directory `/var/pentagi`, composed from
**two** files, per the running containers' own
`com.docker.compose.project.config_files` label:

```
/var/pentagi/docker-compose.yml
/docker/pentagi/docker-compose.override.yml
```

A third file, `/var/pentagi/docker-compose-graphiti.yml`, exists and declares
the `neo4j` and `graphiti` services — but it is **not** part of the composed
project, so those two services do not run. Adding it to the compose invocation
is what would bring them up. Also present in `/var/pentagi` and not part of the
project: `docker-compose-langfuse.yml`, `docker-compose-observability.yml`,
`.env`, `docker-ssl/`, and an upstream `backend/` checkout.

### Compose services (5 running)

All five declare `restart: unless-stopped`. State as captured 2026-09-27.

| Container | Service | Image | State | Published ports | Networks |
|---|---|---|---|---|---|
| `pentagi` | `pentagi` | `vxcontrol/pentagi:latest` | Up, serving | **host LAN address**:8443→8443 (the only non-loopback binding in the stack) | `pentagi-network`, `langfuse-network`, `observability-network` |
| `pentagi-ollama-embedding` | `ollama-embedding` | `ollama/ollama:0.32.13` | Up | none — 11434 reachable on `pentagi-network` only | `pentagi-network` |
| `scraper` | `scraper` | `vxcontrol/scraper:latest` | Up | 127.0.0.1:9443→443 | `pentagi-network` |
| `pgvector` | `pgvector` | `vxcontrol/pgvector:latest` | Up (healthy) | 127.0.0.1:5432 | `pentagi-network` |
| `pgexporter` | `pgexporter` | `quay.io/prometheuscommunity/postgres-exporter:v0.16.0` | Up | 127.0.0.1:9187 | `pentagi-network` |

### `pentagi-vllm` is exited, and is not coming back on its own

| Container | Image | State | Restart policy |
|---|---|---|---|
| `pentagi-vllm` | `vllm/vllm-openai:nightly` | **Exited (0), 4 days** | `no` |

It is the odd one out. In `docker-compose.override.yml` the `vllm` service is
gated behind a compose **profile** and carries `restart: "no"`, so a plain
`docker compose up -d` does not start it and nothing restarts it either. It holds
no endpoint on `pentagi-network` and contributes nothing to the running stack.

### The three terminals are not compose-managed

`pentagi-terminal-1`, `-2` and `-3` carry **no compose labels at all** — no
`com.docker.compose.project`, no `working_dir`, no `config_files`. PentAGI
creates and reaps them itself as agent execution sandboxes, so no
`docker compose` invocation in `/var/pentagi` can see or manage them.

| Container | Image | State | Published ports | Restart policy | Network |
|---|---|---|---|---|---|
| `pentagi-terminal-1` | `vxcontrol/kali-linux` | Up, idle | 0.0.0.0:28002, 0.0.0.0:28003 | `on-failure`, 5 retries | `bridge` |
| `pentagi-terminal-2` | `vxcontrol/kali-linux` | Up, idle | 0.0.0.0:28004, 0.0.0.0:28005 | `on-failure`, 5 retries | `bridge` |
| `pentagi-terminal-3` | `vxcontrol/kali-linux` | Up, idle | 0.0.0.0:28006, 0.0.0.0:28007 | `on-failure`, 5 retries | `bridge` |

Each keeps its own `pentagi-terminal-N-data` volume at `/work` and bind-mounts
the **host Docker socket** at `/var/run/docker.sock`. Note the divergence from
the compose services: the terminals are `on-failure:5`, not `unless-stopped`.

**The terminals are up but idle, and idle means empty.** All three sit at 0.00%
CPU and well under 1 MiB resident. Work that was running inside them did **not**
survive the restart that brought the stack back — the containers were recreated
from scratch, so anything in flight in a terminal sandbox is gone. Do not read
"Up" here as "still working".

### Networks

Three, all owned by the `pentagi` compose project:

| Network | Declared | Notes |
|---|---|---|
| `pentagi-network` | `external: true` in the compose file | the stack's private network; every service except the terminals. External, so compose will not create it on a fresh `up` |
| `langfuse-network` | project-owned | only `pentagi` is attached |
| `observability-network` | project-owned | only `pentagi` is attached |

No other stack on the host references any of the three; they are exclusive to
PentAGI and are not recreated by anything under `/var/dockge/stacks/`.

### Volumes (11, all preserved)

`pentagi_pentagi-data`, `pentagi_pentagi-ssl`, `pentagi_pentagi-ollama`,
`pentagi_pentagi-embedding`, `pentagi_pentagi-postgres-data`,
`pentagi_scraper-ssl`, `pentagi_neo4j_data`, `pentagi_huggingface-cache`,
`pentagi-terminal-1-data`, `pentagi-terminal-2-data`,
`pentagi-terminal-3-data`.

## The LLM backend is Ollama, not vLLM

#3277's Phase 2 proposed vLLM serving Qwen3.5-27B-FP8. **That never ran.** The
`vllm` service is profile-gated and has been exited with code 0 for four days;
the ollama path is what is configured. `OLLAMA_SERVER_URL` and `EMBEDDING_URL`
both point at a 11434 endpoint on `pentagi-network` — an in-network compose
service, not a host port, not a cloud API. The `pentagi-ollama-embedding`
container is the ollama instance serving that port, so the embedding and LLM
configurations both resolve inside `pentagi-network`.

`LLM_SERVER_URL` and `OPEN_AI_SERVER_URL` are also both set, to an `https`
endpoint on a public domain with no explicit port, and `OPEN_AI_KEY` /
`LLM_SERVER_KEY` are both set. So the stack has a live OpenAI-compatible
endpoint configured alongside ollama. Which of the two a given request actually
used is **not** recorded here and no value is reproduced. What matters: the
configured model backend is not the vLLM container, and `pentagi-vllm`
contributed nothing.

### `ghidra-ollama-1` is not PentAGI's

The homeserver's 18.4 GiB `llama-server` holding VRAM belongs to
`ghidra-ollama-1`, which serves `qwen3:14b` on 127.0.0.1:11434 for the Ghidra
analysis stack. It looks superficially like "the ollama PentAGI was pointed at"
and is a different service in a different compose project
(`/var/dockge/stacks/apiary/analysis/ghidra/`). It is out of scope here and must
not be touched: other work depends on it. The same goes for every `hp-*`
honeypot container and for `hp-galah-llm-broker`, the other 11434 listener.

## Configuration: set vs unset

All values live in `/var/pentagi/.env` on the host and are **not** in this
repo. 130+ environment variables exist for this stack; the table below is a
curated selection of the ones whose state is operationally meaningful, **not** an
exhaustive dump. For every key the record is the state and the category — never
a value, never a length, never a masked fragment.

### Set and non-empty

| Key | Category |
|---|---|
| `LLM_SERVER_URL` | `https` endpoint, public domain, no explicit port |
| `LLM_SERVER_KEY` | secret-bearing |
| `LLM_SERVER_MODEL` | model identifier (treated as secret-bearing) |
| `OPEN_AI_SERVER_URL` | `https` endpoint, public domain, no explicit port |
| `OPEN_AI_KEY` | secret-bearing |
| `OLLAMA_SERVER_URL` | in-network ollama service |
| `OLLAMA_SERVER_MODEL` | model identifier |
| `EMBEDDING_URL` | in-network ollama service, same endpoint as above |
| `EMBEDDING_MODEL` | model identifier |
| `EMBEDDING_PROVIDER` | provider selection |
| `DATABASE_URL` | secret-bearing (carries DB credentials) |
| `GRAPHITI_ENABLED` | feature toggle |
| `GRAPHITI_URL` | in-network graphiti service |
| `COOKIE_SIGNING_SALT` | secret-bearing |

### Unset (present in the environment with an empty value)

| Key | |
|---|---|
| `LLM_SERVER_PROVIDER` | no provider override — the generic OpenAI-compatible path is in use |
| `OLLAMA_SERVER_API_KEY` | ollama reachable with no auth |
| `EMBEDDING_KEY` | embedding reachable with no auth |
| `SEARXNG_URL` | SearXNG **not** in use, despite `SEARXNG_*` category settings being present |
| `TAVILY_API_KEY` | no Tavily |
| `ANTHROPIC_API_KEY` | no Anthropic |
| `PERPLEXITY_API_KEY` | no Perplexity |
| `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, `LANGFUSE_BASE_URL` | tracing **not** wired up, even though `pentagi` is attached to `langfuse-network` |
| `OAUTH_GITHUB_CLIENT_ID`, `OAUTH_GOOGLE_CLIENT_ID` | no external SSO |
| `LICENSE_KEY` | community/unlicensed tier |
| `SERVER_SSL_CRT`, `SERVER_SSL_KEY` | no explicit keypair; TLS material comes from the `pentagi_pentagi-ssl` volume instead |

The set-vs-unset split is the useful half of this table and it is worth reading
as a shape: **no search backend, no external LLM vendor key beyond the one
OpenAI-compatible endpoint, no tracing, no SSO, no licence.** The only
credentials present at all are the OpenAI-compatible key pair and the
Postgres/Neo4j/session secrets the stack generates for its own database.

### One real drift worth recording

`LLM_SERVER_URL` and `LLM_SERVER_MODEL` are **empty in `.env`** but non-empty in
the running container's environment, and the two disagree about what the
`LLM_SERVER_URL` value is. `.env` also carries a trailing block of
`LLM_SERVER_*` / `OMNIROUTE_KEY` overrides appended after the vendor sections
it is meant to fill in, so later definitions win. In other words **the
container's environment is the record of what is actually running; `.env` on
disk had already moved on.** Anything reconstructing this stack from `.env`
alone would not reproduce the running configuration, which is a second reason
not to commit it.

## Resources: the limits are unlimited, not zero

Every container in the stack reports `mem=0`, `cpuquota=0`, `nano=0` and an
empty `cpuset`. In Docker those zeros mean **unlimited** — they are the absence
of a limit, not a limit of nothing. Do not "fix" this by adding caps: the stack
is not misconfigured, and nothing here is throttling it.

What it actually consumes, measured on the 48-core host with 92.3 GiB of RAM:

- **~2.3 GiB of 92.3 GiB** resident across the eight containers.
- **Low single-digit percent of one core** at rest. Startup is burstier (briefly
  over one core combined while the services boot), which is why a sample taken
  during a restart cycle reads higher than the steady state.

That is a small, well-behaved footprint. It is also the reason the stack
survives on a box that is otherwise running the honeypot fleet.

### The `Exited (137)` were SIGKILL from a restart cycle, not OOM

Containers caught mid-cycle show `Exited (137)`. Exit 137 is SIGKILL, and here
it came from Docker escalating: the daemon log shows the containers receiving
signal 15, failing to exit inside the 10s grace period, and being force-killed
("failed to exit within 10s of signal 15 - using the force"). `OOMKilled` is
`false` on every container inspected, and the host has ~90 GiB free. **These are
not out-of-memory kills** and there is no memory pressure to fix.

The cycle is external, not the stack's own doing: `RestartCount` is 0
throughout, so no restart policy is bouncing anything, and the terminals are
`on-failure:5` which would have retried a crash rather than staying down. See
"Observed instability" below for what is actually driving it.

## Observed instability: something external is cycling the stack

During the 2026-09-27 capture the stack went down and came back **more than
once**, on a cycle of a few minutes. Sampling shows the full compose set
disappearing and returning within ~70s, with the terminals landing at exit 137
each time. This is not stable service, and it is not the stack self-terminating.

What is established:

- `RestartCount=0` everywhere — no restart policy is involved.
- `OOMKilled=false` and ample free memory — not the OOM killer.
- No `docker compose down`, `stop` or `kill` appears anywhere in the sudo
  command log, even though the daemon demonstrably received a stop signal.
- Repeated `docker compose up -d` invocations *are* logged from `/var/pentagi`
  by user `xore`, which is what brings the stack back after each cycle.

The actor sending the stop has not been identified. Audit rules watching
`docker` and `docker-compose` execution are installed on the host to catch it.
**Until that is resolved, treat "PentAGI is up" as a sampled observation, not a
guarantee** — and note that each cycle recreates the terminal sandboxes, so
in-flight work in them is destroyed again (see "The terminals are up but idle").

## Ops note: inotify exhaustion on the homeserver (recommendation only)

The homeserver hits `inotify:too many open files` from containerd:

```
containerd[2416]: failed to watch oom events
  failed to get memory.events watch FD: failed to create inotify fd:
  too many open files
  runtime=io.containerd.runc.v2
```

Roughly 50–150 occurrences per 45 minutes depending on how much container churn
is happening. Root cause: containerd creates one inotify instance **per
container** to watch `memory.events`, and
`/proc/sys/fs/inotify/max_user_instances` is **128** shared across every root
process, while the box runs ~90 containers. At capture, 133 inotify instances
were already live against that 128 ceiling. It fires when containers churn
(start/stop batches), which is why it looks absent when sampled at rest — and
why the cycling described above makes it worse rather than better.

**This is NOT file-descriptor exhaustion.** It is a different kernel counter
with a much smaller cap: `/proc/sys/fs/file-max` is unlimited, Elasticsearch
sits at a tiny fraction of 524288, and containerd is at 0 of 524288. Chasing
`file-max` will not fix this and raising it would be a red herring.

Recommendation, **not applied**:

```
fs.inotify.max_user_instances=1024
```

This is left unapplied pending Niklas. It is a host-wide change on a box running
the honeypot fleet, and it is his call, not this doc's. Verify the current value
and the live instance count before changing it; the diagnosis above is what
makes the change safe to make, not the number itself.

## What was deliberately left alone

- **`ghidra-ollama-1`** — `Up 4 days (healthy)`, still serving `qwen3:14b` on
  127.0.0.1:11434. Not PentAGI's; other work depends on it.
- **`hp-galah-llm-broker`** — the other 11434 listener, `Up 4 days (healthy)`.
- **Every `hp-*` honeypot container** and every other Arcane/dockge stack —
  ~90 containers running on the host, unchanged.
- **All 11 PentAGI volumes**, the ollama model store inside them, all compose
  files, `.env`, `docker-ssl/` and `.bak/`.
- **The `inotify` sysctl** — recorded, deliberately not applied.

## If it has to be restarted

Everything needed is on the host:

```bash
cd /var/pentagi && docker compose \
  -f docker-compose.yml \
  -f docker-compose.override.yml \
  up -d
```

`pentagi-network` is declared `external: true`, so if it is ever missing compose
will not recreate it — `docker network create pentagi-network` first. Expect the
`.env` drift above to bite: the on-disk file does not match the configuration
that is actually running. Adding `-f docker-compose-graphiti.yml` brings up
`neo4j` and `graphiti`; adding `--profile vllm` would try to start the vLLM
container, which nothing in the current configuration wants.

A restart destroys in-flight terminal sandbox work. Stop and check for whatever
is cycling the stack before issuing one.
