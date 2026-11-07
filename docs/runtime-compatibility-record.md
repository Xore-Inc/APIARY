# Runtime compatibility record

Status: verified on the live homeserver on 2026-08-01 for
[#82](https://github.com/Xore/APIARY/issues/82).

This is a compatibility record, not an event sample. Elasticsearch commands
used only cluster/index metadata, field capabilities, and a `size: 0`
maximum-timestamp aggregation. No `_source`, captured command, credential,
payload, address, domain, or model output was read into this record. The
running Windows QEMU analysis VM was only observed to confirm it stayed
running; it was not signalled, queried, or managed.

## Result

Gate A passes with two corrections to the earlier plans:

1. `torch==2.13.0+cu124` does not exist. The verified GPU pin is
   `torch==2.13.0+cu126` from PyTorch's official `cu126` index.
2. Docker reports `honeynet` as `internal=false`. It is the required shared
   bridge, but it is not an egress-control boundary.

The CPU dependency set, replacement CUDA wheel, embedding library/model
revision, local Ollama artifact, GPU passthrough, capacity, and ingestion path
all pass.

## Host and container runtime

Commands were run after an authenticated shell was established to the
homeserver. Hardware UUIDs are intentionally omitted.

| Check | Command | Observed 2026-08-01 | Result |
|---|---|---|---|
| UTC time | `date -u +%Y-%m-%dT%H:%M:%SZ` | `2026-08-01T11:07:44Z` | PASS |
| OS/kernel | `. /etc/os-release; echo "$PRETTY_NAME"`; `uname -srmo` | Ubuntu 26.04 LTS; Linux 7.0.0-28-generic x86-64 | PASS |
| CPU | `nproc` | 16 logical CPUs | PASS |
| RAM/swap | `free -b` | 98,291,458,048 bytes RAM, 66,144,538,624 available; 8,589,930,496 bytes swap | PASS |
| Root disk | `df -B1 /` | 249,792,131,072 bytes; 13% used | PASS |
| Stack/Docker disk | `df -B1 /opt/stacks /var/lib/docker` | 1,918,879,416,320 bytes; 19% used | PASS |
| GPU | `nvidia-smi --query-gpu=name,driver_version,memory.total,compute_cap --format=csv,noheader` | Quadro RTX 4000; driver 580.173.02; 8192 MiB; capability 7.5 | PASS |
| NVIDIA toolkit | `nvidia-ctk --version` | 1.19.1, commit `09ceee5d…` | PASS |
| Docker/Compose | `docker version --format '{{.Server.Version}}'`; `docker compose version` | 29.6.2; v5.3.1 | PASS |
| NVIDIA runtime | `docker info` (runtime names only) | `io.containerd.runc.v2`, `nvidia`, `runc` | PASS |
| GPU passthrough | `docker run --rm --network none --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader` | Same RTX 4000/driver/VRAM; image already cached | PASS |
| Shared network | `docker network inspect honeynet --format 'name={{.Name}} driver={{.Driver}} internal={{.Internal}}'` | `honeynet`, bridge, `internal=false` | PASS with security correction |

**Correction (2026-10-17):** the GPU row above is the 2026-08-01 measurement and
is kept as recorded. It no longer describes the host. GPU 0 is an NVIDIA RTX 4000
Ada Generation (20475 MiB, per `docs/gpu-llm-analysis-worker.md`), and a Quadro
P2200 is passed to the Windows sandbox VM (#1539). `nvidia-smi` reported driver
615.71.09 on 2026-10-17. `analysis/ghidra/models/approved-models.json` still
records `approved_host.driver` 595.84 and needs re-recording at the next benchmark
pin refresh. The "Quadro RTX 4000 / 8192 MiB" figures were corrected in #602.

The host Python is 3.14.4, but it is not a worker dependency. The worker base
resolved to `python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf`
and reported Python 3.12.13.

## Elasticsearch ingestion and source shape

| Check | Command | Observed | Result |
|---|---|---|---|
| Core containers | `docker inspect` health for Elasticsearch, Filebeat, dashboard, EveBox, Kibana, and Arkime viewer | all running; ES/dashboard healthy; others define no healthcheck | PASS |
| Filebeat output | `docker exec hp-filebeat filebeat test output --strict.perms=false` | DNS, dial, and server conversation passed for every configured output; ES 8.13.4 | PASS |
| ES version | `GET /` | Elasticsearch 8.13.4; Lucene 9.10.0; build `da95df11…` | PASS |
| ES image | `docker inspect hp-elasticsearch`; `docker image inspect` | `elasticsearch:8.13.4`, digest `sha256:dfd318b417be1356d9c7fdd6a5577c8a45553ac9d34354929a416c69c85daa9f` | PASS |
| Cluster | `GET /_cluster/health` | green; one node; 99 active primaries; zero unassigned; not timed out | PASS |
| Source indices | `GET /_cat/indices/honeypot-v2-*?format=json&h=index,health,status,docs.count,store.size&s=index` | four green/open daily backing indices from 2026-07-29 through 2026-08-01 | PASS |
| Freshness | `POST /honeypot-v2-*/_search` with `size:0`, exact count, and `max(@timestamp)` | 765,213 documents; latest `2026-08-01T11:07:43.352Z`, one second before the check | PASS |

The canonical selector is `honeypot-v2-*`; the current backing-index shape is
`.ds-honeypot-v2-YYYY.MM.DD-YYYY.MM.DD-NNNNNN`.

### Redacted field capabilities

Command:

```bash
curl -fsS \
  'http://127.0.0.1:9200/honeypot-v2-*/_field_caps?fields=@timestamp,event.sensor,source.ip,destination.ip,destination.port,network.protocol,process.command_line,threat.indicator.file.hash.sha256,honeypot.session,honeypot.eventid,log.file.path,ot.persona,event.id,event.ingested,log.offset'
```

| Field | Type | Searchable | Aggregatable |
|---|---|---:|---:|
| `@timestamp` | date | yes | yes |
| `event.sensor` | keyword | yes | yes |
| `source.ip` / `destination.ip` | ip | yes | yes |
| `destination.port` | integer | yes | yes |
| `network.protocol` | keyword | yes | yes |
| `process.command_line` | keyword | yes | yes |
| `ot.persona` | keyword | yes | yes |
| `log.file.path` | text | yes | no |

No mapping was returned for `threat.indicator.file.hash.sha256`,
`honeypot.session`, `honeypot.eventid`, `event.id`, `event.ingested`, or
`log.offset`. Raw values may exist in `_source`, but this record did not read
them. Issue #132 owns stable sensor/session/cursor promotion.

## Exact language, library, and model pins

| Artifact | Verification | Exact observed pin | Result |
|---|---|---|---|
| Python worker base | clean worker builds; `python --version` | Python 3.12.13 at the digest above | PASS |
| ES Python client | clean ML/LLM builds/imports | `elasticsearch==8.19.3` against ES 8.13.4 | PASS |
| ES Python client 8.x, post-migration re-check (#2090, 2026-08-26) | live roundtrip from the exact pinned version (`pip install elasticsearch==8.19.3` in a throwaway `python:3.12-slim` container on the honeynet) against the deployed cluster: `info`, `ping`, index create, doc index, refresh, term search, index delete | `elasticsearch==8.19.3` against ES `9.5.1` (`docker.elastic.co/elasticsearch/elasticsearch:9.5.1@sha256:b70b3017fbd35310bc57e7e3f8c0ca42ca0b94df3331f747b7cdcfddae430a5a`), all steps OK | PASS |
| ES Python client 9.x, post-migration check (#2090, 2026-08-26) | same live roundtrip method with `elasticsearch==9.5.0` (the `agent-intrusion-corpus` pin) against the same deployed cluster | `elasticsearch==9.5.0` against ES `9.5.1`; all steps OK | PASS |
| ML CPU environment | clean `ml-worker` build; offline imports; `pip check` | torch 2.13.0+cpu, NumPy 2.4.6, pandas 3.0.5, scikit-learn 1.9.0, PyOD 3.6.2, Numba 0.66.0, llvmlite 0.48.0, Redis client 8.0.1, Requests 2.34.2 | PASS |
| Planned CUDA pin | official `cu124` dry-run install | that index offers 2.4.0–2.6.0; no 2.13.0 wheel | **FAIL — superseded** |
| Replacement CUDA | clean `cu126` install; network-disabled GPU tensor check | `torch==2.13.0+cu126`; CUDA 12.6; cuDNN 9.10.2; `sm_75`; capability 7.5 | PASS |
| Embedding library | clean install on exact CPU environment; offline import/load | `sentence-transformers==3.0.1`; Transformers 4.57.6 | PASS |
| Embedding model | API SHA, build-time prefetch, network-disabled encoding | `sentence-transformers/all-MiniLM-L6-v2@1110a243fdf4706b3f48f1d95db1a4f5529b4d41`; shape `(1, 384)` | PASS |
| Ollama | image/container inspection and CLI version | `ollama/ollama:0.32.0@sha256:57f573b47f1f71ebb445789f279fe3e596a8beab182f7cf486db9205bad87c5a` | PASS |
| Session chat model at #82 verification | local `/api/tags`, metadata only | `qwen3.5:4b`, digest `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd`, GGUF Q4_K_M, 4.7B | PASS; superseded by #158's exact `qwen3.5:9b` qualification |
| Ollama embedding model | `ollama list` | none installed | NOT REQUIRED — ML owns embeddings in v1 |

The CUDA check asserted one device, exact wheel version, capability `(7, 5)`,
and a deterministic matrix checksum; it left no compute process. The embedding
test used synthetic text, downloaded only during image build, and then encoded
with `--network none` and a read-only runtime filesystem.

The #2090 ES-client rows are the recorded re-verification that
`.github/dependabot.yml`'s ignore-rule doctrine requires before any
`elasticsearch` pin moves: the server had moved 8.13.4 → 8.19.20 → 9.5.1
(#1408/#1410) with the client pins held, so every pairing actually in
production was exercised against the live 9.5.1 cluster rather than
assumed from the compatibility table. Both directions of Elastic's N/N-1
policy showed up in this deployment's history: a 9.x client's
`compatible-with=9` was rejected by the 8.x era's servers (#62/#593),
while an 8.x client's `compatible-with=8` is accepted by today's 9.x one.
The roundtrips used a throwaway `pin-verify-2090` index, deleted at the
end; no production index was touched.

## Downstream decisions

- #67 must use `torch==2.13.0+cu126`, retain the verified CPU fallback, and
  prefetch the embedding model by immutable revision.
- #83 replaces the worker's planned `honeynet` attachment with the internal
  `honeypot-llm-data` Elasticsearch network. Together with the internal
  `honeypot-llm` model network, the worker has no Docker route to the Internet.
- #132 remains the owner for mapped session/event/cursor fields.
- Host Python must not leak into worker assumptions; Python 3.12 is the
  verified container contract.
