# Container-scan measurement (#3501) — MEASUREMENT ONLY

**This document changes no behaviour.** `scripts/list-docker-base-images.py`,
`ACCEPTED_CVES`, and `.github/workflows/image-security-scan.yml` are all
untouched by the commit that adds this file. Nothing here is wired into CI.
It is the evidence the container-scan gate decision waits on, and nothing
else.

## What was measured, and how

- **Image refs**: exactly what `scripts/list-docker-base-images.py` prints on
  stdout, deduplicated and sorted. The script's stderr `not scannable:`
  lines are excluded.
- **Scanner**: `trivy image --scanners vuln --severity CRITICAL,HIGH`,
  trivy 0.74.0, run per image against the registry (not a local image).
- **`fixable`** counts findings where trivy reports a non-empty
  `FixedVersion`. That is trivy's own judgement that a patched artifact
  exists — it is not a claim that this repo can or should take it.
- **Date**: 2026-10-04.

Every number below comes from that scan. Nothing is estimated, carried
over from a previous run, or filled in from memory.

## Headline counts

| | |
|---|---|
| image refs emitted | **67** |
| refs with a complete scan | **66** |
| refs with an incomplete scan | **1** |
| total CRITICAL+HIGH findings | **9139** |
| of those, fixable | **5346** |
| of those, no fix published | **3793** |

### Verdicts

| verdict | count | meaning |
|---|---|---|
| `fix-now` | 55 | has at least one finding with a published fix |
| `genuinely-unfixable` | 0 | has findings, none with a published fix |
| `clean` | 11 | zero CRITICAL/HIGH findings — needs no exemption and has none |
| **INCOMPLETE** | **1** | scan did not complete; **no count is reported** |

> The task brief asked for a `no-reason-written` verdict column. Measured,
> that category does not exist as a scan outcome — it is a property of the
> *allowlist*, not of the image. It is reported as its own column below
> instead, because folding it into the verdict would have miscounted
> exempt-but-clean images. **No image came out `genuinely-unfixable`:**
> every one of the 66 fully-scanned images
> with findings has at least one fix available. That is itself a finding
> about the current exemption list — see below.

## Two structural problems, measured

### 1. The brief says 61 images. The script emits 67.

`list-docker-base-images.py` emits **67** unique refs, not 61. No
filter applied here reduces it to 61. If 61 is the number the decision was
meant to be made against, the discrepancy needs resolving before the gate
is armed — the scope of the gate would otherwise be ambiguous. **Not
resolved here**: this document only reports what the script emits today.

### 2. 30 of 40 `ACCEPTED_CVES` keys cannot match any emitted ref.

This is the bare-tag vs digest-pinned problem, and it is much worse than
partial. `list-docker-base-images.py` emits **digest-pinned** refs
(tag`@sha256:...`) for 58 of 67 images; only **9** are emitted bare.
But the keys in `ACCEPTED_CVES` are overwhelmingly written in **bare-tag**
form.

Because `allow_cve_findings(ref)` compares the key against the full printed
reference, a bare-tag key never matches a digest-pinned ref:

- **30 keys match nothing at all.** They are dead entries — worse
  than absent, because each reads as an exemption somebody argued for while
  covering no image.
- **29 more emitted refs have a bare-tag key that will not match**, for the
  same reason.
- Only **10 keys match an emitted ref exactly.**

Net: **10 of 67** images would actually be exempted. The other
57 would be gated. The gate would therefore fail on
55 images that the list appears to excuse — which is
consistent with the reported "7 contradicted exemption reasons" but is much
broader than 7.

Three of the 40 keys *are* written in digest-pinned
form, and all three match; the mechanism works, the spellings are wrong.

### 3. The reasons are contradicted by the scan, mostly.

Of the 39 emitted refs that have a
reason written, **37 have at least one
finding with a published fix**. A reason that says "no patched build is
published" is directly contradicted by trivy reporting a `FixedVersion` for
that image. These are the reasons that need rewriting before the gate is
armed.

## Per-image table

Sorted: incomplete first, then by verdict, then by fixable count descending.

| # | image ref (as emitted by list-docker-base-images.py) | total | fixable | ACCEPTED_CVES key | key matches emitted ref? | current reason | verdict |
|---|---|---|---|---|---|---|---|
| 1 | `docker.n8n.io/n8nio/n8n:latest` | INCOMPLETE | INCOMPLETE | `docker.n8n.io/n8nio/n8n:latest` | exact match | — | **INCOMPLETE** |
| 2 | `alpine/socat:latest@sha256:5f275aa1b6e9889c851f61097142ee050fc6ac4615b4ea64ac1f2b0e81ff8d7f` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 3 | `alpine:edge@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 4 | `busybox:1.38.0@sha256:dc2d74b28e4cf8984fa52af1f39bc7c3d9c73760b41a74d629f5d11b1ab28616` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 5 | `busybox:1.38@sha256:dc2d74b28e4cf8984fa52af1f39bc7c3d9c73760b41a74d629f5d11b1ab28616` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 6 | `busybox:latest@sha256:dc2d74b28e4cf8984fa52af1f39bc7c3d9c73760b41a74d629f5d11b1ab28616` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 7 | `ghcr.io/getarcaneapp/manager:v2.11.1@sha256:527af49cb544f4fea97848692761b8df5b328ea5b24e156318d570a3f2c0e884` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 8 | `kalilinux/kali-rolling:latest@sha256:3093a0bd1f1196f4b10ab8e4a671929a6cd0153768642e6aa20dfced5e4132c5` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 9 | `mcr.microsoft.com/dotnet/aspnet:10.0` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 10 | `mcr.microsoft.com/dotnet/runtime:10.0` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 11 | `mcr.microsoft.com/dotnet/sdk:10.0` | 0 | 0 | `mcr.microsoft.com/dotnet/sdk:10.0` | exact match | build-time SDK used only to COMPILE the sidecar; never present in a running container, so its CVEs are not reachable at runtime. | `clean` |
| 12 | `willfarrell/autoheal@sha256:fc003424b710dec10b0a96527c1e5b256b8a00431e9a2342503eaa73f6c31e14` | 0 | 0 | — none — | NO -- no key at all | (none) | `clean` |
| 13 | `golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db` | 1386 | 1075 | `golang:1.23-bookworm` | NO -- key is bare-tag, ref is digest-pinned | build-time toolchain for the API server; ships in a build stage that the runtime image does not inherit. | `fix-now` |
| 14 | `golang:1.23@sha256:60deed95d3888cc5e4d9ff8a10c54e5edc008c6ae3fba6187be6fb592e19e8c0` | 1386 | 1075 | `golang:1.23` | NO -- key is bare-tag, ref is digest-pinned | build-time toolchain for the API server; ships in a build stage that the runtime image does not inherit. | `fix-now` |
| 15 | `nicolaka/netshoot:latest@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70` | 442 | 440 | `nicolaka/netshoot:latest` | NO -- key is bare-tag, ref is digest-pinned | floating-tag operator toolbox image, pulled by the diagnostic compose file only and never by a deployed stack; its CVEs are inherited from whatever alpine base the tag currently resolves to. | `fix-now` |
| 16 | `python:3.13@sha256:debad600e8d6e754012528dc796488acc52438fea3d28596b87262df9b91c71e` | 680 | 383 | `python:3.13` | NO -- key is bare-tag, ref is digest-pinned | runtime base for the dashboard BFF image; pinned with the Node-side tooling and no patched 3.13 build is published. | `fix-now` |
| 17 | `nvidia/cuda:12.4.1-devel-ubuntu22.04` | 568 | 352 | `nvidia/cuda:12.4.1-devel-ubuntu22.04` | exact match | analysis host GPU toolchain, pinned by driver compatibility with the installed NVIDIA driver; the 12.x family is the only branch that supports it and no patched tag exists upstream. | `fix-now` |
| 18 | `node:22@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d` | 654 | 160 | `node:22` | NO -- key is bare-tag, ref is digest-pinned | build-time and BFF runtime base; the 22.x line is pinned to match the dashboard-next engines field. | `fix-now` |
| 19 | `rust:1-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922` | 640 | 147 | — none — | NO -- no key at all | (none) | `fix-now` |
| 20 | `postgres:16.8` | 216 | 122 | `postgres:16.8` | exact match | state store for the analysis host; the 16 branch is pinned for extension compatibility and 16.8 is the newest tagged build this repo has verified against its schema. | `fix-now` |
| 21 | `postgres:16.8@sha256:301bcb60b8a3ee4ab7e147932723e3abd1cef53516ce5210b39fd9fe5e3602ae` | 216 | 122 | `postgres:16.8@sha256:301bcb60b8a3ee4ab7e147932723e3abd1cef53516ce5210b39fd9fe5e3602ae` | exact match | digest-pinned spelling of the postgres:16.8 entry above; the digest moves on every Dependabot bump, at which point this key retires itself and the gate applies. | `fix-now` |
| 22 | `docker.elastic.co/elasticsearch/elasticsearch:9.5.3@sha256:f456578fc2a620a8a4f4c21d070fff1f6070345adb2be5e5626b65be72aea350` | 116 | 103 | `docker.elastic.co/elasticsearch/elasticsearch:9.5.3` | NO -- key is bare-tag, ref is digest-pinned | 9.5.x is the maintenance branch this fleet is pinned to for index-compatibility; the fix lands in a later 9.5.z, which moves with the digest bump this key is keyed on. | `fix-now` |
| 23 | `mongo:7.0@sha256:b6421fd6d1c5ded6377b397d8983e2f82e2100dc5123332dcfda2065a472be5b` | 99 | 99 | `mongo:7.0@sha256:b6421fd6d1c5ded6377b397d8983e2f82e2100dc5123332dcfda2065a472be5b` | exact match | digest-pinned spelling of the mongo:7.0 entry above; the digest moves on every Dependabot bump, at which point this key retires itself and the gate applies. | `fix-now` |
| 24 | `docker.io/zeek/zeek:8.0@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3` | 221 | 95 | `docker.io/zeek/zeek:8.0` | NO -- key is bare-tag, ref is digest-pinned | the Zeek 8.0 series is the newest this repo's sensor deployment supports; upstream ships fixes in 8.1+, which is a sensor-protocol migration tracked separately from a base-image bump. | `fix-now` |
| 25 | `zeek/zeek:latest@sha256:703f0b22af150d9418739b2a012fbfb5d01ee004aded3bd43b0175010db05928` | 221 | 95 | — none — | NO -- no key at all | (none) | `fix-now` |
| 26 | `docker.io/unsloth/unsloth@sha256:c776f36dc13c869260d08b0573b109fe60e363a675991f24e83e3e03853246d0` | 268 | 93 | `docker.io/unsloth/unsloth` | NO -- key is bare-tag, ref is digest-pinned | model-serving image built for a pinned CUDA/transformers stack; rebuilding it is a model-accuracy change, not a tag bump. | `fix-now` |
| 27 | `ghcr.io/arkime/arkime/arkime:v6-latest@sha256:754ac8d50c8d4136462c3bb3701c400be66310020ab01d5ea94a4e73942b0127` | 169 | 89 | `ghcr.io/arkime/arkime/arkime:v6-latest` | NO -- key is bare-tag, ref is digest-pinned | capture node pinned to the v6 series for on-disk index compatibility with the v6.7.0 readers already deployed; patched v6 tag tracking is in flight and this key retires when the digest moves. | `fix-now` |
| 28 | `ghcr.io/arkime/arkime/arkime:v6.7.0@sha256:754ac8d50c8d4136462c3bb3701c400be66310020ab01d5ea94a4e73942b0127` | 169 | 89 | `ghcr.io/arkime/arkime/arkime:v6.7.0` | NO -- key is bare-tag, ref is digest-pinned | same on-disk-index constraint as the v6-latest entry: a capture and its readers must be the same v6 minor. | `fix-now` |
| 29 | `rust:1-slim-bookworm@sha256:94e9efa4033213dbb70d4f665527e7ece3944ddb7ba1dd2e43f6fd6e2490af58` | 308 | 74 | — none — | NO -- no key at all | (none) | `fix-now` |
| 30 | `mitmproxy/mitmproxy:latest@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f` | 110 | 66 | `mitmproxy/mitmproxy:latest@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f` | exact match | digest-pinned spelling of the mitmproxy entry above; retires itself when the digest moves. | `fix-now` |
| 31 | `mcr.microsoft.com/dotnet/sdk:10.0.101` | 64 | 64 | `mcr.microsoft.com/dotnet/sdk:10.0.101` | exact match | build-time SDK used only to COMPILE the sidecar (sandbox/ghosts builds it); never present in a running container, so its CVEs are not reachable at runtime. | `fix-now` |
| 32 | `jasonish/evebox:latest@sha256:216ef6eb5bfcc1d8d9b13a41ba38eb067060e68c3970fa4579d07c8f5d5a9326` | 55 | 55 | `jasonish/evebox:latest` | NO -- key is bare-tag, ref is digest-pinned | vendor-published image with no upstream patch stream for the tagged build; a rebuild is a vendor-side action. | `fix-now` |
| 33 | `dtagdevsec/conpot:24.04.1@sha256:ff37c322037ad8c1f4f05c2c93f7b60cc5f56b7f37a2c4cbc16901ec70bddb5b` | 52 | 52 | `dtagdevsec/conpot:24.04.1` | NO -- key is bare-tag, ref is digest-pinned | vendor image; this repo applies its own patches at build time from arcane/home/honeypot-conpot, so the base is a starting point rather than the shipped artifact. | `fix-now` |
| 34 | `jasonish/suricata:latest@sha256:51a59543dcb6e5f9d586c06053c6b71d462cea919b45719090443f4af1428780` | 48 | 48 | `jasonish/suricata:latest` | NO -- key is bare-tag, ref is digest-pinned | vendor-published image with no upstream patch stream for the tagged build; a rebuild is a vendor-side action. | `fix-now` |
| 35 | `ollama/ollama:0.34.4@sha256:8262851b2846b87c649eddf3e76beb270c52f4d1bc94559f47efde16b0841551` | 45 | 45 | `ollama/ollama:0.34.4` | NO -- key is bare-tag, ref is digest-pinned | local inference runtime pinned for model-file compatibility; the shipped tag lags upstream security fixes. | `fix-now` |
| 36 | `docker.elastic.co/kibana/kibana:9.5.3@sha256:4530cd98c529bc913ae364067f0233ab6cfb9a560644480b365b45f74a18dbf3` | 66 | 43 | — none — | NO -- no key at all | (none) | `fix-now` |
| 37 | `docker.io/unsloth/unsloth@sha256:84511bee77058158ea48c625b490ad0edae1ea10005c459a4a9a10d0569e5642` | 205 | 36 | `docker.io/unsloth/unsloth` | NO -- key is bare-tag, ref is digest-pinned | model-serving image built for a pinned CUDA/transformers stack; rebuilding it is a model-accuracy change, not a tag bump. | `fix-now` |
| 38 | `docker:29.8.1-dind@sha256:3f3c01aaaebf7cce837356b688b7c059a4749f10bd7660dec7c58fc454a283f0` | 29 | 27 | `docker:29.8.1-dind` | NO -- key is bare-tag, ref is digest-pinned | docker-in-docker daemon used by the sandbox detonation path; it runs with no network access to anything but the analysed sample, so its CVE surface is deliberately isolated. | `fix-now` |
| 39 | `python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5` | 71 | 27 | `python:3.14-slim` | NO -- key is bare-tag, ref is digest-pinned | runtime base for a pinned toolchain; the newest 3.14.slim build published so far, upstream has not shipped a patched one. | `fix-now` |
| 40 | `postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af` | 120 | 26 | `postgres:18.6-bookworm` | NO -- key is bare-tag, ref is digest-pinned | state store pinned to 18.6 for pgvector compatibility; the newest 18.6 build published, upstream has not shipped a patched one. | `fix-now` |
| 41 | `python:3.10-slim@sha256:38758a82a44d1acb9bae3dd5f7d2a55452fb44a5ceca7c4589f360f2c4aa3d0c` | 69 | 25 | `python:3.10-slim` | NO -- key is bare-tag, ref is digest-pinned | build-time base for a pinned toolchain; the running containers use 3.12+ (see the ml-worker/llm-worker Dockerfiles). | `fix-now` |
| 42 | `python:3.11-slim@sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6` | 69 | 25 | `python:3.11-slim` | NO -- key is bare-tag, ref is digest-pinned | build-time base for a pinned toolchain; the running containers use 3.12+ (see the ml-worker/llm-worker Dockerfiles). | `fix-now` |
| 43 | `python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217` | 67 | 23 | `python:3.12-slim` | NO -- key is bare-tag, ref is digest-pinned | runtime base for ml-worker/auth-events-worker; the 3.12 branch is pinned for the pinned pip requirements and no patched 3.12.slim build is published yet. | `fix-now` |
| 44 | `docker.elastic.co/beats/filebeat:9.5.3@sha256:ea135eb5b97f2f4cbcf519464b922c5f794e6ebc2dd93822d4ac0be74ef0e29f` | 37 | 17 | — none — | NO -- no key at all | (none) | `fix-now` |
| 45 | `quay.io/keycloak/keycloak:latest` | 23 | 17 | `quay.io/keycloak/keycloak:latest` | exact match | floating tag; the deployed keycloak is pinned to a specific tag in arcane/home/honeypot-keycloak, this reference is a local-dev default only. | `fix-now` |
| 46 | `dinotools/dionaea:latest@sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca` | 16 | 16 | `dinotools/dionaea:latest` | NO -- key is bare-tag, ref is digest-pinned | vendor image; this repo applies its own patches at build time from arcane/home/honeypot-dionaea, so the base is a starting point rather than the shipped artifact. | `fix-now` |
| 47 | `node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32` | 16 | 15 | `node:22-alpine` | NO -- key is bare-tag, ref is digest-pinned | same 22.x pin as the node:22 entry, alpine variant. | `fix-now` |
| 48 | `ghcr.io/maxmind/geoipupdate:v8.0.0@sha256:51e70dd6f16cd3e4d845ac02d09940b10772a75b9d741427d235a78570923c1d` | 12 | 12 | `ghcr.io/maxmind/geoipupdate:v8.0.0` | NO -- key is bare-tag, ref is digest-pinned | geoipupdate v8 is the major this repo's scheduled refresh script is written against; a newer major is an API migration. | `fix-now` |
| 49 | `grafana/grafana` | 8 | 8 | `grafana/grafana` | exact match | floating tag in the monitoring compose file; the deployed stack pins its own version and this reference is a local-dev default only. | `fix-now` |
| 50 | `technitium/dns-server:15.4.0@sha256:df7d90ef0f7b6fff6916d291a7022cd902290cc31c3141d4158b6c375a641b41` | 8 | 8 | — none — | NO -- no key at all | (none) | `fix-now` |
| 51 | `traefik:v3.7.12@sha256:9c2a54d87f76f5c2f5f2682c68394af92fb12c0a2686798d6462a3f84bd78eaf` | 8 | 8 | — none — | NO -- no key at all | (none) | `fix-now` |
| 52 | `docker.io/library/python:3.12-alpine@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a` | 7 | 7 | `docker.io/library/python:3.12-alpine` | NO -- key is bare-tag, ref is digest-pinned | runtime base for a size-constrained worker; same 3.12 pin as the python:3.12-slim entry, alpine variant. | `fix-now` |
| 53 | `mcr.microsoft.com/dotnet/sdk:10.0.400@sha256:e1fc6e423f543119c406d24e2e687d67c569f18f04a37a8b0005d80ad0dcee80` | 7 | 7 | `mcr.microsoft.com/dotnet/sdk:10.0.400` | NO -- key is bare-tag, ref is digest-pinned | build-time SDK used only to COMPILE the sidecar; never present in a running container, so its CVEs are not reachable at runtime. | `fix-now` |
| 54 | `python:3.12-alpine@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a` | 7 | 7 | — none — | NO -- no key at all | (none) | `fix-now` |
| 55 | `valkey/valkey:9.1.2-alpine3.24@sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd` | 7 | 7 | — none — | NO -- no key at all | (none) | `fix-now` |
| 56 | `redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf` | 6 | 6 | — none — | NO -- no key at all | (none) | `fix-now` |
| 57 | `redis:7.4-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf` | 6 | 6 | — none — | NO -- no key at all | (none) | `fix-now` |
| 58 | `tecnativa/docker-socket-proxy:v0.5.0@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459` | 6 | 6 | — none — | NO -- no key at all | (none) | `fix-now` |
| 59 | `debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171` | 60 | 4 | `debian:bookworm-slim` | NO -- key is bare-tag, ref is digest-pinned | same image as docker.io/library/debian:bookworm-slim, spelled without the registry host; bookworm is the oldest supported branch and receives the slowest fixes. | `fix-now` |
| 60 | `docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171` | 60 | 4 | `docker.io/library/debian:bookworm-slim` | NO -- key is bare-tag, ref is digest-pinned | runtime base for the shipped single-binary sensors; bookworm is the oldest supported Debian branch and receives the slowest fixes. | `fix-now` |
| 61 | `curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13` | 3 | 3 | — none — | NO -- no key at all | (none) | `fix-now` |
| 62 | `php:8.5-cli-alpine@sha256:0554eb53778b5316f6b9a3447c9dfa3cf2141c0c02ff816c42cdc9aa240a34aa` | 3 | 3 | — none — | NO -- no key at all | (none) | `fix-now` |
| 63 | `alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` | 2 | 2 | — none — | NO -- no key at all | (none) | `fix-now` |
| 64 | `eclipse-temurin:21-jdk-jammy@sha256:55fb9bf738f5d9b4a6c01b39337e3070d3e27370dd3c478fd1d5d3cd2233c6d8` | 2 | 2 | `eclipse-temurin:21-jdk-jammy` | NO -- key is bare-tag, ref is digest-pinned | build-time JDK for backend-service; the runtime image is distroless and does not inherit it. | `fix-now` |
| 65 | `golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468` | 2 | 2 | — none — | NO -- no key at all | (none) | `fix-now` |
| 66 | `golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc` | 2 | 2 | — none — | NO -- no key at all | (none) | `fix-now` |
| 67 | `quay.io/oauth2-proxy/oauth2-proxy:v7.15.4@sha256:b1b2021fe8f4004573e8d690dec6c7bb29cc44364572cf8510a05bf3a0ae2ded` | 2 | 2 | — none — | NO -- no key at all | (none) | `fix-now` |
## Incomplete measurement

`docker.n8n.io/n8nio/n8n:latest` — **INCOMPLETE**. The scan died on a
registry pull-rate limit, not on anything to do with the image:

```
remote error: GET https://docker.n8n.io/v2/n8nio/n8n/manifests/latest:
TOOMANYREQUESTS: You have reached your unauthenticated pull rate limit.
```

Retried once, same result. No finding count is reported for it, and its
verdict is left unresolved rather than guessed. It has an exact-match
`ACCEPTED_CVES` key, so it is exempt either way — but that is a fact about
the allowlist, not a measurement of the image, and the exemption itself
rests on a reason nobody has checked against a real scan.

## Dead keys — match no emitted ref

Listed so the rewrite starts from a known set rather than a diff.

- `docker.io/zeek/zeek:8.0`
- `ghcr.io/arkime/arkime/arkime:v6-latest`
- `ghcr.io/arkime/arkime/arkime:v6.7.0`
- `docker.elastic.co/elasticsearch/elasticsearch:9.5.3`
- `nicolaka/netshoot:latest`
- `jasonish/suricata:latest`
- `jasonish/evebox:latest`
- `ollama/ollama:0.34.4`
- `docker.io/unsloth/unsloth`
- `dinotools/dionaea:latest`
- `dtagdevsec/conpot:24.04.1`
- `mcr.microsoft.com/dotnet/sdk:10.0.400`
- `golang:1.23-bookworm`
- `golang:1.23`
- `eclipse-temurin:21-jdk-jammy`
- `mongo:7.0`
- `python:3.10-slim`
- `python:3.11-slim`
- `python:3.12-slim`
- `python:3.13`
- `python:3.14-slim`
- `docker.io/library/python:3.12-alpine`
- `docker.io/library/debian:bookworm-slim`
- `debian:bookworm-slim`
- `docker:29.8.1-dind`
- `postgres:18.6-bookworm`
- `ghcr.io/maxmind/geoipupdate:v8.0.0`
- `mitmproxy/mitmproxy:latest`
- `node:22`
- `node:22-alpine`

## What this does not tell you

- Whether a `fixable` finding is one this repo **should** take. Trivy
  reporting a `FixedVersion` means a patch exists upstream; adopting it may
  be a major-version migration, an on-disk format change, or a driver
  incompatibility. Only a human per image can answer that.
- Anything about the `INCOMPLETE` image.
- Whether the current reasons are wrong in substance or only wrong in
  spelling. Several are contradicted on substance (a fix exists); that is
  separable from the bare-tag/digest problem, and both need fixing.
