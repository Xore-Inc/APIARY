#!/usr/bin/env python3
"""Swarm stack conventions lint (#3590, epic #3587).

Every stack under swarm/stacks/<name>/stack.yml is deployed by its own Arcane
GitOps sync (targetType swarm_stack). This checks the conventions that make
those deploys safe to run unattended. It is the deploy-side companion of
scripts/check-swarm-images.py (#3597), which owns the image half (`build:` and
digest pinning) and is not repeated here.

Per stack:
  - the directory name is a valid Arcane/Docker stack name.
  - top-level `secrets:` are `external: true` with a versioned `name: <x>_vN`.
    Secret values never live in git; they are created on a manager
    (ops/swarm/stackctl.py secret create) and rotated by bumping N.
  - top-level `configs:` are `external: true` with a versioned `name: <x>_vN`
    and an `x-apiary-file:` inside the stack directory. stackctl.py creates the
    config from that file at the commit being deployed. Not `file:`: Arcane
    prunes the configs it manages right after a deploy, which breaks every
    rollback that needs a fresh task (proved in #3590).

Per service:
  - no `restart:` (swarm ignores it), no `container_name:`, no autoheal label.
    Swarm replaces unhealthy tasks itself; autoheal is the compose-era answer
    (#3585) and fights the orchestrator.
  - a `healthcheck:` with a `test:` (not disabled). Health is what makes
    `failure_action: rollback` mean anything.
  - deploy.restart_policy with a condition.
  - deploy.update_config: failure_action rollback, an explicit order and a
    monitor window; deploy.rollback_config: an explicit order and
    failure_action pause.
  - deploy.labels apiary.pause in safe|unit|never (default deny, as in
    scripts/honeypot-pause.sh), with apiary.pause.reason. safe/unit services
    must be replicated (a global service cannot be scaled to 0).
  - no plain secret-looking environment value: PASSWORD/TOKEN/SECRET/API_KEY
    variables use the `_FILE` form pointing into /run/secrets/.
  - an explicit homeserver placement (#3722). The homeserver (labels
    sensor=true gpu=true) is an `Active` node, because a non-Active node
    rejects the network-attachment tasks of its Compose containers. So
    "keep off the sensor/ES host" (#3583) is a constraint, not availability.
    Each service either excludes it (`node.labels.sensor == false`, or
    `node.labels.edge == true` for VPS edge stacks), pins to
    it (`node.labels.sensor == true`, `node.labels.gpu == true` or
    `node.hostname == supermicro`), or opts in with the deploy labels
    `apiary.homeserver: allow` and `apiary.homeserver.reason`.
  - sensor services (`node.labels.sensor == true`, #3593) publish only with
    `mode: host` (the ingress mesh would replace the attacker's source IP),
    and every published port is listed in
    ops/firewall/hosts/homeserver-swarm-host-ports.txt, so
    home-swarm-host-guard.sh keeps it off the LAN (a host-mode port binds
    every address of the node).
  - GPU services (#3594, docs/SWARM-GPU.md): swarm ignores
    `deploy.resources.reservations.devices`, so a GPU is reserved only as the
    generic resource `NVIDIA-GPU`. A service reserving it must pin to
    `node.labels.gpu == true` and use `stop-first` for update and rollback:
    there is one GPU, so a start-first replacement would wait forever for the
    unit its predecessor still holds.

Usage:
  python3 scripts/check-swarm-stacks.py [--root DIR] [FILE...]

Needs PyYAML.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("check-swarm-stacks.py needs PyYAML: python3 -m pip install pyyaml\n")
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]

# Must equal SWARM_STACK_GLOBS in scripts/check-swarm-images.py (#3597); the
# test suite asserts the two agree once both files exist.
SWARM_STACK_GLOBS = (
    "swarm/stacks/*/stack.yml",
    "swarm/stacks/*/stack.yaml",
)
# Linted like a stack, never deployed (not under swarm/stacks/).
TEMPLATE = "swarm/template/stack.yml"

STACK_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
VERSIONED = re.compile(r"^[a-z0-9][a-z0-9_.-]*_v[0-9]+$")
SECRETISH_ENV = re.compile(r"(^|_)(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)$")
PAUSE_VERDICTS = {"safe", "unit", "never"}
RESTART_CONDITIONS = {"any", "on-failure", "none"}
UPDATE_ORDERS = {"start-first", "stop-first"}
GPU_KIND = "NVIDIA-GPU"
GPU_PIN = re.compile(r"^node\.labels\.gpu\s*==\s*true$")
# Constraints that settle whether a task may run on the homeserver (#3722).
_WS = r"\s*"
HOMESERVER_EXCLUDE = re.compile(rf"^node\.labels\.(sensor{_WS}=={_WS}false|edge{_WS}=={_WS}true)$")
HOMESERVER_PIN = re.compile(
    rf"^(node\.labels\.sensor{_WS}=={_WS}true|node\.labels\.gpu{_WS}=={_WS}true|node\.hostname{_WS}=={_WS}supermicro)$"
)


def stack_files(root: Path) -> list[Path]:
    found: set[Path] = set()
    for pattern in SWARM_STACK_GLOBS:
        found.update(p for p in root.glob(pattern) if p.is_file())
    return sorted(found)


def _env_items(env) -> list[tuple[str, str | None]]:
    if not env:
        return []
    if isinstance(env, dict):
        return [(str(k), None if v is None else str(v)) for k, v in env.items()]
    out = []
    for item in env:
        key, sep, value = str(item).partition("=")
        out.append((key, value if sep else None))
    return out


def _labels(raw) -> dict[str, str]:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    out = {}
    for item in raw:
        key, _, value = str(item).partition("=")
        out[key] = value
    return out


SWARM_HOST_PORTS = "ops/firewall/hosts/homeserver-swarm-host-ports.txt"
SENSOR_PIN = re.compile(r"^node\.labels\.sensor\s*==\s*true$")


def _guard_ports(root: Path) -> set[tuple[str, int]]:
    f = root / SWARM_HOST_PORTS
    out: set[tuple[str, int]] = set()
    if f.is_file():
        for line in f.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and not parts[0].startswith("#") and parts[1].isdigit():
                out.add((parts[0], int(parts[1])))
    return out


def _published(ports) -> list[tuple[str, int | None, str]]:
    """(protocol, published, mode) for long-syntax ports; short syntax -> mode 'ingress'."""
    out = []
    for p in ports or []:
        if isinstance(p, dict):
            pub = p.get("published")
            out.append((str(p.get("protocol", "tcp")), int(pub) if pub is not None else None,
                        str(p.get("mode", "ingress"))))
        else:
            out.append(("tcp", None, "ingress"))
    return out


def check_file(path: Path, root: Path, *, template: bool = False) -> list[str]:
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    errors: list[str] = []

    def err(msg: str) -> None:
        errors.append(f"{rel}: {msg}")

    if not template and not STACK_NAME.match(path.parent.name):
        err(f"stack directory {path.parent.name!r} is not a valid stack name (lowercase, digits, - and _)")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{rel}: unparseable YAML: {exc}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict) or not doc["services"]:
        return [f"{rel}: no services"]

    for name, sec in (doc.get("secrets") or {}).items():
        sec = sec or {}
        if not sec.get("external"):
            err(f"secret {name}: must be `external: true`; secret values never enter git (create it with stackctl.py secret create)")
        if not VERSIONED.match(str(sec.get("name", ""))):
            err(f"secret {name}: needs a versioned `name: <base>_vN` (got {sec.get('name')!r})")
        for key in ("file", "environment", "content"):
            if key in sec:
                err(f"secret {name}: `{key}:` would put the value in git or the sync; use an external secret")

    stack_dir = path.parent.resolve()
    for name, cfg in (doc.get("configs") or {}).items():
        cfg = cfg or {}
        if not VERSIONED.match(str(cfg.get("name", ""))):
            err(f"config {name}: needs a versioned `name: <base>_vN` (got {cfg.get('name')!r}); bump N when the file changes")
        for key in ("file", "content", "environment"):
            if key in cfg:
                err(f"config {name}: `{key}:` makes Arcane manage and prune the config, which breaks rollback; "
                    "use `external: true` + `x-apiary-file:`")
        if not cfg.get("external"):
            err(f"config {name}: must be `external: true` (stackctl.py creates it from `x-apiary-file:`)")
        src = cfg.get("x-apiary-file")
        if not src:
            err(f"config {name}: needs `x-apiary-file:` naming its source inside the stack directory")
            continue
        target = (path.parent / str(src)).resolve()
        if not target.is_relative_to(stack_dir):
            err(f"config {name}: file {src!r} leaves the stack directory; Arcane only reads files inside it")
        elif not target.is_file():
            err(f"config {name}: file {src!r} does not exist")

    for svc_name, svc in doc["services"].items():
        svc = svc or {}
        where = f"service {svc_name}"
        for key in ("restart", "container_name"):
            if key in svc:
                err(f"{where}: `{key}:` is ignored by swarm; use deploy.restart_policy / the service name")
        labels = _labels(svc.get("labels"))
        deploy = svc.get("deploy") or {}
        dlabels = _labels(deploy.get("labels"))
        if any(k.startswith("autoheal") for k in (*labels, *dlabels)):
            err(f"{where}: autoheal labels do not belong in a swarm stack; swarm restart_policy + healthcheck replace it (#3585)")

        hc = svc.get("healthcheck")
        if not isinstance(hc, dict) or hc.get("disable") or not hc.get("test"):
            err(f"{where}: needs a healthcheck with `test:`; failure_action: rollback only works on health")

        rp = deploy.get("restart_policy") or {}
        if rp.get("condition") not in RESTART_CONDITIONS:
            err(f"{where}: deploy.restart_policy.condition must be one of {sorted(RESTART_CONDITIONS)}")

        uc = deploy.get("update_config") or {}
        if uc.get("failure_action") != "rollback":
            err(f"{where}: deploy.update_config.failure_action must be `rollback`")
        if uc.get("order") not in UPDATE_ORDERS:
            err(f"{where}: deploy.update_config.order must be start-first or stop-first (stop-first for host-mode ports)")
        if not uc.get("monitor"):
            err(f"{where}: deploy.update_config.monitor must be set (longer than healthcheck start_period + interval x retries)")
        rc = deploy.get("rollback_config") or {}
        if rc.get("order") not in UPDATE_ORDERS:
            err(f"{where}: deploy.rollback_config.order must be start-first or stop-first")
        if rc.get("failure_action") != "pause":
            err(f"{where}: deploy.rollback_config.failure_action must be `pause` (a failed rollback stops for a human)")

        verdict = dlabels.get("apiary.pause")
        if verdict not in PAUSE_VERDICTS:
            err(f"{where}: deploy.labels apiary.pause must be one of safe|unit|never (default deny)")
        elif not dlabels.get("apiary.pause.reason"):
            err(f"{where}: deploy.labels apiary.pause.reason must say why")
        if verdict in {"safe", "unit"} and deploy.get("mode", "replicated") != "replicated":
            err(f"{where}: apiary.pause={verdict} needs mode replicated; a global service cannot be scaled to 0")
        constraints = [str(c).strip() for c in ((deploy.get("placement") or {}).get("constraints") or [])]
        decided = any(HOMESERVER_EXCLUDE.match(c) or HOMESERVER_PIN.match(c) for c in constraints)
        allow = dlabels.get("apiary.homeserver")
        if allow is not None and allow != "allow":
            err(f"{where}: deploy.labels apiary.homeserver must be `allow` (or drop it and constrain placement)")
        elif allow == "allow" and not dlabels.get("apiary.homeserver.reason"):
            err(f"{where}: deploy.labels apiary.homeserver.reason must say why this service may run on the homeserver")
        elif not decided and allow != "allow":
            err(f"{where}: placement must decide the homeserver (#3722): add `node.labels.sensor == false` to keep "
                "off it, pin with `node.labels.sensor == true`, or set deploy.labels apiary.homeserver: allow + reason")

        if any(SENSOR_PIN.match(c) for c in constraints):
            guarded = _guard_ports(root)
            for proto, pub, mode in _published(svc.get("ports")):
                if mode != "host":
                    err(f"{where}: sensor ports must use long syntax with `mode: host`; the ingress mesh "
                        "hides the attacker's source IP (#3593)")
                elif pub is None:
                    err(f"{where}: sensor ports need an explicit `published:` port")
                elif (proto, pub) not in guarded:
                    err(f"{where}: published {proto} {pub} is not in {SWARM_HOST_PORTS}; "
                        "home-swarm-host-guard.sh would leave it open on the LAN")

        reservations = ((deploy.get("resources") or {}).get("reservations") or {})
        if reservations.get("devices"):
            err(f"{where}: deploy.resources.reservations.devices is ignored by swarm; reserve the GPU as "
                f"generic_resources kind {GPU_KIND} (docs/SWARM-GPU.md)")
        kinds = [((g or {}).get("discrete_resource_spec") or {}).get("kind")
                 for g in (reservations.get("generic_resources") or [])]
        if GPU_KIND in kinds:
            if not any(GPU_PIN.match(c) for c in constraints):
                err(f"{where}: a {GPU_KIND} reservation needs the constraint node.labels.gpu == true")
            if uc.get("order") != "stop-first" or rc.get("order") != "stop-first":
                err(f"{where}: a {GPU_KIND} reservation needs stop-first update_config and rollback_config "
                    "(one GPU: a start-first task waits for the unit its predecessor holds)")

        probe = dlabels.get("apiary.probe")
        if probe and not re.match(r"^(tcp:\d+|http:\d+/\S*)$", probe):
            err(f"{where}: apiary.probe {probe!r} must be tcp:PORT or http:PORT/path")

        for key, value in _env_items(svc.get("environment")):
            if SECRETISH_ENV.search(key) and not key.endswith("_FILE"):
                err(f"{where}: environment {key} looks like a secret; use {key}_FILE=/run/secrets/<name>")
            if key.endswith("_FILE") and value is not None and not value.startswith("/run/secrets/") \
                    and SECRETISH_ENV.search(key[: -len("_FILE")]):
                err(f"{where}: {key} should point into /run/secrets/")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("files", nargs="*", type=Path)
    args = ap.parse_args(argv)
    root = args.root.resolve()
    if args.files:
        targets = [(f.resolve(), False) for f in args.files]
    else:
        targets = [(p, False) for p in stack_files(root)]
        tpl = root / TEMPLATE
        if tpl.is_file():
            targets.append((tpl, True))
    errors: list[str] = []
    for path, is_template in targets:
        errors += check_file(path, root, template=is_template)
    if errors:
        sys.stderr.write(f"swarm stack conventions (#3590): {len(errors)} problem(s)\n")
        for e in errors:
            sys.stderr.write(f"  - {e}\n")
        return 1
    print(f"swarm stack conventions (#3590): {len(targets)} file(s) ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
