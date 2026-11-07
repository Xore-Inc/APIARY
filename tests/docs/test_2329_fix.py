#!/usr/bin/env python3
"""Regression test for #2329: OLLAMA_URL must be wired AND backend-service
must join the network that actually carries the `ollama` alias, or
/api/v1/llm-search (llm_search.rs) answers {"available": false} forever.

The pre-fix split-stack state had both halves wrong in a way that is easy
to half-fix and easy to mis-test:

* arcane/home/honeypot-dashboard-backend/compose.yml set OLLAMA_URL
  nowhere and joined backend-service to `honeynet` only, so even a
  correctly-spelled URL named a host that does not resolve from that
  container -- Docker DNS aliases are per-network, not global.
* arcane/home/honeypot-dashboard/compose.yml *declared* honeypot-llm at
  top level (since #151) and attached it to no service at all. A
  declared-but-unattached network is the exact shape of this bug: the
  name is in the file, greps find it, and nothing is on it.

That second point is why this test asserts against parsed service and
network structures rather than raw file text. A whole-file
`"honeypot-llm" in text` check passes on a dangling declaration and
passes on a bare comment, so it cannot see the regression it is named
after; and the mirror-image `"honeypot-llm" not in text` over-asserts,
because these compose files are heavily commented and a comment saying
where the network went is documentation, not drift.

The contract locked in here, end to end:

1. backend-service's OLLAMA_URL is a value ollama_url() accepts. Its
   accept rules are reimplemented below (and negative-tested, so the
   helper cannot go vacuously true) instead of matching one literal
   string: `http://ollama:11434/` and the mapping form of `environment:`
   are behaviour-identical and would fail a literal match for no reason.
2. The host is `ollama` specifically. ollama_url() also accepts
   `localhost` and loopback IPs -- they clear the hardening gate and then
   resolve to the backend container itself, i.e. accepted-then-silently-
   unreachable, the failure mode #2329 already paid for once.
3. backend-service's own `networks:` list carries that network, and still
   carries `honeynet` (dashboard-next reaches it as
   http://backend-service:8081 there).
4. The backend compose declares honeypot-llm `external: true` under its
   fixed name. Non-external, Compose would stand up a *different* network
   of that name with no ollama on it -- a green `up`, a dead endpoint.
5. analysis/ghidra/docker-compose.ghidra.yml really does publish the
   `ollama` alias on that network, on the port OLLAMA_URL names. Nothing
   else checks this cross-file half; a rename there breaks semantic
   search silently.
6. The dashboard compose no longer declares the network, and neither
   compose has a dangling declaration or a service on an undeclared
   network -- the generalised form of the original bug, and of the way
   part 2 of the fix could itself have broken the stack.

Dependency note: the compose subset needed here is parsed by a small
reader in this file rather than with PyYAML. The `tests/docs/` row in
.github/workflows/quality.yml runs `pip install pytest` and nothing else,
and no other CI-run Python in this repo imports yaml -- a hard dependency
would risk a collection error taking down every file in this directory,
not just this one. When PyYAML *is* importable (it is locally), a test
below cross-checks the reader against it on the real files.
"""
import ipaddress
import pathlib
import re
import urllib.parse

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND_COMPOSE = REPO_ROOT / "arcane/home/honeypot-dashboard-backend/compose.yml"
DASHBOARD_COMPOSE = REPO_ROOT / "arcane/home/honeypot-dashboard/compose.yml"
GHIDRA_COMPOSE = REPO_ROOT / "analysis/ghidra/docker-compose.ghidra.yml"

LLM_NETWORK = "honeypot-llm"
OLLAMA_ALIAS = "ollama"


# ---------------------------------------------------------------------
# Minimal block-YAML reader for the Compose subset these files use:
# nested block mappings, `- scalar` sequences, `[a, b]` flow sequences,
# comments, and `&anchor` / `*alias` / `<<:` merge lines. No block
# scalars appear in any of the three files (asserted by the PyYAML
# cross-check below, which would diverge if one were introduced).
# ---------------------------------------------------------------------
def _strip_comment(text: str) -> str:
    quote = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index]
    return text


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _flow_sequence(text: str) -> list:
    inner = text.strip()[1:-1].strip()
    if not inner:
        return []
    return [_unquote(part) for part in inner.split(",")]


def _scalar(text: str):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return _flow_sequence(text)
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "~", ""):
        return None
    return _unquote(text)


def _significant_lines(text: str) -> list:
    lines = []
    for raw in text.splitlines():
        body = _strip_comment(raw).rstrip()
        if not body.strip():
            continue
        lines.append((len(body) - len(body.lstrip(" ")), body.strip()))
    return lines


def _parse_block(lines: list, position: int, indent: int):
    """Lines deeper than `indent` that the caller did not consume belong
    to a shape this reader does not model -- a multi-line flow sequence
    (analysis/ghidra's healthcheck) or a sequence of mappings. They are
    skipped rather than returned on, so one unmodelled construct costs
    that one value instead of silently truncating the whole document."""
    if position < len(lines) and lines[position][0] == indent and lines[position][1].startswith("- "):
        items = []
        while position < len(lines) and lines[position][0] >= indent:
            if lines[position][0] > indent:
                position += 1
                continue
            if not lines[position][1].startswith("- "):
                break
            items.append(_scalar(lines[position][1][2:]))
            position += 1
        return items, position
    mapping = {}
    while position < len(lines) and lines[position][0] >= indent:
        if lines[position][0] > indent:
            position += 1
            continue
        line = lines[position][1]
        if line.startswith("- "):
            break
        key, separator, rest = line.partition(":")
        if not separator:  # not a shape this reader claims to handle
            position += 1
            continue
        key = _unquote(key)
        rest = rest.strip()
        if rest.startswith("&"):  # `x-defaults: &anchor` -- anchor then block
            rest = rest.split(" ", 1)[1].strip() if " " in rest else ""
        position += 1
        if rest:
            mapping[key] = _scalar(rest)
            continue
        if position < len(lines) and lines[position][0] > indent:
            mapping[key], position = _parse_block(lines, position, lines[position][0])
        else:
            mapping[key] = None
    return mapping, position


def _read_compose(path: pathlib.Path) -> dict:
    assert path.is_file(), f"missing compose file: {path}"
    lines = _significant_lines(path.read_text(encoding="utf-8"))
    document, _ = _parse_block(lines, 0, 0)
    assert isinstance(document, dict), f"{path} did not read as a mapping"
    return document


# ---------------------------------------------------------------------
# Compose accessors
# ---------------------------------------------------------------------
def _service(compose: dict, name: str) -> dict:
    services = compose.get("services") or {}
    assert name in services, f"service {name!r} is gone from the compose file"
    return services[name]


def _environment(service: dict) -> dict:
    """Compose accepts `environment:` as a KEY=value list or as a mapping;
    both are behaviour-identical, so normalise instead of assuming one."""
    raw = service.get("environment") or []
    if isinstance(raw, dict):
        return {str(key): "" if value is None else str(value) for key, value in raw.items()}
    entries = {}
    for item in raw:
        key, separator, value = str(item).partition("=")
        entries[key.strip()] = value if separator else ""
    return entries


def _service_networks(service: dict) -> list:
    """The network *keys* a service attaches to. List form, flow-sequence
    form and mapping form (the one that carries `aliases:`) all appear
    across these files."""
    raw = service.get("networks")
    if raw is None:
        return []
    if isinstance(raw, dict):
        return list(raw)
    if isinstance(raw, str):
        return [raw]
    return list(raw)


def _declared_networks(compose: dict) -> dict:
    return compose.get("networks") or {}


def _docker_names(compose: dict) -> dict:
    """key -> the real Docker network name. Without an explicit `name:`
    Compose prefixes the project name, so the key alone says nothing
    about which network two separate stacks actually share."""
    return {key: (body or {}).get("name", key) for key, body in _declared_networks(compose).items()}


def _keys_for_docker_name(compose: dict, docker_name: str) -> list:
    return [key for key, name in _docker_names(compose).items() if name == docker_name]


def _ollama_url_accepts(raw: str):
    """Reimplementation of ollama_url() in
    arcane/home/honeypot-dashboard/backend-service/src/llm_search.rs.
    Returns the base URL the endpoint would use, or None if the value is
    rejected -- which surfaces as {"available": false}, indistinguishable
    at runtime from never setting it at all."""
    if not raw:
        return None
    try:
        url = urllib.parse.urlsplit(raw)
        host = (url.hostname or "").lower()
        url.port  # raises ValueError on an unparseable port
    except ValueError:
        return None
    if url.scheme != "http" or url.username or url.query:
        return None
    if url.path not in ("", "/"):
        return None
    if not host:
        return None
    local = host in (OLLAMA_ALIAS, "localhost")
    if not local:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return None
        local = (
            address.is_loopback or address.is_private or address.is_link_local
            if address.version == 4
            else address.is_loopback
        )
    return raw.rstrip("/") if local else None


def _ghidra_ollama_endpoint():
    """(aliases keyed by Docker network name, container ports) for
    analysis/ghidra's ollama service -- what OLLAMA_URL has to name."""
    compose = _read_compose(GHIDRA_COMPOSE)
    service = _service(compose, OLLAMA_ALIAS)
    names = _docker_names(compose)
    attachments = service.get("networks") or {}
    assert isinstance(attachments, dict), (
        "analysis/ghidra's ollama service must use the mapping form of "
        "networks: -- the alias backend-service resolves lives in it"
    )
    aliases = {
        names.get(key, key): list((body or {}).get("aliases") or [])
        for key, body in attachments.items()
    }
    ports = {str(mapping).rsplit(":", 1)[-1].split("/")[0] for mapping in service.get("ports") or []}
    return aliases, ports


@pytest.fixture(scope="module")
def backend():
    return _read_compose(BACKEND_COMPOSE)


@pytest.fixture(scope="module")
def dashboard():
    return _read_compose(DASHBOARD_COMPOSE)


# ---------------------------------------------------------------------
# The reader itself, so nothing below can pass on a misparse
# ---------------------------------------------------------------------
FIXTURE = """\
# leading comment
name: fixture
x-defaults: &defaults
  restart: always
services:
  listform:
    <<: *defaults
    environment:
      - OLLAMA_URL=http://ollama:11434
      - EMPTY=
    networks:
      - honeynet
      - honeypot-llm
  flowform:
    networks: [oidc-session]
    security_opt: [no-new-privileges:true]
  aliasform:
    ports:
      - '127.0.0.1:11434:11434'
    healthcheck:
      test: ['CMD', 'python3', '-c',
             "import sys; sys.exit(0)"]
      retries: 3
    networks:
      default:
      llm_clients:
        aliases: [ollama]
networks:
  honeynet:
    name: honeynet
    driver: bridge
  # honeypot-llm: a commented-out declaration is not a declaration
  llm_clients:
    name: honeypot-llm
    external: true
"""


def test_reader_handles_every_compose_shape_these_assertions_depend_on():
    document = _parse_block(_significant_lines(FIXTURE), 0, 0)[0]
    assert _environment(document["services"]["listform"]) == {
        "OLLAMA_URL": "http://ollama:11434",
        "EMPTY": "",
    }
    assert _service_networks(document["services"]["listform"]) == ["honeynet", LLM_NETWORK]
    assert _service_networks(document["services"]["flowform"]) == ["oidc-session"]
    assert _service_networks(document["services"]["aliasform"]) == ["default", "llm_clients"]
    assert document["services"]["aliasform"]["networks"]["llm_clients"]["aliases"] == [OLLAMA_ALIAS]
    assert document["services"]["aliasform"]["ports"] == ["127.0.0.1:11434:11434"]
    assert document["networks"]["llm_clients"] == {"name": LLM_NETWORK, "external": True}
    # A commented-out declaration must not become a declaration, and the
    # key-vs-name distinction must survive: `llm_clients` is the key.
    assert _keys_for_docker_name(document, LLM_NETWORK) == ["llm_clients"]
    # The multi-line flow sequence costs only its own value: everything
    # after it still parses (it truncated the whole document before).
    assert document["services"]["aliasform"]["healthcheck"]["retries"] == "3"
    assert list(document) == ["name", "x-defaults", "services", "networks"]


@pytest.mark.parametrize("path", [BACKEND_COMPOSE, DASHBOARD_COMPOSE, GHIDRA_COMPOSE])
def test_reader_agrees_with_pyyaml_on_the_real_files(path):
    """Wherever PyYAML is installed, hold the hand-rolled reader to it on
    exactly the structures asserted below. Skipped, not failed, where it
    is absent -- the point is to catch reader drift, not to reintroduce
    the dependency this file deliberately avoids."""
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; reader cross-check skipped")
    reference = yaml.safe_load(path.read_text(encoding="utf-8"))
    parsed = _read_compose(path)
    assert _declared_networks(parsed) == _declared_networks(reference)
    for name, service in (reference.get("services") or {}).items():
        assert _service_networks(_service(parsed, name)) == _service_networks(service), name
        assert _environment(_service(parsed, name)) == _environment(service), name


def _rendered_ollama_url(backend) -> str:
    """The OLLAMA_URL a default deploy gets: compose interpolation
    `${OLLAMA_URL-default}` / `${OLLAMA_URL:-default}` evaluated with the
    variable unset (#3576 made the value operator-overridable)."""
    raw = _environment(_service(backend, "backend-service")).get("OLLAMA_URL", "")
    match = re.fullmatch(r"\$\{OLLAMA_URL:?-(.*)\}", raw)
    return match.group(1) if match else raw


# ---------------------------------------------------------------------
# Part 1: OLLAMA_URL on backend-service
# ---------------------------------------------------------------------
def test_backend_service_sets_an_ollama_url_the_endpoint_accepts(backend):
    raw = _rendered_ollama_url(backend)
    assert raw, (
        "backend-service must set OLLAMA_URL -- unset is the pre-#2329 state, "
        "where ollama_url() returns None and /api/v1/llm-search permanently "
        'answers {"available": false}'
    )
    assert _ollama_url_accepts(raw), (
        f"OLLAMA_URL={raw!r} is rejected by ollama_url() (llm_search.rs): it "
        "accepts only scheme http, no userinfo, no query, an empty path, and "
        "host `ollama`/`localhost` or a loopback/private/link-local IP. A "
        "rejected value is indistinguishable from unset at runtime."
    )


def test_ollama_url_host_is_the_cross_network_alias_not_loopback(backend):
    """ollama_url() also accepts localhost/127.0.0.1, which clear the
    hardening gate and then resolve to backend-service's own container.
    Ollama's published port is loopback-bound on the *host*, so such a
    value would be accepted and still never reach it."""
    raw = _rendered_ollama_url(backend)
    host = (urllib.parse.urlsplit(raw).hostname or "").lower()
    assert host == OLLAMA_ALIAS, (
        f"OLLAMA_URL host must be {OLLAMA_ALIAS!r} -- the alias published on "
        f"the {LLM_NETWORK} network -- not {host!r}"
    )


@pytest.mark.parametrize(
    "value",
    [
        "",  # the pre-#2329 state: unset or empty
        "https://ollama:11434",  # scheme is not http
        "http://ollama.example.com:11434",  # arbitrary external host
        "http://8.8.8.8:11434",  # public IP
        "http://user@ollama:11434",  # userinfo
        "http://ollama:11434/?x=1",  # query string
        "http://ollama:11434/api/embed",  # non-empty path
        "ollama:11434",  # no scheme
    ],
)
def test_ollama_url_gate_rejects_unusable_values(value):
    """Negative control for the reimplemented gate: without it, a helper
    that returned truthy for everything would make the positive test pass
    no matter what the compose file said."""
    assert _ollama_url_accepts(value) is None, (
        f"{value!r} must be rejected -- it is either unreachable from the "
        "backend container or a way to point embed() at a host the operator "
        "did not choose"
    )


def test_ollama_url_gate_accepts_the_shipped_and_equivalent_forms():
    """Positive control: the gate is not rejecting everything either, and
    a trailing slash normalises the way llm_search.rs does it (embed()
    concatenates "{base}/api/embed")."""
    assert _ollama_url_accepts("http://ollama:11434") == "http://ollama:11434"
    assert _ollama_url_accepts("http://ollama:11434/") == "http://ollama:11434"


# ---------------------------------------------------------------------
# Part 1b: the network that makes the alias resolvable
# ---------------------------------------------------------------------
def test_backend_service_attaches_to_the_llm_network(backend):
    """The core regression, asserted against backend-service's OWN
    networks list. The dashboard compose carried this network name in a
    top-level declaration attached to nothing from #151 until #2329, so a
    whole-file substring check passes while the bug is live."""
    keys = _keys_for_docker_name(backend, LLM_NETWORK)
    assert keys, f"the backend compose declares no network resolving to {LLM_NETWORK!r}"
    attached = _service_networks(_service(backend, "backend-service"))
    assert set(keys) & set(attached), (
        f"backend-service must list one of {keys} in its own networks: block "
        f"(found {attached}). Docker DNS aliases are per-network: "
        f"OLLAMA_URL=http://{OLLAMA_ALIAS}:... does not resolve from a "
        "container that is not on the network carrying that alias."
    )


def test_backend_service_still_attaches_to_honeynet(backend):
    """Adding a network must not replace the existing one: dashboard-next
    reaches this service as http://backend-service:8081 over honeynet."""
    attached = _service_networks(_service(backend, "backend-service"))
    assert set(_keys_for_docker_name(backend, "honeynet")) & set(attached), (
        f"backend-service must stay on honeynet (found {attached}) -- "
        "dashboard-next's BACKEND_URL resolves it by service name there"
    )


def test_backend_compose_declares_the_llm_network_as_external(backend):
    """analysis/ghidra owns this network. Declared non-external, Compose
    creates its own network of the same name with no ollama on it."""
    keys = _keys_for_docker_name(backend, LLM_NETWORK)
    assert keys
    for key in keys:
        body = _declared_networks(backend)[key] or {}
        assert body.get("external") is True, (
            f"networks.{key} must be `external: true` -- the network is owned "
            "by analysis/ghidra/docker-compose.ghidra.yml, which creates it "
            "and puts the ollama alias on it"
        )
        assert body.get("name") == LLM_NETWORK, (
            f"networks.{key} must pin `name: {LLM_NETWORK}` -- without it "
            "Compose looks for a project-prefixed network instead"
        )


def test_ghidra_compose_still_publishes_the_ollama_alias_and_port(backend):
    """Cross-file half of the contract: OLLAMA_URL names an alias and a
    port another file is responsible for, and nothing else fails if that
    side is renamed."""
    aliases, container_ports = _ghidra_ollama_endpoint()
    assert LLM_NETWORK in aliases, (
        f"analysis/ghidra's ollama service no longer joins {LLM_NETWORK}; "
        "backend-service's OLLAMA_URL points at a network with no ollama on it"
    )
    assert OLLAMA_ALIAS in aliases[LLM_NETWORK], (
        f"analysis/ghidra must keep the {OLLAMA_ALIAS!r} alias on "
        f"{LLM_NETWORK} (found {aliases[LLM_NETWORK]}) -- it is the exact host "
        "ollama_url() allowlists"
    )
    raw = _rendered_ollama_url(backend)
    port = urllib.parse.urlsplit(raw).port
    assert str(port) in container_ports, (
        f"OLLAMA_URL port {port} is not a container port ollama listens on "
        f"({sorted(container_ports)}) per analysis/ghidra's compose"
    )


# ---------------------------------------------------------------------
# Part 2: the dashboard compose no longer owns the network
# ---------------------------------------------------------------------
def test_dashboard_compose_no_longer_declares_the_llm_network(dashboard):
    """Checked against declared network names, not raw text, so a comment
    in this heavily-commented file explaining where the network went stays
    documentation rather than a test failure."""
    assert not _keys_for_docker_name(dashboard, LLM_NETWORK), (
        f"honeypot-dashboard/compose.yml must not declare {LLM_NETWORK} -- it "
        "was attached to nothing here and misidentified this stack as the "
        "owner; the real consumer is backend-service in the sibling "
        "honeypot-dashboard-backend stack"
    )


def test_no_dashboard_service_attaches_to_the_llm_network(dashboard):
    for name, service in (dashboard.get("services") or {}).items():
        assert LLM_NETWORK not in _service_networks(service), (
            f"{name} attaches to {LLM_NETWORK}, which this compose file no "
            "longer declares -- `docker compose up` would fail outright"
        )


@pytest.mark.parametrize("path", [BACKEND_COMPOSE, DASHBOARD_COMPOSE])
def test_compose_networks_are_neither_dangling_nor_undeclared(path):
    """Generalised form of both halves of #2329. A declared network no
    service joins is the exact pre-fix shape (part 2); a service naming a
    network no longer declared is how removing one breaks the stack."""
    compose = _read_compose(path)
    declared = set(_declared_networks(compose))
    attached = set()
    for service in (compose.get("services") or {}).values():
        attached.update(_service_networks(service))
    assert not declared - attached, (
        f"{path.name} declares networks no service joins: "
        f"{sorted(declared - attached)} -- a dangling declaration is what made "
        "honeypot-llm look wired to this stack from #151 to #2329"
    )
    assert not attached - declared, (
        f"{path.name} has services on undeclared networks: {sorted(attached - declared)}"
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
