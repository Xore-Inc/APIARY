#!/usr/bin/env python3
"""Regression test for #2368: sync-client-secrets.sh must target exactly the
VPS oauth2-proxy gateways that actually exist in vps/docker-compose.yml.

The bug: the script's `CLIENT_CONTAINERS` map still carried two rows whose
gateway compose service had been deleted elsewhere in the repo -- `dockge`
(removed under #1185, cleanup in #2195) and `apiary-dashboard`'s
`oidc-dashboard` compat gateway (retired by #1026's follow-up). The closing

    docker compose up -d --force-recreate ${synced_containers[*]}

names every gateway on one command line, and Compose validates every named
service before recreating any of them. So a single stale row made the whole
recreate a guaranteed reject: every *valid* gateway synced its new secret to
disk and then never restarted to pick it up.

WHAT THIS TEST ASSERTS, AND WHY IT IS SHAPED THIS WAY

The failure mode is a disagreement *between files*, so asserting that the
script contains seven hand-listed names proves nothing -- it only restates the
source. Every assertion below is therefore a cross-file consistency check
against `vps/docker-compose.yml`, which is the artifact that actually
rejects the run:

  * every map VALUE must be a real top-level compose service.  This is the
    #2368 failure mode itself, and it is checked on the values -- the
    pre-#2368 map had the correct KEY (`apiary-dashboard` is still a real
    realm client) and a dead VALUE (`oidc-dashboard`), so a key-only test
    cannot see the bug at all.
  * every `oidc-*` gateway in compose must appear in the map.  Guards the
    opposite drift: a newly added gateway whose secret is never rotated,
    which fails silently at the next realm rebuild rather than loudly.
  * every map KEY must match both the `${OIDC_SECRETS_DIR}/<key>` bind mount
    and the `OAUTH2_PROXY_CLIENT_ID` of the gateway it points at.  This ties
    the path the script writes to the path the gateway reads and the realm
    client the secret belongs to -- the three ends of the rotation.

Only the key set itself is pinned to a literal (the seven clients as of
#2368), so an intentional gateway addition fails one explicit test with a
readable diff instead of silently widening the contract.

The script-internal #2195 guards are asserted by ordering rather than mere
presence: an abort that runs *after* the first write does not prevent the
half-applied state #2368 produced.

The runbook (docs/KEYCLOAK-OPERATIONS.md) is checked table-by-table against
the same map, because the issue also flagged its "8 gateways, 9 confidential
clients" counting mismatch. Whole-file substring checks are avoided
deliberately: `kibana` occurs throughout the document, so `"kibana" in text`
is true no matter what the enumeration says.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYCLOAK_DIR = REPO_ROOT / "arcane/home/honeypot-keycloak/keycloak"
SCRIPT = KEYCLOAK_DIR / "sync-client-secrets.sh"
COMPOSE = REPO_ROOT / "vps/docker-compose.yml"
RUNBOOK = REPO_ROOT / "docs/KEYCLOAK-OPERATIONS.md"

# The seven VPS-fronted oauth2-proxy gateway clients as of #2368. Pinned so
# that adding or dropping a gateway has to be a deliberate edit here.
EXPECTED_GATEWAY_CLIENTS = {
    "kibana",
    "evebox",
    "arkime",
    "tanner",
    "revdeck",
    "unsloth",  # #3689
    "traefik-dashboard",
}

# Confidential clients that exist in the realm but have no VPS gateway, so
# sync-client-secrets.sh must NOT touch them: client id -> provisioner that
# owns its rotation instead.
NON_GATEWAY_PROVISIONERS = {
    "apiary-dashboard": "provision-dashboard-oidc-secret.sh",
    "apiary-dashboard-rewrite": "provision-dashboard-oidc-secret.sh",  # #3578
    "arcane": "provision-arcane-oidc-secret.sh",
    "auth-events-poller": "provision-events-poller.sh",
}

# The rows that rotted, as (map key, map value). Both gateway services are
# gone from vps/docker-compose.yml; neither pair may come back.
DECOMMISSIONED_ROWS = {
    "dockge": "oidc-dockge",            # #1185 replaced Dockge with Arcane
    "apiary-dashboard": "oidc-dashboard",  # #1026 follow-up: native OIDC
}

SCRIPT_TEXT = SCRIPT.read_text(encoding="utf-8")
COMPOSE_TEXT = COMPOSE.read_text(encoding="utf-8")
RUNBOOK_TEXT = RUNBOOK.read_text(encoding="utf-8")


def _client_containers() -> dict:
    """Parse `declare -A CLIENT_CONTAINERS=(...)` into {client: service}.

    Values are taken up to whitespace so the trailing `# ...` comments the
    fix added do not become part of the service name.
    """
    block = re.search(
        r"declare\s+-A\s+CLIENT_CONTAINERS=\(\s*\n(.*?)\n\s*\)\s*$",
        SCRIPT_TEXT,
        re.DOTALL | re.MULTILINE,
    )
    assert block, "could not find `declare -A CLIENT_CONTAINERS=(...)` in the script"
    rows = re.findall(
        r"^\s*\[([^\]]+)\]=(\S+)", block.group(1), re.MULTILINE
    )
    mapping = dict(rows)
    assert len(mapping) == len(rows), f"duplicate CLIENT_CONTAINERS keys: {rows!r}"
    return mapping


def _compose_services() -> dict:
    """Parse vps/docker-compose.yml into {service name: service body text}.

    Hand-rolled rather than via PyYAML: no other test in this repo takes a
    third-party parser dependency, and the two-space-indent block structure
    is all that is needed here.
    """
    block = re.search(
        r"^services:\n(.*?)(?=\n[A-Za-z_][\w-]*:\s*$|\Z)",
        COMPOSE_TEXT,
        re.DOTALL | re.MULTILINE,
    )
    assert block, "could not find the top-level `services:` block in vps/docker-compose.yml"
    body = block.group(1)
    starts = [(m.group(1), m.start()) for m in re.finditer(r"^  ([\w.-]+):\s*$", body, re.MULTILINE)]
    services = {}
    for i, (name, pos) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(body)
        services[name] = body[pos:end]
    return services


# Parsed once at import so the per-row tests below are parametrized over the
# rows the script ACTUALLY declares. Parametrizing over EXPECTED_GATEWAY_CLIENTS
# instead would skip exactly the rogue row this file exists to catch.
CLIENT_CONTAINERS = _client_containers()


def _markdown_table_after(heading_regex: str) -> list:
    """Return the rows of the first markdown table following a heading line.

    Rows come back as lists of stripped cells with surrounding backticks
    removed. Scoping to one table matters: the runbook has four of them and
    a document-wide scan cannot tell the gateway enumeration apart from the
    non-gateway one.
    """
    anchor = re.search(heading_regex, RUNBOOK_TEXT, re.MULTILINE)
    assert anchor, f"could not locate {heading_regex!r} in the runbook"
    table = re.search(
        r"^\|.*\|\s*\n\|[-|\s]+\|\s*\n((?:\|.*\|\s*\n)+)",
        RUNBOOK_TEXT[anchor.start():],
        re.MULTILINE,
    )
    assert table, f"no markdown table follows {heading_regex!r}"
    rows = []
    for line in table.group(1).strip().splitlines():
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        rows.append(cells)
    return rows


def test_client_containers_map_is_exactly_the_seven_gateway_clients():
    """The pinned key set. Anything else is a deliberate gateway change and
    should have to be written down here too."""
    assert set(CLIENT_CONTAINERS) == EXPECTED_GATEWAY_CLIENTS


@pytest.mark.parametrize("client", sorted(CLIENT_CONTAINERS))
def test_mapped_gateway_service_exists_in_vps_compose(client):
    """The #2368 failure mode, checked on the map VALUE.

    `docker compose up -d --force-recreate <svc>...` resolves every named
    service up front, so one value that names nothing rejects the entire
    recreate -- including the gateways whose secrets were just written.
    """
    service = CLIENT_CONTAINERS[client]
    services = _compose_services()
    assert service in services, (
        f"CLIENT_CONTAINERS[{client}] points at compose service {service!r}, "
        f"which does not exist in vps/docker-compose.yml -- #2368. The closing "
        f"`docker compose up -d --force-recreate` names every synced gateway on "
        f"one command line and Compose validates all of them before recreating "
        f"any, so this single row stops every valid gateway from ever picking "
        f"up its rotated secret."
    )


@pytest.mark.parametrize("client,service", sorted(DECOMMISSIONED_ROWS.items()))
def test_decommissioned_gateway_row_stays_out(client, service):
    """Neither rotted row may return -- and the check is anchored on compose,
    so it keeps meaning something if the decommission is ever reverted."""
    mapping = CLIENT_CONTAINERS
    assert service not in _compose_services(), (
        f"{service!r} is a compose service again; this test's premise "
        f"(that it was decommissioned) no longer holds -- revisit #2368."
    )
    assert service not in mapping.values(), (
        f"CLIENT_CONTAINERS targets decommissioned gateway {service!r} again -- #2368"
    )
    assert mapping.get(client) != service, (
        f"CLIENT_CONTAINERS[{client}]={service!r} is back -- #2368"
    )


def test_every_oauth2_proxy_gateway_in_compose_is_rotated_by_the_script():
    """The opposite drift: a gateway that exists but is not in the map.

    That one fails quietly -- the gateway simply keeps a client secret from
    the previous realm and every login through it breaks after the next
    `--import-realm`, with nothing in the sync run to point at.
    """
    gateways = {name for name in _compose_services() if name.startswith("oidc-")}
    mapped = set(CLIENT_CONTAINERS.values())
    assert gateways == mapped, (
        f"oauth2-proxy gateways in vps/docker-compose.yml and the gateways "
        f"sync-client-secrets.sh rotates have diverged -- #2368.\n"
        f"  in compose, never rotated: {sorted(gateways - mapped)}\n"
        f"  rotated, absent from compose: {sorted(mapped - gateways)}"
    )


@pytest.mark.parametrize("client", sorted(CLIENT_CONTAINERS))
def test_client_id_matches_the_gateways_secret_mount_and_oauth2_proxy_client(client):
    """Tie the three ends of one rotation together.

    The script writes to `$VPS_SECRETS_DIR/<client>/client-secret`; the
    gateway bind-mounts `${OIDC_SECRETS_DIR}/<client>` at /run/oidc-secrets
    and presents `OAUTH2_PROXY_CLIENT_ID: <client>` to Keycloak. If the map
    key drifts from either, the secret lands beside the gateway that needs
    it and logins fail with invalid_client while every step reports success.
    """
    service = CLIENT_CONTAINERS[client]
    body = _compose_services()[service]
    assert re.search(
        rf"OIDC_SECRETS_DIR[^\n]*\}}/{re.escape(client)}:/run/oidc-secrets", body
    ), (
        f"{service} does not mount ${{OIDC_SECRETS_DIR}}/{client} -- the path "
        f"sync-client-secrets.sh writes for client {client!r} is not the path "
        f"this gateway reads."
    )
    assert re.search(rf"OAUTH2_PROXY_CLIENT_ID:\s*{re.escape(client)}\s*$", body, re.MULTILINE), (
        f"{service} does not present OAUTH2_PROXY_CLIENT_ID: {client} -- the "
        f"map key is not the Keycloak client whose secret gets written there."
    )


def test_preflight_realm_check_aborts_before_any_write():
    """#2195's gate is only worth anything ahead of the first write.

    Presence alone is not the contract: an abort placed after the sync loop
    would still leave the half-applied state (#2368: secrets on disk, no
    gateway restarted) it exists to prevent.
    """
    abort = SCRIPT_TEXT.find("ABORT: listed in CLIENT_CONTAINERS but absent")
    assert abort != -1, "the #2195 realm-mismatch abort is gone"
    assert 'get clients -r "$REALM"' in SCRIPT_TEXT, (
        "the pre-flight must query the realm's own client list, not trust the map"
    )
    write = SCRIPT_TEXT.find('| ssh "$VPS_HOST"')
    recreate = SCRIPT_TEXT.find("docker compose up -d --force-recreate")
    assert write != -1 and recreate != -1, "the sync/recreate steps moved; update this test"
    assert abort < write < recreate, (
        "the realm-mismatch abort must precede the first secret write (and the "
        "recreate) -- aborting afterwards still leaves the half-applied state "
        "#2368 reported"
    )
    assert re.search(r"^\s*exit 2\s*$", SCRIPT_TEXT, re.MULTILINE), (
        "the pre-flight must exit non-zero on drift rather than continue"
    )


def test_recreate_is_limited_to_gateways_actually_synced():
    """#2195's other half, which #2368's fix relies on: recreate the
    containers that changed hands this run, never the full static list."""
    recreate = re.search(
        r"docker compose up -d --force-recreate ([^\"']+)", SCRIPT_TEXT
    )
    assert recreate, "could not find the compose recreate invocation"
    arg = recreate.group(1).strip()
    assert arg == "${synced_containers[*]}", (
        f"recreate is invoked with {arg!r}; it must pass only the gateways "
        f"whose secret was actually synced this run -- #2195/#2368"
    )
    assert "no secrets synced; skipping gateway recreation" in SCRIPT_TEXT, (
        "an empty synced set must be reported, not passed to compose as a "
        "zero-service command line"
    )


@pytest.mark.parametrize("client,provisioner", sorted(NON_GATEWAY_PROVISIONERS.items()))
def test_non_gateway_client_is_documented_and_its_provisioner_exists(client, provisioner):
    """The three clients this script deliberately skips must be named in the
    preamble next to the script that does rotate them -- and that script has
    to be a real file, or the note is a dead end at the next rebuild."""
    assert client not in CLIENT_CONTAINERS, (
        f"{client!r} has no VPS oauth2-proxy gateway and must not be in "
        f"CLIENT_CONTAINERS -- #2368"
    )
    assert client in SCRIPT_TEXT, (
        f"the preamble must name non-gateway client {client!r} so a reader "
        f"knows the script is the gateway rotater, not the realm's"
    )
    assert provisioner in SCRIPT_TEXT, (
        f"the preamble must point at {provisioner} as {client!r}'s rotater"
    )
    assert (KEYCLOAK_DIR / provisioner).is_file(), (
        f"{provisioner} referenced by the preamble does not exist on disk"
    )


def test_script_preamble_states_the_realm_client_total():
    """7 handled here + 4 elsewhere = 11. The count is what makes a future
    reader notice the script is not the all-secrets rotater."""
    assert re.search(r"\b11 confidential clients\b", SCRIPT_TEXT), (
        "the preamble must state the realm's 11-confidential-client total"
    )
    assert re.search(r"\b7 VPS oauth2-proxy gateway\b", SCRIPT_TEXT), (
        "the preamble must state how many of them this script handles"
    )


def test_runbook_gateway_table_matches_the_script_map():
    """§3's per-client directory table is the manual fallback for the same
    seven clients; if it and the map disagree, one of them is wrong."""
    rows = _markdown_table_after(r"^\| Directory/client \| Public consumer \|")
    listed = {row[0] for row in rows}
    assert listed == set(CLIENT_CONTAINERS), (
        f"the runbook's per-client gateway table and CLIENT_CONTAINERS have "
        f"diverged -- #2368.\n  runbook only: {sorted(listed - set(CLIENT_CONTAINERS))}"
        f"\n  script only: {sorted(set(CLIENT_CONTAINERS) - listed)}"
    )


def test_runbook_non_gateway_table_lists_every_client_with_real_provisioners():
    """The others, with links that resolve -- the runbook is the only
    place the full clean-rebuild sequence is written down."""
    rows = _markdown_table_after(r"^### Non-gateway confidential clients\s*$")
    listed = {row[0] for row in rows}
    assert listed == set(NON_GATEWAY_PROVISIONERS), (
        f"the runbook's non-gateway client table lists {sorted(listed)}, "
        f"expected {sorted(NON_GATEWAY_PROVISIONERS)} -- #2368"
    )
    for client, _surface, provisioner_cell in rows:
        link = re.search(r"\]\(([^)]+)\)", provisioner_cell)
        assert link, f"the {client!r} row must link its provisioner script"
        target = (RUNBOOK.parent / link.group(1)).resolve()
        assert target.is_file(), (
            f"the {client!r} row links {link.group(1)}, which does not exist"
        )
        assert target.name == NON_GATEWAY_PROVISIONERS[client], (
            f"the {client!r} row links {target.name}, expected "
            f"{NON_GATEWAY_PROVISIONERS[client]}"
        )


def test_runbook_carries_no_stale_gateway_or_client_counts():
    """The counting mismatch #2368 flagged: the runbook claimed 8 gateways
    against 9 confidential clients, so neither number could be trusted."""
    stale = re.findall(
        r"\b(?:6|8|9|six|eight|nine)\s+(?:VPS\s+)?gateway\w*"
        r"|\b(?:7|8|9|10|seven|eight|nine|ten)\s+confidential\w*",
        RUNBOOK_TEXT,
        re.IGNORECASE,
    )
    assert not stale, (
        f"the runbook still carries pre-#2368 counts: {stale!r}. There are seven "
        f"VPS gateways and eleven confidential clients."
    )
    assert re.search(r"\b(?:7|seven)\s+(?:VPS\s+)?gateway", RUNBOOK_TEXT, re.IGNORECASE)
    assert re.search(r"\b(?:11|eleven)\s+confidential", RUNBOOK_TEXT, re.IGNORECASE)


def test_runbook_never_names_dockge_as_a_client():
    """`/var/dockge/stacks/...` is the real Keycloak stack path on the
    homeserver and must stay; `dockge` as a table's client cell must not."""
    for line in RUNBOOK_TEXT.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        first = line.strip().strip("|").split("|")[0].strip().strip("`")
        assert first != "dockge", (
            f"the runbook names dockge as a client in a table row: {line.strip()!r} "
            f"-- its Keycloak client and gateway were removed under #1185/#2195 (#2368)"
        )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
