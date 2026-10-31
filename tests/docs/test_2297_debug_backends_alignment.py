#!/usr/bin/env python3
"""Regression test for #2297: vps/debug-backends.sh probed a deployment
that no longer exists.

Roughly half of the script's hardcoded probe list (a static-site nginx on
8080, and a Flask / Flask+Redis / Node.js / C# ASP.NET / Go API / Rust Axum
quintet on 5000-5004/3000, plus uptime-kuma:3001 and filebrowser:8070) named
services that never exist anywhere in this repository. Those probes used
the hard `probe()` path with no tcp_open guard, so they always failed --
which meant the script's exit gate (`[[ $FAIL -eq 0 ]]`) was permanently
red no matter how healthy the real stack was. Meanwhile every gateway added
since #1062 (dashboard-next:19092, arkime:19080, revdeck:19500,
Keycloak:18080, arcane:3552) was missing, so a real outage in any of those
went undetected.

The fix reconciles the probe list against vps/traefik/dynamic.yml's own
socat-hp-* table (the actual 10.8.0.2 inventory): drops the fictional
entries, adds the missing gateways, moves the profile-gated RevDeck into
the tcp_open-guarded "expected closed" tier alongside Snare (both are only
sometimes up -- a WARN, not a FAIL, per dynamic.yml/docker-compose.yml),
and fixes the Snare remediation text to name the post-#124 project split
(snare-clone lives in honeypot-init, snare itself in honeypot-tanner).
"""
import contextlib
import http.server
import os
import pathlib
import re
import socket
import subprocess
import sys
import threading

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "vps" / "debug-backends.sh"
DYNAMIC_YML = REPO_ROOT / "vps" / "traefik" / "dynamic.yml"

# Raw decoy/honeypot listeners are deliberately exempt from this operator-
# facing diagnostic: they're meant to look broken/weird to attackers, not
# to serve clean HTTP to someone chasing a Traefik 502.
EXEMPT_BRIDGES = {"socat-hp-hellpot", "socat-hp-galah", "socat-hp-http"}

# Matches a live (non-retired) row of dynamic.yml's socat-hp-* comment
# table, e.g. "# socat-hp-dashboard      :8090   ->  10.8.0.2:19090 (...)".
# Retired rows are parenthesized by the file itself, e.g.
# "# (socat-hp-wordpot :8086 -> 10.8.0.2:8091 went with ... #2381.)" --
# excluded by requiring the line start with "# socat-hp-", not "# (".
SOCAT_HP_ROW_RE = re.compile(r"^# (socat-hp-[\w-]+)\s+:\d+\s+.*?10\.8\.0\.2:(\d+)")

# The fictional targets #2297 reported: none of these ever existed in this
# deployment, yet the old script hard-probed them, guaranteeing a permanent
# FAIL exit no matter how healthy the real stack was.
FICTIONAL_HOME_PORTS = {8080, 5000, 5001, 3000, 5002, 5003, 5004, 3001, 8070}
FICTIONAL_LABELS = [
    "www (static nginx)",
    "Flask API",
    "Flask+Redis API",
    "Node.js API",
    "C# ASP.NET API",
    "Go API",
    "Rust Axum API",
    "Uptime Kuma",
    "FileBrowser",
]

# Ports the fixed script now treats as "always expected up" -- see the
# corresponding `probe $WG <port>` calls in vps/debug-backends.sh.
ALWAYS_UP_PORTS = [19092, 19636, 19601, 19091, 19080, 18080, 3552]  # #3749: 19090 retired


def _script_text():
    return SCRIPT.read_text(encoding="utf-8")


def _socat_hp_home_ports():
    """(bridge_name, home_port) pairs from dynamic.yml's own socat-hp-*
    table -- the actual 10.8.0.2 inventory this script must track."""
    pairs = []
    for line in DYNAMIC_YML.read_text(encoding="utf-8").splitlines():
        if not line.startswith("# socat-hp-"):
            continue
        m = SOCAT_HP_ROW_RE.match(line)
        if m:
            pairs.append((m.group(1), int(m.group(2))))
    return pairs


def test_script_exists():
    assert SCRIPT.exists(), f"debug-backends.sh not found at {SCRIPT}"


def test_dynamic_yml_socat_hp_table_still_parses():
    names = {name for name, _ in _socat_hp_home_ports()}
    # Sanity check that the table format hasn't changed out from under the
    # regex above -- if this starts failing, re-check SOCAT_HP_ROW_RE first.
    assert "socat-hp-dashboard-next" in names  # the dashboard bridge since #3749
    assert "socat-hp-arcane" in names
    assert "socat-hp-wordpot" not in names, "retired row should be skipped"


def test_every_non_exempt_socat_hp_bridge_is_probed():
    text = _script_text()
    missing = [
        (name, port)
        for name, port in _socat_hp_home_ports()
        if name not in EXEMPT_BRIDGES and not re.search(rf"\b{port}\b", text)
    ]
    assert not missing, (
        "vps/traefik/dynamic.yml declares socat-hp-* bridges to 10.8.0.2 "
        f"that debug-backends.sh never probes: {missing!r} -- add a probe/"
        "tcp_open check for the home port, or this drifts again (#2297)"
    )


def test_fictional_home_ports_removed():
    text = _script_text()
    present = sorted(p for p in FICTIONAL_HOME_PORTS if re.search(rf"\b{p}\b", text))
    assert not present, (
        f"debug-backends.sh still probes fictional home ports {present!r} "
        "that never existed in this deployment (#2297)"
    )


def test_fictional_labels_removed():
    text = _script_text()
    present = [label for label in FICTIONAL_LABELS if label in text]
    assert not present, f"debug-backends.sh still references fictional service labels {present!r} (#2297)"


def test_wg_is_env_overridable():
    assert 'WG="${WG:-10.8.0.2}"' in _script_text(), (
        "WG must stay overridable via environment (used below to point the "
        "script at local mock servers instead of the real WireGuard peer)"
    )


def test_snare_remediation_names_current_projects():
    text = _script_text()
    assert "snare_clone (one-shot clone container)" not in text
    # Post-#124: snare-clone (honeypot-init) and snare (honeypot-tanner)
    # are two different compose projects -- remediation must cd into the
    # right one before `docker compose up -d`, not run it ambiguously from
    # whatever directory the operator happens to be in.
    assert "cd /opt/stacks/honeypot-init" in text
    assert "cd /opt/stacks/honeypot-tanner" in text


def test_revdeck_is_tcp_gated_not_hard_probed():
    text = _script_text()
    assert "tcp_open $WG 19500" in text, (
        "RevDeck (#2297: profile-gated, not started by default -- see "
        "analysis/ghidra/docker-compose.ghidra.yml's `profiles: ['revdeck']`) "
        "must be tcp_open-guarded like Snare, not hard-probed -- a hard "
        "probe() FAILs the exit gate whenever the optional profile is off"
    )


class _OKHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass


def _mock_host():
    """A per-process loopback address for the mock backends.

    The port numbers below are fixed by debug-backends.sh itself, so they
    cannot be randomised -- but several CI jobs share one self-hosted
    runner host, and two concurrent runs of this file both binding
    127.0.0.1:19090 lose with EADDRINUSE. 127/8 is entirely loopback on
    Linux, so give each process its own address instead. Falls back to
    127.0.0.1 where only that one address is configured (macOS).
    """
    pid = os.getpid()
    candidate = f"127.{(pid >> 8) & 0xFF}.{pid & 0xFF}.1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((candidate, 0))
        return candidate
    except OSError:
        return "127.0.0.1"


MOCK_HOST = _mock_host()


@contextlib.contextmanager
def _servers_on(ports):
    servers = []
    try:
        for port in ports:
            server = http.server.ThreadingHTTPServer((MOCK_HOST, port), _OKHandler)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        yield
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def _run_script():
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=os.environ | {"WG": MOCK_HOST},
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.skipif(sys.platform == "win32", reason="uses /dev/tcp and bash")
def test_exits_zero_when_every_always_up_port_answers():
    """Acceptance criterion from #2297: running against a healthy
    deployment exits 0 with zero failures. Snare/RevDeck are left closed
    (they're WARN-tier optional) to prove those don't sink the gate."""
    with _servers_on(ALWAYS_UP_PORTS):
        result = _run_script()
    assert result.returncode == 0, (
        "script should exit 0 when every non-optional backend answers "
        f"(stdout follows):\n{result.stdout}\n{result.stderr}"
    )
    assert "[FAIL]" not in result.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="uses /dev/tcp and bash")
def test_exits_nonzero_when_an_always_up_port_is_down():
    """The gate must still catch a real outage -- unconditionally exiting
    0 would be as useless as the unconditional-1 bug #2297 reported."""
    broken = ALWAYS_UP_PORTS[1:]  # leave the first port (dashboard) closed
    with _servers_on(broken):
        result = _run_script()
    assert result.returncode != 0, f"script must fail when a real backend is down (stdout follows):\n{result.stdout}"
    assert "[FAIL]" in result.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
