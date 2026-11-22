#!/usr/bin/env python3
"""Regression test for #3312 -- Diagnostics failed every scheduled run, and
none of the failures was the condition it named.

The issue reported four things (home job): no DASHBOARD_SERVICE_TOKEN, an
OIDC discovery 403, missing libvirt sandbox networks/socket and a missing
nwfilter. #3338 checked each one live and found the reporting wrong in every
case, which is why this file exists: each of those findings was a *false*
positive about something that was fine, and a false positive about host
state is indistinguishable from a real one until someone re-reads the run. So
the diagnosis itself is the contract, and every half of it gets a check:

  metrics lane   the token was never missing. It lives in a root:root 0600
                 .env, the runner is not root, and the job's own `sed` read
                 of it failed on permission, not on an absent key. The fix is
                 a root-owned, argument-less helper the runner reaches through
                 a NOPASSWD grant, so the token never enters the job.
  OIDC           the 403 was Cloudflare answering GitHub's runner address
                 ranges; the same URL is 200 from the VPS. The probe has to
                 ask the VPS, or every scheduled run stays red on a healthy
                 endpoint.
  libvirt URI    every virsh call in the audit is bare, and a non-root
                 caller's default URI is the empty per-user session, so
                 active networks on qemu:///system read as "does not exist".
  libvirt socket monolithic libvirtd is the intended stack here, but only
                 virtproxyd was disabled in that branch, leaving the
                 preset-enabled per-driver modular sockets to win the
                 Conflicts= race after a reboot and leave libvirtd.socket
                 dead.

It also pins the last mile: the helper and its grant are host state, and a
merged PR that adds one does not put it on the box. `--helpers-only` is the
narrow path that applies them without stopping the runner service, which is
what a workflow can honestly point an operator at (and the reason this lane
was still red after #3338 merged -- the only route to the grant was a full
re-run, which stops and restarts the homeserver's Actions runner).
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "diagnostics.yml"
INSTALLER = REPO_ROOT / "scripts" / "github-ci-runner" / "install-deploy-runner.sh"
HELPER = REPO_ROOT / "scripts" / "github-ci-runner" / "dashboard-source-health.sh"
AUDIT = REPO_ROOT / "scripts" / "isolation-audit.sh"
HOMESERVER = REPO_ROOT / "scripts" / "install-homeserver.sh"

HELPER_INSTALLED_PATH = "/opt/github-ci-runner-helpers/dashboard-source-health.sh"
ROOT_ONLY_ENV = "/var/dockge/stacks/honeypot-dashboard-backend/.env"  # #3749: the backend's own .env
LEGACY_TOKEN_ENV = "/opt/stacks/honeypot-dashboard/.env"


def _text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# metrics lane: the token is root-only, so the job must not read it at all
# --------------------------------------------------------------------------


def test_workflow_never_reads_the_service_token_itself():
    """The pre-#3312 lane sed'd the key out of a 0600 root-only .env from a
    job running as github-deploy-runner. That read fails on permission, so
    the job then reported the key as absent -- a claim about the host it had
    no way to make. The job must not attempt the read at all any more."""
    workflow = _text(WORKFLOW)
    assert "DASHBOARD_SERVICE_TOKEN" not in workflow, (
        "diagnostics.yml reads DASHBOARD_SERVICE_TOKEN itself again; the key is "
        "root-only and this runner is not root, so the read cannot succeed and "
        "the failure is misreported as a missing key (#3312)"
    )
    for path in (LEGACY_TOKEN_ENV, ROOT_ONLY_ENV):
        assert path not in workflow, (
            f"diagnostics.yml still references {path} directly; the token is "
            "read by the root-owned helper, not by the job (#3312)"
        )


def test_workflow_checks_the_grant_before_running_the_helper():
    """`sudo -n -l <path>` is what distinguishes 'not installed / not
    granted' (a host-provisioning gap) from 'ran and failed' (a real
    pipeline fault). Without the guard, both collapse into one message that
    names the wrong cause -- the shape #3312 was filed about."""
    workflow = _text(WORKFLOW)
    assert f'helper={HELPER_INSTALLED_PATH}' in workflow, (
        "the helper path is not what the job runs; it must be the root-owned "
        f"{HELPER_INSTALLED_PATH} (#3312)"
    )
    probe = workflow.index('sudo -n -l "$helper"')
    run = workflow.index('sudo -n "$helper"')
    assert probe < run, "the grant check must come before the helper is invoked (#3312)"
    # And the grant's absence is reported as a provisioning gap naming the
    # narrow command, not as an unreachable backend.
    assert "--helpers-only" in workflow, (
        "the metrics alert must name install-deploy-runner.sh --helpers-only, "
        "the path that applies the grant without stopping the runner service (#3312)"
    )
    assert "is not installed or not granted" in workflow, (
        "the ungranted-helper branch lost its distinct message (#3312)"
    )


def test_helper_takes_no_arguments_and_keeps_the_token_out_of_argv():
    """Two properties the sudoers grant rests on.

    No arguments: the grant is a bare path, so anything that let a caller
    pass an argument would let the grant be aimed at a different .env than
    the one the operator reviewed.

    Token out of argv: `curl -H` puts the service token in the process list,
    which on this host is visible to every docker-group member. curl's stdin
    config (-K -) keeps it out of argv and out of the job's own environment.
    """
    helper = _text(HELPER)
    assert "$@" not in helper and "$1" not in helper, (
        "the helper must ignore arguments; its sudoers grant names a bare path, "
        "so an argument could redirect the token read (#3312)"
    )
    assert f"env_file={ROOT_ONLY_ENV}" in helper, (
        f"the helper must read the token from {ROOT_ONLY_ENV}, the stack's real "
        f"location (#3312)"
    )
    assert re.search(r"curl\b[^\n]*-K\s+-(?:\s|$)", helper), (
        "the token must be passed to curl through stdin config (-K -), not argv (#3312)"
    )
    assert not re.search(r"curl\b[^\n]*\s-H\s", helper), (
        "curl -H would put the service token in the host's process list (#3312)"
    )
    assert 'header = "X-Service-Token: %s"' in helper, (
        "the helper must send the token as the backend's X-Service-Token header"
    )


def test_grant_is_the_exact_helper_path_with_no_arguments():
    """The grant is the whole security boundary: one root-owned script, one
    path, no arguments, NOPASSWD. Anything wider (a shell, a directory, a
    trailing flag) would hand the runner an arbitrary root command."""
    installer = _text(INSTALLER)
    grant = f"$RUNNER_USER ALL=(root) NOPASSWD: {HELPER_INSTALLED_PATH}\n"
    assert grant in installer, (
        f"sudoers must grant exactly '{HELPER_INSTALLED_PATH}' with no arguments (#3312)"
    )
    # Root-owned and not writable by the runner, or the grant is meaningless:
    # a runner that can rewrite the script can ask sudo to run anything.
    assert re.search(
        r"install -m 0755 -o root -g root\s+\\\n\s*.*dashboard-source-health\.sh",
        installer,
    ), "the helper must be installed root-owned 0755 (#3312)"
    # The grant is only installed after visudo accepts the fragment.
    assert installer.index("visudo -cf") < installer.index("0440 -o root -g root"), (
        "the sudoers fragment must be validated by visudo before it is installed"
    )


# --------------------------------------------------------------------------
# the last mile: applying the grant without disturbing the runner
# --------------------------------------------------------------------------


def test_helpers_only_is_parsed_and_documented():
    installer = _text(INSTALLER)
    assert "--helpers-only)" in installer, "--helpers-only is not parsed (#3312)"
    assert "--helpers-only" in installer.split("set -euo pipefail")[0], (
        "--helpers-only must be documented in the usage header (#3312)"
    )


def test_helpers_only_needs_no_repo():
    """It registers nothing, so it must not demand --repo: the operator
    running it is fixing one grant, not re-registering a runner, and a flag
    they have to look up defeats the point of naming it in the alert."""
    installer = _text(INSTALLER)
    guard = '[[ -n "$helpers_only" || -n "$repo" ]] || usage'
    assert guard in installer, (
        "--helpers-only must not be gated on --repo (#3312)"
    )
    token_fetch = 'if [[ -z "$helpers_only" && -z "$token"'
    assert token_fetch in installer, (
        "--helpers-only must not reach the gh api registration-token fetch (#3312)"
    )


def test_helpers_only_exits_before_every_other_side_effect():
    """The narrow mode is only worth having if it is narrow. A running
    runner keeps the supplementary groups it started with, so the group
    changes and the ownership fix are no-ops for the live service anyway --
    and the runner download / registration / svc.sh stop-start below it is
    exactly the interruption this mode exists to avoid: `svc.sh stop` on an
    installed unit kills whatever job the homeserver is in the middle of."""
    installer = _text(INSTALLER)
    exit_0 = installer.index('Run without --helpers-only for those.\nEOF\n  exit 0')
    for later in (
        "groupadd --system",
        "usermod -aG",
        'find "$dir"',
        "installdependencies.sh",
        "config.sh",
        "./svc.sh stop",
        "./svc.sh start",
    ):
        assert installer.index(later) > exit_0, (
            f"--helpers-only must exit before {later!r}: it is one of the side "
            "effects the narrow mode promises not to have (#3312)"
        )
    # ...and the full path still applies the same grant, so the two modes
    # cannot drift into installing different things.
    assert installer.count("install_root_helpers\n") == 2, (
        "the helper install must be called from both the narrow mode and the "
        "full path -- one call site means one of them silently stopped "
        "installing the grant (#3312)"
    )


@pytest.mark.skipif(
    shutil.which("unshare") is None or shutil.which("visudo") is None,
    reason="needs unshare(1) and visudo(8) to run the installer as root in a throwaway namespace",
)
def test_helpers_only_actually_installs_the_helper_and_the_grant():
    """Runs the real installer, in a user+mount namespace where /opt and
    /etc/sudoers.d are tmpfs, so the two artifacts it claims to write are
    real files and the host is untouched."""
    if not (pathlib.Path("/opt").is_dir() and pathlib.Path("/etc/sudoers.d").is_dir()):
        pytest.skip("no /opt and /etc/sudoers.d to shadow")
    if subprocess.run(["unshare", "-rm", "true"], capture_output=True).returncode != 0:
        pytest.skip("user+mount namespaces unavailable here")

    script = f"""
set -e
mount -t tmpfs tmpfs /opt
mount -t tmpfs tmpfs /etc/sudoers.d
{INSTALLER} --helpers-only
stat -c '%a %U %G' {HELPER_INSTALLED_PATH}
cat /etc/sudoers.d/isolation-audit-github-deploy-runner
visudo -cf /etc/sudoers.d/isolation-audit-github-deploy-runner
"""
    proc = subprocess.run(
        ["unshare", "-rm", "bash", "-c", script],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, (
        f"--helpers-only exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "755 root root" in proc.stdout, (
        f"the installed helper must be root-owned 0755, got:\n{proc.stdout}"
    )
    assert f"github-deploy-runner ALL=(root) NOPASSWD: {HELPER_INSTALLED_PATH}" in proc.stdout, (
        f"the grant for the exact helper path is missing:\n{proc.stdout}"
    )
    # The three isolation-audit grants live in the same fragment; a narrow
    # mode that rewrote the file without them would silently revoke the
    # iptables/ss/aa-status access the audit needs.
    for command in ("/usr/sbin/iptables -S FORWARD", "/usr/bin/ss -tlnp", "/usr/sbin/aa-status"):
        assert f"ALL=(root) NOPASSWD: {command}" in proc.stdout, (
            f"--helpers-only dropped the pre-existing {command} grant (#3312)"
        )


# --------------------------------------------------------------------------
# OIDC: ask the vantage point that is not Cloudflare-blocked
# --------------------------------------------------------------------------


def test_oidc_status_that_fails_the_step_comes_from_the_vps():
    """Cloudflare answers 403 to GitHub-hosted runner ranges and 200 to the
    VPS, the homeserver and a residential client. Failing on the runner's own
    answer is failing on the runner's address, not on OIDC -- which is what
    kept this step red for 160 scheduled runs."""
    workflow = _text(WORKFLOW)
    vps_probe = re.search(
        r'status=\$\(ssh "\$\{ssh_options\[@\]\}" "\$\{VPS_USER:-root\}@\$\{VPS_HOST\}" \\\s*\n'
        r'\s*"curl -s -o /dev/null -w \'%\{http_code\}\' --max-time 10 \'\$url\'"',
        workflow,
    )
    assert vps_probe, "the OIDC probe must curl the discovery URL over SSH to the VPS (#3312)"
    assert re.search(r'runner_status=\$\(curl .*"\$url"', workflow), (
        "the runner's own status is still useful context and must stay reported (#3312)"
    )
    # The comparison that fails the step must be the VPS one, and the
    # runner's must never be part of it.
    assert 'if [ "$status" != "200" ]' in workflow, (
        "the step must still fail on a non-200 OIDC discovery response"
    )
    assert 'runner_status" != "200"' not in workflow and "$runner_status" not in workflow.split(
        'if [ "$status" != "200" ]'
    )[1], "the runner's own 403 must not fail the step (#3312)"
    assert "informational only" in workflow, (
        "the runner's own status must be labelled informational in the summary (#3312)"
    )


# --------------------------------------------------------------------------
# libvirt: the right URI, and the right daemon
# --------------------------------------------------------------------------


def test_audit_pins_the_system_libvirt_uri():
    """Every virsh call in the audit is bare. As a non-root caller (the
    Diagnostics job runs the audit as github-deploy-runner) libvirt's default
    is qemu:///session -- an empty per-user instance with no networks and no
    nwfilters -- so active objects on qemu:///system read as missing."""
    audit = _text(AUDIT)
    pin = 'export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"'
    assert pin in audit, (
        "isolation-audit.sh must pin LIBVIRT_DEFAULT_URI=qemu:///system (#3312)"
    )
    # The first virsh *invocation* -- the file's own comments mention virsh
    # several times, and those must not count.
    first_call = re.search(r"^[^\n#]*\bvirsh \S", audit, re.MULTILINE)
    assert first_call, "isolation-audit.sh no longer calls virsh at all; this check is stale"
    assert audit.index(pin) < first_call.start(), (
        "the URI pin has to precede the first virsh call, not follow it (#3312)"
    )
    # A caller that chose a URI explicitly keeps it: the pin is a default,
    # not an override.
    assert "${LIBVIRT_DEFAULT_URI:-qemu:///system}" in audit, (
        "the pin must remain overridable (#3312)"
    )


def test_homeserver_disables_every_modular_driver_unit():
    """The host runs monolithic libvirtd deliberately. The per-driver modular
    sockets are preset-enabled on EL and each Conflicts= libvirtd; disabling
    only virtproxyd left the rest enabled, they won the race after the
    2026-09-23 reboot, and libvirtd.socket sat inactive with no socket at
    /run/libvirt/libvirt-sock. Each modular daemon ships socket, -ro.socket,
    -admin.socket and .service units, so one of them still being live is
    enough to take libvirtd down with it."""
    homeserver = _text(HOMESERVER)
    for driver in (
        "virtqemud",
        "virtnetworkd",
        "virtnwfilterd",
        "virtstoraged",
        "virtnodedevd",
        "virtsecretd",
        "virtinterfaced",
        "virtproxyd",
    ):
        assert driver in homeserver, (
            f"the monolithic-libvirt branch must disable {driver}'s units too; "
            "any of them left enabled can win the Conflicts= race against "
            "libvirtd and take the socket down (#3312)"
        )
    for suffix in (".socket", "-ro.socket", "-admin.socket", ".service"):
        assert f'"$drv$sfx"' in homeserver, f"the unit sweep must cover {suffix} (#3312)"
    assert "systemctl enable --now libvirtd.socket" in homeserver, (
        "the monolithic branch must enable libvirtd.socket explicitly, not only "
        "disable the modular units (#3312)"
    )


def test_homeserver_reasserts_the_libvirt_group_for_the_runner():
    """install-deploy-runner.sh adds the runner to `libvirt` only if the group
    already exists, and on a fresh host the runner is provisioned before
    libvirt is installed -- so the membership was silently skipped and the
    audit's virsh checks were denied by polkit. The step that guarantees the
    group exists re-asserts it."""
    homeserver = _text(HOMESERVER)
    assert 'usermod -aG libvirt github-deploy-runner' in homeserver, (
        "install-homeserver.sh's libvirt step must re-assert the runner's libvirt "
        "group membership (#3312)"
    )
    step = homeserver[homeserver.index("step_libvirt_install()") :]
    step = step[: step.index("\n}\n")]
    assert "usermod -aG libvirt github-deploy-runner" in step, (
        "the re-assert must live in the libvirt step, where the group is known to exist"
    )
