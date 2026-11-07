#!/usr/bin/env python3
"""Exercise #3316's boot-smoke wiring against stub docker/curl binaries.

The point of these is the wiring, not the containers. Building and running
apiary-backend and dashboard-next is what containers.yml's own job is for;
a unit test that did it would double a 20-minute build to assert something
the workflow already asserts. So DOCKER_BIN/CURL_BIN point at stubs and
every assertion is about what *our* script promises: that it runs the image
by ID, that a healthy container passes, that a boot refusal fails in a
second with the log line that caused it, that a timed-out healthcheck
prints the probes rather than a bare timeout, that the assertions can
actually fail, and that the container and the image are removed on every
path out.

The last class of test is the one that matters most long-term: a smoke whose
expected port or path has drifted from the Dockerfile it smokes is worse
than no smoke, because it is green and meaningless. Those read the
committed Dockerfiles and containers.yml directly, so a rename in either
one has to be made in both.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "scripts" / "boot-smoke-image.sh"
CONTAINERS = ROOT / ".github" / "workflows" / "containers.yml"
BACKEND_DOCKERFILE = (
    ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service" / "Dockerfile"
)
DASHBOARD_DOCKERFILE = (
    ROOT / "arcane" / "home" / "honeypot-dashboard" / "frontend-next" / "Dockerfile"
)
BACKEND_SRC = ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service" / "src"
BACKEND_MAIN = BACKEND_SRC / "main.rs"

IMAGE_ID = "sha256:" + "ab" * 32


# ------------------------------------------------------- the route table --

def declared_backend_routes() -> set[str]:
    r"""Every path backend-service's router registers, as a set of literals.

    Where this reads from moved twice, and both moves are invisible in a
    diff, so they are recorded here rather than left to be rediscovered:

    - #3325's first commit put the route table in `src/main.rs` as
      `Router::new().route("/livez", get(livez))` -- the path spelled out
      beside the handler.
    - #3325's second commit moved every module and the table itself into
      `src/lib.rs`, because the OpenAPI document is generated from the same
      `Router` the process serves and a second binary cannot see a first
      binary's modules. `main.rs` kept only what is genuinely a process.
    - #3325's third commit replaced each `.route(path, method(handler))`
      with `.routes(utoipa_axum::routes!(handler))`, which takes the path
      and the method off the handler's `#[utoipa::path]` annotation. So
      after that commit there is no `path` literal in the table at all --
      `src/lib.rs` is an index of handlers, and the paths live next to the
      handlers, in their own modules.

    So the answer is the set of `path = "..."` values declared by a
    `#[utoipa::path(` attribute anywhere under `src/`, plus any literal
    `.route("..."` registration still present. The second form is not
    expected to match anything today: `contract_covers_every_router_route`
    in `src/openapi.rs` fails if `.route(` appears in `src/lib.rs` at all,
    because `OpenApiRouter` would inherit it as a pass-through that serves
    a route with no OpenAPI operation. It is kept so that a future table
    written in plain axum is still checked rather than silently passing on
    an empty scan.

    Both patterns require the captured value to start with `/`, and that is
    not decoration. `openapi.rs`'s own test module holds
    `const BYPASSING_ROUTES: [&str; 3] = [".route(", ".route_service(",
    ".nest_service("];` -- the very strings `contract_covers_every_router_route`
    greps for -- so a looser `\.route\(\s*\"([^\"]+)\"` reads that Rust string
    literal as a route registration and invents entries. Every real path in
    this crate begins with `/`, so requiring it costs nothing and keeps the
    crate from being evidence about itself.

    That Rust test is also what makes the annotation half sufficient on its
    own: it fails if a `#[utoipa::path]` is not routed, so a declared path
    here is a routed path there.
    """
    paths: set[str] = set()
    for source in sorted(BACKEND_SRC.rglob("*.rs")):
        text = source.read_text(encoding="utf-8")
        for match in re.finditer(r"\.route\(\s*\"(/[^\"]+)\"", text):
            paths.add(match.group(1))
        # Each attribute's own text, from just inside `#[utoipa::path(` to
        # its matching close paren, so a `path = "..."` belonging to some
        # other attribute cannot be mistaken for this one's.
        for start in (m.start() for m in re.finditer(r"#\[utoipa::path\(", text)):
            open_at = start + len("#[utoipa::path(")
            depth = 1
            end = open_at
            while depth > 0 and end < len(text):
                if text[end] == "(":
                    depth += 1
                elif text[end] == ")":
                    depth -= 1
                end += 1
            declared = re.search(r"path\s*=\s*\"(/[^\"]+)\"", text[open_at:end])
            if declared:
                paths.add(declared.group(1))
    return paths


# --------------------------------------------------------------- the stubs --

# One bash stub for both binaries, dispatched on argv[0] by the symlink the
# test creates. Records every invocation so the assertions can be about the
# docker argv the script built, not about what it printed.
DOCKER_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
self=$(basename "$0")
printf '%s' "$self" >>"${STUB_CALLS:?}"
printf ' %s' "$@" >>"${STUB_CALLS:?}"
printf '\n' >>"${STUB_CALLS:?}"

if [ "$self" = "curl" ]; then
  # Last argument is the URL.
  url="${!#}"
  path=${url#*://*/}
  path=${path%%\?*}
  # Same slug the test's answer() helper writes: the path with its leading
  # slash and every non-alphanumeric turned into an underscore.
  slug=$(printf '%s' "/$path" | sed 's/[^A-Za-z0-9]/_/g')
  dir=${STUB_HTTP:?}/$slug
  # -D writes headers, -o writes the body, -w writes the status to stdout.
  out=""
  prev=""
  for a in "$@"; do
    case "$prev" in
      -o) out=$a ;;
      -D) headers=$a ;;
    esac
    prev=$a
  done
  code=000
  [ -f "$dir.code" ] && code=$(cat "$dir.code")
  [ -n "${out:-}" ] && cat "$dir.body" >"$out" 2>/dev/null || true
  [ -n "${headers:-}" ] && cat "$dir.headers" >"$headers" 2>/dev/null || true
  printf '%s' "$code"
  exit 0
fi

cmd=${1:-}
shift || true
case "$cmd" in
  container)
    # Only the "does this name already exist" probe reaches here.
    exit "${STUB_CONTAINER_EXISTS_RC:-1}"
    ;;
  network)
    # `-` not `:-`: an explicitly empty gateway means the network
  # inspect returned nothing, which is the case under test.
  printf '%s\n' "${STUB_BRIDGE_GATEWAY-127.0.0.1}"
    exit 0
    ;;
  run)
    if [ "${STUB_RUN_RC:-0}" != "0" ]; then
      echo "stub: docker run refused" >&2
      exit "$STUB_RUN_RC"
    fi
    printf '%s\n' "c0ffee1234567890"
    exit 0
    ;;
  port)
    printf '%s\n' "${STUB_PUBLISHED:-127.0.0.1:49153}"
    exit 0
    ;;
  inspect)
    fmt=""
    name=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --format) fmt=${2:-}; shift 2 ;;
        *) name=$1; shift ;;
      esac
    done
    case "$fmt" in
      *'.State.Health.Log'*)
        # The per-probe diagnostic. Empty unless the test seeded one.
        [ -f "${STUB_HEALTH_LOG:-/nonexistent}" ] && cat "${STUB_HEALTH_LOG}"
        exit 0
        ;;
      *'exit={{.State.ExitCode}}'*)
        printf '%s\n' "${STUB_DUMP_LINE:-status=running exit=0 oom=false error=}"
        exit 0
        ;;
      *)
        # The health poll: one scripted state per invocation, then the last
        # one forever (a container that never changes state is the normal
        # case, and re-sending the tail keeps the stub small).
        seq_file="${STUB_POLL_SEQ:?}"
        n=$(cat "${STUB_POLL_N:-/dev/null}" 2>/dev/null || echo 0)
        n=$((n + 1))
        printf '%s' "$n" >"${STUB_POLL_N:-/dev/null}"
        total=$(wc -l <"$seq_file")
        if [ "$n" -gt "$total" ]; then n=$total; fi
        sed -n "${n}p" "$seq_file"
        exit 0
        ;;
    esac
    ;;
  logs)
    printf '%s\n' "${STUB_LOGS:-stub log line}"
    exit 0
    ;;
  rm | rmi)
    exit 0
    ;;
  image)
    exit 1
    ;;
esac
echo "stub: unhandled docker $cmd $*" >&2
exit 64
"""


def _write_exec(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class SmokeHarness(unittest.TestCase):
    """Runs boot-smoke-image.sh with stubbed docker/curl."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self.bindir = self.tmp / "bin"
        self.bindir.mkdir()
        stub = _write_exec(self.tmp / "stub", DOCKER_STUB)
        for name in ("docker", "curl"):
            (self.bindir / name).symlink_to(stub)

        self.calls = self.tmp / "calls.log"
        self.calls.write_text("", encoding="utf-8")
        self.http = self.tmp / "http"
        self.http.mkdir()
        self.poll_seq = self.tmp / "poll.seq"
        self.poll_n = self.tmp / "poll.n"
        # A container that comes up and stays up: the ordinary pass.
        self.poll_seq.write_text("running|healthy\n", encoding="utf-8")
        self.poll_n.write_text("0", encoding="utf-8")

    # -- fixture helpers ---------------------------------------------------

    def answer(self, path: str, code: str, body: str = "", headers: str = "") -> None:
        """Pin what the curl stub returns for a URL path."""
        slug = re.sub(r"[^A-Za-z0-9]", "_", path)
        (self.http / f"{slug}.code").write_text(code, encoding="utf-8")
        (self.http / f"{slug}.body").write_text(body, encoding="utf-8")
        (self.http / f"{slug}.headers").write_text(headers, encoding="utf-8")

    def polls(self, *states: str) -> None:
        self.poll_seq.write_text("".join(f"{s}\n" for s in states), encoding="utf-8")
        self.poll_n.write_text("0", encoding="utf-8")

    def poll_count(self) -> int:
        return int(self.poll_n.read_text().strip() or 0)

    def invocations(self, binary: str) -> list[str]:
        return [
            line.split(" ", 1)[1]
            for line in self.calls.read_text().splitlines()
            if line.split(" ", 1)[0] == binary
        ]

    def smoke(self, *args: str, env: dict[str, str] | None = None):
        merged = dict(os.environ)
        # A predictable PATH ahead of the real one, but still carrying the
        # real utilities the script needs (python3, mktemp, date, sleep).
        merged["PATH"] = f"{self.bindir}:{os.environ.get('PATH', '')}"
        merged.update(
            {
                "STUB_CALLS": str(self.calls),
                "STUB_HTTP": str(self.http),
                "STUB_POLL_SEQ": str(self.poll_seq),
                "STUB_POLL_N": str(self.poll_n),
            }
        )
        if env:
            merged.update(env)
        return subprocess.run(
            ["bash", str(SMOKE), *args],
            capture_output=True,
            text=True,
            env=merged,
            check=False,
        )

    def base(self, *extra: str) -> list[str]:
        return [
            "--image-id",
            IMAGE_ID,
            "--name",
            "ci-bootsmoke-test",
            "--container-port",
            "8080",
            *extra,
        ]


# ------------------------------------------------------------- the script ---


class Arguments(SmokeHarness):
    def test_help_prints_the_files_own_header(self) -> None:
        """A help text that has drifted from the code is worse than none."""
        res = self.smoke("--help")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("--expect-json", res.stdout)
        self.assertIn("#3316", res.stdout)

    def test_a_tag_is_not_an_image_id(self) -> None:
        """The brief's 'the exact built image' is the feature: a tag can be
        moved between the build and the smoke, and then the smoke describes
        an image nobody built."""
        res = self.smoke(*self.base()[:1] + ["ghcr.io/Xore/honeypot-backend-service:main"] + self.base()[2:])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("must be an image ID", res.stderr)
        self.assertEqual(self.invocations("docker"), [])

    def test_a_malformed_digest_is_refused(self) -> None:
        res = self.smoke("--image-id", "sha256:zzzz", "--name", "n", "--container-port", "8080")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("malformed digest", res.stderr)

    def test_missing_required_flags_are_named(self) -> None:
        for args, expected in (
            (["--name", "n", "--container-port", "8080"], "--image-id is required"),
            (["--image-id", IMAGE_ID, "--container-port", "8080"], "--name is required"),
            (["--image-id", IMAGE_ID, "--name", "n"], "--container-port is required"),
        ):
            with self.subTest(args=args):
                res = self.smoke(*args)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn(expected, res.stderr)

    def test_an_assertion_flag_missing_its_third_value_is_named(self) -> None:
        """The #2214 shape: a half-specified assertion must not become a
        silently-skipped check."""
        res = self.smoke(*self.base("--expect-status", "label only"))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("needs <label> <path> <code-regex>", res.stderr)

    def test_a_name_already_in_use_is_refused(self) -> None:
        """Reusing it would let a stale container answer 'is this healthy'."""
        res = self.smoke(*self.base(), env={"STUB_CONTAINER_EXISTS_RC": "0"})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("already exists", res.stderr)
        self.assertNotIn("run --detach", "\n".join(self.invocations("docker")))


class HappyPath(SmokeHarness):
    def test_a_healthy_container_passes_every_assertion(self) -> None:
        self.answer("/healthz", "200", '{"live":true}')
        self.answer("/readyz", "200", '{"ready":true,"cluster":"green"}')
        res = self.smoke(
            *self.base(
                "--expect-status",
                "liveness",
                "/healthz",
                "200",
                "--expect-json",
                "readiness",
                "/readyz",
                'd["ready"] is True',
            )
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("reported healthy", res.stdout)
        self.assertIn("ok   liveness", res.stdout)
        self.assertIn("ok   readiness", res.stdout)

    def test_it_runs_the_image_by_id_on_an_ephemeral_loopback_port(self) -> None:
        """A fixed host port is a collision waiting to happen on an executor
        whose docker daemon is shared by seven runner users."""
        self.answer("/healthz", "200")
        res = self.smoke(*self.base("--expect-status", "liveness", "/healthz", "200"))
        self.assertEqual(res.returncode, 0, res.stderr)
        run = next(i for i in self.invocations("docker") if i.startswith("run "))
        self.assertIn(IMAGE_ID, run)
        self.assertIn("--publish 127.0.0.1::8080", run)
        self.assertIn("--detach", run)
        # The assertions are made against the port docker reported, not the
        # container's, so a change in how the mapping is written cannot
        # silently point them at nothing.
        self.assertIn("127.0.0.1:49153", res.stdout)

    def test_uses_no_rm_so_the_logs_survive_until_they_are_captured(self) -> None:
        """--rm would delete the container -- and the log line that explains a
        boot refusal -- the instant it exits, which is exactly when the log
        matters most."""
        self.answer("/healthz", "200")
        res = self.smoke(*self.base("--expect-status", "liveness", "/healthz", "200"))
        self.assertEqual(res.returncode, 0, res.stderr)
        run = next(i for i in self.invocations("docker") if i.startswith("run "))
        self.assertNotIn("--rm", run.split())


class FailurePaths(SmokeHarness):
    def test_a_boot_refusal_fails_fast_and_prints_its_logs(self) -> None:
        """The #2183/#2299 shape this whole check exists for: the container
        exits in under a second and the log line is the answer. Waiting out
        a 120s timeout first would bury the one useful fact."""
        self.polls("exited|starting")
        res = self.smoke(
            *self.base("--health-timeout", "120", "--expect-status", "liveness", "/healthz", "200")
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("exited (exited) before reporting healthy", res.stderr)
        self.assertIn("stub log line", res.stderr)
        # One poll, then it stopped: the timeout was not burned.
        self.assertEqual(self.poll_count(), 1)

    def test_a_healthcheck_timeout_reports_the_probes(self) -> None:
        """'did not become healthy' alone sends people to the container by
        hand; the last few probe results say which half is broken."""
        self.polls("running|starting", "running|unhealthy", "running|unhealthy")
        log = self.tmp / "health.log"
        log.write_text(
            '  exit=1 "wget: can\'t connect to remote host (127.0.0.1): Connection refused\\n"\n',
            encoding="utf-8",
        )
        res = self.smoke(
            *self.base("--health-timeout", "2", "--expect-status", "liveness", "/healthz", "200"),
            env={"STUB_HEALTH_LOG": str(log)},
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("did not report healthy within 2s", res.stderr)
        self.assertIn("last healthcheck probes", res.stderr)
        self.assertIn("Connection refused", res.stderr)
        self.assertIn("stub log line", res.stderr)

    def test_a_docker_run_that_fails_is_reported_with_dockers_own_message(self) -> None:
        res = self.smoke(
            *self.base("--expect-status", "liveness", "/healthz", "200"),
            env={"STUB_RUN_RC": "125"},
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("could not start", res.stderr)
        self.assertIn("docker run refused", res.stderr)

    def test_a_failing_status_assertion_shows_the_body_it_got(self) -> None:
        self.answer("/healthz", "503", "upstream unavailable")
        res = self.smoke(*self.base("--expect-status", "liveness", "/healthz", "200"))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAIL liveness (GET /healthz -> 503)", res.stderr)
        self.assertIn("upstream unavailable", res.stderr)

    def test_a_status_assertion_accepts_a_regex(self) -> None:
        """The dashboard's own contract is '30[27]', not one exact code --
        auth-flow.sh has always accepted the pair."""
        self.answer("/", "307", "", "Location: /auth/login?return_to=%2F\r\n")
        res = self.smoke(*self.base("--expect-status", "guard", "/", "30[27]"))
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_a_failing_redirect_assertion_names_the_status_and_location(self) -> None:
        self.answer("/", "200", "<html>signed in</html>")
        res = self.smoke(*self.base("--expect-redirect", "guard", "/", "/auth/login"))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAIL guard (GET / -> 200)", res.stderr)
        self.assertIn("signed in", res.stderr)

    def test_a_redirect_to_the_wrong_place_fails(self) -> None:
        """3xx alone is not the contract; the destination is."""
        self.answer("/", "302", "", "Location: /somewhere-else\r\n")
        res = self.smoke(*self.base("--expect-redirect", "guard", "/", "/auth/login"))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAIL guard", res.stderr)

    def test_a_json_assertion_can_fail(self) -> None:
        self.answer("/readyz", "200", '{"ready":false,"cluster":"unreachable"}')
        res = self.smoke(
            *self.base("--expect-json", "readiness", "/readyz", 'd["ready"] is True')
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAIL readiness", res.stderr)
        self.assertIn('"cluster":"unreachable"', res.stderr)

    def test_a_json_assertion_over_a_non_json_body_fails_rather_than_passing(self) -> None:
        """The vacuous-pass shape (#2214) one level down: a proxy error page
        that is not JSON at all must not read as a satisfied assertion."""
        self.answer("/readyz", "200", "<html>502 Bad Gateway</html>")
        res = self.smoke(
            *self.base("--expect-json", "readiness", "/readyz", 'd["ready"] is True')
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not JSON", res.stderr)

    def test_one_failing_assertion_fails_the_whole_smoke(self) -> None:
        self.answer("/healthz", "200")
        self.answer("/readyz", "503", "{}")
        res = self.smoke(
            *self.base(
                "--expect-status", "liveness", "/healthz", "200",
                "--expect-json", "readiness", "/readyz", 'd["ready"] is True',
            )
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("1 HTTP assertion(s) failed", res.stderr)


class Degradation(SmokeHarness):
    def test_an_image_without_a_healthcheck_still_gets_its_assertions(self) -> None:
        """An image with no HEALTHCHECK is a coverage gap for the health
        half of this check, not a reason to report a broken image."""
        self.polls("running|none", "running|none", "running|none", "running|none",
                   "running|none", "running|none", "running|none")
        self.answer("/healthz", "200")
        res = self.smoke(
            *self.base("--health-timeout", "120", "--expect-status", "liveness", "/healthz", "200")
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("No HEALTHCHECK to wait on", res.stdout)
        self.assertIn("ok   liveness", res.stdout)

    def test_no_healthcheck_and_no_assertions_measured_nothing(self) -> None:
        """Both halves absent is a wiring mistake in the caller. Reporting it
        as a pass is the exact failure mode this check exists to remove."""
        self.polls(*(["running|none"] * 8))
        res = self.smoke(*self.base("--health-timeout", "120"))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("measured nothing", res.stdout)

    def test_healthcheck_alone_is_a_real_signal_and_only_warns(self) -> None:
        res = self.smoke(*self.base())
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("asserted nothing", res.stdout)
        self.assertIn("reached healthy", res.stdout)


class Cleanup(SmokeHarness):
    def test_the_container_and_the_image_are_removed_on_success(self) -> None:
        self.answer("/healthz", "200")
        res = self.smoke(*self.base("--expect-status", "liveness", "/healthz", "200"))
        self.assertEqual(res.returncode, 0, res.stderr)
        calls = self.invocations("docker")
        self.assertIn("rm -f ci-bootsmoke-test", calls)
        self.assertIn(f"rmi {IMAGE_ID}", calls)

    def test_they_are_removed_on_a_boot_refusal_too(self) -> None:
        self.polls("exited|starting")
        res = self.smoke(
            *self.base("--expect-status", "liveness", "/healthz", "200"),
        )
        self.assertNotEqual(res.returncode, 0)
        calls = self.invocations("docker")
        self.assertIn("rm -f ci-bootsmoke-test", calls)
        self.assertIn(f"rmi {IMAGE_ID}", calls)

    def test_keep_image_leaves_the_image_for_a_human_to_poke_at(self) -> None:
        self.answer("/healthz", "200")
        res = self.smoke(
            *self.base("--expect-status", "liveness", "/healthz", "200", "--keep-image")
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        calls = self.invocations("docker")
        self.assertIn("rm -f ci-bootsmoke-test", calls)
        self.assertNotIn(f"rmi {IMAGE_ID}", calls)

    def test_nothing_is_removed_when_the_run_never_started(self) -> None:
        """A docker run that failed has no container to remove; reaching for
        one anyway would be removing somebody else's."""
        res = self.smoke(
            *self.base("--expect-status", "liveness", "/healthz", "200"),
            env={"STUB_RUN_RC": "125"},
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn("rm -f ci-bootsmoke-test", self.invocations("docker"))


class StubElasticsearch(SmokeHarness):
    """The stub has to be real enough to be worth starting, so these run the
    actual embedded program and speak to it."""

    def start(self, **env: str) -> str:
        self.answer("/healthz", "200", '{"live":true}')
        res = self.smoke(
            *self.base(
                "--stub-es-env",
                "ELASTICSEARCH_URL",
                "--expect-status",
                "liveness",
                "/healthz",
                "200",
            ),
            # Loopback rather than the real bridge gateway: the stub binds a
            # host interface, and a unit test must not require one.
            env={"STUB_BRIDGE_GATEWAY": "127.0.0.1", **env},
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        match = re.search(r"stub Elasticsearch on (http://\S+)", res.stdout)
        self.assertIsNotNone(match, res.stdout)
        return match.group(1)

    def get(self, url: str) -> tuple[int, dict[str, str], dict]:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = json.loads(response.read().decode())
            return response.status, dict(response.headers), body

    def standalone_stub(self) -> str:
        """Run the stub program on its own, the way the container sees it.

        A full smoke run tears the stub down in its EXIT trap, so the
        contract it has to honour can only be checked by starting the
        program directly. Extracted from the script rather than copied, so
        this cannot pass against a stub the script no longer ships.
        """
        source = SMOKE.read_text(encoding="utf-8")
        body = re.search(r"cat >\"\$STUB_ES_PY\" <<'PY'\n(.*?)\nPY\n", source, re.S)
        self.assertIsNotNone(body, "the stub Elasticsearch program is no longer in the script")
        program = self.tmp / "stub-es.py"
        program.write_text(body.group(1) + "\n", encoding="utf-8")
        port_file = self.tmp / "stub.port"
        process = subprocess.Popen(
            [
                "python3",
                str(program),
                "--bind",
                "127.0.0.1",
                "--port",
                "0",
                "--port-file",
                str(port_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        for _ in range(100):
            if port_file.is_file() and port_file.read_text().strip():
                break
            time.sleep(0.05)
        else:  # pragma: no cover - only on a badly broken host
            self.fail("the stub Elasticsearch never reported a port")
        return f"http://127.0.0.1:{port_file.read_text().strip()}"

    def test_the_stub_serves_the_product_document_the_8x_client_demands(self) -> None:
        """Without this header the elasticsearch-rs transport refuses to
        issue any API call, so /readyz would report 'unreachable' against a
        perfectly good stub and every readiness assertion would be a lie."""
        status, headers, body = self.get(self.standalone_stub() + "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Elastic-Product"), "Elasticsearch")
        self.assertEqual(body["version"]["number"], "8.13.0")

    def test_the_stub_reports_a_green_cluster(self) -> None:
        _, _, body = self.get(self.standalone_stub() + "/_cluster/health")
        self.assertEqual(body["status"], "green")

    def test_the_stub_reports_no_write_blocked_indices(self) -> None:
        """An empty object is what a fresh cluster legitimately reports --
        every dashboard-owned index is created on its first write -- and it
        is what es.rs's write_blocked reads as 'writable'."""
        _, _, body = self.get(self.standalone_stub() + "/honeypot-v2-*/_settings?flat_settings=true")
        self.assertEqual(body, {})

    def test_an_unmodelled_request_does_not_become_a_connection_error(self) -> None:
        """Anything the readiness path adds later has to answer rather than
        refuse, or the next assertion fails on the stub instead of on the
        image."""
        _, headers, body = self.get(self.standalone_stub() + "/_cat/indices")
        self.assertEqual(headers.get("X-Elastic-Product"), "Elasticsearch")
        self.assertIsInstance(body, dict)

    def test_stub_es_env_reaches_the_container_under_the_named_var(self) -> None:
        url = self.start()
        run = next(i for i in self.invocations("docker") if i.startswith("run "))
        self.assertIn(f"ELASTICSEARCH_URL={url}", run)
        # ...and the container has to be able to reach the host at all.
        self.assertIn("--add-host host.docker.internal:host-gateway", run)

    def test_no_stub_no_host_alias(self) -> None:
        self.answer("/healthz", "200")
        res = self.smoke(*self.base("--expect-status", "liveness", "/healthz", "200"))
        self.assertEqual(res.returncode, 0, res.stderr)
        run = next(i for i in self.invocations("docker") if i.startswith("run "))
        self.assertNotIn("--add-host", run)

    def test_a_missing_bridge_network_is_a_loud_failure(self) -> None:
        """The stub binds the bridge gateway precisely so it is not exposed
        off-box; an executor without that network has to say so rather than
        quietly binding 0.0.0.0."""
        res = self.smoke(
            *self.base("--stub-es-env", "ELASTICSEARCH_URL"),
            env={"STUB_BRIDGE_GATEWAY": ""},
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("docker bridge gateway", res.stderr)


# --------------------------------------------- drift against what is real ---


class ParityWithTheDockerfiles(unittest.TestCase):
    """A smoke that has drifted from the image it smokes is green and
    meaningless, which is worse than no smoke at all. These read the
    committed Dockerfiles and containers.yml directly."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.containers = CONTAINERS.read_text(encoding="utf-8")
        cls.backend = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        cls.dashboard = DASHBOARD_DOCKERFILE.read_text(encoding="utf-8")

    def step(self, title: str) -> str:
        """The run: block of one named step, as text."""
        match = re.search(
            rf'- name: "{re.escape(title)}".*?\n( {{8}}run: \|.*?)(?=\n {{6}}- )',
            self.containers,
            re.S,
        )
        self.assertIsNotNone(match, f"no run: block for step {title!r}")
        return match.group(1)

    def matrix_rows(self) -> dict[str, list[str]]:
        """image name -> its own lines, comments excluded.

        Comment-aware on purpose. A substring check for 'boot_smoke: true'
        passes on the *prose* that explains the flag, so deleting the flag
        from a row and leaving its comment behind would keep this green --
        which is the same trap check-backend-boot-contract.py documents
        (stdllib, indentation-based, no YAML dependency).
        """
        rows: dict[str, list[str]] = {}
        for name, body in re.findall(r"- image: (\S+)\n((?: {12}.*\n)*)", self.containers):
            rows[name] = [
                line.strip()
                for line in body.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        return rows

    def test_the_two_dashboard_rows_are_the_ones_that_get_smoked(self) -> None:
        """Named rows, not a count of them, so this cannot rot into a
        vacuous pass the way a substring check would -- and the count stays
        as a tripwire, because a *new* long-lived service image is exactly
        the kind of row that has to be smoked too, and this is the place
        that should make a reviewer say so out loud."""
        rows = self.matrix_rows()
        # 19 as of #3131, which added the citrix and sonicwall rows after
        # #3321's comments last named a number; 53 as of #3597, which added
        # one `scoped: true` row per remaining compose build context (none of
        # them long-lived dashboard services, so the smoked set below is
        # unchanged). If this fails, the matrix moved: check the new row
        # before bumping it.
        self.assertEqual(len(rows), 53, "the build matrix changed size")
        smoked = {name for name, lines in rows.items() if "boot_smoke: true" in lines}
        self.assertEqual(smoked, {"backend-service", "dashboard-next"})

    def test_every_other_row_still_builds_exactly_as_before(self) -> None:
        """`push` unchanged, and `load` inert without the flag -- so the
        capture daemons are not loading a 400 MB image into a shared daemon
        on every run."""
        self.assertIn("push: ${{ github.event_name != 'pull_request' }}", self.containers)
        load = re.search(r"^\s+load: (.+)$", self.containers, re.M)
        self.assertIsNotNone(load)
        self.assertIn("matrix.boot_smoke", load.group(1))
        labels = re.search(r"^\s+labels: (.+)$", self.containers, re.M)
        self.assertIsNotNone(labels, "the build step lost its labels: input")
        # The build-row label is appended by a shell step (#3316), because an
        # expression cannot produce the real newline that separates labels --
        # `format('\n...')` emits a literal backslash-n that gets glued onto
        # the previous label's value. So the gating moved from the `labels:`
        # expression to that step's `if:`. The invariant is unchanged: only a
        # boot-smoke row gets the label, and every row still gets the base
        # labels the build-push-action reads.
        labels_value = labels.group(1)
        self.assertIn("steps.metadata.outputs.labels", labels_value)
        self.assertRegex(
            labels_value, r"\$\{\{\s*steps\.buildrow\.outputs\.labels\s*\|\|",
        )
        buildrow = re.search(
            r"- name: Append the boot-smoke build-row label\s*\n"
            r"\s*id: buildrow\s*\n"
            r"\s*if: (.+)$",
            self.containers,
            re.M,
        )
        self.assertIsNotNone(buildrow, "the label-append step is gone")
        self.assertIn("matrix.boot_smoke", buildrow.group(1))

    def test_every_smoked_row_has_a_step_and_no_other_row_does(self) -> None:
        steps = set(re.findall(r"- name: \"?Boot-smoke (\S+)", self.containers))
        self.assertEqual(steps, {"backend-service", "dashboard-next"})
        for image in ("backend-service", "dashboard-next"):
            self.assertIn(f"matrix.image == '{image}'", self.containers)

    def test_the_smokes_run_inside_the_build_job_the_required_gate_aggregates(self) -> None:
        """A step in a job containers-gate does not list would be a smoke
        nobody is waiting for -- and a green run whose gate silently stopped
        covering it is the same failure with a nicer-looking trace."""
        head, _, gate = self.containers.partition("\n  containers-gate:")
        self.assertTrue(gate, "containers-gate job is gone")
        self.assertIn('"Boot-smoke backend-service (#3316)"', head)
        self.assertIn('"Boot-smoke dashboard-next (#3316)"', head)
        # The gate has to depend on the job the smokes run in, or it can
        # never observe their failure. needs: is a flow sequence, so match
        # the build entry itself rather than the word.
        needs = re.search(r"^    needs: \[(.*)\]$", gate, re.M)
        self.assertIsNotNone(needs, "containers-gate no longer declares needs: [...]")
        self.assertIn("build", [n.strip() for n in needs.group(1).split(",")])

    def test_the_container_ports_match_what_each_image_exposes(self) -> None:
        for image, dockerfile, port in (
            ("backend-service", self.backend, "8081"),
            ("dashboard-next", self.dashboard, "8080"),
        ):
            with self.subTest(image=image):
                self.assertIsNotNone(
                    re.search(rf"^EXPOSE {port}$", dockerfile, re.M),
                    f"{image}'s Dockerfile no longer EXPOSEs {port}",
                )
                step = self.step(f"Boot-smoke {image} (#3316)")
                self.assertIn(f"--container-port {port}", step)

    def test_dashboard_next_smokes_the_path_its_own_healthcheck_uses(self) -> None:
        """The vendored theme asset is a deploy requirement (theme.lock), and
        the healthcheck is the only thing that fetches it -- if one of the two
        moves, the smoke would keep passing against the other."""
        healthcheck = re.search(r"^HEALTHCHECK\b", self.dashboard, re.M)
        self.assertIsNotNone(healthcheck, "dashboard-next no longer declares a HEALTHCHECK")
        self.assertIn("/static/theme.css", self.dashboard)
        step = self.step("Boot-smoke dashboard-next (#3316)")
        self.assertTrue(
            "--expect-status 'vendored theme.css is served' /static/theme.css 200" in step,
            "the dashboard-next smoke no longer asserts the healthcheck's own path",
        )

    def test_backend_service_smokes_routes_the_binary_actually_registers(self) -> None:
        """/healthz and /readyz are the two names #3317's liveness/readiness
        split left behind; if a rename ever removes one, this fails rather
        than letting a 404 read as a broken assertion."""
        declared = declared_backend_routes()
        step = self.step("Boot-smoke backend-service (#3316)")
        # Anchored on the flag, past the quoted label, to the bare path --
        # and required to find something, because a pattern that stops
        # matching would otherwise turn this into a green that checks
        # nothing (#2214's shape, third cousin).
        paths = re.findall(r"--expect-\w+ '[^']*' (/[\w/-]+)", step)
        self.assertGreaterEqual(
            len(paths), 2, f"no assertion paths parsed out of the step:\n{step}"
        )
        # The scan is the input to every comparison below, so an empty one
        # would report each route as missing for a reason that has nothing to
        # do with the route. Caught here instead, where the cause is legible:
        # see declared_backend_routes() for where the paths live and why.
        self.assertGreaterEqual(
            len(declared),
            4,
            "no route paths parsed out of backend-service/src -- the table moved "
            "and this scan no longer knows where to look",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertIn(
                    path,
                    declared,
                    f"backend-service no longer registers {path} "
                    f"(declared: {sorted(declared)})",
                )

    def test_the_backend_healthcheck_path_is_a_registered_route_too(self) -> None:
        """The healthcheck is the gate the smoke waits on, and nothing else
        checks that its path still exists -- a rename would leave the
        container permanently unhealthy with a green build."""
        declared = declared_backend_routes()
        healthcheck = re.search(r"--start-period=\d+s \\\n\s+CMD (.*)", self.backend)
        self.assertIsNotNone(healthcheck)
        path = re.search(r"/(\w+)\"", healthcheck.group(1))
        self.assertIsNotNone(path, healthcheck.group(1))
        self.assertIn(
            f"/{path.group(1)}",
            declared,
            f"the backend HEALTHCHECK curls /{path.group(1)}, which "
            f"backend-service no longer registers (declared: {sorted(declared)})",
        )

    def test_dashboard_next_smokes_the_redirect_the_bff_actually_issues(self) -> None:
        """__root.tsx's beforeLoad is what sends an unauthenticated /
        to /auth/login; that is the contract, not a guess about it."""
        root = (
            ROOT / "arcane" / "home" / "honeypot-dashboard" / "frontend-next"
            / "src" / "routes" / "__root.tsx"
        ).read_text(encoding="utf-8")
        self.assertIn("redirect(", root)
        self.assertIn("/auth/login", root)

    def test_nothing_interpolated_into_a_run_block(self) -> None:
        """zizmor's template-injection audit cannot tell an image name from
        attacker input from the outside, so every `${{ }}` reaches a run:
        block through env: (same rule #3321's SBOM step follows)."""
        for title in (
            "Resolve the image ID to boot-smoke (#3316)",
            "Boot-smoke backend-service (#3316)",
            "Boot-smoke dashboard-next (#3316)",
        ):
            with self.subTest(step=title):
                self.assertNotIn("${{", self.step(title))

    def test_the_health_timeout_covers_the_images_own_retry_budget(self) -> None:
        """Both images declare --start-period=20s --interval=15s
        --retries=5, so a broken image exhausts its own budget at 95s. A
        timeout under that would report a slow start as a failure, and one
        far above it turns a boot refusal into a job timeout with no
        explanation."""
        for dockerfile in (self.backend, self.dashboard):
            start = int(re.search(r"--start-period=(\d+)s", dockerfile).group(1))
            interval = int(re.search(r"--interval=(\d+)s", dockerfile).group(1))
            retries = int(re.search(r"--retries=(\d+)", dockerfile).group(1))
            budget = start + interval * retries
            for image in ("backend-service", "dashboard-next"):
                step = self.step(f"Boot-smoke {image} (#3316)")
                timeout = int(re.search(r"--health-timeout (\d+)", step).group(1))
                self.assertGreater(timeout, budget, f"{image}: {timeout}s <= {budget}s budget")
                self.assertLess(timeout, budget + 60, f"{image}: {timeout}s is slack for nothing")


if __name__ == "__main__":
    unittest.main()
