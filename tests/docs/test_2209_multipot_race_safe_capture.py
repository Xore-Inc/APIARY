#!/usr/bin/env python3
"""Regression test for #2209: TestServeSkipsLoggingOwnHealthcheck in
arcane/home/honeypot-multipot/multipot/protocols_logging_test.go read a plain
bytes.Buffer on the main goroutine while serve()'s emitter wrote the same
buffer from its own goroutine. `go test -race ./...` flagged it; plain
`go test ./...` passed, which is why CI (quality.yml runs non-race) never saw
it.

The fix declares a sync.Mutex, routes logger.out through a writerFunc adapter
that holds the mutex for every Write, and holds the same mutex across the
read of buf.String() in the assertion. Both halves are required: locking only
the writer and reading the buffer bare still races (verified -- the detector
reports the read at buf.String() as one side of the pair).

Two layers of coverage here:

* test_go_race_detector_reports_no_race actually runs
  `go test -race -run ^TestServeSkipsLoggingOwnHealthcheck$`. That is the
  real contract, and it catches a partial fix that a text scan cannot. It
  skips when the Go toolchain or loopback networking is unavailable.
* the structural tests enforce the same contract by reading the source, so
  the regression is still caught on hosts with no Go toolchain: a mutex
  exists, logger.out is not a bare &buf, *every* access to the buffer sits
  inside a held critical section, and neither of the two behavioural
  assertions from #1677 was weakened while the race was being fixed.
"""
import os
import pathlib
import re
import shutil
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PKG_DIR = REPO_ROOT / "arcane/home/honeypot-multipot/multipot"
TEST_FILE = PKG_DIR / "protocols_logging_test.go"
FUNC_NAME = "TestServeSkipsLoggingOwnHealthcheck"

# Failure modes that mean "this host cannot run the check", not "the race is
# back". Skipping on these keeps the suite free of false-positive failures on
# sandboxed CI runners; a genuine race is never reported this way.
ENV_FAILURE_MARKERS = (
    "failed to initialize build cache",
    "permission denied",
    "operation not permitted",
    "no such tool",
    "cannot find GOROOT",
    "connect: ",
    "bind: ",
    "socket: ",
    "dial: ",
)


def _src() -> str:
    return TEST_FILE.read_text(encoding="utf-8")


def _func_body(src: str) -> str:
    """Extract the function by brace matching.

    A `(?=\\nfunc\\s+Test)` lookahead silently swallows the rest of the file
    whenever the next declaration is not a Test func, which would let the
    assertions below match against unrelated code and pass for the wrong
    reason.
    """
    start = re.search(r"^func\s+%s\b[^{]*\{" % re.escape(FUNC_NAME), src, re.M)
    assert start, f"{FUNC_NAME} not found in {TEST_FILE}"
    depth = 0
    for i in range(start.end() - 1, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start.start(): i + 1]
    raise AssertionError(f"unbalanced braces in {FUNC_NAME}")


def _name(pattern: str, body: str, what: str) -> str:
    m = re.search(pattern, body)
    assert m, f"{FUNC_NAME} must declare {what} (searched {pattern!r})"
    return m.group(1)


def _unlocked_buffer_accesses(body: str, buf: str, mu: str) -> list:
    """Return every line touching the capture buffer outside the mutex.

    Models the held locks as a stack so `mu.Lock(); defer mu.Unlock()` inside
    a closure releases when that closure's block closes, rather than leaving
    the lock looking held for the rest of the function -- which would let a
    bare buf.String() in the assertion masquerade as protected.
    """
    locks = []  # release depth per held lock; None until a defer claims it
    depth = 0
    offenders = []
    access = re.compile(
        r"\b%s\s*\.\s*(String|Bytes|Len|Write|WriteString|Read|Reset)\b"
        % re.escape(buf)
    )
    strings_re = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]*`')
    for lineno, line in enumerate(body.splitlines(), start=1):
        code = line.split("//", 1)[0]
        # Braces inside string literals are not block delimiters.
        braces = strings_re.sub("", code)

        if access.search(code) and not locks:
            offenders.append((lineno, line.strip()))

        depth += braces.count("{")
        if re.search(r"\bdefer\s+%s\.Unlock\(\)" % re.escape(mu), code):
            for lock in reversed(locks):
                if lock[0] is None:
                    lock[0] = depth
                    break
        elif re.search(r"\b%s\.Lock\(\)" % re.escape(mu), code):
            locks.append([None])
        elif re.search(r"\b%s\.Unlock\(\)" % re.escape(mu), code):
            for i in range(len(locks) - 1, -1, -1):
                if locks[i][0] is None:
                    locks.pop(i)
                    break
        depth -= braces.count("}")
        while locks and locks[-1][0] is not None and depth < locks[-1][0]:
            locks.pop()
    return offenders


def test_test_file_exists():
    assert TEST_FILE.exists(), f"{TEST_FILE} not found"


def test_go_race_detector_reports_no_race():
    """The contract itself: the test is clean under `go test -race`.

    This is what a source scan cannot prove. A fix that guards the writer but
    leaves the assertion's buf.String() bare passes every text assertion below
    and still trips the detector here.
    """
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go toolchain not installed on this host")
    # CI disables CGO for ordinary Go builds; the race detector requires it.
    env = dict(os.environ, GOFLAGS="-mod=mod", CGO_ENABLED="1")
    try:
        proc = subprocess.run(
            [go, "test", "-race", "-count=1", "-run", f"^{FUNC_NAME}$", "."],
            cwd=PKG_DIR,
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"`go test -race -run ^{FUNC_NAME}$` timed out after 600s")
    out = proc.stdout + proc.stderr
    assert "WARNING: DATA RACE" not in out, (
        "the #2209 data race is back -- serve()'s emitter and the test's read "
        f"of the capture buffer are unsynchronised again:\n{out}"
    )
    if proc.returncode != 0:
        if any(marker in out for marker in ENV_FAILURE_MARKERS):
            pytest.skip(f"Go race run unavailable in this environment:\n{out}")
        pytest.fail(f"`go test -race -run ^{FUNC_NAME}$` failed:\n{out}")


def test_capture_buffer_is_guarded_by_a_mutex():
    """The race was a write/read pair on one bytes.Buffer with no
    happens-before edge; a mutex is what supplies it."""
    body = _func_body(_src())
    mu = _name(r"var\s+(\w+)\s+sync\.Mutex\b", body, "a sync.Mutex")
    assert re.search(r"\b%s\.Lock\(\)" % re.escape(mu), body), (
        f"{mu} is declared but never locked"
    )
    assert re.search(r"\b%s\.Unlock\(\)" % re.escape(mu), body), (
        f"{mu} is locked but never unlocked -- the test would deadlock"
    )


def test_logger_out_is_not_the_bare_buffer():
    """The pre-fix code passed &buf straight to logger.out, so every emit
    from serve()'s goroutine wrote the buffer with no lock at all."""
    body = _func_body(_src())
    buf = _name(r"var\s+(\w+)\s+bytes\.Buffer\b", body, "a bytes.Buffer capture")
    out = re.search(r"out:\s*([^,\n]+)", body)
    assert out, "the test must build a logger with an out: writer"
    assert not re.match(r"^&%s\b" % re.escape(buf), out.group(1).strip()), (
        f"logger.out must not be the bare &{buf} -- serve() writes it from "
        "its own goroutine while the assertion reads it, which is exactly "
        "the #2209 race"
    )


def test_every_buffer_access_is_inside_the_critical_section():
    """The half the structural check has to get right.

    Guarding only the writerFunc leaves the assertion's buf.String() racing
    against it -- that is the side the detector actually reported. Every touch
    of the buffer, read or write, must sit inside a held critical section.
    """
    body = _func_body(_src())
    buf = _name(r"var\s+(\w+)\s+bytes\.Buffer\b", body, "a bytes.Buffer capture")
    mu = _name(r"var\s+(\w+)\s+sync\.Mutex\b", body, "a sync.Mutex")
    offenders = _unlocked_buffer_accesses(body, buf, mu)
    assert not offenders, (
        f"{buf} is accessed without holding {mu} at:\n"
        + "\n".join(f"  line {n} of {FUNC_NAME}: {text}" for n, text in offenders)
    )


def test_serve_still_runs_concurrently():
    """The race is only interesting because serve() runs on its own
    goroutine. Making the call synchronous would silence the detector while
    destroying what the test covers -- it would stop exercising the real
    accept loop that #1677's guard depends on."""
    body = _func_body(_src())
    assert re.search(r"\bgo\s+serve\(", body), (
        f"{FUNC_NAME} must launch serve() in a goroutine so it exercises the "
        "real accept loop; a synchronous call would block forever and would "
        "no longer reproduce the concurrent-writer condition"
    )


def test_handler_skip_assertion_preserved():
    """#1677's primary assertion: the protocol handler must not run at all
    for a loopback-sourced (healthcheck) connection. The #2209 fix touches
    buffer access only and must not weaken this."""
    body = _func_body(_src())
    assert re.search(
        r"case\s*<-\s*handlerCalled\s*:\s*\n\s*t\.Fatal", body
    ), (
        "the assertion that the protocol handler never runs for the "
        "container's own healthcheck must remain -- #2209 guards the race, "
        "it does not relax the #1677 contract"
    )


def test_connect_event_assertion_preserved():
    """#1677's secondary assertion: the healthcheck must not be logged as a
    sensor interaction. serve()'s one-time startup 'listening' event is
    expected; a per-connection 'connect' event is the failure."""
    body = _func_body(_src())
    assert "decodeEvents" in body, (
        "the test must still decode the captured log lines"
    )
    assert re.search(
        r"if\s+ev\.Event\s*==\s*\"connect\"\s*\{[^}]*t\.Fatalf", body, re.DOTALL
    ), (
        "the t.Fatalf on a 'connect' event for the container's own "
        "healthcheck must remain"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
