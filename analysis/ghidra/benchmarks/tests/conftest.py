#!/usr/bin/env python3
"""No test in this suite reaches ssh, docker or a GPU.

`evaluate_slot()` is the harness's entry point for a model, and it opens a
`ModelSession` when the caller passes none. `ModelSession.open()` is a real
engine launch: it resolves a GGUF over ssh, then `LlamaCppServer.start()` polls
`wait_for_gpu()` against the card. That loop is bounded at
`GPU_WAIT_TIMEOUT_SECONDS` (600) and, when the card is held by another run,
sleeps 5s at a time until that ceiling -- so a test that reaches the real world
blocks for ten minutes and then reports a fallback nobody asked for.

That is not hypothetical. `test_harmony_chat.py`'s
`test_the_slot_reports_not_ok_rather_than_a_false_clean_run` hung the whole
suite for exactly this reason: `gpt-oss:20b` is a tag the GPU host does have a
manifest for, so the tag list resolved it and the engine started for real. Its
class siblings got away with it only because their tags resolve to nothing --
so nothing in the file was guarding them, and the next tag that does resolve
would hang again.

The guard lives here rather than in each test, for the reason
`stub_transport` already documents: each test file loads its own copy of
`evaluate-models.py` under a different module name, so a patch applied in one
file leaves the other four still live. `serving.Remote` is the single
constructor that opens the ssh route and every one of those copies reaches the
engine through it.

The substitute behaves as a GPU host that cannot be reached: every call raises
`EngineUnavailable`. That is a start failure, which `ModelSession.open()`
catches and falls back to Ollama from -- by decision, not by accident. A slot
driven with a stubbed `request_json` therefore runs on the transport the test
stubbed, and the 19 tests that let `evaluate_slot` build its own session say
exactly what they said before. A test that means to exercise the llama.cpp path
passes its own remote (`test_serving_engine.FakeRemote`), which this never
touches.

Deliberately not here: a blanket pytest timeout. That hides the cause this file
exists to name, and it would fail a slow-but-correct test on a busy host.
"""

import sys
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
if str(BENCHMARKS_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS_DIR))

import pytest  # noqa: E402 -- serving is imported by path, so the path comes first

import serving  # noqa: E402


class UnreachableHost:
    """Stands in for `Remote` as a GPU host that is not reachable.

    Raising `EngineUnavailable` rather than answering is the point: `open()`
    treats it as "llama.cpp cannot serve this" and falls back to Ollama, which is
    the pre-engine behaviour every existing caller relies on. A fake that
    answered would have the engine start for real -- through a tunnel, a
    container and a 600s card poll -- which is the thing being prevented.
    """

    def __init__(self, *_args, **_kwargs):
        self.closed = False

    def _refuse(self, call):
        raise serving.EngineUnavailable(
            f"Remote.{call} would reach the GPU host over ssh; tests do not. "
            f"Drive the engine with a fake remote (test_serving_engine."
            f"FakeRemote), or drive the slot on its stubbed request_json."
        )

    def run(self, *_args, **_kwargs):
        self._refuse("run")

    def docker(self, *_args, **_kwargs):
        self._refuse("docker")

    def read_in_container(self, *_args, **_kwargs):
        self._refuse("read_in_container")

    def open_tunnel(self, *_args, **_kwargs):
        self._refuse("open_tunnel")

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def no_live_engine(monkeypatch):
    """No test opens the ssh/docker route to the GPU host."""
    monkeypatch.setattr(serving, "Remote", UnreachableHost)