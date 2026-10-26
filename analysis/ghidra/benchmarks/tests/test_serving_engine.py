#!/usr/bin/env python3
"""llama.cpp serves the benchmark; Ollama is the fallback; the KV retry is an OOM.

The engine change is decided entirely by how a model loads, and the three ways
that can go wrong are the three that produced wrong answers before:

1. **The retry fires on something that is not an OOM.** An unsupported
   architecture was nearly mistaken for insufficient VRAM. Retrying that case
   spends a second identical load and files the real cause under VRAM, so the
   retry is authorised by exactly one predicate and these tests drive that
   predicate both ways -- including on text that merely mentions memory.
2. **A model is routed by what it looks like.** Never by parameter count, tag or
   filename: a wrong guess there is the same class of bug. These tests assert
   llama.cpp is attempted for models of every size class and that a *failed
   attempt* is what routes to Ollama, not a prediction.
3. **A result that does not say which engine served it.** Engine, flags, KV
   retry, fallback reason, achieved tok/s and VRAM all have to reach the record,
   because a tok/s column read across two engines at 6x the decode cost is the
   table that becomes meaningless.

The engine seam itself has to be translation-correct or nothing else matters:
   - `done_reason` must come back as `stop`/`length`, because
     `classify_outcome` and `was_capped` read it and an untranslated
     finish_reason scores cap-cut text as a real answer;
   - the llama.cpp tok/s must be computed from the same nanosecond field the
     Ollama path divides by 1e9;
   - the tool-round loop must run on llama.cpp too, not only on the fallback.

No llama.cpp, no GPU, no network and no containers: `Remote`, the container
launch and `urlopen` are all stubbed, and the assertions read the argv, the
bodies and the stored records.

Run: pytest analysis/ghidra/benchmarks/tests/test_serving_engine.py -q
"""

import argparse
import contextlib
import importlib.util
import inspect
import io
import json
import re
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

LLAMA_IMAGE = "ghcr.io/ggml-org/llama.cpp:full-cuda"

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_DIR))


def _load(path, name):
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


serving = _load(BENCHMARKS_DIR / "serving.py", "serving")
evaluate_models = _load(BENCHMARKS_DIR / "evaluate-models.py", "evaluate_models")
transcripts = _load(BENCHMARKS_DIR / "transcripts.py", "transcripts")
LLAMACPP_CAPTURE = json.loads(
    (BENCHMARKS_DIR / "tests/fixtures/llamacpp_structured_capture.json").read_text()
)
LLAMACPP_CAPTURES = {
    capture["label"]: capture for capture in LLAMACPP_CAPTURE["captures"]
}
# A COMPLETE exchange recorded off the socket: tools offered, a tool call
# returned, the result sent back, the final answer. llamacpp_structured_capture
# stops at the first tool call, so nothing pinned the second turn before this.
LLAMACPP_ROUNDTRIP = json.loads(
    (BENCHMARKS_DIR / "tests/fixtures/llamacpp_tool_roundtrip.json").read_text()
)


# --- a stub host that records everything it was asked to do ----------------

class FakeRemote:
    """Stands in for ssh+docker. Records argv; answers from a script.

    `launches` is the ordered list of container `run` argv lists, so a test can
    assert on what was started and, crucially, how many times: the KV retry is
    visible as a second launch carrying `--no-kv-offload`.
    """

    def __init__(self, *, health=True, state="running", vram=2, exit_code="1",
                 start_failures=(), log_text=""):
        self.health = health
        self.state = state
        self.vram = vram
        self.exit_code_value = exit_code
        self.log_text = log_text
        self.launches = []
        self.removed = []
        self.reads = []
        self.log_reads = []
        self.tunnels = []
        self.closed = False
        # Popped by docker("run", ...): the health state that launch produces.
        self.start_failures = list(start_failures)

    # -- Remote's interface ------------------------------------------------
    def run(self, *argv, timeout=120):
        if argv and argv[0] == "nvidia-smi":
            return mock.Mock(returncode=0, stdout=f"{self.vram}\n", stderr="")
        return mock.Mock(returncode=0, stdout="", stderr="")

    def docker(self, *argv, timeout=120):
        if argv[:1] == ("run",):
            self.launches.append(list(argv))
            if self.start_failures:
                failure = self.start_failures.pop(0)
                return mock.Mock(returncode=failure[0], stdout="", stderr=failure[1])
            return mock.Mock(returncode=0, stdout="deadbeef\n", stderr="")
        if argv[:1] == ("logs",):
            # Counted, not just returned: `residency()` is an ssh round-trip,
            # and how many times a run makes it is part of what is under test.
            self.log_reads.append(list(argv))
            return mock.Mock(returncode=0, stdout=self.log_text, stderr="")
        if argv[:1] == ("inspect",) and "{{.State.Status}}" in " ".join(argv):
            return mock.Mock(returncode=0, stdout=self.state, stderr="")
        if argv[:1] == ("inspect",) and "{{.State.ExitCode}}" in " ".join(argv):
            return mock.Mock(returncode=0, stdout=self.exit_code_value, stderr="")
        if argv[:1] == ("rm",):
            self.removed.append(list(argv))
            return mock.Mock(returncode=0, stdout="", stderr="")
        return mock.Mock(returncode=0, stdout="", stderr="")

    def read_in_container(self, path, *, volume=None):
        self.reads.append(path)
        return json.dumps(MANIFEST)

    def open_tunnel(self, local_port, remote_port):
        self.tunnels.append((local_port, remote_port))

    def close(self):
        self.closed = True

    # -- what a test asserts on -------------------------------------------
    def flags_of(self, index=0):
        """The server flags of launch `index`, without the `-m <gguf>` pair.

        Everything after the image is the container's command; the model file is
        not a flag -- it has its own recorded field -- so the two are compared as
        separate things. Slicing from the image rather than from the binary is
        what keeps this correct once the binary moved to `--entrypoint`, where it
        appears *before* the image. A method, not a property, because the retry
        assertions are about launch *1* rather than launch 0.
        """
        argv = self.launches[index]
        tail = argv[argv.index(serving.LLAMA_IMAGE) + 1:]
        return tail[:tail.index("-m")] + tail[tail.index("-m") + 2:]

    @property
    def gguf_of(self, index=0):
        argv = self.launches[index]
        return argv[argv.index("-m") + 1]


MANIFEST = {
    "schemaVersion": 2,
    "layers": [
        {"mediaType": "application/vnd.ollama.image.model",
         "digest": "sha256:d7e4b00a7d7a8d03d4eed9b0f3f61a427e9f0fc5dea6aeb414e41dee23dc8ecc",
         "size": 15628378336},
        {"mediaType": "application/vnd.ollama.image.template",
         "digest": "sha256:109037be", "size": 136},
    ],
}


def start(session, healthy=True):
    """session.open() with the readiness probe answered by the stub.

    Without this the real /health poll runs against a port nothing is listening
    on, which is not a failure the harness recognises -- it is a 1800s wait for
    a model that is never going to answer. Every test that opens a session goes
    through here; the tests about readiness itself drive _await_ready directly.
    """
    with mock.patch.object(serving.LlamaCppServer, "healthy", return_value=healthy):
        return session.open()


def make_session(remote, model="gemma2:27b", **kwargs):
    kwargs.setdefault("num_ctx", 24576)
    # `/api/tags` is read on the llama.cpp path, to resolve the tag the manifest
    # filename is made of, so the stub answers it the way the real server does
    # for a model that is installed: listing that model by its own `name:tag`.
    kwargs.setdefault("request_json",
                      lambda *a, **k: {"models": [{"name": model}]})
    kwargs.setdefault("request_timeout", lambda body: 300)
    return serving.ModelSession(model, "http://127.0.0.1:11435", remote=remote, **kwargs)


# --- the retry predicate ---------------------------------------------------

class OOMPredicateTest(unittest.TestCase):
    """Only a measured OOM authorises --no-kv-offload."""

    # The review's decision matrix, verbatim. Both directions fail on a
    # substring rule, which is why this is a table and not two lists: the
    # healthy row is the one that used to fire the retry (it contains "vram" and
    # "kv cache size"), and the three "failed to load model: <cause>" rows are
    # the ones a load failure used to be filed under VRAM regardless of cause.
    OOM_TABLE = (
        # (text, retry?)
        ("llama_model_loader: - kv cache size  15486.02 MiB\n"
         "main: CUDA0 model buffer size 15088.32 MiB (15088.32 MiB) into VRAM", False),
        ("ggml_cuda: cudaMalloc failed: out of memory", True),
        ("llama_model_load: error loading model: unable to allocate CUDA0 buffer "
         "of size 500.00 MiB", True),
        ("llama_model_load: error loading model: insufficient VRAM", True),
        ("failed to load model: the file is corrupted", False),
        ("failed to open GGUF file: No such file or directory", False),
        ("model architecture is not supported", False),
        ("llama-server was still loading after 1800s", False),
        ("server did not become ready in time", False),
        # Finding 4: a non-OOM load failure that matched anyway. A missing file
        # was retried -- re-loading a 27B for nothing -- and then filed under
        # VRAM, which is the masking the module docstring says it prevents.
        ("failed to load model: not a gguf", False),
        ("failed to load model: file does not exist", False),
        ("failed to load model", False),
    )

    def test_the_whole_matrix_is_decided_as_specified(self):
        for text, retry in self.OOM_TABLE:
            with self.subTest(retry=retry, text=text.splitlines()[0]):
                self.assertEqual(serving.is_vram_oom(text), retry)

    def test_a_cudamalloc_failure_is_recognised_in_any_casing(self):
        """The marker is compared against lowered text, so it must be written
        lowered. `cudaMalloc` has an internal capital; a marker written
        "cuda malloc failed" matches no line the server can emit, which dropped
        the one allocator failure it reports most often."""
        for text in ("cudaMalloc failed", "CUDAMalloc failed", "CUDAmalloc failed",
                     "ggml_cuda: cudaMalloc failed: out of memory"):
            self.assertTrue(serving.is_vram_oom(text), f"missed a real OOM: {text}")

    def test_every_marker_is_written_lowercase(self):
        """Guards the defect above at its source rather than through one example.

        The predicate lowercases the log and the markers, so a marker carrying
        capitals is unreachable code -- silently, because nothing about it fails
        to import.
        """
        for marker in serving.VRAM_OOM_PHRASES + serving.VRAM_OOM_SUBJECT:
            self.assertEqual(marker, marker.lower(), f"unreachable marker: {marker}")

    def test_an_allocator_failure_needs_a_device_to_allocate_on(self):
        """Both halves are required.

        The phrase alone appears in benign text and the subject alone appears in
        every healthy allocation-size line. Requiring both is what lets a healthy
        27B load log -- which names both a size and the card -- stay off the
        retry path, because it names no failure.
        """
        self.assertFalse(serving.is_vram_oom(
            "the allocation plan needs 15486.02 MiB of kv cache"))

    def test_other_load_failures_are_not_oom(self):
        # The three that must NOT trigger the retry. An unsupported
        # architecture here is the incident that produced a "needs more VRAM"
        # reading for a model that would never fit at any size.
        for text in (
            "unsupported model architecture: 'qwen3moe'",
            "unknown model file format: not a gguf",
            "error: the file does not exist",
            "invalid argument: -c requires a positive integer",
            "llama-server: unrecognized argument --nope",
            # A KV cache too big for the card is a real sizing failure, but it is
            # not an allocator failure, and --no-kv-offload does not fix it: the
            # KV still has to fit somewhere. Retrying here is the exact second
            # identical 30-minute load this rule exists to prevent.
            "llama_model_load: kv cache self size 320.00 MiB exceeds the available space",
            "",
            None,
        ):
            self.assertFalse(serving.is_vram_oom(text), f"false OOM: {text!r}")

    def test_a_generic_memory_word_is_not_an_oom(self):
        """`out of memory` must be the phrase, not the concept.

        This is the near-miss the rule exists to exclude: a model that says "I
        ran out of memory" in its own reasoning, or a server line about memory
        accounting, would otherwise be retried as a VRAM fault.
        """
        self.assertFalse(serving.is_vram_oom("the model said: I have 40k tokens of memory"))
        self.assertFalse(serving.is_vram_oom("model does not support this instruction"))

    def test_oom_matching_is_case_insensitive(self):
        self.assertTrue(serving.is_vram_oom("CUDA out of memory"))
        self.assertTrue(serving.is_vram_oom("CUDAMalloc failed"))


# --- selection -------------------------------------------------------------

class SelectionTest(unittest.TestCase):
    def test_llama_cpp_is_tried_for_every_model_regardless_of_size(self):
        """No size, name or "looks big" heuristic may gate the attempt.

        A 27B and a 1B take the same path. Asserted on the attempt itself: the
        roster is 143 models and 43 of them are 27B or larger, so any
        parameter-count gate would silently exclude the whole hard half of it.
        """
        for model in ("gemma2:27b", "qwen3:0.6b", "codellama:7b",
                      "GLM-4.6-REAP-218B:IQ1_S", "baronllm-llama3.1:q6_k"):
            with self.subTest(model=model):
                remote = FakeRemote()
                session = make_session(remote, model=model)
                start(session)
                self.assertEqual(session.engine, "llama.cpp")
                self.assertEqual(len(remote.launches), 1)
                self.assertNotIn("--no-kv-offload", remote.flags_of(0))

    def test_a_non_oom_load_failure_falls_back_without_a_retry(self):
        remote = FakeRemote(state="exited", log_text="unsupported model architecture: 'qwen3moe'")
        session = make_session(remote)
        start(session)
        self.assertEqual(session.engine, "ollama")
        self.assertEqual(len(remote.launches), 1, "an unsupported architecture must not be retried")
        self.assertIn("unsupported model architecture", session.fallback_reason)

    def test_a_genuine_oom_retries_once_and_the_retry_still_reaches_the_model(self):
        """The retry survives; only the flag it used to carry is gone.

        A fit-managed load no longer OOMs the way a hand-placed one did, but
        `start()` still retries a genuine VRAM OOM once, and the retry is worth
        keeping tested for the reason that matters most: `server_flags()` now
        ignores `kv_offload`, so the second launch is byte-identical to the
        first. Whatever the retry now buys is re-asking the same question.
        Asserted here rather than left implicit -- a silent second identical
        30-minute load is exactly what the retry rule was written to prevent.
        """
        remote = FakeRemote(state="exited", log_text="ggml_cuda: cudaMalloc failed: out of memory")
        with mock.patch.object(serving.LlamaCppServer, "_await_ready",
                               side_effect=[RuntimeError("exited"), None]):
            session = make_session(remote)
            start(session)
        self.assertEqual(session.engine, "llama.cpp")
        self.assertEqual(len(remote.launches), 2, "one genuine OOM is still retried once")
        self.assertNotIn("--no-kv-offload", remote.flags_of(0))
        self.assertNotIn("--no-kv-offload", remote.flags_of(1))
        self.assertEqual(
            remote.flags_of(1), remote.flags_of(0),
            "kv_offload is ignored, so the retry launches the same command; "
            "it can only help if the OOM was transient")
        self.assertTrue(session.provenance()["kv_offload_disabled"])
        self.assertIsNone(session.fallback_reason,
                          "a model the retry saved is not a fallback")

    def test_a_retry_that_also_fails_falls_back_to_ollama(self):
        """Both attempts OOM. That is a model llama.cpp cannot serve, so Ollama
        takes it -- with the KV retry recorded, not hidden behind the fallback."""
        remote = FakeRemote(state="exited", log_text="cudaMalloc failed")
        with mock.patch.object(serving.LlamaCppServer, "_await_ready",
                               side_effect=RuntimeError("cudaMalloc failed")):
            session = make_session(remote)
            start(session)
        self.assertEqual(session.engine, "ollama")
        self.assertEqual(len(remote.launches), 2)
        self.assertNotIn("--no-kv-offload", remote.flags_of(1))
        self.assertIn("cudaMalloc failed", session.fallback_reason)

    def test_the_retry_happens_after_waiting_for_the_gpu_to_be_free(self):
        """A retry that starts while the failed container still holds VRAM OOMs
        for the wrong reason, and the OOM gets attributed to the new model."""
        remote = FakeRemote(state="exited", log_text="cudaMalloc failed")
        waits = []

        def wait(self):
            waits.append(remote.vram)
            remote.vram = 2          # the card frees once the container is gone
            return {"reached_idle": True, "vram_used_mib": 2, "idle_threshold_mib": 508}

        with mock.patch.object(serving.LlamaCppServer, "_await_ready",
                               side_effect=[RuntimeError("exited"), None]), \
             mock.patch.object(serving.LlamaCppServer, "wait_for_gpu", wait):
            session = make_session(remote)
            start(session)
        self.assertEqual(len(waits), 2, "the GPU must be re-waited before the retry")
        self.assertEqual(remote.vram, 2)

    def test_the_retry_happens_once_and_only_once(self):
        remote = FakeRemote(state="exited", log_text="cudaMalloc failed")
        with mock.patch.object(serving.LlamaCppServer, "_await_ready",
                               side_effect=RuntimeError("cudaMalloc failed")):
            session = make_session(remote)
            start(session)
        self.assertEqual(len(remote.launches), 2,
                         "one retry, not a loop until something works")

    def test_the_fallback_transport_is_the_unchanged_ollama_path(self):
        """The fallback must be byte-identical to the /api/chat path."""
        remote = FakeRemote(state="exited", log_text="unsupported model architecture")
        posted = []

        def request_json(url, body=None, timeout=None):
            posted.append((url, body, timeout))
            return {"message": {"content": "{}"}, "done_reason": "stop"}

        session = make_session(remote, request_json=request_json)
        start(session)
        session.transport(f"{session.base_url}/api/chat", {"model": "gemma2:27b"})
        # The llama.cpp start reads `/api/tags` to resolve the tag the manifest
        # filename is made of, so the chat call is picked out rather than assumed
        # to be the first thing posted: what is under test is that the *chat*
        # body is the one Ollama always got, unchanged.
        chat = [call for call in posted if call[0].endswith("/api/chat")]
        self.assertEqual(len(chat), 1)
        self.assertEqual(chat[0][0], "http://127.0.0.1:11435/api/chat")
        self.assertEqual(chat[0][1], {"model": "gemma2:27b"})

    def test_a_failed_load_is_the_only_thing_that_ever_routes_to_ollama(self):
        """Recorded, not inferred. The fallback reason must name what happened."""
        remote = FakeRemote(state="exited", log_text="error: file does not exist")
        session = make_session(remote)
        start(session)
        provenance = session.provenance()
        self.assertEqual(provenance["engine"], "ollama")
        self.assertEqual(provenance["fallback_engine"], "ollama")
        self.assertIn("does not exist", provenance["fallback_reason"])


# --- GGUF resolution -------------------------------------------------------

class GgufResolutionTest(unittest.TestCase):
    def test_the_model_layer_blob_is_the_gguf(self):
        """Ollama stores the GGUF as a blob named by its own digest.

        This is what makes "nothing needs re-downloading" true: the blob IS the
        file, not an archive holding one.
        """
        gguf = serving.gguf_from_manifest(MANIFEST)
        self.assertEqual(
            gguf,
            "/root/.ollama/models/blobs/sha256-d7e4b00a7d7a8d03d4eed9b0f3f61a427e9f0fc5dea6aeb414e41dee23dc8ecc",
        )

    def test_a_manifest_without_a_model_layer_is_refused(self):
        with self.assertRaises(ValueError):
            serving.gguf_from_manifest(
                {"layers": [{"mediaType": "application/vnd.ollama.image.template"}]})

    def test_both_manifest_namespaces_resolve(self):
        """`registry.ollama.ai/library/...` and `hf.co/...` are both in use here."""
        self.assertEqual(
            serving.manifest_path("gemma2:27b", OLLAMA_TAGS),
            "/root/.ollama/models/manifests/registry.ollama.ai/library/gemma2/27b",
        )
        self.assertEqual(
            serving.manifest_path("hf.co/org/repo:Q4_K_M", OLLAMA_TAGS),
            "/root/.ollama/models/manifests/hf.co/org/repo/Q4_K_M",
        )

    # --- the on-disk layout, asserted against the box and not against us ---
    # Every expected string below is a path read off the host, not a path this
    # module produced and then agreed with itself about. The previous suite
    # asserted `registry.ollama.ai/library/gemma2:27b` -- a `:` inside a filename,
    # which is not a shape Ollama has ever stored -- and passed 651 tests while
    # llama.cpp had never once loaded a model.

    ON_DISK_PATHS = (
        # (name as written, manifest read by /api/tags for it, exact path)
        ("gemma2", "gemma2:27b",
         "/root/.ollama/models/manifests/registry.ollama.ai/library/gemma2/27b"),
        ("qwen3-8-27b-q4km", "qwen3-8-27b-q4km:latest",
         "/root/.ollama/models/manifests/registry.ollama.ai/library/"
         "qwen3-8-27b-q4km/latest"),
        ("qwen3", "qwen3:14b",
         "/root/.ollama/models/manifests/registry.ollama.ai/library/qwen3/14b"),
        ("deephat-v1-7b-heretic-abliterated-fixed",
         "deephat-v1-7b-heretic-abliterated-fixed:q4_k_s",
         "/root/.ollama/models/manifests/registry.ollama.ai/library/"
         "deephat-v1-7b-heretic-abliterated-fixed/q4_k_s"),
        ("ravenx-cyberagent-35b", "ravenx-cyberagent-35b:Q4_K_M",
         "/root/.ollama/models/manifests/registry.ollama.ai/library/"
         "ravenx-cyberagent-35b/Q4_K_M"),
        ("hf.co/mradermacher/DeepHat-V1-7B-GGUF", "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M",
         "/root/.ollama/models/manifests/hf.co/mradermacher/DeepHat-V1-7B-GGUF/Q4_K_M"),
        ("hf.co/mradermacher/DeepHat-V1-7B-Heretic-Abliterated-i1-GGUF",
         "hf.co/mradermacher/DeepHat-V1-7B-Heretic-Abliterated-i1-GGUF:i1-Q4_K_S",
         "/root/.ollama/models/manifests/hf.co/mradermacher/"
         "DeepHat-V1-7B-Heretic-Abliterated-i1-GGUF/i1-Q4_K_S"),
    )

    def test_the_paths_match_the_layout_found_on_the_box(self):
        """Character for character, mixed case and quant separators intact.

        `Q4_K_M`, `q4_k_s` and `i1-Q4_K_S` are copied as the model was created.
        Case-folding them produces a filename that does not exist, which is the
        same class of failure as the `:` -- so the assertion pins the case, not
        just the shape.
        """
        for written, reported, expected in self.ON_DISK_PATHS:
            tags = [{"name": reported}]
            with self.subTest(model=written):
                self.assertEqual(
                    serving.manifest_path(written, tags), expected,
                    "the server's spelling must win")
                # The caller's own fully-written tag reaches the same file.
                self.assertEqual(serving.manifest_path(reported, tags), expected)

    def test_a_fully_qualified_name_round_trips_through_its_own_output(self):
        """The tag-list spelling fed back in, unchanged.

        The seven paths above are asserted as literal strings, so nothing in
        them exercises `manifest_path`'s own parsing -- they are a table the
        function is checked against, not a round trip. This closes that: each
        name the live `/api/tags` reports (185 tags, checked live on this box,
        `curl http://127.0.0.1:11435/api/tags`) goes in and comes out as the
        same file, split on the `:` that sits after the last `/`.

        Both spellings of every entry are covered, because they are the two
        callers there are. `resolve_gguf()` is handed whatever the manifest
        wrote -- often short -- while `ModelSession._start_llama_cpp()` reads the
        tag list and hands it the fully qualified form. A parser that fixed one
        and not the other would be caught here and nowhere else.

        These are the shapes that break it, taken from what this host reports:

        - `hf.co/org/repo:Q4_K_M` -- a `:` after the last `/`, so a split on the
          first `/`, or on the last `:`, lands on the wrong place;
        - `qwen3-8-27b-q4km:latest` -- a bare library tag that needs the
          `registry.ollama.ai/library/` namespace;
        - `keep/<built-name>:src` -- a namespace of its own, added as-is;
        - quantisations with a dash (`i1-Q4_K_S`), a dot (`f16`), and mixed
          case (`Q4_K_M` vs `q4_k_s`), none of which may be case-folded.
        """
        live = [
            # (as /api/tags reports it, as a manifest may write it, exact path)
            ("qwen3-8-27b-q4km:latest", "qwen3-8-27b-q4km",
             "/root/.ollama/models/manifests/registry.ollama.ai/library/"
             "qwen3-8-27b-q4km/latest"),
            ("hf.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:"
             "Huihui-Qwen3.8-27B-abliterated-UD-DW-Q4_K_M",
             "hf.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF",
             "/root/.ollama/models/manifests/hf.co/huihui-ai/"
             "Huihui-Qwen3.8-27B-abliterated-GGUF/"
             "Huihui-Qwen3.8-27B-abliterated-UD-DW-Q4_K_M"),
            ("hf.co/mradermacher/DeepHat-V1-7B-Heretic-Abliterated-GGUF:"
             "i1-Q4_K_S",
             "hf.co/mradermacher/DeepHat-V1-7B-Heretic-Abliterated-GGUF",
             "/root/.ollama/models/manifests/hf.co/mradermacher/"
             "DeepHat-V1-7B-Heretic-Abliterated-GGUF/i1-Q4_K_S"),
            ("hf.co/mradermacher/Colibri_8b_v0.1-GGUF:f16",
             "hf.co/mradermacher/Colibri_8b_v0.1-GGUF",
             "/root/.ollama/models/manifests/hf.co/mradermacher/"
             "Colibri_8b_v0.1-GGUF/f16"),
            ("keep/rex86-merged_q8_0:src", "keep/rex86-merged_q8_0",
             "/root/.ollama/models/manifests/keep/rex86-merged_q8_0/src"),
            ("gemma2:27b", "gemma2",
             "/root/.ollama/models/manifests/registry.ollama.ai/library/"
             "gemma2/27b"),
            ("qwen2.5-coder-7b-base:q4_k_m", "qwen2.5-coder-7b-base",
             "/root/.ollama/models/manifests/registry.ollama.ai/library/"
             "qwen2.5-coder-7b-base/q4_k_m"),
        ]
        for reported, written, expected in live:
            tags = [{"name": reported}]
            with self.subTest(reported=reported):
                # What /api/tags said, fed straight back in.
                self.assertEqual(serving.manifest_path(reported, tags), expected)
                # What a manifest wrote, resolved out of that tag list.
                self.assertEqual(serving.manifest_path(written, tags), expected)
                # And the output is itself a valid input: the split it performs
                # has to be reproducible on the string it produced, or the
                # function is not idempotent and a caller that passes a
                # resolved path back gets a different file.
                self.assertEqual(
                    serving.manifest_path(reported, tags),
                    serving.manifest_path(reported, [{"name": reported}]),
                )
                # The tag really is a segment of its own, so no caller can read
                # the `:` as part of a filename.
                self.assertNotIn(":", expected.rsplit("/", 1)[-1])

    def test_a_fully_qualified_name_is_used_as_it_stands(self):
        """`registry.ollama.ai/library/...` in, `registry.ollama.ai/library/...`
        out -- no prefix added, nothing stripped, case intact.

        Whether this host's `/api/tags` answers short (`gemma2:27b`) or fully
        qualified (`registry.ollama.ai/library/gemma2:27b`) is a property of the
        Ollama build, not of this code, and this box cannot be read from here to
        settle it. Both are therefore answered rather than assumed: a bare name
        that the tag list misses is refused (below), and a qualified one is used
        verbatim.
        """
        self.assertEqual(
            serving.manifest_path(
                "registry.ollama.ai/library/gemma2:27b",
                [{"name": "registry.ollama.ai/library/gemma2:27b"}]),
            "/root/.ollama/models/manifests/registry.ollama.ai/library/gemma2/27b",
        )

    def test_a_bare_name_the_tag_list_does_not_carry_is_refused(self):
        """Not quietly turned into `.../library/<name>/latest`.

        If the tag list carries only the qualified spelling, a bare name does not
        resolve, and the only way to produce a path from it would be to assume
        both the `library/` namespace and the `latest` filename. The first is a
        default this function is allowed to apply; the second is a guess, and a
        guess here becomes an `OSError` filed as `fallback_reason`. Refusing
        sends the reader to the roster spelling instead.
        """
        qualified = [{"name": "registry.ollama.ai/library/gemma2:27b"}]
        with self.assertRaises(serving.UnresolvableModel):
            serving.manifest_path("gemma2", qualified)

    def test_no_returned_path_is_a_filename_containing_a_colon(self):
        """The failure signal for the whole class: a `:` after the last `/`.

        Ollama's manifests are 115 files with zero directory-style entries, so
        any returned path whose final component carries a `:` is not a shape this
        host has ever stored. Checked across every name and tag shape this
        function accepts, so the invariant does not have to be re-argued each
        time a namespace is added.
        """
        # Every name shape that reaches here: both namespaces, the qualified
        # form /api/tags reports, tags with mixed case, dashes and underscores,
        # and the bare names that have to be resolved out of the tag list.
        names = ["gemma2:27b", "qwen3-8-27b-q4km:latest", "qwen3:14b",
                 "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M",
                 "hf.co/mradermacher/DeepHat-V1-7B-Heretic-Abliterated-i1-GGUF:i1-Q4_K_S",
                 "ravenx-cyberagent-35b:Q4_K_M",
                 "deephat-v1-7b-heretic-abliterated-fixed:q4_k_s",
                 "registry.ollama.ai/library/qwen3:14b",
                 "gemma2", "qwen3-8-27b-q4km"]
        tags = [{"name": reported} for _w, reported, _p in self.ON_DISK_PATHS]
        root = "/root/.ollama/models/manifests/"
        for name in names:
            with self.subTest(model=name):
                path = serving.manifest_path(name, tags)
                self.assertNotIn(":", path.rsplit("/", 1)[-1],
                                 f"{path!r} names a file that cannot exist")
                self.assertTrue(path.startswith(root), path)
                # The tag is a segment of its own: the whole path is the
                # manifests root, the repo the server reported, and the tag --
                # one segment each, no `:` gluing the last two together.
                resolved = path[len(root):].split("/")
                repo = path[len(root):].rsplit("/", 1)[0]
                self.assertEqual(
                    len(path.split("/")) - len(root.rstrip("/").split("/")),
                    len(repo.split("/")) + 1, path)
                self.assertEqual(resolved[-1], path.rsplit("/", 1)[-1])
                # And it is a file, not a directory-shaped manifest: on this
                # host there are 115 of them and zero directories.
                self.assertNotEqual(resolved[-1], resolved[-2], path)

    def test_an_untagged_name_resolves_from_the_server_not_from_a_default(self):
        """Bug 1: `qwen3-8-27b-q4km` is how Ollama *reports* nothing wrong with.

        Every library tag on this roster is written without one, so the old
        parser raised `ValueError: model tag has no tag part` on most of the
        roster -- and `ModelSession.open()` caught it and fell back to Ollama,
        so the run reported success having never loaded a GGUF.

        The tag is now read from `/api/tags` rather than assumed, because
        `:latest` is a coincidence of this roster, not a rule: the manifests on
        disk are `<repo>/<tag>` where the tag is a quantisation
        (`ravenx-cyberagent-35b/Q4_K_M`), so a default that happened to be
        right here would be wrong the first time an `hf.co/` repo is served.

        Asserted against the exact string Ollama's `/api/tags` returns for the
        model in the smoke manifest (`/tmp/smoke-manifest.json`,
        `slots.ghidra.artifact.tag`), not against the parser in isolation: the
        pair that has to hold is "the name a manifest carries" -> "the manifest
        path of the tag Ollama reports for it".
        """
        reported_by_ollama = "qwen3-8-27b-q4km:latest"
        from_manifest = "qwen3-8-27b-q4km"
        tags = [{"name": reported_by_ollama}]

        # Both spellings must land on the same file, not merely both succeed.
        self.assertEqual(
            serving.manifest_path(from_manifest, tags),
            serving.manifest_path(reported_by_ollama, tags),
        )
        self.assertEqual(
            serving.manifest_path(from_manifest, tags),
            "/root/.ollama/models/manifests/registry.ollama.ai/library/"
            "qwen3-8-27b-q4km/latest",
        )

    def test_an_untagged_name_with_nothing_to_resolve_it_from_is_refused(self):
        """`hf.co/org/repo` is not `hf.co/org/repo:latest`.

        There is no such manifest: the files under `hf.co/<org>/<repo>` are named
        after the quantisation. Inventing `:latest` here produces a path that
        cannot exist, and the resulting `OSError` is caught by `open()` and filed
        as `fallback_reason` -- a server problem on the record for what is a
        missing tag in a manifest. Raised as `UnresolvableModel` instead, which
        `open()` deliberately lets escape rather than fall back.
        """
        with self.assertRaises(serving.UnresolvableModel):
            serving.manifest_path("hf.co/org/repo")
        with self.assertRaises(serving.UnresolvableModel):
            serving.manifest_path("gemma2", [])

    def test_an_ambiguous_bare_name_is_refused_rather_than_guessed(self):
        """`:latest` and `:q5` both match a bare name; neither is the answer."""
        both = [{"name": "qwen3-8-27b-q4km:latest"}, {"name": "qwen3-8-27b-q4km:q5"}]
        with self.assertRaises(serving.UnresolvableModel):
            serving.manifest_path("qwen3-8-27b-q4km", both)

    def test_a_full_tag_survives_when_the_server_does_not_list_the_model(self):
        """The server is authoritative, not mandatory.

        `/api/tags` can be unreadable or simply not list a model that is
        installed; the caller's own `:tag` is then the only tag there is, and
        refusing it would trade a working run for a loud one. This is the same
        rule `canonical_tag` already documents for `/api/show` and `/api/ps`.
        """
        self.assertEqual(
            serving.manifest_path("gemma2:27b", []),
            "/root/.ollama/models/manifests/registry.ollama.ai/library/gemma2/27b",
        )
        self.assertEqual(
            serving.manifest_path("hf.co/org/repo:Q4_K_M", []),
            "/root/.ollama/models/manifests/hf.co/org/repo/Q4_K_M",
        )

    def test_only_a_name_that_names_nothing_is_refused(self):
        """Refused *loudly*: these raise out of open(), not into the fallback.

        The distinction is the whole point. An untagged name is a model Ollama
        can serve; an empty one is a manifest typo, and answering it by falling
        back would score whichever model happened to be resident.
        """
        for junk in ("", "   ", ":", "/"):
            with self.subTest(model=junk):
                with self.assertRaises(serving.UnresolvableModel):
                    serving.manifest_path(junk)

    def test_an_untagged_name_never_produces_a_path_and_a_fallback_reason(self):
        """The failure mode being eliminated, at the level it is observable.

        A bare name with nothing to resolve it from used to become
        `.../qwen3-8-27b-q4km:latest`, an `OSError` reading it, and a
        `fallback_reason` naming a path -- which reads like llama.cpp declining a
        model it could have served. Now the read never happens: the name raises
        `UnresolvableModel` out of `open()` and the container is never asked.
        """
        remote = FakeRemote()
        session = make_session(remote, model="qwen3-8-27b-q4km",
                               request_json=lambda *a, **k: {"models": []})
        with self.assertRaises(serving.UnresolvableModel):
            start(session)
        self.assertEqual(remote.reads, [])
        self.assertEqual(remote.launches, [])
        self.assertIsNone(session.fallback_reason)
        self.assertIsNone(session.transport)

    def test_the_tags_are_read_once_per_session_and_before_the_container(self):
        """One `/api/tags` per session, and no container before it has answered.

        The read is what turns a human's model name into a filename, so a
        container started before it would be launched against a guess. Ordering
        is the whole assertion; the count only guards against a second read per
        start attempt, which would show up as a double read on the KV retry.
        """
        urls = []

        def request_json(url, body=None, timeout=None):
            urls.append(url)
            return {"models": [{"name": "gemma2:27b"}]}

        remote = FakeRemote()
        session = make_session(remote, model="gemma2", request_json=request_json)
        start(session)
        self.assertEqual(urls, ["http://127.0.0.1:11435/api/tags"])
        self.assertEqual(
            remote.reads,
            ["/root/.ollama/models/manifests/registry.ollama.ai/library/gemma2/27b"])

    def test_an_unresolvable_name_stops_the_run_instead_of_falling_back(self):
        """The regression that produced a run that "succeeded" on the fallback.

        The bug was not that the parser raised -- it was that `open()` caught
        every exception and recorded it as `fallback_reason`, so a name that is
        not a model looked exactly like a server that could not load one.
        """
        session = make_session(FakeRemote(), model="")
        with self.assertRaises(serving.UnresolvableModel):
            start(session)
        self.assertIsNone(session.engine)
        self.assertIsNone(session.fallback_engine)
        self.assertIsNone(session.fallback_reason)
        self.assertIsNone(session.transport)

    def test_a_full_tag_survives_untouched(self):
        """Not over-applied: the default never rewrites a tag that was given."""
        self.assertEqual(serving.with_default_tag("gemma2:27b"), "gemma2:27b")
        self.assertEqual(
            serving.with_default_tag("hf.co/org/repo:Q4_K_M"), "hf.co/org/repo:Q4_K_M"
        )

    def test_the_launch_loads_the_resolved_gguf(self):
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        self.assertEqual(remote.gguf_of, serving.gguf_from_manifest(MANIFEST))
        self.assertIn(serving.LLAMA_IMAGE, remote.launches[0])


# --- flags -----------------------------------------------------------------

class FlagsTest(unittest.TestCase):
    def test_fit_ctx_carries_the_window_and_placement_is_left_to_fit(self):
        """The whole memory policy is `--fit-ctx <num_ctx>`, and nothing else.

        This build defaults to `-ngl auto` and `--fit on`, which let
        llama-server compute the layer split at startup. Setting `-c` or `-ngl`
        by hand switches that calculation off -- measured on a 21.7 GB model
        against a 20475 MiB card, `-c 24576 -ngl 30` crashed the allocator
        while `--fit-ctx 24576` offloaded 41/42 layers at 74.18 tok/s.
        """
        flags = serving.server_flags(24576)
        self.assertEqual(flags[flags.index("--fit-ctx") + 1], "24576")
        self.assertNotIn("-c", flags, "-c switches fit's own calculation off")
        self.assertNotIn("-ngl", flags, "-ngl switches fit's own calculation off")

    def test_tool_calling_always_renders_through_jinja(self):
        """`--jinja` is pinned, not inherited from the image's default.

        Tool calls are rendered through the model's chat template. This build
        happens to default `--jinja` on, which is exactly why it needs pinning:
        a default belongs to the image, not to our contract, and a llama.cpp
        upgrade that flips it would turn every tool call into plain prose
        without a single failing test. That is the same failure as `-lv 4` --
        a setting whose absence is invisible until a score quietly changes.
        """
        self.assertIn("--jinja", serving.server_flags(24576))

    def test_no_kv_offload_is_never_emitted(self):
        """The old retry flag is gone from both branches.

        `--no-kv-offload` moves the KV cache, not model layers, so it cannot
        help a model larger than the card, and it decoded at 7.4 tok/s. The
        kwarg is kept only so old call sites keep working, so the pair
        asserted here is the contract: `kv_offload` changes nothing.
        """
        for kv_offload in (False, True):
            with self.subTest(kv_offload=kv_offload):
                self.assertNotIn(
                    "--no-kv-offload", serving.server_flags(24576, kv_offload=kv_offload))
        self.assertEqual(
            serving.server_flags(24576, kv_offload=False),
            serving.server_flags(24576, kv_offload=True),
            "kv_offload is accepted and ignored, so both call sites get the same argv")

    def test_the_configured_window_is_the_one_on_the_wire(self):
        """NUM_CTX must reach llama-server, not just Ollama's options."""
        remote = FakeRemote()
        session = make_session(remote, num_ctx=evaluate_models.NUM_CTX)
        start(session)
        flags = remote.flags_of(0)
        self.assertEqual(flags[flags.index("--fit-ctx") + 1],
                         str(evaluate_models.NUM_CTX))

    def test_the_entrypoint_is_overridden_with_the_absolute_binary(self):
        """The image's ENTRYPOINT is `/app/tools.sh`, a subcommand dispatcher.

        Handing it the server as an argument made it print
        `Unknown command: /app/llama-server` plus a usage list and exit 0, so
        the container started and exited while loading -- for every model, on
        every run, with a real GPU, a real GGUF and a healthy fallback
        recording the wrong reason. tools.sh only reaches llama-server inside
        one branch (`tools.sh:33`, and that one is a relative `./llama-server`,
        so it depends on WORKDIR too), which is why appending a tools.sh
        subcommand is not the fix: overriding the entrypoint is.
        """
        remote = FakeRemote()
        start(make_session(remote))
        argv = remote.launches[0]
        self.assertEqual(argv[argv.index("--entrypoint") + 1], serving.LLAMA_BINARY)
        # Absolute, not the relative form tools.sh itself uses: a relative path
        # resolves against WORKDIR, so it works or does not with the image tag.
        self.assertTrue(serving.LLAMA_BINARY.startswith("/"),
                        f"entrypoint must be absolute, got {serving.LLAMA_BINARY!r}")
        self.assertNotIn("./llama-server", argv)
        # Override in place of the binary-as-argument: with the image ENTRYPOINT
        # left alone, argv[0] inside the container is tools.sh again and the
        # usage list is what answers.
        self.assertEqual(argv[argv.index(serving.LLAMA_IMAGE) + 1], "-m")

    def test_the_kv_retry_launch_carries_the_same_entrypoint(self):
        """Both launches, not just the first.

        `--no-kv-offload` goes through `_launch` again, so an override applied
        only on the first attempt would retry into the same tools.sh usage list
        and then file a real OOM as an unrunnable server.
        """
        remote = FakeRemote(state="exited", log_text="cudaMalloc failed")
        with mock.patch.object(serving.LlamaCppServer, "_await_ready",
                               side_effect=RuntimeError("cudaMalloc failed")):
            start(make_session(remote))
        self.assertEqual(len(remote.launches), 2)
        for index in range(2):
            argv = remote.launches[index]
            self.assertEqual(argv[argv.index("--entrypoint") + 1], serving.LLAMA_BINARY)


# --- residency: measured placement, not the flags that asked for it --------

# The real load log of the measured 41/42 run, verbatim. `CPU_Mapped model
# buffer size` is in it on purpose: that line reports the mmap'd file, appears in
# a healthy run, and must not be mistaken for a measurement of the card.
FIT_LOG = (
    "llama_context: n_ctx                 = 24576\n"
    "load_tensors: offloaded 41/42 layers to GPU\n"
    "load_tensors:        CUDA0 model buffer size = 17880.66 MiB\n"
    "load_tensors:        CPU_Mapped model buffer size = 4231.19 MiB\n"
    "llama_kv_cache:      CUDA0 KV buffer size =    480.00 MiB\n"
    "llama_model_load: loaded meta data\n"
    "main: model loaded\n"
)


def server_for(log_text):
    return serving.LlamaCppServer(
        FakeRemote(log_text=log_text), "gemma2:27b",
        {"gguf": "/g", "gguf_sha256": "abc123"},
        num_ctx=24576, request_timeout=evaluate_models.request_timeout,
    )


# The log of a CPU-decoded run, verbatim: fit probes the device with a
# throwaway model, retries, and gives up on the card. Three `offloaded N/M`
# lines and only the last one describes the weights that would serve.
PROBE_THEN_CPU_LOG = (
    "common_params_fit_impl: getting device memory data for initial parameters:\n"
    "load_tensors: offloaded 42/42 layers to GPU\n"
    "load_tensors:        CUDA0 model buffer size =     0.00 MiB\n"
    "load_tensors:        CPU_Mapped model buffer size = 18056.75 MiB\n"
    "common_params_fit_impl: projected to use 25441 MiB of device memory vs. "
    "486 MiB of free device memory\n"
    "common_params_fit_impl: context size reduced from 262144 to 24576\n"
    "load_tensors: offloaded  1/42 layers to GPU\n"
    "load_tensors:        CUDA0 model buffer size =     0.00 MiB\n"
    "load_tensors: offloaded 0/42 layers to GPU\n"
    "load_tensors:        CUDA0 model buffer size =     0.00 MiB\n"
    "load_tensors:        CPU_Mapped model buffer size = 18056.75 MiB\n"
    "llama_kv_cache:      CUDA0 KV buffer size =     0.00 MiB\n"
    "llama_context: n_ctx                 = 24576\n"
    "common_fit_params: successfully fit params to free device memory\n"
    "llama_model_load: loaded meta data\n"
    "main: model loaded\n"
)


class ResidencyTest(unittest.TestCase):
    """`residency()` is the record's only source of where the model lives.

    "model loaded" is printed for a CPU-only run exactly as for a GPU one, so
    the layer line is the only thing that distinguishes them. A flag is a
    request; a count read out of the log is a measurement.
    """

    def test_a_partial_fit_log_is_parsed_into_every_field(self):
        place = server_for(FIT_LOG).residency()
        self.assertEqual(place["gpu_layers"], 41)
        self.assertEqual(place["layers_total"], 42)
        self.assertEqual(place["vram_mib"], 17880.66)
        self.assertEqual(place["kv_cache_mib"], 480.00)
        self.assertEqual(place["n_ctx"], 24576)
        # The intended behaviour for a model larger than the card: 41 in VRAM,
        # one shed to host RAM. Not a failure state.
        self.assertIs(place["ram_offloaded"], True)

    def test_a_missing_line_is_none_and_never_a_number(self):
        """`None` and `0` are different claims.

        An absent line means the measurement is unavailable, not that the card
        held nothing; a fabricated zero fails a healthy model for the wrong
        reason, which is the whole reason `_require_gpu_residency()` only acts
        when the log states a layer count.
        """
        place = server_for("llama_model_load: loaded meta data\nmain: model loaded\n").residency()
        for field in ("gpu_layers", "layers_total", "vram_mib", "kv_cache_mib",
                      "n_ctx", "ram_offloaded"):
            with self.subTest(field=field):
                self.assertIsNone(place[field])

    def test_a_full_offload_is_not_ram_offloaded(self):
        place = server_for(FIT_LOG.replace("offloaded 41/42", "offloaded 42/42")).residency()
        self.assertEqual(place["gpu_layers"], 42)
        self.assertIs(place["ram_offloaded"], False)

    def test_a_cpu_only_load_is_ram_offloaded(self):
        place = server_for(FIT_LOG.replace("offloaded 41/42", "offloaded 0/42")).residency()
        self.assertEqual(place["gpu_layers"], 0)
        self.assertEqual(place["layers_total"], 42)
        self.assertIs(place["ram_offloaded"], True)

    def test_the_cpu_mapped_line_is_not_the_vram_measurement(self):
        """It reports the mmap'd file and is present in a healthy 41/42 run."""
        place = server_for(FIT_LOG).residency()
        self.assertNotEqual(place["vram_mib"], 4231.19)

    def test_a_probe_placement_is_not_the_placement(self):
        """The first `offloaded N/M` is a throwaway probe model, not this one.

        Fit measures device memory by loading a probe, and the probe logs its
        own placement before the real weights load. Reading the first match
        reported the probe's `42/42` for a run that shed every layer to RAM, and
        the residency guard passed it as a full GPU offload.
        """
        place = server_for(PROBE_THEN_CPU_LOG).residency()
        self.assertEqual(place["gpu_layers"], 0)
        self.assertEqual(place["layers_total"], 42)
        self.assertEqual(place["vram_mib"], 0.0)
        self.assertEqual(place["kv_cache_mib"], 0.0)
        self.assertIs(place["ram_offloaded"], True)

    def test_a_layer_count_a_zero_buffer_contradicts_is_not_a_placement(self):
        """`offloaded N/M` is printed before allocation, so N>0 proves nothing.

        The probe's `42/42` sits next to `CUDA0 model buffer size = 0.00 MiB`:
        nothing was placed on the card. Taking the count on its own lets a
        CPU-only run be recorded as a legitimate llama.cpp grade, which is
        exactly what the residency guard exists to prevent. One placement line,
        so this fails only if the buffer size is not required to back it.
        """
        place = server_for(
            "load_tensors: offloaded 42/42 layers to GPU\n"
            "load_tensors:        CUDA0 model buffer size =     0.00 MiB\n"
            "load_tensors:        CPU_Mapped model buffer size = 18056.75 MiB\n"
            "main: model loaded\n"
        ).residency()
        self.assertEqual(place["gpu_layers"], 0)
        self.assertEqual(place["vram_mib"], 0.0)
        self.assertIs(place["ram_offloaded"], True)

    def test_the_final_load_of_a_healthy_run_is_the_one_reported(self):
        """The last placement's own buffers, not the probe's `0.00 MiB`.

        A healthy fit probes the device first too, so taking the first match
        records a working 41/42 GPU run as the probe that preceded it -- and
        the mirror image of the same mistake, a full GPU run refused.
        """
        log = (
            "common_params_fit_impl: getting device memory data for initial parameters:\n"
            "load_tensors: offloaded 42/42 layers to GPU\n"
            "load_tensors:        CUDA0 model buffer size =     0.00 MiB\n"
            "common_params_fit_impl: projected to use 25441 MiB of device memory vs. "
            "20100 MiB of free device memory\n"
            "load_tensors: offloaded 41/42 layers to GPU\n"
            "load_tensors:        CUDA0 model buffer size = 17880.66 MiB\n"
            "llama_kv_cache:      CUDA0 KV buffer size =    480.00 MiB\n"
            "llama_context: n_ctx                 = 24576\n"
            "main: model loaded\n"
        )
        place = server_for(log).residency()
        self.assertEqual(place["gpu_layers"], 41)
        self.assertEqual(place["layers_total"], 42)
        self.assertEqual(place["vram_mib"], 17880.66)
        self.assertEqual(place["kv_cache_mib"], 480.00)
        self.assertIs(place["ram_offloaded"], True)

    def test_the_record_names_both_the_negotiated_context_and_the_floor(self):
        """`n_ctx` alone is a lie by omission when fit moves it.

        `--fit-ctx N` is documented as the *minimum* context fit may set, not a
        request for exactly N, so fit routinely settles on something else: with
        `--fit-ctx 24576` on a 131072-context model measured 2026-10-05 it
        logged `context size reduced from 131072 to 98048` and served at
        `n_ctx = 98048`. Run 2026-10-05-20261005T134600Z-3aee521a recorded that
        98k-shaped number in `reproducibility.n_ctx` beside a request body
        saying 24576, and nothing said which one the model actually ran with.

        Per-request `n_ctx` cannot reconcile them -- llama-server accepts the
        field and ignores it (a 935-token prompt sent with `n_ctx: 256` still
        logged `n_ctx_slot = 24576`). Context is a server-lifetime fact, so the
        record has to carry both numbers under names that say which is which.
        """
        # The real measured shape: fit reduced context, and the served value
        # differs from the floor that was passed on the command line.
        log = (
            "common_params_fit_impl: context size reduced from 131072 to 98048\n"
            "load_tensors: offloaded 33/33 layers to GPU\n"
            "load_tensors:        CUDA0 model buffer size =  5871.99 MiB\n"
            "llama_context: n_ctx                 = 98048\n"
            "main: model loaded\n"
        )
        server = serving.LlamaCppServer(
            FakeRemote(log_text=log), "baronllm-llama3.1:q6_k",
            {"gguf": "/g", "gguf_sha256": "abc123"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        place = server.provenance()
        # What the model actually ran with, measured off the server's own log.
        self.assertEqual(place["n_ctx"], 98048)
        # The floor that was asked for, so the gap is stated rather than implied.
        self.assertEqual(place["n_ctx_requested"], 24576)

    def test_a_context_that_needs_no_fitting_reports_the_same_value_twice(self):
        """No negotiation happened, so the two names carry one number."""
        place = server_for(FIT_LOG).provenance()
        self.assertEqual(place["n_ctx"], 24576)
        self.assertEqual(place["n_ctx_requested"], 24576)

    def test_the_placement_survives_a_log_longer_than_the_tail_bound(self):
        """The measurement lines are printed at LOAD; the tail bound is not.

        Measured on homeserver 2026-10-05 against the production flags
        (`--fit-ctx 24576 -lv 4`): the load phase is 13,194 collapsed
        characters, of which `offloaded 33/33 layers to GPU` is at ~10,000.
        `server_log()` ended in `[-2000:]`, so on a server that has decoded
        anything the placement line was cut away and every residency field
        read `None` -- the `gpu_layers: null` on all four slots of run
        2026-10-05-20261005T134600Z-3aee521a, on a run that plainly offloaded
        33/33. `n_ctx` survived only because it sits near the end of the load
        phase, which is why that field was populated and the rest were not.

        The tail bound exists to cap what is held in memory and shipped over
        ssh, not to bound what is *searched*: the parse has to see the load
        lines, so the search runs over the whole captured log.
        """
        # A real log: the load phase, then ~40KB of decode chatter after it,
        # which is what pushed the placement line past a 2000-char tail.
        long_log = FIT_LOG + ("0.99.999.999 I slot print_timing: id 1 | task 7 | "
                              "eval time = 187.02 ms / 10 tokens\n" * 3000)
        place = server_for(long_log).residency()
        self.assertEqual(place["gpu_layers"], 41)
        self.assertEqual(place["layers_total"], 42)
        self.assertEqual(place["vram_mib"], 17880.66)
        self.assertEqual(place["n_ctx"], 24576)

    def test_the_placement_is_read_once_and_survives_teardown(self):
        """The measurement is taken while the container exists, once.

        `docker logs` on a removed container returns nothing, and parsing
        nothing yields `None` for every field -- which is exactly how a run
        that plainly offloaded to the card recorded `gpu_layers: null`. The
        value has to come from the read made at load time, and no later read
        may be needed or attempted.
        """
        remote = FakeRemote(log_text=FIT_LOG)
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "abc123"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        server._require_gpu_residency()
        reads_after_load = len(remote.log_reads)

        server.teardown()
        # A removed container answers `docker logs` with nothing at all.
        remote.log_text = ""
        place = server.residency()

        self.assertEqual(place["gpu_layers"], 41)
        self.assertEqual(place["layers_total"], 42)
        self.assertEqual(place["vram_mib"], 17880.66)
        self.assertEqual(place["kv_cache_mib"], 480.00)
        self.assertEqual(place["n_ctx"], 24576)
        self.assertIs(place["ram_offloaded"], True)
        self.assertEqual(len(remote.log_reads), reads_after_load,
                         "the cached value must not be re-read after teardown")

    def test_a_repeated_read_is_one_ssh_round_trip_not_several(self):
        """`provenance()` and `_require_gpu_residency()` both want it.

        They are called at the same moment in the launch path, and each is an
        `ssh docker logs`. Caching is what makes the second one free.
        """
        remote = FakeRemote(log_text=FIT_LOG)
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "abc123"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        server._require_gpu_residency()
        server.provenance()
        server.provenance()
        self.assertEqual(len(remote.log_reads), 1)


class GpuResidencyGuardTest(unittest.TestCase):
    """A grade decoded on the CPU is worthless here, so this is a failure.

    llama-server prints "model loaded" for a CPU-only run exactly as it does
    for a GPU one, and fit can reach that state by shedding every layer.
    Partial (41/42) is intended and must not trip the guard.
    """

    def test_a_cpu_only_load_is_refused(self):
        server = server_for(FIT_LOG.replace("offloaded 41/42", "offloaded 0/42"))
        with self.assertRaises(serving.EngineUnavailable) as caught:
            server._require_gpu_residency()
        self.assertIn("0/42", str(caught.exception))

    def test_a_partial_offload_is_allowed(self):
        server_for(FIT_LOG)._require_gpu_residency()  # must not raise

    def test_a_full_offload_is_allowed(self):
        server_for(FIT_LOG.replace("offloaded 41/42", "offloaded 42/42")
                   )._require_gpu_residency()  # must not raise

    def test_an_absent_layer_line_passes(self):
        """Unavailable measurement is not a zero-layer load.

        The guard is on the guard: refusing a model because its server did not
        print the line would fail healthy models for a formatting reason, on a
        llama.cpp build that spells it differently.
        """
        server_for("main: model loaded\n")._require_gpu_residency()  # must not raise

    def test_a_cpu_only_load_ends_the_session_in_a_fallback(self):
        """End to end: 0/42 must not reach Ollama, or it silently succeeds.

        `EngineUnavailable` is what `ModelSession.open()` catches to route the
        model to the fallback, so without the guard a CPU-decoded run would be
        recorded as an llama.cpp one.
        """
        remote = FakeRemote(log_text=FIT_LOG.replace("offloaded 41/42", "offloaded 0/42"))
        session = make_session(remote)
        start(session)
        self.assertEqual(session.engine, "ollama")
        self.assertIn("0/42 layers in VRAM", session.fallback_reason)

    def test_a_probe_before_a_cpu_only_load_is_still_refused(self):
        """The live bug: the probe's 42/42 used to pass this guard.

        A confirmed CPU-decoded run reported `gpu_layers: 42` because the probe
        was read, so the grade was stored as a legitimate llama.cpp result.
        """
        server = server_for(PROBE_THEN_CPU_LOG)
        with self.assertRaises(serving.EngineUnavailable) as caught:
            server._require_gpu_residency()
        self.assertIn("0/42", str(caught.exception))


class EnginePrintTest(unittest.TestCase):
    """The fallback clause is gated on `fallback_engine`, not on the name.

    `ENGINE_LLAMACPP` is "llamacpp" while the engine reports "llama.cpp", so a
    name comparison never matched and every healthy run printed
    `serving on llama.cpp (llama.cpp unavailable, fell back: None)`. That line
    is how a whole roster gets judged, so a contradiction in the success path
    is not cosmetic.
    """

    def _open(self, remote):
        def request_json(url, body=None, timeout=None):
            return {"models": [{"name": "gemma2:27b"}]} if url.endswith("/api/tags") else {}

        args = argparse.Namespace(engine=evaluate_models.ENGINE_LLAMACPP)
        out = io.StringIO()
        with mock.patch.object(evaluate_models, "request_json", request_json), \
             mock.patch.object(serving, "Remote", return_value=remote), \
             mock.patch.object(serving.LlamaCppServer, "healthy", return_value=True), \
             contextlib.redirect_stdout(out):
            evaluate_models.open_session(
                args, "http://127.0.0.1:11435", "gemma2:27b", 24576)
        return out.getvalue()

    def test_a_healthy_run_prints_no_fallback_clause(self):
        printed = self._open(FakeRemote())
        self.assertIn("engine: serving on llama.cpp", printed)
        self.assertNotIn("fell back", printed)
        self.assertNotIn("unavailable", printed)

    def test_a_real_fallback_prints_the_reason(self):
        remote = FakeRemote(state="exited", log_text="unsupported model architecture")
        printed = self._open(remote)
        self.assertIn("engine: serving on ollama", printed)
        self.assertIn("fell back", printed)
        self.assertIn("unsupported model architecture", printed)


# --- wire translation ------------------------------------------------------

class RecordedRoundTripTest(unittest.TestCase):
    """The second turn, against wire bodies recorded off a live llama-server.

    Every assertion here reads a body the server actually received, not one to_wire
    produced in this process -- so a change to the translation that the server
    would have accepted, and rejected, differently is caught rather than argued.
    """

    def setUp(self):
        self.turns = {t["turn"]: t for t in LLAMACPP_ROUNDTRIP["turns"]}
        self.assertIn(2, self.turns, "the capture must reach a second turn")

    def test_the_exchange_completed_with_a_prose_answer(self):
        first = self.turns[1]["response_raw"]["choices"][0]
        second = self.turns[2]["response_raw"]["choices"][0]
        self.assertEqual(first["finish_reason"], "tool_calls")
        self.assertEqual(second["finish_reason"], "stop")
        self.assertTrue(second["message"]["content"].strip(),
                        "the follow-up must answer in prose, not in silence")

    def test_the_second_turn_carried_the_assistant_tool_calls_message(self):
        roles = [m["role"] for m in self.turns[2]["request_wire"]["messages"]]
        self.assertIn("assistant", roles)
        self.assertIn("tool", roles)

    def test_the_tool_result_is_keyed_to_the_call_it_answers(self):
        messages = self.turns[2]["request_wire"]["messages"]
        assistant = next(m for m in messages if m.get("tool_calls"))
        result = next(m for m in messages if m["role"] == "tool")
        self.assertTrue(result["tool_call_id"])
        self.assertEqual(result["tool_call_id"], assistant["tool_calls"][0]["id"])

    def test_the_captured_wire_is_what_to_wire_produces_today(self):
        """The recorded body is the contract. If translation drifts, the
        recorded wire stops matching and this fails, rather than the drift going
        unnoticed because both sides moved together in some future run."""
        messages = self.turns[2]["request_wire"]["messages"]
        # Re-translate turn 1's assistant message plus the tool result and
        # compare the id pairing the server actually received.
        from_wire_message = serving.from_wire(self.turns[1]["response_raw"])["message"]
        rebuilt = serving.to_wire({"messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
            from_wire_message,
            {"role": "tool", "content": "wrote src/main.rs (36 chars)",
             "tool_name": "write_file"},
        ]})
        self.assertEqual(
            rebuilt["messages"][3]["tool_call_id"],
            messages[2]["tool_calls"][0]["id"],
        )


class TranslationTest(unittest.TestCase):
    def test_a_capped_llama_cpp_answer_is_stored_as_truncated(self):
        """The reason this seam is test-driven rather than trusted.

        llama.cpp calls it `finish_reason: "length"`. Untranslated, it is a
        finish reason this harness has never seen, so classify_outcome stores
        the answer as `truncated` under a spelling of its own and was_capped --
        which every scorer reads to force a zero -- silently disagrees with the
        stored outcome.
        """
        result = serving.from_wire({
            "choices": [{"message": {"content": "partial"}, "finish_reason": "length"}],
            "timings": {"predicted_n": 16000},
        })
        self.assertEqual(result["done_reason"], "length")
        self.assertEqual(transcripts.classify_outcome(error=None, done_reason=result["done_reason"]),
                         transcripts.OUTCOME_TRUNCATED)
        self.assertTrue(transcripts.was_capped({"done_reason": result["done_reason"]}))

    def test_a_clean_llama_cpp_stop_is_stored_as_ok(self):
        result = serving.from_wire({
            "choices": [{"message": {"content": "done"}, "finish_reason": "stop"}],
        })
        self.assertEqual(result["done_reason"], "stop")
        self.assertEqual(transcripts.classify_outcome(error=None, done_reason=result["done_reason"]),
                         transcripts.OUTCOME_OK)
        self.assertFalse(transcripts.was_capped({"done_reason": result["done_reason"]}))

    def test_a_tool_call_finish_reason_is_not_a_truncation(self):
        result = serving.from_wire({
            "choices": [{"message": {"content": ""}, "finish_reason": "tool_calls"}],
        })
        self.assertEqual(result["done_reason"], "stop")

    def test_an_absent_finish_reason_stays_absent(self):
        """None is carved out of CLEAN_DONE_REASONS deliberately; absent is not
        evidence of truncation, and translating None into 'stop' would
        certify a generation the server never reported finishing."""
        self.assertIsNone(serving.from_wire({"choices": [{"message": {"content": "x"}}]})["done_reason"])

    def test_tokens_per_second_is_computed_from_nanoseconds(self):
        """chat() divides eval_duration by 1e9; the field must already be in ns.

        Getting this wrong reports a rate 1e9 times too small, which is not a
        number any reader would catch -- it would just read as "slow".
        """
        result = serving.from_wire({
            "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
            "timings": {"predicted_n": 1000, "predicted_ms": 20000, "prompt_n": 10},
        })
        self.assertEqual(result["eval_count"], 1000)
        self.assertEqual(result["eval_duration"], 20_000 * 1_000_000)
        # 1000 tokens in 20000 ms is 50 tok/s. If the ms->ns conversion were
        # missing, this would read as 5e-8 -- a rate no reader would catch as
        # wrong, it would just look like a very slow model.
        rate = round(1000 / (result["eval_duration"] / 1e9), 2)
        self.assertAlmostEqual(rate, 50.0, places=6)

    def test_sampling_survives_the_translation(self):
        """A llama.cpp answer must be decoded the way the record says it was."""
        wire = serving.to_wire({
            "options": {"temperature": 0, "num_predict": 16000, "seed": 144,
                        "repeat_penalty": 1.3, "repeat_last_n": 256},
            "messages": [{"role": "system", "content": "s"},
                         {"role": "user", "content": "u"}],
        })
        self.assertEqual(wire["temperature"], 0)
        self.assertEqual(wire["max_tokens"], 16000)
        self.assertEqual(wire["seed"], 144)
        self.assertEqual(wire["repeat_penalty"], 1.3)
        self.assertEqual(wire["repeat_last_n"], 256)
        self.assertFalse(wire["stream"])

    def test_the_harmony_path_adds_its_sampling_to_the_request(self):
        """Dropping the harmony update must not leave a green translation test."""
        requests = []

        def transport(_url, body):
            requests.append(body)
            return {"message": {"content": "complete"}, "done_reason": "stop"}

        evaluate_models.chat(
            "http://ignored", "gpt-oss:20b", "system", "prompt", 8192,
            False, evaluate_models.HARMONY_NUM_PREDICT, transport=transport,
        )

        for key, value in evaluate_models.HARMONY_SAMPLING.items():
            self.assertEqual(requests[0]["options"][key], value)

    def test_json_mode_becomes_a_response_format(self):
        self.assertEqual(serving.to_wire({"format": "json", "messages": []})["response_format"],
                         {"type": "json_object"})

    def test_declared_response_formats_pass_through_untouched(self):
        for declared in ("json_object", "json_schema", "text"):
            with self.subTest(declared=declared):
                spec = {"type": declared, "marker": {"untouched": True}}
                wire = serving.to_wire({"format": spec, "messages": []})
                self.assertEqual(wire["response_format"], spec)

    def test_a_keyword_named_property_is_not_treated_as_a_schema_keyword(self):
        schema = {
            "type": "object",
            "properties": {"not": {"type": "string"}},
        }
        self.assertEqual(
            serving.to_wire({"format": schema, "messages": []})["response_format"],
            {"type": "json_object", "schema": schema},
        )

    def test_local_refs_resolve_against_the_schema_root(self):
        for definitions in ("$defs", "definitions"):
            with self.subTest(definitions=definitions):
                schema = {
                    "type": "object",
                    definitions: {"entry": {"type": "string"}},
                    "properties": {
                        "value": {"$ref": f"#/{definitions}/entry"},
                    },
                }
                self.assertEqual(
                    serving.to_wire({"format": schema, "messages": []})[
                        "response_format"
                    ],
                    {"type": "json_object", "schema": schema},
                )

    def test_an_unknown_schema_keyword_is_rejected_with_its_reason(self):
        schema = {"type": "object", "unevaluatedProperties": False}
        with self.assertRaises(serving.UnsupportedFormat) as caught:
            serving.to_wire({"format": schema, "messages": []})
        self.assertIn("keyword", str(caught.exception))
        self.assertIn("json_schema_to_grammar", str(caught.exception))

    def test_a_non_dict_format_is_rejected_with_its_reason(self):
        with self.assertRaises(serving.UnsupportedFormat) as caught:
            serving.to_wire({"format": "peg-native", "messages": []})
        self.assertIn("str", str(caught.exception))
        self.assertIn("PEG grammar", str(caught.exception))

    def test_the_captured_session_schema_uses_the_accepted_llama_cpp_shape(self):
        captured = LLAMACPP_CAPTURES["sessions-schema-asis"]
        self.assertEqual(serving.to_wire(captured["harness_body"]),
                         captured["wire_request"])
        self.assertEqual(
            captured["wire_request"]["response_format"],
            {"type": "json_object", "schema": evaluate_models.session_schema()},
        )
        self.assertEqual(captured["raw_response"]["choices"][0]["finish_reason"], "stop")

    def test_ollama_only_fields_are_not_sent(self):
        wire = serving.to_wire({"think": True, "keep_alive": "10m", "messages": []})
        self.assertNotIn("think", wire)
        self.assertNotIn("keep_alive", wire)

    def test_tool_results_are_paired_to_their_calls(self):
        """llama.cpp needs ids to match a tool result to its call; Ollama's shape
        carries none, so they are synthesized here. A tool result with an
        unpaired id is an orphan the server may answer with silence."""
        wire = serving.to_wire({"messages": [
            {"role": "user", "content": "do it"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "write_file", "arguments": {"path": "a", "content": "b"}}},
            ]},
            {"role": "tool", "content": "wrote a", "tool_name": "write_file"},
        ]})
        call_id = wire["messages"][1]["tool_calls"][0]["id"]
        self.assertEqual(wire["messages"][2]["tool_call_id"], call_id)
        self.assertEqual(
            json.loads(wire["messages"][1]["tool_calls"][0]["function"]["arguments"]),
            {"path": "a", "content": "b"},
        )

    def test_each_tool_result_gets_its_own_calls_id(self):
        """Two calls in one assistant turn must get two distinct result ids.

        The defect: `calls_seen` counted forward and every tool message then took
        `call_{calls_seen - 1}`, the LAST call of the turn before it. Both
        results came out as `call_1` -- the first answered the wrong call and
        `call_0` was never answered. llama.cpp's templates key a result off the
        matching `tool_call_id`, so that renders a result for a call the model
        never sees, which is the malformed-tool-name 500 measured on the wire.
        """
        wire = serving.to_wire({"messages": [
            {"role": "user", "content": "do it"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "write_file", "arguments": {"path": "a"}}},
                {"function": {"name": "write_file", "arguments": {"path": "b"}}},
            ]},
            {"role": "tool", "content": "wrote a", "tool_name": "write_file"},
            {"role": "tool", "content": "wrote b", "tool_name": "write_file"},
        ]})
        call_ids = [c["id"] for c in wire["messages"][1]["tool_calls"]]
        self.assertEqual(len(set(call_ids)), 2, "the two calls must not share an id")
        self.assertEqual(wire["messages"][2]["tool_call_id"], call_ids[0])
        self.assertEqual(wire["messages"][3]["tool_call_id"], call_ids[1])

    def test_tool_ids_are_unique_across_a_whole_conversation(self):
        """Two exchanges in one history each restarted at `call_0` (measured on
        the wire). The OpenAI shape these ids are written for treats an id as
        unique per conversation, and a template that matched a result to the
        first call with that id would pair round 3's result with round 1's."""
        wire = serving.to_wire({"messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "write_file", "arguments": {"path": "a"}}}]},
            {"role": "tool", "content": "wrote a", "tool_name": "write_file"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "read_file", "arguments": {"path": "a"}}}]},
            {"role": "tool", "content": "contents", "tool_name": "read_file"},
        ]})
        ids = [call["id"] for message in wire["messages"]
               for call in message.get("tool_calls", [])]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2, f"ids repeated across turns: {ids}")
        # And the second result answers the second call, not the first.
        self.assertEqual(wire["messages"][2]["tool_call_id"], ids[0])
        self.assertEqual(wire["messages"][4]["tool_call_id"], ids[1])

    def test_tool_ids_restart_per_turn_and_survive_a_second_exchange(self):
        """Ids are positional per turn, so round 3 re-translates the same
        history to the same ids. Without that, a result in a later round is
        paired to a call from a turn the model no longer has in context."""
        body = {"messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "read_file", "arguments": {"path": "a"}}}]},
            {"role": "tool", "content": "one", "tool_name": "read_file"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "read_file", "arguments": {"path": "b"}}}]},
            {"role": "tool", "content": "two", "tool_name": "read_file"},
        ]}
        wire = serving.to_wire(body)
        # Every result answers the call immediately above it, in order.
        for index, message in enumerate(wire["messages"]):
            if message["role"] != "tool":
                continue
            preceding = wire["messages"][index - 1]
            self.assertEqual(
                message["tool_call_id"],
                preceding["tool_calls"][0]["id"],
                f"result at index {index} is not paired with the call above it",
            )
        # Re-translating the same history yields the same ids, so the round
        # after a tool exchange is byte-identical to the one before it.
        self.assertEqual(serving.to_wire(body), wire)

    def test_a_tool_result_is_never_left_without_an_id(self):
        """A result with no call to pair against still has to carry a key:
        llama.cpp drops a tool message that has no `tool_call_id`, so an empty
        value would turn this history into an orphan rather than a bad pair."""
        wire = serving.to_wire({"messages": [
            {"role": "user", "content": "go"},
            {"role": "tool", "content": "orphan", "tool_name": "read_file"},
        ]})
        self.assertTrue(wire["messages"][1]["tool_call_id"])

    def test_structured_tool_calls_are_preserved_in_the_response(self):
        """The coder slot carries its answer in tool_calls with empty content;
        dropping them records an empty answer for the whole turn."""
        result = serving.from_wire({"choices": [{"message": {
            "content": "",
            "tool_calls": [{"function": {"name": "write_file", "arguments": {"path": "a"}}}],
        }, "finish_reason": "tool_calls"}]})
        self.assertEqual(evaluate_models.assistant_text(result["message"]) != "", True)

    def test_captured_openai_tool_arguments_become_the_harness_dict_shape(self):
        captured = LLAMACPP_CAPTURES["coder-tools"]
        raw_arguments = captured["raw_response"]["choices"][0]["message"][
            "tool_calls"
        ][0]["function"]["arguments"]
        self.assertIsInstance(raw_arguments, str)

        message = serving.from_wire(captured["raw_response"])["message"]
        arguments = message["tool_calls"][0]["function"]["arguments"]
        self.assertIsInstance(arguments, dict)

        round_trip = serving.to_wire({"messages": [message]})
        self.assertEqual(
            round_trip["messages"][0]["tool_calls"][0]["function"]["arguments"],
            raw_arguments,
        )

    def test_revdeck_uses_the_sampling_that_stopped_the_captured_loop(self):
        """revdeck must go out with its own sampling.

        The captured `revdeck-prose` request is the one a revdeck body really
        produced, so asserting the harness reproduces its `options` proves the
        per-slot exception is actually on the wire -- not merely defined in
        `REVDECK_SAMPLING` and never applied.
        """
        captured = LLAMACPP_CAPTURES["revdeck-prose"]
        case = next(
            case for case in evaluate_models.REV_CASES
            if case.name == "process-injection"
        )
        requests = []

        def transport(_url, body):
            requests.append(body)
            return {"message": {"content": "complete"}, "done_reason": "stop"}

        with mock.patch.object(evaluate_models, "REV_CASES", (case,)):
            evaluate_models.score_revdeck(
                "http://ignored", captured["harness_body"]["model"], 16384,
                transport=transport,
            )

        self.assertEqual(
            requests[0]["options"]["repeat_penalty"],
            evaluate_models.REVDECK_SAMPLING["repeat_penalty"],
        )
        self.assertEqual(
            requests[0]["options"]["repeat_last_n"],
            evaluate_models.REVDECK_SAMPLING["repeat_last_n"],
        )
        # The other slots keep their own sampling; the exception is not global.
        self.assertNotEqual(evaluate_models.REVDECK_SAMPLING,
                            evaluate_models.HARMONY_SAMPLING)
        self.assertEqual(
            captured["raw_response"]["choices"][0]["finish_reason"], "stop"
        )


# --- the transport ---------------------------------------------------------

class TransportTest(unittest.TestCase):
    def test_a_generation_gets_the_harness_sized_timeout(self):
        """A 16000-token budget and an 8-token probe must not be cut at the same
        wall clock, exactly as on the Ollama path."""
        seen = {}

        class FakeResponse:
            def __init__(self, payload):
                self._payload = json.dumps(payload).encode()

            def read(self):
                return self._payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def urlopen(request, timeout=None):
            seen["url"] = request.full_url
            seen["body"] = json.loads(request.data)
            seen["timeout"] = timeout
            return FakeResponse({
                "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                "timings": {"predicted_n": 10, "predicted_ms": 1000},
            })

        server = serving.LlamaCppServer(
            FakeRemote(), "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
            num_ctx=24576,
            request_timeout=evaluate_models.request_timeout,
        )
        with mock.patch.object(serving.urllib.request, "urlopen", urlopen):
            out = server.request_json("http://ignored/api/chat", {
                "options": {"num_predict": 16000}, "messages": [],
            })
        self.assertIn("/v1/chat/completions", seen["url"])
        self.assertEqual(seen["body"]["max_tokens"], 16000)
        self.assertEqual(
            seen["timeout"], evaluate_models.request_timeout({"options": {"num_predict": 16000}}),
        )
        self.assertEqual(out["message"]["content"], "hi")

    def test_the_tool_round_loop_runs_on_llama_cpp(self):
        """bench_tools drives multi-round tools through the same callable, so the
        coder slot's exchange has to work on llama.cpp and not only on the
        fallback. A real loop, a real tool result, a real second request."""
        import bench_tools

        remote = FakeRemote()
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        bodies = []

        class FakeResponse:
            def __init__(self, payload):
                self._payload = json.dumps(payload).encode()

            def read(self):
                return self._payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        replies = [
            {"choices": [{"message": {"content": "", "tool_calls": [
                {"function": {"name": "read_file", "arguments": {"path": "x"}}}]},
                "finish_reason": "tool_calls"}]},
            {"choices": [{"message": {"content": "final"}, "finish_reason": "stop"}],
             "timings": {"predicted_n": 5, "predicted_ms": 100}},
        ]

        def urlopen(request, timeout=None):
            bodies.append(json.loads(request.data))
            return FakeResponse(replies[len(bodies) - 1])

        body = {"options": {"num_predict": 512}, "messages": [
            {"role": "system", "content": "s"}, {"role": "user", "content": "u"}]}
        with mock.patch.object(serving.urllib.request, "urlopen", urlopen):
            first = server.request_json("http://ignored/api/chat", body)
            final = bench_tools.conduct_tool_rounds(
                server.request_json, "http://ignored/api/chat", body, first)
        self.assertEqual(len(bodies), 2)
        self.assertIn("tool_turns", final)
        self.assertEqual(final["tool_turns"][0]["tool"], "read_file")
        self.assertEqual(final["message"]["content"], "final")
        # The followup carries the assistant turn and its tool result, both
        # translated into llama.cpp's own shape.
        roles = [m["role"] for m in bodies[1]["messages"]]
        self.assertIn("tool", roles)
        self.assertTrue(any(m.get("tool_call_id") for m in bodies[1]["messages"]))


# --- lifecycle -------------------------------------------------------------

class LifecycleTest(unittest.TestCase):
    def test_a_slow_load_is_not_a_failure(self):
        """A 27B takes minutes. 'Not ready yet' must not end the attempt."""
        remote = FakeRemote(health=False)
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        # Becomes healthy on the third poll.
        healthy = [False, False, True]
        with mock.patch.object(serving.LlamaCppServer, "healthy",
                               side_effect=lambda: healthy.pop(0)), \
             mock.patch.object(serving.time, "sleep", lambda _s: None):
            server._await_ready()
        self.assertEqual(healthy, [])

    def test_a_container_that_exits_does_not_wait_out_the_whole_timeout(self):
        """A load OOM kills the process. Polling it for 1800s would learn
        nothing for half an hour."""
        remote = FakeRemote(state="exited", exit_code="1", log_text="cudaMalloc failed")
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        with self.assertRaises(RuntimeError) as caught, \
             mock.patch.object(serving.time, "sleep", lambda _s: None):
            server._await_ready()
        self.assertIn("exited", str(caught.exception))

    def test_the_gpu_wait_stops_at_the_base_overhead(self):
        """A card holding nothing but desktop overhead counts as idle.

        The threshold is deliberately loose. It only has to separate a card
        with nothing on it from a card with a model on it -- a single layer is
        hundreds of MiB -- and must sit ABOVE whatever the host's baseline
        happens to read. Pinning it to one observation of that baseline is what
        made the wait unsatisfiable: it read 508 idle once, the threshold was
        set to 508, and the card later read 556, so nothing ever loaded.
        """
        for idle_reading in (508, 512, 546, 556):
            remote = FakeRemote(vram=idle_reading)
            server = serving.LlamaCppServer(
                remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
                num_ctx=24576, request_timeout=evaluate_models.request_timeout,
            )
            with mock.patch.object(serving.time, "sleep", lambda _s: None):
                waited = server.wait_for_gpu()
            self.assertTrue(waited["reached_idle"], idle_reading)

        # And the threshold must still be below a single loaded model, or the
        # wait would pass while a server is still holding VRAM.
        self.assertLess(serving.GPU_IDLE_MIB, 4000)

    def test_a_held_card_is_waited_out_before_the_next_start(self):
        remote = FakeRemote(vram=7974)
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        # Polled until the card is free, and the reading that ended the wait is
        # the one recorded -- re-reading after the loop could report a different
        # card state than the one the wait decided on.
        readings = [7974, 7974, 502]
        with mock.patch.object(serving.time, "sleep", lambda _s: None), \
             mock.patch.object(serving.LlamaCppServer, "vram_used_mib", lambda self: readings.pop(0)):
            waited = server.wait_for_gpu()
        self.assertEqual(readings, [], "the card must be polled until it is free")
        self.assertTrue(waited["reached_idle"])
        self.assertEqual(waited["vram_used_mib"], 502)
        self.assertFalse(waited["unmeasurable"])

    def test_a_card_that_cannot_be_read_is_not_reported_as_idle(self):
        """`reached_idle` distinguishes "already free" from "proceeded anyway".

        An unread card is neither. vram_used_mib() returns None when nvidia-smi
        fails over ssh, and reading that as free recorded a verified-idle wait on
        a card that may be holding a stale 7974 MiB -- the opposite of the truth,
        on the one field that carries it.
        """
        remote = FakeRemote()
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        with mock.patch.object(serving.time, "sleep", lambda _s: None), \
             mock.patch.object(serving.LlamaCppServer, "vram_used_mib", lambda self: None):
            waited = server.wait_for_gpu()
        self.assertFalse(waited["reached_idle"])
        self.assertTrue(waited["unmeasurable"])
        self.assertIsNone(waited["vram_used_mib"])

    def test_a_gpu_wait_that_times_out_records_that_it_did(self):
        """Proceeding is a decision, so it has to be in the record rather than
        inferred from a run that happened to work."""
        remote = FakeRemote(vram=19000)
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "s"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        with mock.patch.object(serving.time, "monotonic",
                               side_effect=[0, 0, 10_000, 10_000]), \
             mock.patch.object(serving.time, "sleep", lambda _s: None), \
             mock.patch.object(serving.LlamaCppServer, "vram_used_mib", lambda self: 19000):
            waited = server.wait_for_gpu()
        self.assertFalse(waited["reached_idle"])
        self.assertFalse(waited["unmeasurable"])
        self.assertEqual(waited["vram_used_mib"], 19000)

    def test_teardown_removes_the_container_and_closes_the_tunnel(self):
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        session.close()
        self.assertTrue(remote.removed, "the container must not outlive its slot")
        self.assertTrue(remote.closed)

    def test_a_failed_model_still_releases_its_container(self):
        """A model that dies mid-slot still holds VRAM; that is how a stale
        model held 7974 MiB for minutes and OOMed the next one."""
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            session.close()
        self.assertTrue(remote.removed)


# --- the record ------------------------------------------------------------

class RecordingTest(unittest.TestCase):
    """A result that does not say which engine produced it is not interpretable."""

    def provenance_for(self, *, remote=None, kv=False):
        remote = remote or FakeRemote()
        server = serving.LlamaCppServer(
            remote, "gemma2:27b", {"gguf": "/g", "gguf_sha256": "abc123"},
            num_ctx=24576, request_timeout=evaluate_models.request_timeout,
        )
        server.kv_retry = kv
        server.vram_oom_first_attempt = kv
        server.gpu_wait = {"reached_idle": True, "vram_used_mib": 508,
                           "idle_threshold_mib": 508}
        # The record is ModelSession.provenance(), which merges the server's
        # engine facts with the fallback and VRAM fields; asserting on the
        # server's half alone is what let the merged half go untested.
        session = serving.ModelSession(
            "gemma2:27b", "http://127.0.0.1:11435",
            num_ctx=24576, request_json=lambda *a, **k: {},
            request_timeout=lambda body: 300, remote=remote,
        )
        session.engine, session.server = "llama.cpp", server
        return session.provenance(vram_used_mib=15486)

    def test_every_required_fact_is_present(self):
        provenance = self.provenance_for(kv=True)
        for field in ("engine", "flags", "kv_offload_disabled", "fallback_engine",
                      "fallback_reason", "vram_used_mib", "gguf", "gguf_sha256",
                      "gpu_layers", "layers_total", "vram_mib", "kv_cache_mib",
                      "n_ctx", "ram_offloaded"):
            self.assertIn(field, provenance)
        self.assertEqual(provenance["engine"], "llama.cpp")
        self.assertTrue(provenance["kv_offload_disabled"])
        self.assertNotIn("--no-kv-offload", provenance["flags"])

    def test_the_recorded_flags_are_the_flags_that_ran(self):
        """The flags in the record must be the ones on the command line, or a
        reader cannot reproduce the run they are reading."""
        remote = FakeRemote()
        session = make_session(remote, num_ctx=24576)
        start(session)
        provenance = session.provenance()
        self.assertEqual(provenance["flags"], remote.flags_of(0))
        self.assertEqual(
            provenance["flags"][provenance["flags"].index("--fit-ctx") + 1], "24576")

    def test_a_no_retry_run_records_that_no_retry_happened(self):
        self.assertIs(self.provenance_for(kv=False)["kv_offload_disabled"], False)

    def test_the_fallback_engine_and_its_reason_are_recorded(self):
        remote = FakeRemote(state="exited", log_text="unsupported model architecture")
        session = make_session(remote)
        start(session)
        provenance = session.provenance(vram_used_mib=15486)
        self.assertEqual(provenance["engine"], "ollama")
        self.assertEqual(provenance["fallback_engine"], "ollama")
        self.assertIn("unsupported model architecture", provenance["fallback_reason"])
        self.assertEqual(provenance["vram_used_mib"], 15486)

    def test_a_llama_cpp_run_records_no_fallback(self):
        provenance = self.provenance_for().copy()
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        provenance = session.provenance()
        self.assertIsNone(provenance["fallback_engine"])
        self.assertIsNone(provenance["fallback_reason"])

    def test_vram_at_the_time_is_carried(self):
        self.assertEqual(self.provenance_for()["vram_used_mib"], 15486)

    def test_an_ollama_run_reports_the_same_keys_as_a_llama_cpp_run(self):
        """Two rows a reader has to compare must have the same shape, or the
        comparison silently skips whatever only one engine recorded."""
        remote = FakeRemote(state="exited", log_text="unsupported model architecture")
        session = make_session(remote)
        start(session)
        # No key is excluded any more. The llama.cpp half used to be absent on a
        # fallback row, so a reader comparing the two had to know in advance
        # which engine produced which -- which is the state this test exists to
        # end. A key present and null says "this engine does not apply"; a key
        # missing says nothing at all.
        self.assertEqual(set(session.provenance()), set(self.provenance_for()))

    def test_a_record_read_after_teardown_still_names_its_engine(self):
        """Finding 7: the model row is assembled after close().

        close() tears the server down and clears the handle, so a read that
        trusted `self.server` alone reported a llama.cpp run as an Ollama one --
        and a llama.cpp row and an Ollama row became identical but for a stray
        engine string, which is the mixed-engine table becoming unreadable.
        """
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        before = session.provenance()
        session.close()
        after = session.provenance()
        self.assertEqual(after["engine"], "llama.cpp")
        self.assertEqual(after["gguf_sha256"], before["gguf_sha256"])
        self.assertEqual(after["flags"], before["flags"])
        self.assertIsNotNone(after["image"])
        self.assertEqual(set(after), set(before))

    def test_a_failed_start_releases_the_container_it_left_running(self):
        """Finding 4: a load that raises after `docker run -d` leaves a live
        container holding VRAM.

        The container here is still *running* -- the load timed out, which is
        the case that leaks, because a container that exited holds nothing. The
        fallback then returns a working Ollama transport, so the caller has no
        reason to know a container exists and the next model's load OOMs against
        it. That is the "stale model held 7974 MiB for minutes" incident.

        Asserted on removals after the start attempt: `start()` removes once
        itself while retrying, so the count is compared against what a clean
        launch costs rather than against zero.
        """
        remote = FakeRemote(state="running", health=False)
        session = make_session(remote)
        with mock.patch.object(serving.LlamaCppServer, "_await_ready",
                               side_effect=RuntimeError(
                                   "llama-server was still loading after 1800s")), \
             mock.patch.object(serving.LlamaCppServer, "healthy", return_value=False):
            start(session)
        self.assertEqual(session.engine, "ollama")
        self.assertEqual(session.server, None,
                         "no llama.cpp handle may outlive a failed start")
        self.assertGreaterEqual(len(remote.removed), 2,
                                "the abandoned llama-server container must not outlive the attempt")
        self.assertTrue(all(argv[:2] == ["rm", "-f"] for argv in remote.removed))

    def test_a_successful_close_leaves_nothing_running(self):
        """The other direction: a served model is released exactly once, by
        close(). start() removes a stale container of the same name before
        launching, so the count is one before close() and two after -- never
        three, which is what a double teardown would look like."""
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        self.assertEqual(len(remote.removed), 2, "the pre-start teardown + old-container cleanup")
        session.close()
        self.assertEqual(len(remote.removed), 3)
        self.assertIsNone(session.server)


class SlotReportingTest(unittest.TestCase):
    """evaluate_slot() must publish the serving facts next to the score."""

    def run_slot(self, remote):
        session = make_session(remote)
        start(session)
        posted = []

        def request_json(url, body=None, timeout=None):
            posted.append((url, body))
            if url.endswith("/api/tags"):
                return {"models": [{"name": "gemma2:27b", "digest": "d", "size": 15,
                                    "details": {"family": "gemma", "parameter_size": "27B",
                                                "quantization_level": "Q4_K_M"}}]}
            if url.endswith("/api/ps"):
                return {"models": []}
            if url.endswith("/api/show"):
                return {"capabilities": ["tools", "completion"]}
            return {"message": {"content": "{}"}, "eval_count": 10,
                    "eval_duration": 1_000_000_000, "done_reason": "stop"}

        session.request_json = request_json
        result = evaluate_models.evaluate_slot(
            "http://127.0.0.1:11435", "revdeck", "gemma2:27b",
            evaluate_models.qualification_request("revdeck", 8192),
            None, "A", session,
        )
        return result

    def test_the_slot_result_carries_the_engine(self):
        result = self.run_slot(FakeRemote())
        self.assertEqual(result["serving"]["engine"], "llama.cpp")
        self.assertIn("flags", result["serving"])

    def test_the_slot_result_carries_the_gguf_it_loaded(self):
        result = self.run_slot(FakeRemote())
        self.assertEqual(result["serving"]["gguf_sha256"],
                         serving.gguf_from_manifest(MANIFEST).rsplit("sha256-", 1)[-1])

    def test_a_legacy_caller_with_no_session_still_works(self):
        """Every existing caller and test passes base_url only, and gets the
        Ollama path -- the pre-change behaviour, unchanged."""
        result = evaluate_models.evaluate_slot(
            "http://ollama", "revdeck", "test-model:latest",
            evaluate_models.qualification_request("revdeck", 8192),
        )
        self.assertIn("serving", result)
        self.assertEqual(result["serving"]["engine"], "ollama")


class TranscriptAttributionTest(unittest.TestCase):
    """Finding 6: a transcript record has to say which engine produced it."""

    def _writer(self, tmpdir):
        return transcripts.TranscriptWriter(
            Path(tmpdir), transcripts.RunMetadata(
                benchmark="bench", provenance=transcripts.PROVENANCE_SYNTHETIC))

    def _record(self, session, tmpdir):
        """One real record, written through evaluate_slot on a stub writer.

        The session is opened here through `start()`, not by evaluate_slot, so
        the readiness poll never runs for real against a port nothing is
        listening on -- the same 1800s no-failure wait every other test here
        avoids.
        """
        writer = self._writer(tmpdir)

        def request_json(url, body=None, timeout=None):
            if url.endswith("/api/tags"):
                return {"models": [{"name": "gemma2:27b", "digest": "d", "size": 15,
                                    "details": {"family": "gemma", "parameter_size": "27B",
                                                "quantization_level": "Q4_K_M"}}]}
            if url.endswith("/api/ps"):
                return {"models": []}
            if url.endswith("/api/show"):
                return {"capabilities": ["tools", "completion"]}
            return {"message": {"content": "{}"}, "eval_count": 10,
                    "eval_duration": 1_000_000_000, "done_reason": "stop"}

        session.request_json = request_json
        start(session)
        # The session's transport is the real llama.cpp client, which would post
        # to a port nothing is listening on. What is under test is what the
        # recorder is handed, not the socket, so the transport is stubbed after
        # the engine has been decided -- the engine facts have to survive that.
        session.transport = request_json
        evaluate_models.evaluate_slot(
            "http://127.0.0.1:11435", "revdeck", "gemma2:27b",
            evaluate_models.qualification_request("revdeck", 8192),
            writer, "A", session,
        )
        return json.loads(writer.path.read_text().splitlines()[0])

    def test_a_llama_cpp_record_carries_the_engine_on_the_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            record = self._record(make_session(FakeRemote()), tmpdir)
        self.assertEqual(record["reproducibility"]["engine"], "llama.cpp")
        self.assertIs(record["reproducibility"]["kv_offload_disabled"], False)
        self.assertIsNone(record["reproducibility"]["fallback_engine"])

    def test_the_measured_placement_reaches_the_written_record(self):
        """The six placement keys, carrying the server's own measurement.

        `Reproducibility` declared three engine fields and emitted exactly
        those, so a provenance dict that held the measurement perfectly still
        had it dropped on the way to the JSONL -- 28 records with a null
        `gpu_layers` beside an engine that had obviously offloaded.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            record = self._record(make_session(FakeRemote(log_text=FIT_LOG)), tmpdir)
        reproducibility = record["reproducibility"]
        for field in ("gpu_layers", "layers_total", "vram_mib", "kv_cache_mib",
                      "n_ctx", "ram_offloaded"):
            with self.subTest(field=field):
                self.assertIn(field, reproducibility)
        self.assertEqual(reproducibility["gpu_layers"], 41)
        self.assertEqual(reproducibility["layers_total"], 42)
        self.assertEqual(reproducibility["vram_mib"], 17880.66)
        self.assertEqual(reproducibility["kv_cache_mib"], 480.00)
        self.assertEqual(reproducibility["n_ctx"], 24576)
        self.assertIs(reproducibility["ram_offloaded"], True)

    def test_a_log_with_nothing_to_measure_records_null_not_a_guess(self):
        """A server that printed no placement line leaves every key null.

        Absence is the honest reading; a zero would say the card held nothing
        and fail a healthy model for the wrong reason.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            record = self._record(make_session(FakeRemote(log_text="main: model loaded\n")), tmpdir)
        for field in ("gpu_layers", "layers_total", "vram_mib", "kv_cache_mib",
                      "n_ctx", "ram_offloaded"):
            with self.subTest(field=field):
                self.assertIsNone(record["reproducibility"][field])

    def test_a_fallback_record_says_ollama_took_over(self):
        remote = FakeRemote(state="exited", log_text="unsupported model architecture")
        with tempfile.TemporaryDirectory() as tmpdir:
            record = self._record(make_session(remote), tmpdir)
        self.assertEqual(record["reproducibility"]["engine"], "ollama")
        self.assertEqual(record["reproducibility"]["fallback_engine"], "ollama")

    def test_the_record_keeps_the_achieved_rate_it_reads_off(self):
        """tok/s and VRAM have to reach the transcript, not only the report.

        A stored tokens/second with no engine beside it means two different
        things on the two engines -- RAM-offloaded decode runs at roughly a
        sixth of the on-card rate -- so the number is unreadable on its own.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            record = self._record(make_session(FakeRemote()), tmpdir)
        self.assertIsNotNone(record["timing"]["tokens_per_second"])
        self.assertIsNotNone(record["timing"]["output_tokens"])

    def test_a_record_written_without_a_session_is_still_honest(self):
        """Every legacy caller passes base_url only and gets the Ollama path.

        Absence of engine attribution is not the same as a wrong one, but an
        Ollama run really was served by Ollama, so it says so.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = self._writer(tmpdir)

            def request_json(url, body=None, timeout=None):
                if url.endswith("/api/tags"):
                    return {"models": [{"name": "gemma2:27b", "digest": "d", "size": 15,
                                        "details": {"family": "gemma",
                                                    "parameter_size": "27B",
                                                    "quantization_level": "Q4_K_M"}}]}
                if url.endswith("/api/show"):
                    return {"capabilities": ["tools", "completion"]}
                if url.endswith("/api/ps"):
                    return {"models": []}
                return {"message": {"content": "{}"}, "done_reason": "stop",
                        "eval_count": 10, "eval_duration": 1_000_000_000}

            # evaluate_slot opens a session of its own, and that session tries
            # llama.cpp first. The stub host cannot load anything, so this lands
            # on the Ollama fallback -- which is exactly the legacy behaviour
            # this test pins: no session passed, Ollama served, and the record
            # says so rather than staying silent.
            with mock.patch.object(evaluate_models, "request_json", request_json), \
                 mock.patch.object(serving, "Remote", return_value=FakeRemote(
                     state="exited", log_text="unsupported model architecture")):
                result = evaluate_models.evaluate_slot(
                    "http://ollama", "revdeck", "gemma2:27b",
                    evaluate_models.qualification_request("revdeck", 8192), writer)
            lines = list(Path(tmpdir).rglob("transcripts.jsonl"))
            self.assertEqual(len(lines), 1, "the run must have written a transcript")
            record = json.loads(lines[0].read_text().splitlines()[0])
        self.assertEqual(record["reproducibility"]["engine"], "ollama")
        self.assertEqual(record["reproducibility"]["fallback_engine"], "ollama")
        self.assertIsNotNone(record["timing"]["tokens_per_second"])


class EngineFlagTest(unittest.TestCase):
    """Finding 5: --engine ollama has to be honoured on the --manifest path."""

    def _args(self, engine):
        return argparse.Namespace(engine=engine)

    def test_pinning_ollama_starts_no_container(self):
        session = evaluate_models.open_session(
            self._args(evaluate_models.ENGINE_OLLAMA), "http://127.0.0.1:11435",
            "gemma2:27b", 24576,
        )
        self.assertEqual(session.engine, "ollama")
        self.assertIsNotNone(session.transport)
        self.assertIsNone(session.server)
        self.assertIsNone(session.fallback_engine)

    def test_the_default_engine_still_prefers_llama_cpp(self):
        remote = FakeRemote()
        with mock.patch.object(serving.LlamaCppServer, "healthy", return_value=True), \
             mock.patch.object(serving, "Remote", return_value=remote):
            session = evaluate_models.open_session(
                self._args(evaluate_models.ENGINE_LLAMACPP), "http://127.0.0.1:11435",
                "gemma2:27b", 24576,
            )
        self.assertEqual(session.engine, "llama.cpp")
        self.assertEqual(len(remote.launches), 1)

    def test_the_manifest_path_reads_the_flag_too(self):
        """The defect: --manifest built a session and called open() itself.

        The whole slot is evaluated on a stubbed transport, so the assertion
        that matters is simply that no container was ever launched for a run the
        operator pinned to Ollama.
        """
        launched = []

        def request_json(url, body=None, timeout=None):
            if url.endswith("/api/tags"):
                return {"models": [{"name": "gemma2:27b", "digest": "d", "size": 15,
                                    "details": {"family": "gemma", "parameter_size": "27B",
                                                "quantization_level": "Q4_K_M"}}]}
            if url.endswith("/api/ps"):
                return {"models": []}
            if url.endswith("/api/show"):
                return {"capabilities": ["tools", "completion"]}
            return {"message": {"content": "{}"}, "eval_count": 10,
                    "eval_duration": 1_000_000_000, "done_reason": "stop"}

        with tempfile.TemporaryDirectory() as tmpdir:
            context = 8192
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_path.write_text(json.dumps({"slots": {"revdeck": {
                "artifact": {"tag": "gemma2:27b"},
                "qualification_request": evaluate_models.qualification_request(
                    "revdeck", context),
            }}}))
            args = argparse.Namespace(
                manifest=str(manifest_path), slots=["revdeck"], tier="A",
                engine=evaluate_models.ENGINE_OLLAMA,
                output=str(Path(tmpdir) / "report.json"),
                context=context, models=[],
            )
            remote = FakeRemote()
            # healthy is stubbed as well as the host, so a regression that
            # ignores the flag fails on the assertion below instead of hanging
            # out a 1800s readiness poll against a tunnel nothing opened.
            with mock.patch.object(evaluate_models, "request_json", request_json), \
                 mock.patch.object(evaluate_models, "optional_version", lambda _u: "0.0"), \
                 mock.patch.object(serving, "Remote", return_value=remote), \
                 mock.patch.object(serving.LlamaCppServer, "healthy", return_value=True):
                evaluate_models.run(args, "http://127.0.0.1:11435", None)

            report = json.loads((Path(tmpdir) / "report.json").read_text())
        # No container, and the slot still ran: on Ollama, as pinned.
        self.assertEqual(remote.launches, [], "--engine ollama must not start a container")
        self.assertEqual(report["slots"]["revdeck"]["serving"]["engine"], "ollama")


# --- Bug 1: Ollama's own spelling wins --------------------------------------

# What /api/tags returns for the model in the smoke manifest
# (/tmp/smoke-manifest.json, slots.ghidra.artifact.tag). The tag is always
# spelled out by the server; the manifest carried the bare name.
QWEN3 = {"name": "qwen3-8-27b-q4km:latest", "digest": "bdbd181c",
         "size": 9276198565,
         "details": {"family": "qwen3", "parameter_size": "14.8B",
                     "quantization_level": "Q4_K_M"}}
# The same weights at a second quantisation, listed side by side. Real on this
# roster: the sweep scripts pull several quants of one model.
QWEN3_Q5 = {"name": "qwen3-8-27b-q4km:q5", "digest": "aaaa1111", "size": 1,
            "details": {"family": "qwen3", "parameter_size": "14.8B",
                        "quantization_level": "Q5_K_M"}}
OLLAMA_TAGS = [QWEN3]


class CanonicalNameTest(unittest.TestCase):
    """A name from the server beats a name from a manifest, when both exist.

    Bug 1's third requirement, and the one that removes the class rather than
    the instance: the mismatch is not that this manifest spelled a model without
    a tag, it is that two different strings can mean one model. Anything the
    server lists is authoritative.
    """

    def test_the_servers_spelling_replaces_a_bare_manifest_name(self):
        self.assertEqual(
            serving.canonical_tag(OLLAMA_TAGS, "qwen3-8-27b-q4km"),
            "qwen3-8-27b-q4km:latest",
        )

    def test_an_exact_match_is_never_moved_onto_another_model(self):
        """`:q5` is a different quantisation of the same weights.

        Resolving it to `:latest` would serve the wrong quantisation under the
        name that asked for this one, which is worse than the parse bug being
        fixed.
        """
        both = [QWEN3, QWEN3_Q5]
        self.assertEqual(
            serving.canonical_tag(both, "qwen3-8-27b-q4km:q5"),
            "qwen3-8-27b-q4km:q5",
        )
        self.assertEqual(
            serving.canonical_tag(both, "qwen3-8-27b-q4km:latest"),
            "qwen3-8-27b-q4km:latest",
        )

    def test_a_bare_name_matching_two_tags_is_left_ambiguous(self):
        """`:latest` and `:q5` are both candidates for a bare name.

        Picking one would load different weights than the roster meant and
        record it under the name asked for. A miss fails on the real tag; a
        guess does not fail at all, which is the worse outcome.
        """
        self.assertIsNone(serving.canonical_tag([QWEN3, QWEN3_Q5], "qwen3-8-27b-q4km"))

    def test_an_unlisted_name_is_left_exactly_as_the_caller_wrote_it(self):
        """This only ever improves a name; it never invents or rejects one."""
        self.assertIsNone(serving.canonical_tag(OLLAMA_TAGS, "not-installed:latest"))
        self.assertIsNone(serving.canonical_tag([], "qwen3-8-27b-q4km"))

    def test_a_tag_row_with_only_a_model_key_still_counts(self):
        """Ollama has used both keys across versions; both are read."""
        self.assertEqual(
            serving.canonical_tag([{"model": "x:1.5b"}], "x"),
            "x:1.5b",
        )

    def test_the_artifact_is_addressed_by_the_servers_spelling(self):
        """End to end: the stored tag is what Ollama would answer about.

        This is the string every later read uses -- /api/show, /api/ps, and the
        GGUF manifest path -- so a manifest that spells the model loosely still
        gets a run that addresses one model throughout.
        """
        artifact = evaluate_models._artifact_of(OLLAMA_TAGS[0], "qwen3-8-27b-q4km:latest")
        self.assertEqual(artifact["tag"], "qwen3-8-27b-q4km:latest")
        self.assertEqual(artifact["digest"], "bdbd181c")

    def test_the_session_resolves_the_gguf_of_the_name_the_server_reports(self):
        """The two halves together, which is what the smoke run needed.

        A manifest said `qwen3-8-27b-q4km`; the server says
        `qwen3-8-27b-q4km:latest`. The container must load the manifest *of the
        server's name*, or it loads nothing and the run falls back for a reason
        that names a parser rather than a server.
        """
        remote = FakeRemote()
        session = make_session(remote, model="qwen3-8-27b-q4km")
        session.model = serving.canonical_tag(OLLAMA_TAGS, session.model)
        start(session)
        self.assertEqual(
            remote.reads,
            ["/root/.ollama/models/manifests/registry.ollama.ai/library/"
             "qwen3-8-27b-q4km/latest"],
        )
        self.assertEqual(session.engine, "llama.cpp")

    def test_open_session_replaces_the_manifest_spelling_before_serving(self):
        """The one call site every engine goes through does the swap.

        Asserted on what the container was asked to load, not on the helper:
        a caller that forgot to call it would leave the parser reading the bare
        name, and the failure would only show up on a real host.
        """
        remote = FakeRemote()

        def request_json(url, body=None, timeout=None):
            return {"models": OLLAMA_TAGS} if url.endswith("/api/tags") else {}

        args = argparse.Namespace(engine=evaluate_models.ENGINE_LLAMACPP)
        with mock.patch.object(evaluate_models, "request_json", request_json), \
             mock.patch.object(serving, "Remote", return_value=remote), \
             mock.patch.object(serving.LlamaCppServer, "healthy", return_value=True):
            session = evaluate_models.open_session(
                args, "http://127.0.0.1:11435", "qwen3-8-27b-q4km", 24576)
        self.assertEqual(session.model, "qwen3-8-27b-q4km:latest")
        self.assertEqual(
            remote.reads,
            ["/root/.ollama/models/manifests/registry.ollama.ai/library/"
             "qwen3-8-27b-q4km/latest"],
        )


# --- Bug 2: two engines, two endpoints -------------------------------------

def _http_error(code):
    return urllib.error.HTTPError(
        "http://127.0.0.1:11434/api/tags", code, "Not Found", {}, None)


# The exact body this workstation's 11434 answers with. Recorded live in
# CLOSE_SUMMARY.md:35-37 and again as the smoke run's failure. An
# OpenAI-shaped server's wording, which is the diagnostic: a real Ollama has no
# "unknown endpoint", it has tags.
NOT_OLLAMA_BODY = json.dumps({
    "message": "Unknown endpoint: GET /api/tags",
    "type": "invalid_request_error",
    "code": "not_found",
}).encode()


class NotAnOllama:
    """The server on this box's 11434: OpenAI-shaped, 404s /api/tags."""

    def __call__(self, url, body=None, timeout=None):
        raise urllib.error.HTTPError(
            "http://127.0.0.1:11434/api/tags", 404, "Not Found",
            {"Content-Type": "application/json"}, io.BytesIO(NOT_OLLAMA_BODY))


class EndpointProbeTest(unittest.TestCase):
    """A 404 from /api/tags is a wrong endpoint, not a model that failed."""

    def test_a_404_on_api_tags_is_reported_as_the_wrong_endpoint(self):
        with self.assertRaises(serving.WrongEndpoint) as raised:
            serving.probe_ollama_endpoint("http://127.0.0.1:11434", NotAnOllama())
        message = str(raised.exception)
        self.assertIn("11434", message)
        self.assertIn("not Ollama", message)
        # Must not read like a model failure. This string is what a reader
        # debugs from, and the whole bug was that it named the model instead.
        self.assertNotIn("model tag is not installed", message)

    def test_a_200_that_is_not_a_tag_list_is_also_the_wrong_endpoint(self):
        """An OpenAI server behind a router may answer 200 with /v1/models."""
        def openai_shaped(url, body=None, timeout=None):
            return {"object": "list", "data": [{"id": "qwen3-8-27b-q4km"}]}

        with self.assertRaises(serving.WrongEndpoint):
            serving.probe_ollama_endpoint("http://127.0.0.1:11434", openai_shaped)

    def test_a_real_ollama_returns_its_tags(self):
        payload = serving.probe_ollama_endpoint(
            "http://127.0.0.1:11435", lambda *a, **k: {"models": OLLAMA_TAGS})
        self.assertEqual(payload["models"], OLLAMA_TAGS)

    def test_an_unreachable_server_is_not_mislabelled_as_the_wrong_endpoint(self):
        """A refused connection is a different problem from a wrong server.

        Collapsing the two would send a reader to fix a URL that is correct.
        """
        def refused(url, body=None, timeout=None):
            raise urllib.error.URLError("connection refused")

        with self.assertRaises(urllib.error.URLError):
            serving.probe_ollama_endpoint("http://127.0.0.1:11435", refused)

    def test_a_500_is_passed_through_rather_than_reclassified(self):
        """Only a 404 is evidence about the endpoint's *shape*."""
        def failing(url, body=None, timeout=None):
            raise _http_error(500)

        with self.assertRaises(urllib.error.HTTPError) as raised:
            serving.probe_ollama_endpoint("http://127.0.0.1:11435", failing)
        self.assertEqual(raised.exception.code, 500)

    def test_the_slot_reports_a_wrong_endpoint_instead_of_a_missing_model(self):
        """The reported symptom, before and after.

        `model_artifact` raises `model tag is not installed` when /api/tags is
        readable and simply does not list the model. When /api/tags 404s, the
        cause is the URL -- and that is now what the slot reports.
        """
        def request_json(url, body=None, timeout=None):
            if url.endswith("/api/tags"):
                raise urllib.error.HTTPError(
                    url, 404, "Not Found", {},
                    io.BytesIO(NOT_OLLAMA_BODY))
            return {"models": [], "message": {"content": "{}"},
                    "eval_count": 1, "eval_duration": 1_000_000_000,
                    "done_reason": "stop"}

        with mock.patch.object(evaluate_models, "request_json", request_json), \
             mock.patch.object(serving, "Remote", return_value=FakeRemote(
                 state="exited", log_text="unsupported model architecture")):
            result = evaluate_models.evaluate_slot(
                "http://127.0.0.1:11434", "revdeck", "qwen3-8-27b-q4km",
                evaluate_models.qualification_request("revdeck", 8192))
        self.assertFalse(result["ok"])
        self.assertIn("not Ollama", result["error"])
        self.assertNotIn("model tag is not installed", result["error"])


class BaseUrlDefaultTest(unittest.TestCase):
    """The default has to be where Ollama is, per the repo's own config."""

    def test_the_default_is_the_homeserver_forward_not_the_local_11434(self):
        """On this workstation 11434 is a llama.cpp-shaped server.

        `ssh -L 11435:127.0.0.1:11434 homeserver` is the forward every other
        invocation of this harness already uses
        (docs/analysis/ghidra/benchmarks/README.md:166, CLOSE2_SUMMARY.md:4,
        .issue-rosterslots.md:107). The old default pointed at the local
        11434, which is a different server entirely -- that is Bug 2.
        """
        self.assertEqual(evaluate_models.DEFAULT_OLLAMA_BASE_URL,
                         "http://127.0.0.1:11435")
        # The default argparse would actually use, read off the parser main()
        # builds, so a later re-inline of the literal cannot pass this.
        source = inspect.getsource(evaluate_models.main)
        self.assertIn("DEFAULT_OLLAMA_BASE_URL", source)
        self.assertNotIn('default="http://127.0.0.1:11434"', source)

    def test_the_default_port_is_a_forward_of_the_port_the_compose_publishes(self):
        """11435 is a forward to the compose file's 11434, not a second service.

        analysis/ghidra/docker-compose.ghidra.yml:81 publishes ollama on
        127.0.0.1:11434 on the analysis host; docs/gpu-llm-analysis-worker.md:549
        names the container `ghidra-ollama-1`. So the harness's 11435 and the
        compose's 11434 are the same server behind an `ssh -L`, which is what
        makes the default correct rather than a different port someone liked.

        Read from the compose file rather than restated, so an edit to the
        published port fails here instead of silently invalidating the comment
        above the constant.
        """
        compose = (BENCHMARKS_DIR.parent / "docker-compose.ghidra.yml").read_text()
        published = re.search(r"'127\.0\.0\.1:(\d+):11434'", compose).group(1)
        self.assertEqual(published, "11434")
        forward = evaluate_models.DEFAULT_OLLAMA_BASE_URL.rsplit(":", 1)[-1]
        self.assertEqual(int(forward), int(published) + 1)


class EndpointSeparationTest(unittest.TestCase):
    """The two engines' URLs are named separately in the record.

    They were one field, which is how an Ollama fallback ended up pointing at a
    server with no /api/* surface at all: the llama.cpp path has its own
    tunneled port, and the record could not say which of the two it had used.
    """

    def provenance(self, session):
        return session.provenance()

    def test_the_record_names_the_ollama_endpoint_and_the_llamacpp_one(self):
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        record = self.provenance(session)
        self.assertEqual(record["ollama_base_url"], "http://127.0.0.1:11435")
        self.assertTrue(record["llamacpp_endpoint"].endswith("/v1/chat/completions"))
        self.assertIn("11435", record["ollama_base_url"])

    def test_the_llamacpp_endpoint_is_the_tunnelled_port_not_the_ollama_one(self):
        """The two must not be the same URL. That identity is the bug."""
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        record = self.provenance(session)
        self.assertNotEqual(record["llamacpp_endpoint"].rsplit("/", 1)[0],
                            record["ollama_base_url"])

    def test_the_record_survives_teardown_with_both_endpoints(self):
        """read after close() -- the same snapshot rule as `engine`."""
        remote = FakeRemote()
        session = make_session(remote)
        start(session)
        session.close()
        record = session.provenance()
        self.assertEqual(record["engine"], "llama.cpp")
        self.assertTrue(record["llamacpp_endpoint"].endswith("/v1/chat/completions"))
        self.assertEqual(record["ollama_base_url"], "http://127.0.0.1:11435")

    def test_a_fallback_run_reports_the_ollama_endpoint_and_no_llamacpp_one(self):
        """The fallback path is the one that was wrong, so it is the one pinned.

        A run that fell back never published a llama.cpp endpoint, and saying
        otherwise would put an /api/* URL on the record as though it had served
        anything.
        """
        remote = FakeRemote(state="exited", log_text="unsupported model architecture")
        session = make_session(remote)
        start(session)
        record = session.provenance()
        self.assertEqual(record["engine"], "ollama")
        self.assertEqual(record["fallback_engine"], "ollama")
        self.assertEqual(record["ollama_base_url"], "http://127.0.0.1:11435")
        self.assertIsNone(record["llamacpp_endpoint"])

    def test_the_ollama_transport_still_posts_to_api_chat(self):
        """The shape difference itself, kept explicit in the code."""
        posted = []
        session = make_session(FakeRemote(), model="gemma2:27b")
        session.request_json = lambda url, body=None, timeout=None: posted.append(url)
        session.engine = "ollama"
        transport = serving.ollama_transport(session.base_url, session.request_json)
        transport(f"{session.base_url}/api/chat", {"model": "gemma2:27b"})
        self.assertEqual(posted, ["http://127.0.0.1:11435/api/chat"])


# --- the manifest path, end to end -----------------------------------------
#
# The smoke run produced 0 transcript records before failing in engine
# selection, so nothing after that point had ever been exercised against a real
# model. These drive the whole --manifest loop with a stub host and a stub
# writer: no GPU, no containers, no network, but every line that runs between
# "the session opened" and "the record was written".

class ManifestPathTest(unittest.TestCase):
    def manifest(self, tmpdir, tags, slots):
        path = Path(tmpdir) / "manifest.json"
        path.write_text(json.dumps({"slots": {
            name: {"artifact": {"tag": tag},
                   "qualification_request": evaluate_models.qualification_request(
                       name, 8192)}
            for name, tag in slots.items()
        }}))
        return path

    # The installed roster this stub server reports, for every model the
    # manifest path names below.
    TAGS = [
        {"name": f"{tag}", "digest": "bdbd181c", "size": 9276198565,
         "details": {"family": "qwen3", "parameter_size": "14.8B",
                     "quantization_level": "Q4_K_M"}}
        for tag in ("qwen3-8-27b-q4km:latest", "gemma2:27b", "gemma2:latest")
    ]

    def request_json(self, url, body=None, timeout=None):
        if url.endswith("/api/tags"):
            return {"models": self.TAGS}
        if url.endswith("/api/ps"):
            return {"models": []}
        if url.endswith("/api/show"):
            return {"capabilities": ["tools", "completion"]}
        if url.endswith("/api/version"):
            return {"version": "0.34.4"}
        return {"message": {"content": "{}"}, "eval_count": 10,
                "eval_duration": 1_000_000_000, "done_reason": "stop"}

    def args_for(self, manifest_path, tmpdir, slots, engine=None):
        return argparse.Namespace(
            manifest=str(manifest_path), slots=slots, tier="A",
            # The default engine, not `--engine ollama`: the case under test is
            # the *fallback* path, and a pinned Ollama run has no fallback by
            # definition (fallback_engine is legitimately None there).
            engine=engine or evaluate_models.ENGINE_LLAMACPP,
            output=str(Path(tmpdir) / "report.json"),
            context=8192, models=[],
        )

    def run_manifest(self, tmpdir, tags, slots):
        manifest_path = self.manifest(tmpdir, tags, slots)
        args = self.args_for(manifest_path, tmpdir, list(slots))
        # A stub host whose llama-server exits on load, so every slot exercises
        # the *fallback* path -- the one the smoke run never reached.
        remote = FakeRemote(state="exited", log_text="unsupported model architecture")
        with mock.patch.object(evaluate_models, "request_json", self.request_json), \
             mock.patch.object(serving, "Remote", return_value=remote), \
             mock.patch.object(serving.LlamaCppServer, "healthy", return_value=True):
            code = evaluate_models.run(args, "http://127.0.0.1:11435", None)
        report = json.loads((Path(tmpdir) / "report.json").read_text())
        return code, report

    def test_the_fallback_engine_reaches_a_written_record(self):
        """The smoke run wrote 0 records, so this had never been observed.

        Every field `Reproducibility` promises -- engine, KV offload, fallback
        engine -- plus the achieved rate, has to be on the stored line and not
        only in the report the run assembles afterwards. A transcript read on
        its own months later is the case that has to be attributable.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = transcripts.TranscriptWriter(
                Path(tmpdir) / "run", transcripts.RunMetadata(
                    benchmark="bench", provenance=transcripts.PROVENANCE_SYNTHETIC))
            manifest_path = self.manifest(tmpdir, OLLAMA_TAGS, {"revdeck": "gemma2:27b"})
            args = self.args_for(manifest_path, tmpdir, ["revdeck"])
            remote = FakeRemote(state="exited",
                                log_text="unsupported model architecture")
            with mock.patch.object(evaluate_models, "request_json", self.request_json), \
                 mock.patch.object(serving, "Remote", return_value=remote), \
                 mock.patch.object(serving.LlamaCppServer, "healthy", return_value=True):
                evaluate_models.run(args, "http://127.0.0.1:11435", writer)
            lines = list((Path(tmpdir) / "run").rglob("transcripts.jsonl"))
            self.assertEqual(len(lines), 1, "the manifest path must write records")
            record = json.loads(lines[0].read_text().splitlines()[0])

        reproducibility = record["reproducibility"]
        self.assertEqual(reproducibility["engine"], "ollama")
        self.assertEqual(reproducibility["fallback_engine"], "ollama")
        self.assertIs(reproducibility["kv_offload_disabled"], False)
        # The whole point of the block: a score read next to what produced it.
        self.assertEqual(reproducibility["tier"], "A")
        self.assertIsNotNone(reproducibility["prompt_contract"])
        self.assertIsNotNone(record["timing"]["tokens_per_second"])
        self.assertIsNotNone(record["timing"]["output_tokens"])

    def test_a_reproducibility_block_is_written_on_every_record(self):
        """Same key set on every line, so two records can be compared."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = transcripts.TranscriptWriter(
                Path(tmpdir) / "run", transcripts.RunMetadata(
                    benchmark="bench", provenance=transcripts.PROVENANCE_SYNTHETIC))
            manifest_path = self.manifest(tmpdir, OLLAMA_TAGS,
                                          {"revdeck": "gemma2:27b", "sessions": "gemma2:27b"})
            args = self.args_for(manifest_path, tmpdir, ["revdeck", "sessions"])
            remote = FakeRemote(state="exited",
                                log_text="unsupported model architecture")
            with mock.patch.object(evaluate_models, "request_json", self.request_json), \
                 mock.patch.object(serving, "Remote", return_value=remote), \
                 mock.patch.object(serving.LlamaCppServer, "healthy", return_value=True):
                evaluate_models.run(args, "http://127.0.0.1:11435", writer)
            lines = list((Path(tmpdir) / "run").rglob("transcripts.jsonl"))[0]
            records = [json.loads(line) for line in lines.read_text().splitlines()]

        self.assertGreater(len(records), 1)
        self.assertEqual({tuple(sorted(r["reproducibility"])) for r in records},
                         {tuple(sorted(records[0]["reproducibility"]))})

    def test_one_unresolvable_slot_does_not_cost_the_run_the_others(self):
        """Per-slot isolation, now that a session is opened on this path.

        A model name that names nothing raises out of `open_session()` instead
        of falling back. That raise has to be caught per slot: if it escaped
        the loop, one bad manifest entry would end the run before the second
        slot was ever evaluated, which is the isolation this loop has always
        provided on the positional-model path.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            code, report = self.run_manifest(
                tmpdir, OLLAMA_TAGS,
                {"sessions": "gemma2:27b", "revdeck": "  ", "ghidra": "gemma2:27b"})

        self.assertEqual(sorted(report["slots"]), ["ghidra", "revdeck", "sessions"])
        # The two sound slots ran to completion; the one naming nothing is the
        # only failure, and it did not cost the other two their results.
        self.assertTrue(report["slots"]["sessions"]["ok"], report["slots"]["sessions"])
        self.assertTrue(report["slots"]["ghidra"]["ok"], report["slots"]["ghidra"])
        self.assertEqual(report["slots"]["sessions"]["serving"]["engine"], "ollama")
        self.assertFalse(report["slots"]["revdeck"]["ok"])
        self.assertIn("not a model name", report["slots"]["revdeck"]["error"])
        self.assertNotIn("not a model name",
                         report["slots"]["sessions"].get("error", ""))
        # The run still exits non-zero: one failed slot is a failed run.
        self.assertEqual(code, 1)

    def test_a_failing_slot_still_reports_which_engine_failed(self):
        """The isolation path must not lose the engine attribution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _, report = self.run_manifest(
                tmpdir, OLLAMA_TAGS, {"revdeck": "  "})
        serving_facts = report["slots"]["revdeck"]["serving"]
        self.assertIn("engine", serving_facts)
        self.assertIn("flags", serving_facts)
        self.assertIsNone(serving_facts["engine"])


if __name__ == "__main__":
    unittest.main()
