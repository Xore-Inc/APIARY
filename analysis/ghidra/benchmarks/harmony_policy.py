"""One route to `evaluate-models.py`'s harmony serving rules (#3172 follow-up).

`evaluate-models.py` owns the #2233 harmony serving adaptation: the family test,
the output-budget floor, and the refusals that stop a producer from sending a
budget it does not declare. Its filename has a hyphen, so nothing outside this
directory can `import` it -- which is how every producer that needs one of those
rules ended up either with its own `importlib` workaround (record_baseline.py,
probe-gpu-capabilities.py, probe-judge-repeat-stability.py) or, worse, with its
own private copy of the family markers.

This module holds no rule of its own. It resolves the one module that owns them
and forwards, so "is this model harmony-served" and "what happens if one is
pointed here" are answered by a single definition no producer can drift from.
Callers pass the model plus the budget their own request body carries, so the
refusal can name both numbers, and `producer` so the message says which script
refused rather than leaving it to be guessed from a traceback.

Reaching for the owner through one loader is the whole point of the module: the
propagation this closes had already failed twice, and each time the second half
was the same -- each producer deciding for itself what harmony-served means.
`evaluate-models.py`'s tag test and `record_baseline.py`'s architecture test do
not answer the same question, and the difference is exactly the kind of gap a
label without `gpt-oss` in it (CyberPal2.0-20B is GptOssForCausalLM) slips into.

Run: imported, never run. The rules themselves live in `evaluate-models.py`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_EVALUATE_MODELS_NAME = "evaluate_models"
_EVALUATE_MODELS_PATH = Path(__file__).resolve().parent / "evaluate-models.py"
_evaluate_models = None


def evaluate_models():
    """The module that owns the harmony rules, loaded by path at most once.

    Resolved on first use, not at import: `evaluate-models.py` verifies the
    contract-pinned coder corpus as it is executed, and a claim extraction or an
    engine sweep must not fail to start because an unrelated corpus fixture is
    mid-edit.
    """
    global _evaluate_models
    if _evaluate_models is None:
        _evaluate_models = sys.modules.get(_EVALUATE_MODELS_NAME)
        if _evaluate_models is None:
            spec = importlib.util.spec_from_file_location(
                _EVALUATE_MODELS_NAME, _EVALUATE_MODELS_PATH)
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            # Registered before exec: dataclass processing inside it looks its
            # own module up in sys.modules, which spec-created modules are not
            # in until inserted.
            sys.modules[_EVALUATE_MODELS_NAME] = module
            spec.loader.exec_module(module)
            _evaluate_models = module
    return _evaluate_models


def refuse_harmony_model_without_adaptation(
        model: str, *, producer: str, num_predict: int) -> None:
    """Refuse `model` if it is harmony-served and `producer` cannot serve it.

    A gate, not a value: it returns None for a model this producer can measure
    and raises SystemExit naming the producer, the budget that producer sends
    and the floor it falls short of, for anything it cannot.
    """
    evaluate_models().require_no_harmony_serving(
        model, producer=producer, num_predict=num_predict)