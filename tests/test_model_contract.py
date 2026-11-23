"""Input/output contract of the shipped models and of the evaluation model."""
import pytest

# ML stack is optional for the API-only CI job; requirements-eval.txt installs it.
for _mod in ("numpy", "pandas", "sklearn", "scipy", "xgboost"):
    pytest.importorskip(_mod)

from pathlib import Path

import numpy as np
import pandas as pd

import joblib
import xgboost as xgb
from lab.feature_adapter import PHANTOMFLOW_FEATURES

MODELS = Path(__file__).resolve().parent.parent / "models"


def test_shipped_xgb_takes_47_features_and_returns_4_class_probabilities():
    model = xgb.XGBClassifier()
    model.load_model(MODELS / "xgb_model.json")
    assert model.n_features_in_ == len(PHANTOMFLOW_FEATURES) == 47
    X = np.random.default_rng(0).normal(size=(5, 47)).astype(np.float32)
    p = model.predict_proba(X)
    assert p.shape == (5, 4)
    assert np.allclose(p.sum(axis=1), 1, atol=1e-5)


def test_shipped_preprocessors_map_47_to_47_and_fill_nans():
    imputer = joblib.load(MODELS / "imputer_47.pkl")
    scaler = joblib.load(MODELS / "scaler_47.pkl")
    out = scaler.transform(imputer.transform(np.full((3, 47), np.nan, dtype=np.float32)))
    assert out.shape == (3, 47) and np.isfinite(out).all()


def test_evaluation_model_contract():
    from evaluation.run import fit

    cfg = {"seed": 0, "model": {"n_estimators": 5, "max_depth": 2}, "class_weight": True}
    X = pd.DataFrame({"a": [0, 1, 0, 1, 0, 1], "b": [np.nan, 1, 2, 3, 4, 5]})
    y = pd.Series([False, True, False, True, False, False])
    p = fit(X, y, cfg).predict_proba(X)
    assert p.shape == (6, 2) and np.allclose(p.sum(axis=1), 1)
