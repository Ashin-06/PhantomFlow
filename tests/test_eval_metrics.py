import pytest

# ML stack is optional for the API-only CI job; requirements-eval.txt installs it.
for _mod in ("numpy", "pandas", "sklearn", "scipy", "xgboost"):
    pytest.importorskip(_mod)

import numpy as np

from evaluation.metrics import best_f1_threshold, binary_report, multiclass_report


def test_binary_report_counts_and_rates():
    y = [1, 1, 0, 0, 0, 0]
    s = [0.9, 0.2, 0.8, 0.1, 0.1, 0.1]
    r = binary_report(y, s, 0.5)
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (1, 1, 1, 3)
    assert r["precision"] == 0.5 and r["recall"] == 0.5 and r["f1"] == 0.5
    assert r["fpr"] == 0.25
    assert r["prevalence"] == pytest.approx(1 / 3)
    assert 0 < r["pr_auc"] <= 1 and 0 <= r["roc_auc"] <= 1


def test_single_class_has_no_auc_and_no_fake_perfect_score():
    r = binary_report([0, 0, 0], [0.1, 0.2, 0.3], 0.5)
    assert r["pr_auc"] is None and r["roc_auc"] is None
    assert r["recall"] == 0.0 and r["f1"] == 0.0


def test_inverted_scores_give_auc_below_half():
    y = np.r_[np.ones(50), np.zeros(50)]
    assert binary_report(y, -y, 0.0)["roc_auc"] == 0.0


def test_best_f1_threshold_on_separable_scores():
    assert best_f1_threshold([0, 0, 1, 1], [0.1, 0.2, 0.7, 0.9]) == 0.7


def test_best_f1_threshold_is_max_over_candidates():
    rng = np.random.default_rng(0)
    y = rng.random(300) < 0.2
    s = np.round(y * 0.3 + rng.random(300), 2)   # rounding creates ties
    thr = best_f1_threshold(y, s)
    best = max(binary_report(y, s, t)["f1"] for t in np.unique(s))
    assert binary_report(y, s, thr)["f1"] == pytest.approx(best)


def test_multiclass_report_one_vs_rest():
    classes = ["a", "b", "c"]
    y = np.array(["a", "b", "c", "a"])
    proba = np.array([[0.8, 0.1, 0.1], [0.1, 0.8, 0.1], [0.6, 0.2, 0.2], [0.9, 0.05, 0.05]])
    r = multiclass_report(y, proba, classes)
    assert r["a"]["tp"] == 2 and r["a"]["fp"] == 1
    assert r["c"]["recall"] == 0.0 and r["c"]["n_pos"] == 1
