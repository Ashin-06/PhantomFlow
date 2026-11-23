"""One-command evaluation on CICIDS2017 and CTU-13.

    python -m evaluation.download     # once
    python -m evaluation.run          # writes eval/results.json and eval/results.md

Protocol (pinned in evaluation/config.toml):
  * CICIDS2017: chronological 60/20/20 split inside each class.
  * CTU-13: split by scenario (capture); no scenario appears in two splits.
  * Cross-dataset: train on one dataset, test on the other's test captures.
  * Thresholds: max-F1 on the validation split of the training dataset.
    Test labels are never used for any choice.
"""
import json
import tomllib
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

from evaluation import features as F
from evaluation.metrics import best_f1_threshold, binary_report, multiclass_report

CONFIG = Path(__file__).with_name("config.toml")
OUT = Path("eval")


def load(cfg: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    d = Path(cfg["data_dir"])
    cic = F.cicids_frame(pd.read_parquet(d / "cicids2017.parquet"))
    cic["split"] = F.time_split(cic, tuple(cfg["split"]["cicids_fracs"]))
    ctu = F.ctu13_frame(pd.read_parquet(d / "ctu13.parquet"))
    s = cfg["split"]
    ctu["split"] = np.select([ctu["scenario"].isin(s["ctu13_train"]), ctu["scenario"].isin(s["ctu13_val"]),
                              ctu["scenario"].isin(s["ctu13_test"])], ["train", "val", "test"], "unused")
    return cic, ctu


def fit(X, y, cfg: dict, n_class: int = 2):
    model = xgb.XGBClassifier(**cfg["model"], random_state=cfg["seed"])
    model.fit(X, y)
    return model


def binary_experiment(train: pd.DataFrame, tests: dict, feats: list, cfg: dict) -> dict:
    """Train botnet-vs-benign on train[split==train], threshold on train[split==val]."""
    tr, va = train[train["split"] == "train"], train[train["split"] == "val"]
    model = fit(tr[feats], tr["label"].eq("botnet"), cfg)
    thr = best_f1_threshold(va["label"].eq("botnet"), model.predict_proba(va[feats])[:, 1])
    return {name: binary_report(df["label"].eq("botnet"), model.predict_proba(df[feats])[:, 1], thr)
            for name, df in tests.items()}


def cicids_multiclass(cic: pd.DataFrame, feats: list, cfg: dict) -> dict:
    classes = sorted(cic["label"].unique())
    idx = {c: i for i, c in enumerate(classes)}
    tr, va, te = (cic[cic["split"] == s] for s in ("train", "val", "test"))
    model = fit(tr[feats], tr["label"].map(idx), cfg, len(classes))
    b = idx["benign"]
    thr = best_f1_threshold(va["label"].ne("benign"), 1 - model.predict_proba(va[feats])[:, b])
    p = model.predict_proba(te[feats])
    return {"per_class": multiclass_report(te["label"], p, classes),
            "attack_vs_benign": binary_report(te["label"].ne("benign"), 1 - p[:, b], thr)}


def run_variant(cic: pd.DataFrame, ctu: pd.DataFrame, cfg: dict) -> dict:
    feats = list(F.FEATURES)
    cic_bot = cic[cic["label"].isin(["benign", "botnet"])]
    ctu_tests = {f"ctu13-s{s}": ctu[ctu["scenario"] == s] for s in cfg["split"]["ctu13_test"]}
    cic_test = {"cicids2017-test": cic_bot[cic_bot["split"] == "test"]}
    return {
        "cicids2017_multiclass_time_split": cicids_multiclass(cic, feats, cfg),
        "cicids2017_botnet_time_split": binary_experiment(cic_bot, cic_test, feats, cfg),
        "ctu13_botnet_scenario_split": binary_experiment(ctu, ctu_tests, feats, cfg),
        "cross_cicids2017_to_ctu13": binary_experiment(cic_bot, ctu_tests, feats, cfg),
        "cross_ctu13_to_cicids2017": binary_experiment(ctu, cic_test, feats, cfg),
    }


def fmt(v) -> str:
    return "n/a" if v is None else f"{v:.3f}"


def to_markdown(results: dict) -> str:
    head = ("| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |\n"
            "|---|---|---|---|---|---|---|---|---|---|\n")
    row = lambda k, r: (f"| {k} | {r['n']} | {r['n_pos']} | {r['prevalence']:.4f} | {fmt(r['precision'])} | "
                        f"{fmt(r['recall'])} | {fmt(r['f1'])} | {fmt(r['fpr'])} | {fmt(r['pr_auc'])} | "
                        f"{fmt(r['roc_auc'])} |\n")
    md = []
    for variant, exps in results.items():
        md.append(f"## Variant: {variant}\n")
        for exp, res in exps.items():
            md.append(f"### {exp}\n\n" + head)
            if "per_class" in res:
                md += [row(c, r) for c, r in res["per_class"].items()]
                md.append(row("all attacks vs benign (val threshold)", res["attack_vs_benign"]))
            else:
                md += [row(k, r) for k, r in res.items()]
            md.append("\n")
    return "".join(md)


def main() -> None:
    cfg = tomllib.loads(CONFIG.read_text())
    cic, ctu = load(cfg)
    results = {v["name"]: run_variant(cic, ctu, cfg) for v in cfg["variants"]}
    OUT.mkdir(exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    (OUT / "results.md").write_text(to_markdown(results))
    print(to_markdown(results))


if __name__ == "__main__":
    main()
