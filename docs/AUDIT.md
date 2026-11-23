# Pipeline audit (2026-11)

This audit responds to an external review of PhantomFlow's cross-dataset results.
It covers train/test leakage, label handling, dataset shift, class imbalance and
threshold calibration. Bugs that were fixed in code are marked **fixed**. The
evaluation of record is now `python -m evaluation.run` (see `docs/EVALUATION.md`).
The JSON files in `eval/` from before this audit (`eval_ctu13_scenario9.json`,
`eval_cicids2018_s3.json`, `final_results.json`) are kept for the record but
should not be cited.

## 1. Test-set tuning (leakage)

* **fixed**: `train/full_training_run.py` chose the stage-1 model by its recall on
  the first 30,000 rows of CTU-13 scenario 8. It then reported scenario 8 as the
  out-of-distribution test set in `eval/final_results.json`. That is model
  selection on the test set. Validation now uses a separate scenario, and an
  assertion stops the validation set from also being a test set.
* The selection rule was "recall >= 65% at a fixed score cut-off", with no precision
  floor. The result reported 100% recall and 0.23% precision on scenario 8: about
  435 false alarms per true detection. Botnet flows were under 1% of that sample,
  so the detector was close to alarming on everything. The same "100% recall" on
  UNSW-NB15 comes with 31.9% precision.

## 2. Label handling

* **fixed**: CTU-13 label maps matched `flow=Normal`. The real labels are
  `flow=From-Normal-...` and `flow=To-Normal-...`, and only 1 of 72,822 normal
  flows in scenario 8 starts with `flow=Normal`. The verified-normal flows were
  silently dropped, and the **Background** flows (unlabelled, not verified
  benign) were counted as benign. The maps now match substrings and drop
  Background.
* **fixed**: the registry entry `ctu13_scenario13` pointed at Botnet-52
  (`capture20110818-2`), which is scenario 11 (Rbot). Comments that named the
  botnet families were also wrong.
* No label inversion: botnet maps to class 1 (`c2_beacon`) in both training and
  evaluation.

## 3. Metrics that could not fail

* **fixed**: `eval_cicids2018_s3.json` reports macro F1 = 1.000 and
  `auc_benign = NaN`. A NaN AUC means the 109,051 evaluated rows held only one
  class, so "predict benign everywhere" scores a macro F1 of 1.0. The evaluator now
  refuses single-class samples.
* The "stage 3 adversarial" test adds Gaussian noise. It is a noise-robustness
  check, not an adversarial evaluation, and it is now labelled that way.

## 4. Why the CTU-13 scenario 9 AUC was below 0.5

Run `python -m evaluation.legacy_repro`. It loads the shipped
`models/xgb_model.json` with `imputer_47.pkl` and `scaler_47.pkl`, and uses the
old adapter and the old label semantics:

| Quantity | Value |
|---|---|
| Scenario 9 flows (background / normal / botnet) | 1,872,554 / 29,967 / 184,987 |
| First 100,000 flows in time order | 99,348 background, 652 normal, **0 botnet** |
| Of the 47 model inputs, how many CTU-13 provides | **6** (41 are imputed constants) |
| Share of flows predicted benign | **100%** (all 2,087,508) |
| AUC, botnet vs background + normal | 0.406 |
| AUC, botnet vs normal only | 0.469 |

The legacy JSON could not be reproduced exactly: in time order, the first 100k
flows of scenario 9 contain no botnet flows. The diagnosis holds on the full
scenario, though:

* **Macro F1 of about 0.50** is what predicting "benign" for every flow gives on
  two classes (benign F1 near 1, botnet F1 = 0).
* **AUC below 0.5 is real shift, not an inversion.** The model learned from
  CICIDS-style flows where attack traffic is larger. Single-feature AUCs (botnet
  vs benign; > 0.5 means botnet values are larger) show the relation flips between
  captures:

| Capture | duration | packets | bytes | src bytes | dst port |
|---|---|---|---|---|---|
| CICIDS2017 (Ares botnet) | 0.537 | 0.695 | 0.556 | 0.715 | **0.995** |
| CTU-13 s1 (Neris) | 0.688 | 0.423 | 0.209 | 0.355 | 0.329 |
| CTU-13 s9 (Neris) | 0.551 | 0.371 | 0.347 | 0.333 | 0.346 |
| CTU-13 s8 (Murlo) | 0.215 | 0.188 | 0.180 | 0.187 | 0.882 |
| CTU-13 s10 (Rbot) | 0.120 | 0.088 | 0.808 | 0.878 | 0.025 |

A model that ranks "more bytes means more suspicious" will rank CTU-13 Neris
flows below chance. `dst_port` alone separates the CICIDS2017 botnet at AUC 0.995,
because its C2 used a fixed port. That is a capture-specific shortcut, not
behaviour.

## 5. Feature semantics

* **fixed**: `orig_pkts` was fwd + bwd packets for CICIDS and UNSW (a total), and
  TotPkts for CTU-13. It is now the originator's packets, or NaN where the dataset
  has no such field.
* **fixed**: `failed_connection_ratio` was the RST flag count for CICIDS and a
  handshake time (`synack`) for UNSW. Both are removed.
* Remaining, documented: CICFlowMeter byte counts are payload bytes and Argus byte
  counts include headers. Most of the 47 features (TLS, DNS, periodicity) do not
  exist in any public flow dataset used here, so they are imputed constants
  during training and evaluation.

## 6. Preprocessing and imbalance

* **fixed**: when an attack class had no samples yet, the online trainer added up
  to 20,000 all-zero rows labelled as that attack class. This taught XGBoost that
  an all-zero (fully imputed) flow is an attack. One zero-weight placeholder row
  now keeps the class index without adding signal.
* **fixed**: the final XGBoost model was refit **without class balancing** on the
  last buffer only, so the saved model mostly reflected the final dataset in the
  stream. It now uses the same balanced fit as the periodic retrains.
* Not fixed (legacy trainer): the imputer and scaler are fitted on the first
  chunk of the stream (CICIDS Monday, all benign) plus 10 zero rows.
  Periodic XGBoost retrains see only the recent buffer plus replayed attacks.
* Not fixed (legacy scripts, documented): `train/train_all.py` and
  `train/train_lstm.py` split randomly by flow, so the same hosts and sessions
  appear in train and test. `train/full_training_run.py` (exfil and DNS stages)
  fits the scaler before `train_test_split`. `run_online.py`'s "honest group
  evaluation" splits by a hash of the flow ID, not by host or time. None of these
  are used for the numbers in `docs/EVALUATION.md`.

## 7. Threshold calibration

Legacy thresholds (z = -3 / -5 / -7, and 0.5 on probabilities) were fixed or
chosen on test data. The new harness picks each threshold on a validation split
from the training distribution and applies it unchanged to the test sets. That
shows how badly a threshold transfers across datasets (`docs/EVALUATION.md`).
