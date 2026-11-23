# Evaluation

Reproduce everything below with:

```sh
pip install -r requirements-eval.txt
python -m evaluation.download   # about 1.3 GB downloaded, 46 MB kept in data/
python -m evaluation.run        # about 2 minutes; writes eval/results.{json,md}
```

Everything is pinned in `evaluation/config.toml`: data sources with sha256,
splits, model hyperparameters (fixed, not tuned) and the seed.

## Data

| Dataset | Source | Used flows |
|---|---|---|
| CICIDS2017 | Corrected release by Engelen et al. (2021). It fixes CICFlowMeter bugs and relabels flows. | 2.02M. "Attempted" flows are dropped, as are classes too small to split (Infiltration: 36, Heartbleed: 11). |
| CTU-13 | All 13 binetflow files, via a Hugging Face mirror (the official host was unreachable). Per-scenario counts match the published CTU-13 table, e.g. s9: 184,987 botnet and 29,967 normal. | 683k normal + botnet. The 18.4M **Background** flows are excluded because they are unlabelled. |

Both datasets are reduced to the 7 flow features that both CICFlowMeter and
Argus export: duration, packets, bytes, source bytes, bytes per packet, source
byte fraction and destination port. Within-dataset and cross-dataset numbers
therefore use identical inputs. The TLS, DNS and timing features of the full
PhantomFlow pipeline **cannot be evaluated** on these datasets, because neither
dataset records them.

## Protocol

* **CICIDS2017, within dataset, by time.** Inside each class, the earliest 60% of
  flows go to train, the next 20% to validation and the last 20% to test. Each
  attack ran in a single window, so a global time cut would remove whole classes
  from training. With this split, test flows of a class are always later than its
  training flows.
* **CTU-13, by scenario (capture).** Train on scenarios 1, 3-7 and 10-12, validate
  on 2 and 13, and test on 9 (Neris, a family also present in training) and 8
  (Murlo, a family never seen in training). No capture appears in two splits.
* **Cross-dataset.** Train and validate on one dataset, then test on the other
  dataset's test captures.
* **Threshold.** Each threshold maximises F1 on the *validation split of the
  training dataset*, then is applied unchanged. In the cross-dataset rows, the
  target dataset's labels are never used.
* **Metrics.** Precision, recall, F1 and false-positive rate are computed at that
  threshold. PR-AUC (average precision) and ROC-AUC are threshold-free. PR-AUC
  must be compared with the prevalence column, which is the PR-AUC of a random
  scorer.

## Results

## Variant: baseline
### cicids2017_multiclass_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| benign | 417593 | 316514 | 0.7579 | 0.992 | 0.998 | 0.995 | 0.026 | 1.000 | 0.999 |
| botnet | 417593 | 148 | 0.0004 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |
| bruteforce | 417593 | 1387 | 0.0033 | 1.000 | 0.990 | 0.995 | 0.000 | 1.000 | 1.000 |
| ddos | 417593 | 19029 | 0.0456 | 1.000 | 0.999 | 0.999 | 0.000 | 1.000 | 1.000 |
| dos | 417593 | 34327 | 0.0822 | 0.999 | 0.926 | 0.961 | 0.000 | 0.990 | 0.999 |
| portscan | 417593 | 46167 | 0.1106 | 0.985 | 0.998 | 0.992 | 0.002 | 0.998 | 1.000 |
| webattack | 417593 | 21 | 0.0001 | 0.000 | 0.000 | 0.000 | 0.000 | 0.015 | 0.960 |
| all attacks vs benign (val threshold) | 417593 | 101079 | 0.2421 | 0.993 | 0.973 | 0.983 | 0.002 | 0.996 | 0.999 |

### cicids2017_botnet_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 0.961 | 0.993 | 0.977 | 0.000 | 0.999 | 1.000 |

### ctu13_botnet_scenario_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.222 | 0.999 | 0.363 | 0.295 | 0.453 | 0.929 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.954 | 0.962 | 0.958 | 0.290 | 0.991 | 0.950 |

### cross_cicids2017_to_ctu13

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.000 | 0.000 | 0.000 | 0.000 | 0.251 | 0.702 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.000 | 0.000 | 0.000 | 0.000 | 0.878 | 0.560 |

### cross_ctu13_to_cicids2017

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 0.000 | 0.953 | 0.001 | 0.921 | 0.044 | 0.933 |

## What the numbers say

**Within CICIDS2017 the task is close to solved, but this says little about
detection.** Most classes score F1 >= 0.96. This dataset is known to contain
shortcuts. Destination port alone separates the botnet class at ROC-AUC 0.995
(`docs/AUDIT.md`, section 4), because the Ares C2 used a fixed port. Web attacks
(21 test flows) are never detected, though their PR-AUC is still above the
prevalence.

**Within CTU-13, the scenario split is much harder.**
* On scenario 9 (Neris, a family seen in training), F1 is 0.958. With
  Background removed, 86% of the remaining flows are botnet, though, so the
  29.0% FPR is the more telling number: nearly 1 in 3 normal flows raises an alarm.
* On scenario 8 (Murlo, a family not seen in training), recall stays high but
  precision falls to 0.22, at the same ~30% FPR.

**Across datasets, the model does not transfer.**
* CICIDS2017 to CTU-13: the threshold chosen on CICIDS validation never fires on
  CTU-13 (recall 0). Ranking quality is near chance on scenario 9 (ROC-AUC 0.560)
  and weak on scenario 8 (0.702).
* CTU-13 to CICIDS2017: the CTU threshold flags 92% of benign CICIDS flows. With
  0.05% prevalence, precision is 0.001.

The causes are the ones in `docs/AUDIT.md`:
1. The feature-to-label relation flips between captures (botnet flows are larger
   than benign in CICIDS2017 and smaller in CTU-13).
2. Absolute scales differ between tools: CICFlowMeter counts payload bytes,
   Argus counts bytes with headers.
3. The port shortcut does not carry over.

**Limits of this evaluation.**
* Only flow-level features shared by both datasets are evaluated.
* CTU-13 Background traffic is excluded, so real-world false-positive rates
  would be measured against a far larger and more varied benign population.
* The CICIDS2017 botnet test set has only 148 flows.
* Each threshold is the best-F1 point on validation; other operating points
  (for example a fixed FPR budget) would give different precision and recall.

The earlier figures in `eval/eval_*.json` and `eval/final_results.json` are
superseded and should not be cited (see `docs/AUDIT.md`).
