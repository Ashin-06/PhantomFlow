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

