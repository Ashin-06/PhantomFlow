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

## Variant: no_port
### cicids2017_multiclass_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| benign | 417593 | 316514 | 0.7579 | 0.992 | 0.998 | 0.995 | 0.027 | 0.999 | 0.997 |
| botnet | 417593 | 148 | 0.0004 | 1.000 | 0.986 | 0.993 | 0.000 | 1.000 | 1.000 |
| bruteforce | 417593 | 1387 | 0.0033 | 1.000 | 0.974 | 0.987 | 0.000 | 0.985 | 0.999 |
| ddos | 417593 | 19029 | 0.0456 | 1.000 | 0.999 | 0.999 | 0.000 | 0.999 | 1.000 |
| dos | 417593 | 34327 | 0.0822 | 0.999 | 0.927 | 0.962 | 0.000 | 0.983 | 0.997 |
| portscan | 417593 | 46167 | 0.1106 | 0.985 | 0.998 | 0.991 | 0.002 | 0.995 | 1.000 |
| webattack | 417593 | 21 | 0.0001 | 0.000 | 0.000 | 0.000 | 0.000 | 0.001 | 0.876 |
| all attacks vs benign (val threshold) | 417593 | 101079 | 0.2421 | 0.993 | 0.974 | 0.983 | 0.002 | 0.993 | 0.997 |

### cicids2017_botnet_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 1.000 | 0.986 | 0.993 | 0.000 | 1.000 | 1.000 |

### ctu13_botnet_scenario_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.237 | 0.987 | 0.383 | 0.267 | 0.841 | 0.972 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.958 | 0.946 | 0.952 | 0.256 | 0.990 | 0.945 |

### cross_cicids2017_to_ctu13

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.000 | 0.000 | 0.000 | 0.000 | 0.329 | 0.755 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.000 | 0.000 | 0.000 | 0.000 | 0.918 | 0.671 |

### cross_ctu13_to_cicids2017

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 0.001 | 0.959 | 0.001 | 0.885 | 0.002 | 0.823 |

## Variant: no_port+capture_norm
### cicids2017_multiclass_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| benign | 417593 | 316514 | 0.7579 | 0.992 | 0.961 | 0.976 | 0.025 | 0.998 | 0.995 |
| botnet | 417593 | 148 | 0.0004 | 0.948 | 0.980 | 0.963 | 0.000 | 0.994 | 1.000 |
| bruteforce | 417593 | 1387 | 0.0033 | 0.999 | 0.976 | 0.988 | 0.000 | 0.982 | 0.999 |
| ddos | 417593 | 19029 | 0.0456 | 1.000 | 0.999 | 0.999 | 0.000 | 0.999 | 1.000 |
| dos | 417593 | 34327 | 0.0822 | 1.000 | 0.929 | 0.963 | 0.000 | 0.986 | 0.998 |
| portscan | 417593 | 46167 | 0.1106 | 0.790 | 0.999 | 0.882 | 0.033 | 0.993 | 0.999 |
| webattack | 417593 | 21 | 0.0001 | 0.000 | 0.000 | 0.000 | 0.000 | 0.040 | 0.919 |
| all attacks vs benign (val threshold) | 417593 | 101079 | 0.2421 | 0.983 | 0.947 | 0.965 | 0.005 | 0.987 | 0.995 |

### cicids2017_botnet_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 1.000 | 0.980 | 0.990 | 0.000 | 0.994 | 1.000 |

### ctu13_botnet_scenario_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.172 | 0.975 | 0.292 | 0.396 | 0.769 | 0.948 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.920 | 0.893 | 0.906 | 0.482 | 0.963 | 0.819 |

### cross_cicids2017_to_ctu13

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.000 | 0.000 | 0.000 | 0.000 | 0.150 | 0.565 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.000 | 0.000 | 0.000 | 0.000 | 0.886 | 0.615 |

### cross_ctu13_to_cicids2017

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 0.001 | 1.000 | 0.001 | 0.626 | 0.001 | 0.631 |

## Variant: no_port+capture_norm+class_weight
### cicids2017_multiclass_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| benign | 417593 | 316514 | 0.7579 | 0.992 | 0.959 | 0.975 | 0.025 | 0.998 | 0.995 |
| botnet | 417593 | 148 | 0.0004 | 0.382 | 1.000 | 0.553 | 0.001 | 0.999 | 1.000 |
| bruteforce | 417593 | 1387 | 0.0033 | 0.999 | 0.977 | 0.988 | 0.000 | 0.983 | 0.999 |
| ddos | 417593 | 19029 | 0.0456 | 1.000 | 0.999 | 0.999 | 0.000 | 1.000 | 1.000 |
| dos | 417593 | 34327 | 0.0822 | 1.000 | 0.931 | 0.964 | 0.000 | 0.988 | 0.998 |
| portscan | 417593 | 46167 | 0.1106 | 0.787 | 0.999 | 0.881 | 0.034 | 0.997 | 1.000 |
| webattack | 417593 | 21 | 0.0001 | 0.028 | 0.381 | 0.052 | 0.001 | 0.010 | 0.876 |
| all attacks vs benign (val threshold) | 417593 | 101079 | 0.2421 | 0.981 | 0.944 | 0.962 | 0.006 | 0.989 | 0.995 |

### cicids2017_botnet_time_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 0.170 | 1.000 | 0.291 | 0.002 | 0.996 | 1.000 |

### ctu13_botnet_scenario_split

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.139 | 0.979 | 0.243 | 0.510 | 0.802 | 0.962 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.916 | 0.934 | 0.925 | 0.527 | 0.962 | 0.826 |

### cross_cicids2017_to_ctu13

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| ctu13-s8 | 78949 | 6127 | 0.0776 | 0.000 | 0.000 | 0.000 | 0.000 | 0.246 | 0.684 |
| ctu13-s9 | 214954 | 184987 | 0.8606 | 0.000 | 0.000 | 0.000 | 0.000 | 0.907 | 0.633 |

### cross_ctu13_to_cicids2017

| Test set | n | Positives | Prevalence | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017-test | 316662 | 148 | 0.0005 | 0.001 | 1.000 | 0.001 | 0.739 | 0.001 | 0.642 |

