# train/anti_overfit_config.py
"""
Every hyperparameter here has a specific overfitting-prevention reason.
"""

LSTM_CONFIG = {
    "hidden_size": 128,
    "num_layers": 2,
    "dropout": 0.4,          # Higher dropout = stronger regularization
    "weight_decay": 1e-4,    # L2 regularization on all weights

    # Early stopping — CRITICAL
    "patience": 7,           # Stop if val F1 doesn't improve for 7 epochs
    "min_delta": 0.001,      # Minimum improvement to count

    # Gradient clipping — prevents exploding gradients on long sequences
    "grad_clip": 1.0,

    # Label smoothing — prevents overconfident predictions
    # Instead of [0, 1] targets, uses [0.05, 0.95]
    # Forces model to hedge — better calibration
    "label_smoothing": 0.1,

    # Data augmentation for sequences
    # Randomly add Gaussian noise to IAT values during training
    # Forces model to learn pattern, not exact values
    "iat_noise_std": 0.05,   # 5% noise on IAT features
}

XGBOOST_DNS_CONFIG = {
    "n_estimators": 500,
    "max_depth": 6,           # Shallow trees = less overfit than deep trees
    "learning_rate": 0.03,    # Slow learning = better generalization
    "subsample": 0.7,         # Use 70% of data per tree (row subsampling)
    "colsample_bytree": 0.7,  # Use 70% of features per tree (feature subsampling)
    "colsample_bylevel": 0.7,
    "reg_alpha": 0.1,         # L1 regularization
    "reg_lambda": 1.0,        # L2 regularization
    "min_child_weight": 5,    # Minimum samples in leaf — prevents tiny splits
    "gamma": 0.1,             # Minimum gain to make a split
    "early_stopping_rounds": 50,
    "eval_metric": ["auc", "aucpr"],  # PR-AUC more meaningful for imbalanced
}

# Cross-validation strategy
CV_CONFIG = {
    "strategy": "TimeSeriesCV",  # NOT StratifiedKFold — temporal data needs time-based CV
    # TimeSeriesCV: fold 1 trains on month 1, tests on month 2
    #               fold 2 trains on months 1-2, tests on month 3
    # This simulates real deployment where you train on past, predict future
    "n_splits": 5,
    "gap": 0,                # No gap between train and test in each fold
}
