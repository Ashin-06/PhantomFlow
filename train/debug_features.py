import joblib
import pandas as pd
import numpy as np

def main():
    imputer = joblib.load("models/imputer.pkl")
    scaler = joblib.load("models/scaler.pkl")
    lr = joblib.load("models/sgd_model.pkl")

    # Load UNSW test set
    test_url = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv"
    df_unsw = pd.read_csv(test_url)
    df_unsw["attack_cat"] = df_unsw["attack_cat"].str.strip()
    c2_cats = ["Backdoors", "Backdoor", "Worms"]
    df_unsw_c2 = df_unsw[df_unsw["attack_cat"].isin(c2_cats)].copy()
    df_unsw_benign = df_unsw[df_unsw["attack_cat"] == "Normal"].copy()

    X_unsw_c2 = pd.DataFrame()
    X_unsw_c2["duration_s"] = df_unsw_c2["dur"]
    X_unsw_c2["total_bytes"] = df_unsw_c2["sbytes"] + df_unsw_c2["dbytes"]
    X_unsw_c2["orig_bytes"] = df_unsw_c2["sbytes"]
    X_unsw_c2["orig_pkts"] = df_unsw_c2["spkts"] + df_unsw_c2["dpkts"]
    X_unsw_c2["resp_bytes"] = df_unsw_c2["dbytes"]
    X_unsw_c2["bytes_ratio"] = df_unsw_c2["sbytes"] / (df_unsw_c2["dbytes"] + 1.0)

    X_unsw_benign = pd.DataFrame()
    X_unsw_benign["duration_s"] = df_unsw_benign["dur"]
    X_unsw_benign["total_bytes"] = df_unsw_benign["sbytes"] + df_unsw_benign["dbytes"]
    X_unsw_benign["orig_bytes"] = df_unsw_benign["sbytes"]
    X_unsw_benign["orig_pkts"] = df_unsw_benign["spkts"] + df_unsw_benign["dpkts"]
    X_unsw_benign["resp_bytes"] = df_unsw_benign["dbytes"]
    X_unsw_benign["bytes_ratio"] = df_unsw_benign["sbytes"] / (df_unsw_benign["dbytes"] + 1.0)

    print("UNSW C2 Features Mean:")
    print(X_unsw_c2.mean())
    print("\nUNSW Benign Features Mean:")
    print(X_unsw_benign.mean())

    X_c2_scaled = scaler.transform(imputer.transform(np.where(np.isinf(X_unsw_c2.values), np.nan, X_unsw_c2.values)))
    dec_c2 = lr.decision_function(X_c2_scaled)
    print("\nUNSW C2 Decision Scores:")
    print(pd.Series(dec_c2).describe())

    print("\nModel Coefficients:")
    for col, coef in zip(X_unsw_c2.columns, lr.coef_[0]):
        print(f"  {col}: {coef:.4f}")
    print(f"  Intercept: {lr.intercept_[0]:.4f}")

if __name__ == "__main__":
    main()
