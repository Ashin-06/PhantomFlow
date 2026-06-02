import joblib
import pandas as pd
import numpy as np

def main():
    imputer = joblib.load("models/imputer.pkl")
    scaler = joblib.load("models/scaler.pkl")
    lr = joblib.load("models/sgd_model.pkl")

    test_url = "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv"
    df_unsw = pd.read_csv(test_url)
    df_unsw["attack_cat"] = df_unsw["attack_cat"].str.strip()
    c2_cats = ["Backdoors", "Backdoor", "Worms"]
    df_unsw_c2 = df_unsw[df_unsw["attack_cat"].isin(c2_cats)].copy()

    X_unsw_c2 = pd.DataFrame()
    X_unsw_c2["duration_s"] = df_unsw_c2["dur"]
    X_unsw_c2["total_bytes"] = df_unsw_c2["sbytes"] + df_unsw_c2["dbytes"]
    X_unsw_c2["orig_bytes"] = df_unsw_c2["sbytes"]
    X_unsw_c2["orig_pkts"] = df_unsw_c2["spkts"] + df_unsw_c2["dpkts"]
    X_unsw_c2["resp_bytes"] = df_unsw_c2["dbytes"]
    X_unsw_c2["bytes_ratio"] = df_unsw_c2["sbytes"] / (df_unsw_c2["dbytes"] + 1.0)

    X_c2_scaled = scaler.transform(imputer.transform(X_unsw_c2.values))
    dec_c2 = lr.decision_function(X_c2_scaled)
    df_unsw_c2["dec_score"] = dec_c2

    # Find rows with dec_score close to -3.188702
    matching = df_unsw_c2[np.abs(df_unsw_c2["dec_score"] - (-3.188702)) < 1e-4]
    print(f"Number of rows matching -3.188702: {len(matching)}")
    print("\nFeature values for first few matching rows:")
    cols_to_show = ["dur", "sbytes", "dbytes", "spkts", "dpkts"]
    print(matching[cols_to_show].head(10))

if __name__ == "__main__":
    main()
