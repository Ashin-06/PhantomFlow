# train/diag_stage2.py
import time
import numpy as np
import pandas as pd
from scipy import signal
from lab.stream_reader import DatasetStreamer
from lab.feature_adapter import UniversalAdapter

def extract_stage2_features(history: list) -> list:
    intervals = [
        history[i]["ts"] - history[i-1]["ts"]
        for i in range(1, len(history))
    ]
    durations = [f.get("duration_s", 0) for f in history]
    arr = np.array(intervals)

    iat_cv = np.std(arr) / (np.mean(arr) + 1e-9)
    trend  = float(np.corrcoef(range(len(arr)), arr)[0, 1]) if len(arr) > 2 else 0.0
    dur_cv = np.std(durations) / (np.mean(durations) + 1e-9)
    h_len  = float(len(history))
    reg    = float(max(0.0, 1.0 - min(1.0, iat_cv / 2.0)))

    p_score = 0.0
    dom_period = 0.0
    if len(arr) >= 6:
        normed = (arr - np.mean(arr)) / (np.std(arr) + 1e-9)
        acf = np.correlate(normed, normed, mode='full')
        acf = acf[len(acf)//2:]
        acf /= (acf[0] + 1e-9)
        peaks, _ = signal.find_peaks(acf[1:], height=0.2, prominence=0.1)
        if len(peaks) > 0:
            best_lag = peaks[np.argmax(acf[peaks + 1])] + 1
            p_score    = float(acf[best_lag])
            dom_period = float(np.mean(arr) * best_lag)

    return arr, [iat_cv, p_score, dom_period, trend, dur_cv, h_len, reg]

def main():
    streamer = DatasetStreamer()
    adapter = UniversalAdapter()
    
    histories_c2 = {}
    c2_samples = 0
    
    for chunk in streamer.stream("ctu13_scenario9", max_rows=100000):
        adapted = adapter.adapt(chunk, "ctu13_scenario9")
        if len(adapted) == 0:
            continue
            
        for idx, row in adapted.iterrows():
            flow = row.to_dict()
            orig_row = chunk.loc[idx]
            src = orig_row.get("SrcAddr", "unknown")
            ts_str = orig_row.get("StartTime", None)
            if not ts_str:
                continue
            ts = pd.to_datetime(ts_str).timestamp()
            label = int(flow.get("label", 0) == 1)
            
            if label == 1:
                if src not in histories_c2:
                    histories_c2[src] = []
                histories_c2[src].append({"ts": ts, "duration_s": flow.get("duration_s", 0)})
                if len(histories_c2[src]) > 50:
                    histories_c2[src].pop(0)
                    
                if len(histories_c2[src]) >= 7:
                    arr, feats = extract_stage2_features(histories_c2[src])
                    print(f"Host: {src} | C2 History Len: {len(histories_c2[src])}")
                    print(f"  Intervals (arr): {arr.tolist()}")
                    print(f"  Feats: iat_cv={feats[0]:.4f}, p_score={feats[1]:.4f}, dom_period={feats[2]:.4f}, reg={feats[6]:.4f}")
                    c2_samples += 1
                    if c2_samples >= 10:
                        return

if __name__ == "__main__":
    main()
