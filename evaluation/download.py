"""Fetch CICIDS2017 (corrected) and CTU-13, verify sha256, convert to compact parquet.

    python -m evaluation.download

Writes data/cicids2017.parquet, data/ctu13.parquet and a 2% Background sample
(data/ctu13_background_sample.parquet), then deletes the raw
downloads afterwards (about 1.3 GB transient, about 52 MB kept).
"""
import hashlib
import io
import sys
import tomllib
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd

CONFIG = Path(__file__).with_name("config.toml")

# CTU-13 scenario number for each binetflow file (Garcia et al., 2014).
CTU13_SCENARIOS = {
    "capture20110810.binetflow": 1, "capture20110811.binetflow": 2,
    "capture20110812.binetflow": 3, "capture20110815.binetflow": 4,
    "capture20110815-2.binetflow": 5, "capture20110816.binetflow": 6,
    "capture20110816-2.binetflow": 7, "capture20110816-3.binetflow": 8,
    "capture20110817.binetflow": 9, "capture20110818.binetflow": 10,
    "capture20110818-2.binetflow": 11, "capture20110819.binetflow": 12,
    "capture20110815-3.binetflow": 13,
}

CICIDS_COLS = {
    "Timestamp": "ts", "Src IP": "src_ip", "Dst IP": "dst_ip", "Dst Port": "dst_port",
    "Protocol": "proto", "Flow Duration": "duration_us",
    "Total Fwd Packet": "fwd_pkts", "Total Bwd packets": "bwd_pkts",
    "Total Length of Fwd Packet": "fwd_bytes", "Total Length of Bwd Packet": "bwd_bytes",
    "Label": "label_raw",
}


def fetch(url: str, dest: Path, sha256: str) -> Path:
    """Download url to dest unless already present, then check sha256."""
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"downloading {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(url, timeout=60) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        tmp.rename(dest)
    h = hashlib.sha256()
    with open(dest, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    if h.hexdigest() != sha256:
        sys.exit(f"sha256 mismatch for {dest}: got {h.hexdigest()}, expected {sha256}")
    return dest


def ctu13_class(label: pd.Series) -> pd.Series:
    """Map raw CTU-13 labels to background / normal / botnet.

    Background flows are unlabelled in CTU-13 (not verified benign), so they
    are kept apart rather than counted as benign.
    """
    out = pd.Series("background", index=label.index)
    out[label.str.contains("Normal", regex=False)] = "normal"
    out[label.str.contains("Botnet", regex=False)] = "botnet"
    return out


def build_ctu13(cfg: dict, data_dir: Path) -> None:
    parts, counts, bg = [], [], []
    for name, sha in cfg["files"]:
        path = fetch(cfg["base_url"] + name, data_dir / "raw" / "ctu13" / name, sha)
        df = pd.read_parquet(path, columns=["Duration", "DstPort", "TotPkts", "TotBytes",
                                            "SrcBytes", "Label", "source_file", "dataset",
                                            "__index_level_0__"])
        # The mirror also carries later Stratosphere "normal" captures; keep CTU-13 only.
        df = df[df["dataset"] == "merged_binetflow"].drop(columns=["dataset"])
        df["cls"] = ctu13_class(df["Label"])
        df["scenario"] = df["source_file"].map(CTU13_SCENARIOS)
        if df["scenario"].isna().any():
            sys.exit(f"unknown source_file values in {name}")
        counts.append(df.groupby(["scenario", "cls"]).size())
        parts.append(df[df["cls"] != "background"])
        # 2% of Background per shard: unlabelled reference traffic, used only
        # for per-capture normalisation statistics, never as a class.
        bg.append(df[df["cls"] == "background"].sample(frac=0.02, random_state=0))
    df = pd.concat(parts, ignore_index=True)
    df = df.rename(columns={"Duration": "duration_s", "DstPort": "dst_port", "TotPkts": "tot_pkts",
                            "TotBytes": "tot_bytes", "SrcBytes": "src_bytes", "Label": "label_raw",
                            "__index_level_0__": "order"})
    df["is_cc"] = df["label_raw"].str.contains("CC", regex=False) & (df["cls"] == "botnet")
    # Row order inside each original file is time order (binetflow is sorted by StartTime).
    df = df.sort_values(["scenario", "order"]).drop(columns=["source_file"]).reset_index(drop=True)
    df.to_parquet(data_dir / "ctu13.parquet", index=False)
    ref = pd.concat(bg).rename(columns={"Duration": "duration_s", "DstPort": "dst_port", "TotPkts": "tot_pkts",
                                        "TotBytes": "tot_bytes", "SrcBytes": "src_bytes"})
    ref[["scenario", "duration_s", "dst_port", "tot_pkts", "tot_bytes", "src_bytes"]].to_parquet(
        data_dir / "ctu13_background_sample.parquet", index=False)
    table = pd.concat(counts).groupby(level=[0, 1]).sum().unstack(fill_value=0)
    table.to_csv(data_dir / "ctu13_counts.csv")
    print(table)


def build_cicids(cfg: dict, data_dir: Path) -> None:
    path = fetch(cfg["url"], data_dir / "raw" / "CICIDS2017_improved.zip", cfg["sha256"])
    frames = []
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if not info.filename.lower().endswith(".csv"):
                continue
            print(f"reading {info.filename}")
            with z.open(info) as f:
                df = pd.read_csv(io.TextIOWrapper(f, encoding="utf-8", errors="replace"),
                                 usecols=list(CICIDS_COLS), low_memory=False)
            df = df.rename(columns=CICIDS_COLS)
            df["day"] = Path(info.filename).stem.lower()
            frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df.to_parquet(data_dir / "cicids2017.parquet", index=False)
    print(df["label_raw"].value_counts())


def main() -> None:
    cfg = tomllib.loads(CONFIG.read_text())
    data_dir = Path(cfg["data_dir"])
    data_dir.mkdir(exist_ok=True)
    targets = sys.argv[1:] or ["cicids2017", "ctu13"]
    if "ctu13" in targets:
        build_ctu13(cfg["sources"]["ctu13"], data_dir)
    if "cicids2017" in targets:
        build_cicids(cfg["sources"]["cicids2017"], data_dir)
    # ponytail: raw files are deleted to save disk; rerun re-downloads them.
    for p in sorted((data_dir / "raw").rglob("*"), reverse=True):
        p.rmdir() if p.is_dir() else p.unlink()


if __name__ == "__main__":
    main()
