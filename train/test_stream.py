# train/test_stream.py
import requests
import pandas as pd

def test_ctu13():
    url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow"
    print(f"Connecting to CTU-13 Scenario 1: {url}...")
    try:
        resp = requests.get(url, stream=True, timeout=10)
        print(f"Status Code: {resp.status_code}")
        if resp.status_code == 200:
            lines = []
            for i, line in enumerate(resp.iter_lines()):
                if i > 10:
                    break
                lines.append(line.decode('utf-8'))
            print("First 10 lines from CTU-13 binetflow:")
            print("\n".join(lines))
    except Exception as e:
        print(f"CTU-13 Connection failed: {e}")

def test_cicids():
    url = "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    print(f"Connecting to CICIDS 2017 Friday: {url}...")
    try:
        resp = requests.get(url, stream=True, timeout=10)
        print(f"Status Code: {resp.status_code}")
        if resp.status_code == 200:
            lines = []
            for i, line in enumerate(resp.iter_lines()):
                if i > 5:
                    break
                lines.append(line.decode('utf-8'))
            print("First 5 lines from CICIDS2017:")
            print("\n".join(lines))
    except Exception as e:
        print(f"CICIDS Connection failed: {e}")

if __name__ == "__main__":
    test_ctu13()
    test_cicids()
