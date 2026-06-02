# train/test_scenario8.py
import requests

url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816.binetflow.labeled"
print(f"Connecting to Scenario 8: {url}...")
headers = {"User-Agent": "PhantomFlow-Research/1.0 (academic use)"}
resp = requests.get(url, stream=True, headers=headers, timeout=10)

unique_labels = {}
total_lines = 0

for line in resp.iter_lines():
    if not line:
        continue
    decoded = line.decode("utf-8", errors="ignore").strip()
    total_lines += 1
    
    parts = decoded.split(",")
    if len(parts) >= 15:
        label = parts[14]
        unique_labels[label] = unique_labels.get(label, 0) + 1

    if total_lines >= 50000:
        break

print(f"Scanned {total_lines} lines of Scenario 8:")
for lbl, count in sorted(unique_labels.items(), key=lambda x: x[1], reverse=True):
    print(f"  {lbl}: {count}")
