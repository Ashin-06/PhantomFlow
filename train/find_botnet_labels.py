# train/find_botnet_labels.py
import requests

url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow"
print(f"Scanning stream for botnet labels...")
headers = {"User-Agent": "PhantomFlow-Research/1.0 (academic use)"}
resp = requests.get(url, stream=True, headers=headers)

unique_labels = set()
botnet_count = 0
total_lines = 0

for line in resp.iter_lines():
    if not line:
        continue
    decoded = line.decode("utf-8", errors="ignore").strip()
    total_lines += 1
    
    parts = decoded.split(",")
    if len(parts) >= 15:
        label = parts[14]
        if "Botnet" in label or "botnet" in label:
            botnet_count += 1
            if botnet_count <= 5:
                print(f"Found botnet label at line {total_lines}: {label}")
        unique_labels.add(label)

    if total_lines >= 1500000:
        break

print(f"\nScan complete up to 1,500,000 lines.")
print(f"Total lines scanned: {total_lines}")
print(f"Total Botnet lines found: {botnet_count}")
print("All unique labels found:")
for lbl in sorted(unique_labels):
    if "Botnet" in lbl or "botnet" in lbl:
        print(f"  [BOTNET] {lbl}")
    else:
        print(f"  {lbl}")
