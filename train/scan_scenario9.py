# train/scan_scenario9.py
import requests

url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow"
print(f"Scanning Scenario 9 for botnet lines...")
headers = {"User-Agent": "PhantomFlow-Research/1.0 (academic use)"}
resp = requests.get(url, stream=True, headers=headers)

botnet_lines = []
total_lines = 0

for line in resp.iter_lines():
    if not line:
        continue
    decoded = line.decode("utf-8", errors="ignore").strip()
    total_lines += 1
    
    if "Botnet" in decoded or "botnet" in decoded:
        botnet_lines.append((total_lines, decoded))
        if len(botnet_lines) <= 10:
            print(f"Found botnet line at {total_lines}: {decoded}")
            
    if total_lines >= 800000:
        break

print(f"\nScan complete up to 800,000 lines.")
print(f"Total lines scanned: {total_lines}")
print(f"Total botnet lines found: {len(botnet_lines)}")
