# train/test_url_status.py
import requests

urls = {
    "Scenario 1": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow",
    "Scenario 8": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816.binetflow.labeled",
    "Scenario 9": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow"
}

headers = {"User-Agent": "PhantomFlow-Research/1.0 (academic use)"}

for name, url in urls.items():
    print(f"\nChecking {name}...")
    try:
        resp = requests.get(url, stream=True, headers=headers, timeout=10)
        print(f"  Status Code: {resp.status_code}")
        if resp.status_code == 200:
            lines = []
            for line in resp.iter_lines():
                lines.append(line.decode('utf-8', errors='ignore'))
                if len(lines) >= 5:
                    break
            print("  First 5 lines:")
            for l in lines:
                print(f"    {l}")
    except Exception as e:
        print(f"  Error: {e}")
