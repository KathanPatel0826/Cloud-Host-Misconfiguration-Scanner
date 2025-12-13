import subprocess
from pathlib import Path
import json

# Where normalized results will be saved
OUT = Path("reports/aws_scan.json")
# Where prowler writes raw JSONL files
OUTPUT_DIR = Path("output")

def run_aws_scan():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("[*] Starting AWS scan (Prowler)...")

    # Update -f / -p if your region or profile differs
    cmd = [
        "prowler", "aws",
        "--output-formats", "json-asff",
        "--region", "us-east-2",
        "-p", "default",
        "-o", str(OUTPUT_DIR)
    ]

    print("[*] Running:", " ".join(cmd))
    rc = subprocess.run(cmd).returncode
    if rc != 0:
        raise RuntimeError(f"prowler exited with code {rc}")

    # Find newest prowler-output-*.json file
    candidates = sorted(
        OUTPUT_DIR.glob("prowler-output-*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    if not candidates:
        raise FileNotFoundError("No prowler JSON found in ./output")
    latest = candidates[0]

    # Convert JSONL -> JSON array and keep only objects
    items = []
    with latest.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):      # ✅ Only keep real JSON objects
                    items.append(obj)
            except json.JSONDecodeError:
                # Ignore malformed/empty lines
                pass

    # Write normalized JSON array to reports/aws_scan.json
    OUT.write_text(json.dumps(items, indent=2))
    print(f"[+] AWS scan saved to {OUT} ({len(items)} findings) [from {latest.name}]")
