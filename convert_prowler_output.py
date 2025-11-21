# convert_prowler_output.py
# This script converts the newline-delimited prowler output into a single JSON array.

from pathlib import Path
import json

# Find the newest prowler output file in the "output" folder
outdir = Path("output")
latest_files = sorted(outdir.glob("prowler-output-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
if not latest_files:
    print("No prowler JSON files found in ./output/")
    exit(1)

latest = latest_files[0]
print(f"[*] Found prowler output: {latest.name}")

# Convert JSON-Lines to JSON array
items = []
with latest.open(encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            pass

# Write normalized JSON to reports/aws_scan.json
reports_dir = Path("reports")
reports_dir.mkdir(exist_ok=True)
output_file = reports_dir / "aws_scan.json"
output_file.write_text(json.dumps(items, indent=2))

print(f"[+] Converted {len(items)} findings → {output_file}")
