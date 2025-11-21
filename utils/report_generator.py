import json
from pathlib import Path

AWS_IN = Path("reports/aws_scan.json")
LYNIS_IN = Path("reports/lynis-report.dat")
OUT = Path("reports/combined_summary.json")

def generate_summary():
    summary = {"aws_findings_count": None, "lynis_lines": 0}
    if AWS_IN.exists():
        try:
            data = json.loads(AWS_IN.read_text())
            summary["aws_findings_count"] = len(data) if isinstance(data, list) else 0
        except Exception as e:
            summary["aws_findings_count"] = f"error_parsing:{e}"
    if LYNIS_IN.exists():
        summary["lynis_lines"] = sum(1 for _ in LYNIS_IN.open())
    OUT.write_text(json.dumps(summary, indent=2))
    print("[+] Combined summary saved to", OUT)
