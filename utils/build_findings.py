#!/usr/bin/env python3
"""
utils/build_findings.py

Build a single normalized findings list for the report/dashboard.

- Reads AWS findings from reports/aws_scan.json
- Reads Lynis results from reports/lynis-report.dat
- Writes reports/combined_findings.json
"""

import json
from pathlib import Path

AWS_IN = Path("reports/aws_scan.json")
LYNIS_IN = Path("reports/lynis-report.dat")
OUT = Path("reports/combined_findings.json")


def load_aws_findings():
    """Load normalized AWS findings (list of dicts) from aws_scan.json."""
    if not AWS_IN.exists():
        print("[!] No AWS findings file, skipping:", AWS_IN)
        return []

    try:
        data = json.loads(AWS_IN.read_text())
    except Exception as e:
        print(f"[!] Failed to parse {AWS_IN}: {e}")
        return []

    if not isinstance(data, list):
        print("[!] aws_scan.json top-level is not a list, skipping")
        return []

    findings = []
    for rec in data:
        if not isinstance(rec, dict):
            continue

        fid = rec.get("id")
        title = rec.get("title") or ""
        sev = (rec.get("severity") or "info").lower()
        svc = rec.get("service")
        if svc:
            svc = str(svc).lower()
        else:
            svc = None

        f = {
            "id": fid,
            "title": title,
            "description": rec.get("description") or title,
            "severity": sev,
            "asset": "—",
            "service": svc,
            "asset_criticality": rec.get("asset_criticality", 1.0),
            "confidence": rec.get("confidence", 1.0),
            "compliance": rec.get("compliance", []),
            "source": "aws",
        }
        findings.append(f)

    print(f"[+] Loaded {len(findings)} AWS findings")
    return findings


def load_lynis_findings():
    """
    Parse Lynis .dat file into findings.

    We look for lines like:
      suggestion[]=TEST-0001|Description text|...
      warning[]=TEST-0002|Description text|...
    """
    if not LYNIS_IN.exists():
        print("[!] No Lynis report, skipping:", LYNIS_IN)
        return []

    findings = []
    try:
        for line in LYNIS_IN.read_text().splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("suggestion[]=") or line.startswith("warning[]="):
                payload = line.split("=", 1)[1]
                parts = payload.split("|")
                if len(parts) >= 2:
                    finding_id = parts[0].strip()
                    desc = parts[1].strip()
                else:
                    finding_id = None
                    desc = payload

                if line.startswith("warning[]="):
                    sev = "medium"
                else:
                    sev = "low"

                findings.append(
                    {
                        "id": finding_id,
                        "title": desc,
                        "description": desc,
                        "severity": sev,
                        "asset": "kaliscanner",
                        "service": "linux",
                        "asset_criticality": 1.0,
                        "confidence": 1.0,
                        "compliance": [],
                        "source": "linux",
                    }
                )
    except Exception as e:
        print(f"[!] Failed to parse {LYNIS_IN}: {e}")
        return []

    print(f"[+] Loaded {len(findings)} Lynis findings")
    return findings


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)

    all_findings = []
    all_findings.extend(load_aws_findings())
    all_findings.extend(load_lynis_findings())

    OUT.write_text(json.dumps(all_findings, indent=2))
    print(f"[+] Combined {len(all_findings)} findings -> {OUT}")


if __name__ == "__main__":
    main()
