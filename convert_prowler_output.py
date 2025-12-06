#!/usr/bin/env python3
import json
from pathlib import Path

REPORTS_DIR = Path("reports")
RAW_FILE = REPORTS_DIR / "aws_scan.json"   # input: raw Prowler JSON
OUT_FILE = REPORTS_DIR / "aws_scan.json"   # output: normalized list (same path)


def extract_records(raw):
    if isinstance(raw, list):
        return raw

    if isinstance(raw, dict):
        # Prowler usually returns a list at the top level, but just in case:
        # look for the first list-valued field.
        for v in raw.values():
            if isinstance(v, list):
                return v

    # Fallback: nothing useful
    return []


def normalize_record(row):
    """
    Convert one raw Prowler row into our normalized finding dict.
    """
    check_id = (
        row.get("CheckID")
        or row.get("check_id")
        or row.get("ControlID")
        or row.get("control_id")
    )

    title = (
        row.get("CheckTitle")
        or row.get("check_title")
        or row.get("Message")
        or row.get("Description")
        or ""
    )

    severity = (row.get("Severity") or row.get("severity") or "info").lower()

    # Service field from Prowler; we intentionally do NOT put account or resource IDs.
    service = row.get("Service") or row.get("ServiceName") or row.get("service")
    if service:
        service = str(service).lower()
    else:
        service = None

    finding = {
        "id": check_id,
        "title": title,
        "severity": severity,
        "service": service,
        # security choice: do NOT include account ID / resource ID
        "asset": None,
        "asset_criticality": 1.0,
        "confidence": 1.0,
        "source": "prowler",
    }
    return finding


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if not RAW_FILE.exists():
        print(f"[!] Raw Prowler JSON not found at {RAW_FILE}")
        return

    try:
        raw = json.loads(RAW_FILE.read_text())
    except Exception as e:
        print(f"[!] Failed to parse {RAW_FILE}: {e}")
        return

    records = extract_records(raw)
    if not isinstance(records, list):
        print("[!] Prowler data is not a list; nothing to normalize")
        return

    normalized = []
    for row in records:
        if not isinstance(row, dict):
            continue
        normalized.append(normalize_record(row))

    OUT_FILE.write_text(json.dumps(normalized, indent=2))
    print(f"[+] Wrote normalized JSON array with {len(normalized)} findings to {OUT_FILE}")


if __name__ == "__main__":
    main()
