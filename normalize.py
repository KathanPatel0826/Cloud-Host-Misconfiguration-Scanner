#!/usr/bin/env python3
"""
normalize.py — Data Handling & JSON Normalization for CYB590 Cloud & Host Misconfiguration Scanner

Usage examples:
  # Typical: feed individual scanner outputs
  python3 normalize.py --in output/prowler-output-*.json reports/lynis-report*.dat --out out/

  # Or: feed a combined JSON you've already merged elsewhere
  python3 normalize.py --in combined_scanner.json --out out/

What it produces:
  out/normalized_findings.json     # unified schema across scanners
  out/compliance_summary.json      # per-framework pass/fail aggregation
  (stdout)                         # one-line run summary

Optional file:
  compliance_map.yaml  # Regex/exact mappings: check_id -> [ "CIS_xxx:1.2.3", "NIST_800-53:AC-3" ]
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from collections import defaultdict

# -------- Configs --------

SEVERITY_MAP = {
    "critical": "critical", "crit": "critical",
    "high": "high",
    "medium": "medium", "med": "medium",
    "low": "low",
    "informational": "info", "information": "info", "info": "info", "passed": "info", "pass": "info"
}

RISK_WEIGHT = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}

# Lazy YAML import (optional dependency)
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# -------- Helpers --------

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def ensure_dir(d: str) -> None:
    os.makedirs(d, exist_ok=True)

def safe_sev(v: Optional[str]) -> str:
    if not v:
        return "info"
    key = str(v).strip().lower()
    return SEVERITY_MAP.get(key, key if key in RISK_WEIGHT else "info")

def weight_for(sev: str) -> int:
    return RISK_WEIGHT.get(sev, 0)

def coalesce(*vals, default=None):
    for v in vals:
        if v not in (None, "", []):
            return v
    return default

# -------- Compliance mapping --------

def load_compliance_map(path: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Returns:
      {
        "prowler": { "<exact or regex>": ["CIS_AWS_1.2:1.2.3", "NIST_800-53:AC-3"], ... },
        "lynis":   { "<exact or regex>": [...] }
      }
    """
    empty = {"prowler": {}, "lynis": {}}
    if not path or not os.path.isfile(path) or yaml is None:
        return empty
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return {
        "prowler": data.get("prowler", {}) or {},
        "lynis": data.get("lynis", {}) or {},
    }

def from_prowler_native_compliance(raw: Dict[str, Any]) -> List[str]:
    """Prowler sometimes includes Compliance/ComplianceRequirements fields."""
    controls: List[str] = []
    comp = raw.get("Compliance") or raw.get("ComplianceRequirements")
    if isinstance(comp, list):
        for item in comp:
            if isinstance(item, str):
                controls.append(item.strip())
            elif isinstance(item, dict):
                fw = item.get("Framework") or item.get("Standard") or item.get("FrameworkName")
                req = item.get("Requirement") or item.get("Control") or item.get("Id") or item.get("Section")
                if fw and req:
                    controls.append(f"{fw}:{req}")
    elif isinstance(comp, dict):
        for fw, req in comp.items():
            if isinstance(req, list):
                controls.extend([f"{fw}:{r}" for r in req])
            elif isinstance(req, str):
                controls.append(f"{fw}:{req}")
    return [c for c in controls if isinstance(c, str) and c.strip()]

def map_compliance(scanner: str, check_id: str, raw: Dict[str, Any], cmap: Dict[str, Dict[str, List[str]]]) -> List[str]:
    controls: List[str] = []
    # 1) Native Prowler metadata
    if scanner == "prowler":
        controls.extend(from_prowler_native_compliance(raw))

    # 2) YAML mappings (exact/regex)
    mapping = cmap.get(scanner, {})
    for pattern, mapped in mapping.items():
        try:
            if pattern == check_id or re.search(pattern, check_id, re.IGNORECASE):
                controls.extend(mapped or [])
        except re.error:
            # bad regex in map; fall back to exact
            if pattern == check_id:
                controls.extend(mapped or [])

    # unique + sorted
    return sorted({c.strip() for c in controls if isinstance(c, str) and c.strip()})

# -------- Parsers --------

def parse_prowler(obj: Dict[str, Any], cmap: Dict[str, Dict[str, List[str]]]) -> Optional[Dict[str, Any]]:
    """
    Expected fields (varies by prowler version):
      CheckID / CheckId, Status, Severity, Service, ResourceId/ResourceArn, AccountId, Region, Message, Remediation, etc.
    """
    # Skip PASS/INFO unless you want to keep all; we keep FAIL/WARN-like by default
    status_raw = str(obj.get("Status", obj.get("status", ""))).upper()
    # Common FAIL markers
    status = "FAIL" if status_raw in ("FAIL", "ALARM", "WARNING", "WARN") else status_raw or "UNKNOWN"

    # Keep all findings; you can filter later in reporting if needed
    check_id = coalesce(obj.get("CheckID"), obj.get("CheckId"), obj.get("CheckIDShort"), obj.get("Id"), default="unknown")
    sev = safe_sev(obj.get("Severity"))
    service = coalesce(obj.get("Service"), obj.get("Category"), default="unknown")
    region = obj.get("Region") or obj.get("AwsRegion") or ""
    account = obj.get("AccountId") or obj.get("Account") or ""
    resource = coalesce(obj.get("ResourceId"), obj.get("ResourceArn"), obj.get("Resource") , default="")
    title = coalesce(obj.get("CheckTitle"), obj.get("Title"), obj.get("CheckName"), default=str(check_id))
    desc = coalesce(obj.get("Message"), obj.get("Description"), obj.get("Risk"), default="")
    ts = coalesce(obj.get("Timestamp"), obj.get("CreatedAt"), obj.get("UpdatedAt"), default=now_iso())

    compliance = map_compliance("prowler", str(check_id), obj, cmap)

    norm = {
        "scanner": "prowler",
        "check_id": str(check_id),
        "title": str(title),
        "description": str(desc),
        "severity": sev,
        "status": status,  # normalized high-level status
        "service": str(service),
        "resource": str(resource),
        "region": str(region),
        "account": str(account),
        "timestamp": str(ts),
        "compliance": compliance,
        "raw": {
            "original": obj
        }
    }
    return norm

def parse_lynis_dat(text: str, cmap: Dict[str, Dict[str, List[str]]]) -> Iterable[Dict[str, Any]]:
    """
    Lynis .dat is key=value lines; findings often appear as:
      suggestion[]=SSH-7408|Disable root login ...
      warning[]=ACCT-9630|Enable process accounting ...
    We'll parse suggestion[] and warning[] as failing statuses; ok[] as PASS.
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        if "suggestion[]=" in ln or "warning[]=" in ln:
            # Format: key[]=ID|Message
            _, payload = ln.split("=", 1)
            parts = payload.split("|", 1)
            test_id = parts[0].strip()
            msg = parts[1].strip() if len(parts) > 1 else ""
            sev = "medium" if "warning" in ln else "low"
            status = "FAIL"
            title = msg.split(".")[0][:140] if msg else test_id
            compliance = map_compliance("lynis", test_id, {}, cmap)
            yield {
                "scanner": "lynis",
                "check_id": test_id,
                "title": title,
                "description": msg,
                "severity": sev,
                "status": status,
                "service": "host",
                "resource": os.uname().nodename if hasattr(os, "uname") else "host",
                "region": "",
                "account": "",
                "timestamp": now_iso(),
                "compliance": compliance,
                "raw": {"line": ln}
            }
        elif "ok[]=" in ln:
            # PASS entries (keep but low weight)
            _, payload = ln.split("=", 1)
            parts = payload.split("|", 1)
            test_id = parts[0].strip()
            msg = parts[1].strip() if len(parts) > 1 else ""
            title = msg.split(".")[0][:140] if msg else test_id
            compliance = map_compliance("lynis", test_id, {}, cmap)
            yield {
                "scanner": "lynis",
                "check_id": test_id,
                "title": title,
                "description": msg,
                "severity": "info",
                "status": "PASS",
                "service": "host",
                "resource": os.uname().nodename if hasattr(os, "uname") else "host",
                "region": "",
                "account": "",
                "timestamp": now_iso(),
                "compliance": compliance,
                "raw": {"line": ln}
            }

# -------- Aggregation / Risk / Compliance Summary --------

def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    for f in findings:
        sev = f.get("severity", "info")
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
        total += 1

    # Average risk = mean of weights across all findings (including info=0)
    # You can filter PASS here if desired; we keep everything for transparency.
    weights = [weight_for(f.get("severity", "info")) for f in findings]
    avg_risk = round(sum(weights) / max(1, len(weights)), 2)

    # Simple A–F grade
    # 0–0.5 A, 0.51–1.5 B, 1.51–2.5 C, 2.51–3.5 D, 3.51–4.5 E, >4.5 F
    def letter(r: float) -> str:
        if r <= 0.5: return "A"
        if r <= 1.5: return "B"
        if r <= 2.5: return "C"
        if r <= 3.5: return "D"
        if r <= 4.5: return "E"
        return "F"

    return {
        "totals": {"findings": total, **counts},
        "risk": {"avg": avg_risk, "grade": letter(avg_risk)}
    }

def build_compliance_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Structure:
    {
      "CIS_AWS_1.2": {
        "failing_controls": { "CIS_AWS_1.2:3.1": 2, ... },
        "passing_controls": { ... }
      },
      "NIST_800-53": { ... }
    }
    """
    agg: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(lambda: {"failing_controls": defaultdict(int),
                                                                     "passing_controls": defaultdict(int)})
    for f in findings:
        status = (f.get("status") or "").upper()
        for ctrl in f.get("compliance", []) or []:
            fw = ctrl.split(":", 1)[0] if ":" in ctrl else "Unknown"
            if status in ("FAIL", "ALARM", "WARNING", "SUGGESTION"):
                agg[fw]["failing_controls"][ctrl] += 1
            else:
                agg[fw]["passing_controls"][ctrl] += 1

    # Convert nested defaultdicts to plain dicts
    def plain(d):
        if isinstance(d, defaultdict):
            d = {k: plain(v) for k, v in d.items()}
        elif isinstance(d, dict):
            d = {k: plain(v) for k, v in d.items()}
        return d

    return plain(agg)

# -------- Main --------

def main():
    ap = argparse.ArgumentParser(description="Normalize scanner outputs into a unified JSON with risk & compliance mapping.")
    ap.add_argument("--in", dest="inputs", nargs="+", required=True,
                    help="Input files: prowler JSON (*.json), lynis .dat, or a combined JSON.")
    ap.add_argument("--out", dest="out_dir", default="out", help="Output directory (default: out)")
    ap.add_argument("--compliance-map", dest="cmap_path", default="compliance_map.yaml",
                    help="YAML map of check IDs/patterns to compliance controls (default: compliance_map.yaml)")
    args = ap.parse_args()

    out_dir = args.out_dir
    ensure_dir(out_dir)

    cmap = load_compliance_map(args.cmap_path)

    findings: List[Dict[str, Any]] = []

    for path in args.inputs:
        if not os.path.exists(path):
            print(f"[WARN] input not found: {path}", file=sys.stderr)
            continue

        # Heuristic: JSON → prowler or combined; .dat/.txt → lynis
        lower = path.lower()
        try:
            if lower.endswith(".json"):
                data = load_json_file(path)
                # Prowler may emit a list, or a dict with 'Findings'/'Results'
                objs: List[Dict[str, Any]] = []
                if isinstance(data, list):
                    objs = [x for x in data if isinstance(x, dict)]
                elif isinstance(data, dict):
                    # If it's a combined structure, flatten best-effort
                    if "Findings" in data and isinstance(data["Findings"], list):
                        objs = [x for x in data["Findings"] if isinstance(x, dict)]
                    elif "Results" in data and isinstance(data["Results"], list):
                        objs = [x for x in data["Results"] if isinstance(x, dict)]
                    else:
                        # try to guess it's already normalized
                        if "scanner" in data and "check_id" in data:
                            objs = [data]
                        else:
                            # pick all dicts anywhere shallow
                            for v in data.values():
                                if isinstance(v, list):
                                    objs.extend([x for x in v if isinstance(x, dict)])
                for obj in objs:
                    norm = parse_prowler(obj, cmap)
                    if norm:
                        findings.append(norm)

            elif lower.endswith(".dat") or lower.endswith(".txt") or "lynis" in lower:
                text = load_text_file(path)
                findings.extend(list(parse_lynis_dat(text, cmap)))

            else:
                # Fallback: try JSON parse, else treat as text lynis style
                try:
                    data = load_json_file(path)
                    if isinstance(data, list):
                        for obj in data:
                            if isinstance(obj, dict):
                                norm = parse_prowler(obj, cmap)
                                if norm:
                                    findings.append(norm)
                    elif isinstance(data, dict):
                        # Already normalized?
                        arr = data.get("findings")
                        if isinstance(arr, list):
                            findings.extend([x for x in arr if isinstance(x, dict)])
                except Exception:
                    text = load_text_file(path)
                    findings.extend(list(parse_lynis_dat(text, cmap)))

        except Exception as e:
            print(f"[WARN] failed to parse {path}: {e}", file=sys.stderr)

    # Sort findings by severity DESC then title
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_order.get(f.get("severity", "info"), 9), f.get("title", "")))

    # Compute summaries
    summary = summarize(findings)
    compliance_summary = build_compliance_summary(findings)

    # Write outputs
    normalized_path = os.path.join(out_dir, "normalized_findings.json")
    compliance_path = os.path.join(out_dir, "compliance_summary.json")

    with open(normalized_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    with open(compliance_path, "w", encoding="utf-8") as f:
        json.dump(compliance_summary, f, indent=2)

    # One-line console summary for Jenkins logs
    print(f"[normalize] findings={summary['totals']['findings']} "
          f"crit={summary['totals']['critical']} high={summary['totals']['high']} "
          f"med={summary['totals']['medium']} low={summary['totals']['low']} "
          f"info={summary['totals']['info']} avgRisk={summary['risk']['avg']} "
          f"grade={summary['risk']['grade']} -> "
          f"{os.path.relpath(normalized_path)} , {os.path.relpath(compliance_path)}")

if __name__ == "__main__":
    main()
