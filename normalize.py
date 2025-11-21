#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

# ---------------------------
# Maps
# ---------------------------

SEVERITY_MAP = {
    "critical":"critical","crit":"critical",
    "high":"high",
    "medium":"medium","med":"medium",
    "low":"low",
    "informational":"info","info":"info","none":"info",
    "5":"critical","4":"high","3":"medium","2":"low","1":"info","0":"info",
}

STATUS_MAP = {
    "pass":"pass","ok":"pass","passed":"pass","success":"pass",
    "fail":"fail","failed":"fail","error":"fail",
    "warning":"warn","warn":"warn",
    "info":"info","manual":"info","not_applicable":"info","na":"info",
}

# ---------------------------
# Helpers
# ---------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _s(x: Any) -> Optional[str]:
    """Coerce to a clean string (handles dict/list gracefully)."""
    if x is None:
        return None
    if isinstance(x, (int, float, bool)):
        return str(x)
    if isinstance(x, dict):
        # try common text-like keys
        for k in ("text","Text","desc","Desc","message","Message"):
            v = x.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        try:
            return json.dumps(x, ensure_ascii=False)
        except Exception:
            return str(x)
    if isinstance(x, (list, tuple)):
        parts = [p for p in (_s(i) for i in x) if p]
        return "; ".join(parts) if parts else None
    try:
        s = str(x).strip()
        return s or None
    except Exception:
        return None

def _norm_severity(value: Optional[str]) -> str:
    if not value: return "info"
    v = str(value).strip().lower()
    return SEVERITY_MAP.get(v, v if v in {"critical","high","medium","low","info"} else "info")

def _norm_status(value: Optional[str]) -> str:
    if not value: return "info"
    v = str(value).strip().lower()
    return STATUS_MAP.get(v, v if v in {"pass","fail","warn","info"} else "info")

# ---------------------------
# Unified schema (no remediation, no cis_benchmark)
# ---------------------------

UnifiedFinding = Dict[str, Any]
SCHEMA_FIELDS = [
    "source","scanner","asset","service","control_id","title","description",
    "status","severity","timestamp","raw"
]

def _mk_finding(
    *, source: str, scanner: str, asset: Optional[str], service: Optional[str],
    control_id: Optional[str], title: Optional[str], description: Optional[str],
    status: Optional[str], severity: Optional[str], timestamp: Optional[str],
    raw: Dict[str, Any],
) -> UnifiedFinding:
    return {
        "source": source or "unknown",
        "scanner": scanner or "unknown",
        "asset": _s(asset),
        "service": _s(service),
        "control_id": _s(control_id),
        "title": _s(title),
        "description": _s(description),
        "status": _norm_status(status),
        "severity": _norm_severity(severity),
        "timestamp": timestamp or now_iso(),
        "raw": raw,
    }

# ---------------------------
# Adapters
# ---------------------------

def adapt_prowler(record: Dict[str, Any]) -> UnifiedFinding:
    return _mk_finding(
        source="aws",
        scanner="prowler",
        asset=record.get("resource") or record.get("account_id") or record.get("ACCOUNT_ID"),
        service=record.get("service") or record.get("Service"),
        control_id=record.get("check_id") or record.get("ControlId") or record.get("Id"),
        title=record.get("check_title") or record.get("Title") or record.get("CheckTitle"),
        description=record.get("description") or record.get("Description"),
        status=record.get("status") or record.get("Status"),
        severity=record.get("severity") or record.get("Severity"),
        timestamp=record.get("timestamp") or record.get("Timestamp"),
        raw=record,
    )

def adapt_lynis(record: Dict[str, Any]) -> UnifiedFinding:
    service = record.get("category") or record.get("group") or "linux"
    title = record.get("title") or record.get("test") or record.get("test_id")
    return _mk_finding(
        source="linux",
        scanner="lynis",
        asset=record.get("host") or record.get("hostname") or record.get("node"),
        service=service,
        control_id=record.get("test_id") or record.get("id") or record.get("control_id"),
        title=title,
        description=record.get("description") or record.get("detail") or title,
        status=record.get("status") or record.get("result"),
        severity=record.get("severity") or record.get("level"),
        timestamp=record.get("timestamp") or record.get("time"),
        raw=record,
    )

# ---------------------------
# Loaders / Parsers
# ---------------------------

def load_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def parse_lynis_dat(path: str) -> List[Dict[str, Any]]:
    """
    Parse Lynis report.dat (key=value lines) into records.
    Converts warning[] / suggestion[] / hint[] lines into findings.
    Example: warning[]=FIRE-4512|iptables module(s) loaded, but no rules active|...
    """
    text = load_text(path)
    records: List[Dict[str, Any]] = []
    host = None

    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line or line.startswith("#"):
            continue

        key, val = line.split("=", 1)
        k = key.strip().lower()
        v = val.strip()

        if k in ("hostname", "host", "system"):
            host = v

        def _rec(title: str, status: str, severity: str) -> Dict[str, Any]:
            code, msg = None, v
            if "|" in v:
                parts = v.split("|")
                if parts and parts[0] and not parts[0].startswith("text:"):
                    code = parts[0]
                    msg = "|".join(parts[1:]).strip() or parts[0]
            return {
                "scanner": "lynis",
                "host": host,
                "category": "linux",
                "test_id": code,
                "title": title,
                "description": msg,
                "status": status,
                "severity": severity,
                "timestamp": None,
            }

        if k.startswith("warning["):
            records.append(_rec("Warning", "fail", "medium"))
        elif k.startswith("suggestion["):
            records.append(_rec("Suggestion", "warn", "low"))
        elif k.startswith("hint["):
            records.append(_rec("Hint", "info", "info"))

    return records

def load_json(path: str) -> Any:
    """Load JSON; if it fails, try NDJSON (one JSON object per line)."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
        arr = []
        for ln in lines:
            try:
                arr.append(json.loads(ln))
            except Exception:
                pass
        return arr

def detect_shape_and_iter(raw: Any) -> Iterable[Dict[str, Any]]:
    """Yield dict records from common shapes."""
    if isinstance(raw, list):
        for r in raw:
            if isinstance(r, dict):
                yield r
        return
    if isinstance(raw, dict):
        for key in ("findings","results","records","items","Checks"):
            val = raw.get(key)
            if isinstance(val, list):
                for r in val:
                    if isinstance(r, dict):
                        yield r
                return
        if raw and all(isinstance(v, dict) for v in raw.values()):
            for r in raw.values():
                yield r
            return
    return []

# ---------------------------
# Adapter routing / dedupe
# ---------------------------

def pick_adapter(record: Dict[str, Any]) -> str:
    s = " ".join(record.keys()).lower()
    if any(k in record for k in ("check_id","check_title")) or "prowler" in json.dumps(record).lower():
        return "prowler"
    if any(k in record for k in ("test_id","lynis")) or record.get("scanner") == "lynis":
        return "lynis"
    src = (record.get("source") or "").lower()
    if src == "aws": return "prowler"
    if src == "linux": return "lynis"
    if any(k in s for k in ("host","hostname","ssh","pam","sysctl")):
        return "lynis"
    return "prowler"

def make_dedupe_key(f: UnifiedFinding) -> str:
    parts = [
        f.get("source") or "",
        f.get("scanner") or "",
        f.get("asset") or "",
        f.get("service") or "",
        f.get("control_id") or "",
        f.get("title") or "",
        f.get("status") or "",
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

# ---------------------------
# HTML report (grouped + colored; columns derive from SCHEMA_FIELDS)
# ---------------------------

def _counts(findings: List[UnifiedFinding]) -> Dict[str, Dict[str, int]]:
    counts: Dict[str, Dict[str, int]] = {}
    for f in findings:
        source = (f.get("source") or "unknown").lower()
        status = (f.get("status") or "info").lower()
        counts.setdefault(source, {})[status] = counts.setdefault(source, {}).get(status, 0) + 1
        counts.setdefault("TOTAL", {})[status] = counts.setdefault("TOTAL", {}).get(status, 0) + 1
    return counts

def _render_counts_table(counts: Dict[str, Dict[str, int]]) -> str:
    statuses = ["fail","warn","pass","info"]
    rows = []
    for src in sorted([k for k in counts.keys() if k != "TOTAL"]) + ["TOTAL"]:
        cells = [f"<td class='src'>{src}</td>"]
        for st in statuses:
            n = counts.get(src, {}).get(st, 0)
            cells.append(f"<td class='status {st}'>{n}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    head = "<tr><th>source</th>" + "".join(f"<th>{s}</th>" for s in statuses) + "</tr>"
    return f"<table class='summary'><thead>{head}</thead><tbody>{''.join(rows)}</tbody></table>"

def _severity_class(sev: str) -> str:
    s = (sev or "").lower()
    if s in {"critical","high"}: return "sev-high"
    if s == "medium": return "sev-med"
    if s == "low": return "sev-low"
    return "sev-info"

def write_html(findings: List[UnifiedFinding], out_path: str) -> None:
    groups = {
        "AWS (prowler)": [f for f in findings if (f.get("source") == "aws")],
        "Linux (lynis)": [f for f in findings if (f.get("source") == "linux")],
        "Other": [f for f in findings if (f.get("source") not in ("aws","linux"))],
    }
    cols = [c for c in SCHEMA_FIELDS if c != "raw"]

    def esc(x: Any) -> str:
        return (str(x).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))

    section_html = []
    for title, items in groups.items():
        if not items:
            continue
        def sort_key(f: UnifiedFinding):
            order = {"fail":0, "warn":1, "pass":2, "info":3}
            sev_order = {"critical":0, "high":1, "medium":2, "low":3, "info":4}
            return (order.get((f.get("status") or "info").lower(), 9),
                    sev_order.get((f.get("severity") or "info").lower(), 9),
                    f.get("title") or "")
        items = sorted(items, key=sort_key)

        rows_html = []
        for f in items:
            cells = []
            for c in cols:
                val = f.get(c, "")
                if c == "severity":
                    cells.append(f"<td class='{_severity_class(str(val))}'>{esc(val)}</td>")
                elif c == "status":
                    cells.append(f"<td class='status {(esc((val or '').lower()))}'>{esc(val)}</td>")
                else:
                    cells.append(f"<td>{esc(val)}</td>")
            rows_html.append("<tr>" + "".join(cells) + "</tr>")

        head_html = "<tr>" + "".join(f"<th>{esc(c)}</th>" for c in cols) + "</tr>"
        table_html = f"<h2>{esc(title)}</h2><table><thead>{head_html}</thead><tbody>{''.join(rows_html)}</tbody></table>"
        section_html.append(table_html)

    counts = _counts(findings)
    summary_html = _render_counts_table(counts)

    html = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Normalized Findings Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }}
    h1 {{ margin-top: 0; }}
    h2 {{ margin: 24px 0 8px; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 14px; vertical-align: top; }}
    th {{ background: #f5f5f5; text-align: left; position: sticky; top: 0; }}
    .meta {{ color: #555; margin-bottom: 12px; }}
    .summary th, .summary td {{ text-align: center; }}
    .status.fail {{ background: #fde2e1; font-weight: 600; }}
    .status.warn {{ background: #fff4d6; font-weight: 600; }}
    .status.pass {{ background: #e7f6ec; }}
    .status.info {{ background: #eef2f7; }}
    .sev-high {{ background: #ffe5e9; }}
    .sev-med  {{ background: #fff4d6; }}
    .sev-low  {{ background: #eef7ff; }}
    .sev-info {{ background: #f6f6f6; }}
    .src {{ text-transform: uppercase; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Normalized Findings</h1>
  <div class="meta">Generated: {esc(now_iso())} • Total findings: {len(findings)}</div>
  <h2>Summary</h2>
  {summary_html}
  {''.join(section_html) if section_html else '<p>No findings.</p>'}
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

# ---------------------------
# Normalize + write
# ---------------------------

def normalize_files(paths: List[str]) -> List[UnifiedFinding]:
    normalized: List[UnifiedFinding] = []
    seen: set[str] = set()

    for p in paths:
        try:
            if p.lower().endswith(".dat"):
                for rec in parse_lynis_dat(p):
                    uf = adapt_lynis(rec)
                    key = make_dedupe_key(uf)
                    if key in seen: 
                        continue
                    seen.add(key)
                    normalized.append(uf)
                continue
            raw = load_json(p)
        except Exception as e:
            print(f"[warn] Could not read {p}: {e}", file=sys.stderr)
            continue

        for rec in detect_shape_and_iter(raw):
            adapter = pick_adapter(rec)
            uf = adapt_prowler(rec) if adapter == "prowler" else adapt_lynis(rec)
            key = make_dedupe_key(uf)
            if key in seen:
                continue
            seen.add(key)
            normalized.append(uf)

    return normalized

def write_outputs(findings: List[UnifiedFinding], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)

    json_path = os.path.join(out_dir, "normalized_findings.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    cols = [c for c in SCHEMA_FIELDS if c != "raw"]
    csv_path = os.path.join(out_dir, "normalized_findings.csv")

    def csv_escape(val: Any) -> str:
        s = "" if val is None else str(val)
        if any(ch in s for ch in [",", '"', "\n", "\r"]):
            s = '"' + s.replace('"', '""') + '"'
        return s

    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(",".join(cols) + "\n")
        for row in findings:
            f.write(",".join(csv_escape(row.get(c)) for c in cols) + "\n")

    html_path = os.path.join(out_dir, "report.html")
    write_html(findings, html_path)

    print(f"[ok] Wrote: {json_path}")
    print(f"[ok] Wrote: {csv_path}")
    print(f"[ok] Wrote: {html_path}")

# ---------------------------
# Routing / dedupe helpers / CLI
# ---------------------------

def make_dedupe_key(f: UnifiedFinding) -> str:
    parts = [
        f.get("source") or "",
        f.get("scanner") or "",
        f.get("asset") or "",
        f.get("service") or "",
        f.get("control_id") or "",
        f.get("title") or "",
        f.get("status") or "",
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

def pick_adapter(record: Dict[str, Any]) -> str:
    s = " ".join(record.keys()).lower()
    if any(k in record for k in ("check_id","check_title")) or "prowler" in json.dumps(record).lower():
        return "prowler"
    if any(k in record for k in ("test_id","lynis")) or record.get("scanner") == "lynis":
        return "lynis"
    src = (record.get("source") or "").lower()
    if src == "aws": return "prowler"
    if src == "linux": return "lynis"
    if any(k in s for k in ("host","hostname","ssh","pam","sysctl")):
        return "lynis"
    return "prowler"

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Normalize scanner outputs to a unified schema and generate reports.")
    ap.add_argument("--in", dest="inputs", nargs="+", required=True,
                    help="Input file(s): prowler JSON, lynis-report.dat, combined JSON, etc.")
    ap.add_argument("--out", dest="out_dir", required=True, help="Output directory for normalized files")
    return ap.parse_args()

def main() -> None:
    args = parse_args()
    findings = normalize_files(args.inputs)
    if not findings:
        print("[warn] No findings parsed. Check input file(s).", file=sys.stderr)
    write_outputs(findings, args.out_dir)

if __name__ == "__main__":
    main()
