#!/usr/bin/env python3
import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from jinja2 import Template

# ----------------------------
# Config
# ----------------------------

SEVERITY_WEIGHT = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

GRADE_THRESHOLDS = [
    ("A", 0, 10),
    ("B", 11, 25),
    ("C", 26, 50),
    ("D", 51, 80),
    ("F", 81, 10**9),
]

HTML_TEMPLATE = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Risk Report</title>
  <style>
    body {
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      margin: 16px;
      font-size: 13px;
    }
    h1,h2 { margin: 0 0 8px; }
    .muted { color: #666; }
    .kpi {
      display:inline-block;
      margin-right:16px;
      padding:8px 10px;
      border:1px solid #eee;
      border-radius:12px;
    }
    table {
      width:100%;
      border-collapse: collapse;
      margin-top:10px;
      table-layout: fixed;
    }
    th, td {
      padding: 6px 4px;
      border-bottom: 1px solid #eee;
      text-align: left;
      font-size: 12px;
      word-wrap: break-word;
    }
    .badge {
      padding: 2px 6px;
      border-radius: 10px;
      font-size: 11px;
    }
    .sev-critical { background: #ffe5e5; }
    .sev-high { background: #ffeeda; }
    .sev-medium { background: #fff6cc; }
    .sev-low { background: #eaf7ff; }
    .sev-info { background: #eeeff2; }
    .grade { font-weight: bold; }
  </style>
</head>
<body>

  <h1>Cloud &amp; Host Misconfiguration Risk Report</h1>
  <div class="muted small">Generated: {{ generated_at }}</div>

  <div class="section">
    <div class="kpi"><div class="muted small">Total Findings</div><div><b>{{ totals.findings }}</b></div></div>
    <div class="kpi"><div class="muted small">Total Risk Score</div><div><b>{{ totals.score }}</b></div></div>
    <div class="kpi"><div class="muted small">Risk Grade</div><div class="grade">{{ totals.grade }}</div></div>
  </div>

  <div class="section">
    <h2>Severity Breakdown</h2>
    <table>
      <thead><tr><th>Severity</th><th>Count</th><th>Weighted Score</th></tr></thead>
      <tbody>
        {% for sev in ["critical","high","medium","low","info"] %}
        <tr>
          <td><span class="badge sev-{{ sev }}">{{ sev|capitalize }}</span></td>
          <td>{{ breakdown.counts.get(sev, 0) }}</td>
          <td>{{ breakdown.weights.get(sev, 0) }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top Critical Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Title</th>
          <th>Severity</th>
          <th>Asset</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        {% for f in top_findings %}
        <tr>
          <td>{{ f.get("title") or f.get("id") }}</td>
          <td><span class="badge sev-{{ f['severity'] }}">{{ f['severity']|capitalize }}</span></td>
          <td>{{ f.get("asset") or "—" }}</td>
          <td>{{ f["_score"] }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Appendix: All Findings</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Severity</th>
          <th>Asset</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        {% for f in all_findings %}
        <tr>
          <td>{{ f.get("id") or loop.index }}</td>
          <td>{{ f.get("title") or "—" }}</td>
          <td><span class="badge sev-{{ f['severity'] }}">{{ f['severity']|capitalize }}</span></td>
          <td>{{ f.get("asset") or "—" }}</td>
          <td>{{ f["_score"] }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Grading Policy</h2>
    <div class="muted small">
      Score = severity × asset_criticality × confidence.<br>
      Weights: Critical=10, High=7, Medium=4, Low=1, Info=0.<br>
      Grades: A=0–10, B=11–25, C=26–50, D=51–80, F=81+.
    </div>
  </div>

</body>
</html>
"""

# ----------------------------
# Helpers
# ----------------------------

def score_finding(f):
    sev = (f.get("severity") or "").lower().strip()
    w = SEVERITY_WEIGHT.get(sev, 0)
    ac = float(f.get("asset_criticality", 1.0))
    conf = float(f.get("confidence", 1.0))
    return round(w * ac * conf, 2)

def grade_from_score(total):
    for letter, lo, hi in GRADE_THRESHOLDS:
        if lo <= total <= hi:
            return letter
    return "F"

# ----------------------------
# Main
# ----------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--out", dest="outdir", required=True)
    ap.add_argument("--pdf", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    findings = json.loads(Path(args.infile).read_text())

    # Compute scores & severity breakdown
    cleaned = []
    counts = Counter()
    weight_by_sev = defaultdict(float)

    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in SEVERITY_WEIGHT:
            sev = "info"
        f["severity"] = sev
        f["_score"] = score_finding(f)

        cleaned.append(f)
        counts[sev] += 1
        weight_by_sev[sev] += f["_score"]

    total_score = sum(f["_score"] for f in cleaned)
    grade = grade_from_score(total_score)

    # Asset aggregation
    by_asset = defaultdict(lambda: {"score": 0, "count": 0})
    for f in cleaned:
        key = f.get("asset") or "—"
        by_asset[key]["score"] += f["_score"]
        by_asset[key]["count"] += 1

    assets_top = sorted(
        [{"asset": k, "score": v["score"], "count": v["count"]} for k, v in by_asset.items()],
        key=lambda x: x["score"],
        reverse=True
    )[:10]

    top_findings = sorted(cleaned, key=lambda f: f["_score"], reverse=True)[:15]

    html = Template(HTML_TEMPLATE).render(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        totals={"findings": len(cleaned), "score": total_score, "grade": grade},
        breakdown={"counts": counts, "weights": weight_by_sev},
        assets_top=assets_top,
        top_findings=top_findings,
        all_findings=cleaned,
        grading_text=""
    )

    Path(f"{args.outdir}/risk_report.html").write_text(html)
    print("Wrote: reports/risk_report.html")

    if args.pdf:
        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(f"{args.outdir}/risk_report.pdf")
            print("Wrote: reports/risk_report.pdf")
        except Exception as e:
            print("PDF generation failed:", e)

if __name__ == "__main__":
    main()
