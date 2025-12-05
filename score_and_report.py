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
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    h1,h2 { margin: 0 0 8px; }
    .muted { color: #666; }
    .kpi { display:inline-block; margin-right:24px; padding:10px 14px; border:1px solid #eee; border-radius:12px; }
    table { width:100%; border-collapse: collapse; margin-top:14px; }
    th, td { padding: 10px; border-bottom: 1px solid #eee; text-align: left; }
    .badge { padding: 2px 8px; border-radius: 12px; font-size: 12px; }
    .sev-critical { background: #ffe5e5; }
    .sev-high { background: #ffeeda; }
    .sev-medium { background: #fff6cc; }
    .sev-low { background: #eaf7ff; }
    .sev-info { background: #eeeff2; }
    .grade { font-weight: 700; }
    .small { font-size: 12px; }
    .section { margin-top: 28px; }
    .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#f7f7f9; padding:2px 6px; border-radius:6px; }
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
            <td><span class="badge sev-{{sev}}">{{ sev|capitalize }}</span></td>
            <td>{{ breakdown.counts.get(sev, 0) }}</td>
            <td>{{ breakdown.weights.get(sev, 0) }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top Risky Assets</h2>
    <table>
      <thead><tr><th>Asset</th><th>Total Score</th><th>Findings</th></tr></thead>
      <tbody>
        {% for a in assets_top %}
          <tr>
            <td>{{ a.asset or "—" }}</td>
            <td>{{ a.score }}</td>
            <td>{{ a.count }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Top Critical Findings</h2>
    <table>
      <thead><tr><th>Title</th><th>Severity</th><th>Asset</th><th>Service</th><th>Score</th></tr></thead>
      <tbody>
        {% for f in top_findings %}
          <tr>
            <td>{{ f.get("title") or f.get("id") }}</td>
            <td><span class="badge sev-{{ f['severity'] }}">{{ f['severity']|capitalize }}</span></td>
            <td>{{ f.get("asset") or "—" }}</td>
            <td>{{ f.get("service") or "—" }}</td>
            <td>{{ f["_score"] }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Grading Policy</h2>
    <div class="small muted">
      Finding score = severity_weight × asset_criticality × confidence.
      Thresholds: {{ grading_text }}.
      Weights: critical=10, high=7, medium=4, low=1, info=0.
    </div>
  </div>

  <div class="section">
    <h2>Appendix: All Findings</h2>
    <table>
      <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Asset</th><th>Service</th><th>Score</th></tr></thead>
      <tbody>
        {% for f in all_findings %}
          <tr>
            <td class="code">{{ f.get("id") or loop.index }}</td>
            <td>{{ f.get("title") or "—" }}</td>
            <td><span class="badge sev-{{ f['severity'] }}">{{ f['severity']|capitalize }}</span></td>
            <td>{{ f.get("asset") or "—" }}</td>
            <td>{{ f.get("service") or "—" }}</td>
            <td>{{ f["_score"] }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

</body>
</html>
"""

# ----------------------------
# Lynis helpers – replace "Suggestion" with real description
# ----------------------------

LYNIS_REPORT = Path("reports/lynis-report.dat")


def get_lynis_descriptions():
    descriptions = []
    if not LYNIS_REPORT.exists():
        return descriptions

    with LYNIS_REPORT.open(errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("suggestion[]=") or line.startswith("warning[]="):
                payload = line.split("=", 1)[1]
                parts = payload.split("|")
                if len(parts) >= 2:
                    descriptions.append(parts[1].strip())
    return descriptions


def patch_linux_titles(findings):
    descs = get_lynis_descriptions()
    if not descs:
        return
    idx = 0
    for f in findings:
        if (
            f.get("asset") == "kaliscanner"
            and f.get("service") == "linux"
            and f.get("title") in (None, "", "Suggestion")
            and idx < len(descs)
        ):
            f["title"] = descs[idx]
            idx += 1

# ----------------------------
# Scoring helpers
# ----------------------------

def score_finding(f):
    sev = (f.get("severity") or "").lower().strip()
    w = SEVERITY_WEIGHT.get(sev, 0)
    ac = float(f.get("asset_criticality", 1.0) or 1.0)
    conf = float(f.get("confidence", 1.0) or 1.0)
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
    ap.add_argument("--in", dest="infile", required=True,
                    help="Normalized findings JSON (list)")
    ap.add_argument("--out", dest="outdir", required=True,
                    help="Output directory")
    ap.add_argument("--pdf", action="store_true",
                    help="Also emit PDF using WeasyPrint if available")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with open(args.infile, "r") as fh:
        findings = json.load(fh)

    # 🔹 Fix Linux "Suggestion" titles before scoring
    patch_linux_titles(findings)

    cleaned = []
    counts = Counter()
    weight_by_sev = defaultdict(float)

    # Normalize severity and compute scores
    for f in findings:
        sev = (f.get("severity") or "info").lower().strip()
        if sev not in SEVERITY_WEIGHT:
            sev = "info"
        f["severity"] = sev
        f["_score"] = score_finding(f)
        cleaned.append(f)
        counts[sev] += 1
        weight_by_sev[sev] += f["_score"]

    total_score = round(sum(f["_score"] for f in cleaned), 2)
    grade = grade_from_score(total_score)

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "score": total_score,
        "grade": grade,
        "counts": {
            "critical": int(counts.get("critical", 0)),
            "high": int(counts.get("high", 0)),
            "medium": int(counts.get("medium", 0)),
            "low": int(counts.get("low", 0)),
            "info": int(counts.get("info", 0)),
        },
    }
    summary_path = os.path.join(args.outdir, "risk_summary.json")
    with open(summary_path, "w") as sf:
        json.dump(summary, sf, indent=2)
    print(f"Wrote: {summary_path}")

    by_asset = defaultdict(lambda: {"score": 0.0, "count": 0})
    for f in cleaned:
        key = f.get("asset") or "—"
        by_asset[key]["score"] += f["_score"]
        by_asset[key]["count"] += 1

    assets_top = [
        {"asset": a, "score": round(v["score"], 2), "count": v["count"]}
        for a, v in sorted(by_asset.items(), key=lambda kv: kv[1]["score"], reverse=True)[:10]
    ]

    top_findings = sorted(cleaned, key=lambda x: x["_score"], reverse=True)[:15]

    grading_text = ", ".join([f"{g}: {lo}–{hi}" for g, lo, hi in GRADE_THRESHOLDS])

    html = Template(HTML_TEMPLATE).render(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        totals={"findings": len(cleaned), "score": total_score, "grade": grade},
        breakdown={
            "counts": dict(counts),
            "weights": {k: round(v, 2) for k, v in weight_by_sev.items()},
        },
        assets_top=assets_top,
        top_findings=top_findings,
        all_findings=cleaned,
        grading_text=grading_text,
    )

    html_path = os.path.join(args.outdir, "risk_report.html")
    with open(html_path, "w") as fh:
        fh.write(html)

    if args.pdf:
        try:
            from weasyprint import HTML as WHTML
            pdf_path = os.path.join(args.outdir, "risk_report.pdf")
            WHTML(string=html).write_pdf(pdf_path)
            print(f"Wrote: {html_path}")
            print(f"Wrote: {pdf_path}")
        except Exception as e:
            print(f"Wrote: {html_path}")
            print(f"PDF generation failed (install WeasyPrint deps). Error: {e}")
    else:
        print(f"Wrote: {html_path}")

if __name__ == "__main__":
    main()
