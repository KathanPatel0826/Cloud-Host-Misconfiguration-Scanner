#!/usr/bin/env bash
set -euo pipefail

# -------------------------------
# Default Paths
# -------------------------------
ROOT_DIR="$(pwd)"
OUT_DIR="${OUT_DIR:-out}"
REPORT_DIR="${REPORT_DIR:-reports}"
LOG_DIR="${LOG_DIR:-logs}"
VENV="${VENV:-${ROOT_DIR}/.venv}"
mkdir -p "$OUT_DIR" "$REPORT_DIR" "$LOG_DIR"

# -------------------------------
# 1. Run Prowler + Lynis (optional if already done earlier)
# -------------------------------
echo "[*] Running security scanners..." | tee -a "$LOG_DIR/steps.log"
# prowler -M json > "output/prowler-output-$(date +%s).json" || true
# lynis audit system --quiet --logfile "$LOG_DIR/lynis.log" --report-file "reports/lynis-report.dat" || true

# -------------------------------
# 2. Normalize + Compliance Mapping
# -------------------------------
echo "[*] Normalizing scanner outputs (Prowler + Lynis) ..." | tee -a "$LOG_DIR/steps.log"
. "$VENV/bin/activate" 2>/dev/null || true

python3 normalize.py \
  --in output/prowler-output-*.json reports/lynis-report*.dat \
  --out "$OUT_DIR" || echo "[!] Normalization skipped if no raw files found"

# -------------------------------
# 3. Ensure compliance_summary.json exists
# -------------------------------
if [ ! -f "$OUT_DIR/compliance_summary.json" ] && [ -f "$OUT_DIR/normalized_findings.json" ]; then
  echo "[*] Building compliance_summary.json from normalized_findings.json ..."
  python3 - <<'PY'
import json, os
src="out/normalized_findings.json"; dst="out/compliance_summary.json"
from collections import defaultdict
agg = defaultdict(lambda: {'failing_controls': defaultdict(int),'passing_controls': defaultdict(int)})
with open(src, 'r', encoding='utf-8') as f:
    findings = json.load(f)
for f in findings:
    status = (f.get('status') or '').upper()
    for ctrl in (f.get('compliance') or []):
        fw = ctrl.split(':', 1)[0] if ':' in ctrl else 'Unknown'
        bucket = 'failing_controls' if status in ('FAIL','ALARM','WARNING','SUGGESTION') else 'passing_controls'
        agg[fw][bucket][ctrl] += 1
def plain(d): 
    return {k:(plain(v) if isinstance(v,dict) else v) for k,v in d.items()}
os.makedirs('out', exist_ok=True)
with open(dst, 'w', encoding='utf-8') as f:
    json.dump(plain(agg), f, indent=2)
print("[✓] compliance_summary.json created at", dst)
PY
fi

# -------------------------------
# 4. Generate Reports
# -------------------------------
echo "[*] Generating report..." | tee -a "$LOG_DIR/steps.log"
python3 generate_report.py --in "$OUT_DIR/normalized_findings.json" --out "$REPORT_DIR"

if [ -f "$REPORT_DIR/risk_report.html" ]; then
  echo "[i] Risk report generated at: $REPORT_DIR/risk_report.html"
fi

# -------------------------------
# 5. Stable copies for Jenkins alerting
# -------------------------------
if [ -f "$REPORT_DIR/summary.json" ]; then
  cp "$REPORT_DIR/summary.json" "$ROOT_DIR/last_summary.json"
fi
if [ -f "$REPORT_DIR/report.html" ]; then
  cp "$REPORT_DIR/report.html" "$ROOT_DIR/last_report.html"
fi

# -------------------------------
# 6. Summary
# -------------------------------
echo "[✓] Pipeline completed successfully."
echo "Normalized: $OUT_DIR/normalized_findings.json"
echo "Compliance: $OUT_DIR/compliance_summary.json"
echo "Summary:    $REPORT_DIR/summary.json"
echo "HTML:       $REPORT_DIR/report.html"
