#!/usr/bin/env bash
set -euo pipefail

# -------------------------------
#  Default Paths
# -------------------------------
ROOT_DIR="$(pwd)"
OUT_DIR="${OUT_DIR:-out}"
REPORT_DIR="${REPORT_DIR:-reports}"
LOG_DIR="${LOG_DIR:-logs}"
mkdir -p "$OUT_DIR" "$REPORT_DIR" "$LOG_DIR"

# -------------------------------
#  1. Run Prowler & Lynis
# -------------------------------
echo "[*] Running security scanners..." | tee -a "$LOG_DIR/steps.log"
# Example Prowler + Lynis commands (adjust if already run earlier)
# prowler -M json > "output/prowler-output-$(date +%s).json"
# lynis audit system --quiet --logfile "$LOG_DIR/lynis.log" --report-file "reports/lynis-report.dat"

# -------------------------------
#  2. Normalize + Compliance Mapping
# -------------------------------
echo "[*] Normalizing scanner outputs (Prowler + Lynis) ..." | tee -a "$LOG_DIR/steps.log"
. "$VENV/bin/activate" 2>/dev/null || true

python3 normalize.py \
  --in output/prowler-output-*.json reports/lynis-report*.dat \
  --out "$OUT_DIR"

echo "[✓] Normalization complete. Generated:"
echo "     - $OUT_DIR/normalized_findings.json"
echo "     - $OUT_DIR/compliance_summary.json"

# -------------------------------
#  3. Generate HTML / PDF Reports
# -------------------------------
echo "[*] Generating report..." | tee -a "$LOG_DIR/steps.log"
python3 generate_report.py --in "$OUT_DIR/normalized_data.json" --out "$REPORT_DIR"

# Optional: if your reporting script produces risk_report.html/pdf
if [ -f "$REPORT_DIR/risk_report.html" ]; then
  echo "[i] Risk report generated at: $REPORT_DIR/risk_report.html"
fi

# -------------------------------
#  4. Stable copies for Jenkins (alerting & artifact tracking)
# -------------------------------
if [ -f "$REPORT_DIR/summary.json" ]; then
  cp "$REPORT_DIR/summary.json" "$ROOT_DIR/last_summary.json"
fi

if [ -f "$REPORT_DIR/report.html" ]; then
  cp "$REPORT_DIR/report.html" "$ROOT_DIR/last_report.html"
fi

# -------------------------------
#  5. Summary
# -------------------------------
echo "[✓] Pipeline completed successfully."
echo "Normalized: $OUT_DIR/normalized_data.json"
echo "Summary:    $REPORT_DIR/summary.json"
echo "HTML:       $REPORT_DIR/report.html"
