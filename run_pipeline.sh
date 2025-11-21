#!/usr/bin/env bash
set -euo pipefail

# --- defaults (keep these near the top) ---
ROOT_DIR="$(pwd)"
OUT_DIR="${OUT_DIR:-out}"
REPORT_DIR="${REPORT_DIR:-reports}"
LOG_DIR="${LOG_DIR:-logs}"
mkdir -p "$OUT_DIR" "$REPORT_DIR" "$LOG_DIR"

# … your prowler + lynis + normalize steps …

echo "[*] Generating report..." | tee -a "$LOG_DIR/steps.log"
python3 generate_report.py --in "$OUT_DIR/normalized_data.json" --out "$REPORT_DIR"

# --- stable copies for Jenkins alerting (ADD THIS BLOCK) ---
if [ -f "$REPORT_DIR/summary.json" ]; then
  cp "$REPORT_DIR/summary.json" "$ROOT_DIR/last_summary.json"
fi
if [ -f "$REPORT_DIR/report.html" ]; then
  cp "$REPORT_DIR/report.html" "$ROOT_DIR/last_report.html"
fi

echo "[✓] Done."
echo "Normalized: $OUT_DIR/normalized_data.json"
echo "Summary:    $REPORT_DIR/summary.json"
echo "HTML:       $REPORT_DIR/report.html"
