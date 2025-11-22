#!/usr/bin/env bash
set -euo pipefail

# ==============================
# Paths & env (override via Jenkins env if needed)
# ==============================
ROOT_DIR="$(pwd)"
OUT_DIR="${OUT_DIR:-out}"
REPORT_DIR="${REPORT_DIR:-reports}"
LOG_DIR="${LOG_DIR:-logs}"
VENV="${VENV:-${ROOT_DIR}/.venv}"

mkdir -p "$OUT_DIR" "$REPORT_DIR" "$LOG_DIR"

# Activate venv if present (don't fail if missing)
. "$VENV/bin/activate" 2>/dev/null || true

echo "[*] Pipeline start @ $(date -Is)" | tee -a "$LOG_DIR/steps.log"

# ==============================
# 1) (Optional) Run scanners here
#    Leave them commented if you feed stored outputs
# ==============================
# echo "[*] Running scanners..." | tee -a "$LOG_DIR/steps.log"
# prowler -M json > "output/prowler-output-$(date +%s).json" || true
# lynis audit system --quick --quiet \
#   --logfile "$LOG_DIR/lynis.log" \
#   --report-file "reports/lynis-report.dat" || true

# ==============================
# 2) Normalize raw outputs (Prowler + Lynis)
# ==============================
echo "[*] Normalizing scanner outputs..." | tee -a "$LOG_DIR/steps.log"
python3 normalize.py \
  --in output/prowler-output-*.json reports/lynis-report*.dat \
  --out "$OUT_DIR" || echo "[!] Normalization skipped (no raw files matched)"

# If normalization didn’t emit the canonical file, make an empty one
if [ ! -f "$OUT_DIR/normalized_findings.json" ]; then
  echo "[]" > "$OUT_DIR/normalized_findings.json"
  echo "[i] Created empty $OUT_DIR/normalized_findings.json"
fi

# ==============================
# 3) Build compliance_summary.json from normalized data
# ==============================
echo "[*] Building compliance summary..." | tee -a "$LOG_DIR/steps.log"
python3 - <<'PY'
import json, os
from collections import defaultdict

SRC = "out/normalized_findings.json"
DST = "out/compliance_summary.json"

with open(SRC, "r", encoding="utf-8") as f:
    findings = json.load(f)

agg = defaultdict(lambda: {
    "failing_controls": defaultdict(int),
    "passing_controls": defaultdict(int),
})

for item in findings:
    status = (item.get("status") or "").upper()
    for ctrl in (item.get("compliance") or []):
        fw = ctrl.split(":", 1)[0] if ":" in ctrl else "Unknown"
        bucket = "failing_controls" if status in ("FAIL", "ALARM", "WARNING", "SUGGESTION") else "passing_controls"
        agg[fw][bucket][ctrl] += 1

def plain(d):
    if isinstance(d, dict):
        return {k: plain(v) for k, v in d.items()}
    return d

os.makedirs("out", exist_ok=True)
with open(DST, "w", encoding="utf-8") as f:
    json.dump(plain(agg), f, indent=2)
print(f"[✓] Wrote {DST}")
PY

# ==============================
# 4) Generate HTML/PDF reports
# ==============================
echo "[*] Generating report..." | tee -a "$LOG_DIR/steps.log"
python3 generate_report.py \
  --in "$OUT_DIR/normalized_findings.json" \
  --out "$REPORT_DIR"

# (If your generator emits a risk report too, it’ll be in $REPORT_DIR)
[ -f "$REPORT_DIR/risk_report.html" ] && echo "[i] Risk report: $REPORT_DIR/risk_report.html"

# ==============================
# 5) Stable copies for alerting (Jenkins can email/slack these)
# ==============================
if [ -f "$REPORT_DIR/summary.json" ]; then
  cp -f "$REPORT_DIR/summary.json" "$ROOT_DIR/last_summary.json"
fi
if [ -f "$REPORT_DIR/report.html" ]; then
  cp -f "$REPORT_DIR/report.html" "$ROOT_DIR/last_report.html"
fi

# ==============================
# 6) Debug listing (shows up in Jenkins console)
# ==============================
echo "---- DEBUG: contents of out/ ----"
ls -al "$OUT_DIR" || true
echo "---- DEBUG: contents of reports/ ----"
ls -al "$REPORT_DIR" || true

# ==============================
# 7) Summary
# ==============================
echo "[✓] Pipeline completed."
echo "Normalized JSON : $OUT_DIR/normalized_findings.json"
echo "Compliance JSON : $OUT_DIR/compliance_summary.json"
echo "Summary JSON    : $REPORT_DIR/summary.json (if generated)"
echo "HTML Report     : $REPORT_DIR/report.html"
