#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(pwd)"
OUT_DIR="${OUT_DIR:-out}"
REPORT_DIR="${REPORT_DIR:-reports}"
LOG_DIR="${LOG_DIR:-logs}"
VENV="${VENV:-${ROOT_DIR}/.venv}"
mkdir -p "$OUT_DIR" "$REPORT_DIR" "$LOG_DIR"

echo "[*] Step: Normalize + Compliance Mapping" | tee -a "$LOG_DIR/steps.log"
. "$VENV/bin/activate" 2>/dev/null || true

# Discover inputs (if any)
PROWLER_GLOBS=( output/prowler-output-*.json )
LYNIS_GLOBS=( reports/lynis-report*.dat )
FOUND_PROWLER=$(ls ${PROWLER_GLOBS[*]} 2>/dev/null || true)
FOUND_LYNIS=$(ls ${LYNIS_GLOBS[*]} 2>/dev/null || true)

set -x
if [[ -n "${FOUND_PROWLER}" || -n "${FOUND_LYNIS}" ]]; then
  # We have raw scanner outputs – run normalize.py
  python3 normalize.py \
    --in ${FOUND_PROWLER:-} ${FOUND_LYNIS:-} \
    --out "$OUT_DIR"
else
  # No raw outputs – build compliance from existing normalized file if present
  if [[ -f "$OUT_DIR/normalized_findings.json" ]]; then
    python3 - "$OUT_DIR/normalized_findings.json" "$OUT_DIR/compliance_summary.json" <<'PY'
import json, sys, os
src, dst = sys.argv[1], sys.argv[2]
with open(src, 'r', encoding='utf-8') as f:
    findings = json.load(f)
from collections import defaultdict
agg = defaultdict(lambda: {"failing_controls": defaultdict(int),
                           "passing_controls": defaultdict(int)})
for f in findings:
    status = (f.get("status") or "").upper()
    for ctrl in (f.get("compliance") or []):
        fw = ctrl.split(":", 1)[0] if ":" in ctrl else "Unknown"
        if status in ("FAIL","ALARM","WARNING","SUGGESTION"):
            agg[fw]["failing_controls"][ctrl] += 1
        else:
            agg[fw]["passing_controls"][ctrl] += 1
def plain(d):
    if isinstance(d, dict):
        return {k: plain(v) for k, v in d.items()}
    return d
os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
with open(dst, "w", encoding="utf-8") as f:
    json.dump(plain(agg), f, indent=2)
print("Compliance summary written:", dst)
PY
  else
    echo "[!] Neither scanner outputs nor out/normalized_findings.json found. Cannot build compliance."
  fi
fi
set +x

# Sanity check – fail fast if normalized file is totally missing
if [[ ! -f "$OUT_DIR/normalized_findings.json" ]]; then
  echo "[!] Missing $OUT_DIR/normalized_findings.json – report cannot be generated."
  ls -l "$OUT_DIR" || true
  exit 1
fi

# Try to ensure compliance exists (don’t fail the build if it doesn’t)
if [[ -f "$OUT_DIR/compliance_summary.json" ]]; then
  echo "[✓] compliance_summary.json present."
else
  echo "[i] compliance_summary.json not found; continuing without compliance summary."
fi

echo "[*] Step: Generate report" | tee -a "$LOG_DIR/steps.log"
# NOTE: use normalized_findings.json (NOT normalized_data.json)
python3 generate_report.py --in "$OUT_DIR/normalized_findings.json" --out "$REPORT_DIR"

# Stable copies for Jenkins alerting
if [[ -f "$REPORT_DIR/summary.json" ]]; then
  cp "$REPORT_DIR/summary.json" "$ROOT_DIR/last_summary.json"
fi
if [[ -f "$REPORT_DIR/report.html" ]]; then
  cp "$REPORT_DIR/report.html" "$ROOT_DIR/last_report.html"
fi

echo "[✓] Done."
echo "Normalized: $OUT_DIR/normalized_findings.json"
echo "Compliance: $OUT_DIR/compliance_summary.json"
echo "Summary:    $REPORT_DIR/summary.json"
echo "HTML:       $REPORT_DIR/report.html"
