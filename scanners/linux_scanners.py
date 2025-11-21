import subprocess
from pathlib import Path

OUT = Path("reports/lynis-report.dat")

def run_linux_scan():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    print("[*] Running Lynis host audit (requires sudo)...")
    rc = subprocess.run(["sudo", "lynis", "audit", "system", "--quiet", "--report-file", str(OUT)]).returncode
    if rc != 0:
        raise RuntimeError(f"Lynis exited with code {rc}")
    print("[+] Lynis report saved to", OUT)
