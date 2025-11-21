import subprocess
from pathlib import Path
import os

OUT = Path("reports/lynis-report.dat")

def run_linux_scan():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    print("[*] Running Lynis host audit (requires sudo)...")

    # Run the Lynis scan with sudo
    rc = subprocess.run([
        "sudo", "lynis", "audit", "system",
        "--quiet", "--report-file", str(OUT)
    ]).returncode

    # Handle non-zero return code
    if rc != 0:
        raise RuntimeError(f"Lynis exited with code {rc}")

    # Fix file ownership & permissions after the scan
    user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    subprocess.run(["sudo", "chown", f"{user}:{user}", str(OUT)])
    subprocess.run(["sudo", "chmod", "644", str(OUT)])

    print(f"[+] Lynis report saved to {OUT}")

