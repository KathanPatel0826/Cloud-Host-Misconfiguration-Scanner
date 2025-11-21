import subprocess
from pathlib import Path

OUT = Path("reports/aws_scan.json")

def run_aws_scan():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    print("[*] Starting AWS scan (Prowler)...")

    # prefer a local prowler binary
    proc = subprocess.run(["prowler", "-M", "json", "-q"], capture_output=True, text=True)
    if proc.returncode != 0:
        print("[!] prowler exited with code", proc.returncode)
        print(proc.stderr)
        raise RuntimeError("Prowler failed")
    OUT.write_text(proc.stdout)
    print("[+] AWS scan saved to", OUT)
