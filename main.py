from pathlib import Path
from scanners.aws_scanner import run_aws_scan
from scanners.linux_scanner import run_linux_scan
from utils.report_generator import generate_summary

def main():
    print("=== Cloud & Host Misconfiguration Scanner ===")

    try:
        run_aws_scan()  # <-- no reuse_existing arg
    except Exception as e:
        print("[!] AWS scan failed:", e)

    if not Path("reports/lynis-report.dat").exists():
        try:
            run_linux_scan()
        except Exception as e:
            print("[!] Linux scan failed:", e)
    else:
        print("[i] Using existing reports/lynis-report.dat")

    generate_summary()
    print("=== All done. Reports in 'reports/' ===")

if __name__ == "__main__":
    main()
