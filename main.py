import argparse
import requests
from scanner.headers import check_headers
from scanner.fuzzer import check_sensitive_files
from scanner.reporter import print_report, save_json

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost)")
    parser.add_argument("--output", default="report.json", help="Output JSON report path")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    print(f"\n  Starting scan on: {target}\n")

    session = requests.Session()
    session.headers.update({"User-Agent": "WebVulnScanner/1.0"})

    findings = []

    print("  [*] Checking security headers...")
    try:
        resp = session.get(target, timeout=10)
        findings += check_headers(resp)
    except Exception as e:
        print(f"  [!] Could not reach target: {e}")
        return

    print("  [*] Fuzzing for sensitive files...")
    findings += check_sensitive_files(target, session)

    print_report(findings, target)
    save_json(findings, target, args.output)

if __name__ == "__main__":
    main()
