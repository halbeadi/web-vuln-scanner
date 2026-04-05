import argparse
import requests
from scanner.headers import check_headers
from scanner.fuzzer import check_sensitive_files
from scanner.crawler import crawl
from scanner.sqli import check_sqli
from scanner.xss import check_xss
from scanner.reporter import print_report, save_json

def dvwa_login(session, base_url):
    login_url = f"{base_url}/login.php"
    try:
        # Get CSRF token first
        resp = session.get(login_url, timeout=10)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        token = soup.find("input", {"name": "user_token"})
        token_val = token["value"] if token else ""

        # Login
        session.post(login_url, data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token_val,
        }, timeout=10)

        # Set security to low so forms are vulnerable
        session.get(f"{base_url}/security.php", timeout=5)
        session.post(f"{base_url}/security.php", data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": token_val,
        }, timeout=5)

        print("  [*] Logged into DVWA (security level: low)\n")
    except Exception as e:
        print(f"  [!] DVWA login failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--output", default="report.json", help="Output JSON report path")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl")
    parser.add_argument("--dvwa", action="store_true", help="Enable DVWA login")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    print(f"\n  Starting scan on: {target}\n")

    session = requests.Session()
    session.headers.update({"User-Agent": "WebVulnScanner/1.0"})

    # Login to DVWA if flag is set
    if args.dvwa:
        dvwa_login(session, target)

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

    print("  [*] Crawling site...")
    pages, forms = crawl(target, session, max_pages=args.max_pages)

    if forms:
        print(f"  [*] Found {len(forms)} form(s) — testing for SQLi and XSS...\n")
        print("  [*] Testing for SQL Injection...")
        findings += check_sqli(forms, session)
        print("  [*] Testing for XSS...")
        findings += check_xss(forms, session)
    else:
        print("  [*] No forms found — skipping SQLi/XSS tests")

    print_report(findings, target)
    save_json(findings, target, args.output)

if __name__ == "__main__":
    main()
