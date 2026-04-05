import json
from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLOR = {
    "HIGH":   Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW":    Fore.CYAN,
}

def print_report(findings, target):
    print(f"\n{'='*55}")
    print(f"  Scan Report — {target}")
    print(f"{'='*55}")
    if not findings:
        print(Fore.GREEN + "  No issues found.")
        return
    for f in findings:
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"\n  [{color}{f['severity']}{Style.RESET_ALL}] {f['type']}")
        print(f"         {f['detail']}")
    print(f"\n{'='*55}")
    print(f"  Total issues: {len(findings)}")
    print(f"{'='*55}\n")

def save_json(findings, target, path="report.json"):
    with open(path, "w") as f:
        json.dump({"target": target, "findings": findings}, f, indent=2)
    print(f"  Report saved to {path}")
