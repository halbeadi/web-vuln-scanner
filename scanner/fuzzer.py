SENSITIVE_PATHS = [
    ".env", ".git/config", "admin/", "phpinfo.php",
    "config.php", "backup.sql", "wp-admin/",
    "server-status", ".htaccess", "debug/",
    "api/v1/users", "console/", "actuator/health",
]

def check_sensitive_files(base_url, session):
    findings = []
    base_url = base_url.rstrip("/")
    for path in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"
        try:
            resp = session.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in (200, 403):
                findings.append({
                    "type": "Sensitive File/Path Exposed",
                    "severity": "HIGH" if resp.status_code == 200 else "MEDIUM",
                    "detail": f"{url} returned HTTP {resp.status_code}",
                })
        except Exception:
            pass
    return findings
