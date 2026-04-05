SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against protocol downgrade attacks",
    "Content-Security-Policy": "Prevents XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features",
}

def check_headers(response):
    findings = []
    for header, description in SECURITY_HEADERS.items():
        if header not in response.headers:
            findings.append({
                "type": "Missing Security Header",
                "severity": "MEDIUM",
                "detail": f"{header} — {description}",
            })
    server = response.headers.get("Server", "")
    if server:
        findings.append({
            "type": "Server Header Leaking Info",
            "severity": "LOW",
            "detail": f"Server header exposes: {server}",
        })
    return findings
