SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' AND 1=2--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3",
    "odbc_exec",
    "ora-01756",
    "mysql_fetch",
    "syntax error",
]

def check_sqli(forms, session):
    findings = []

    for form in forms:
        for payload in SQLI_PAYLOADS:
            data = {}
            for inp in form["inputs"]:
                if inp["type"] not in ("submit", "hidden", "checkbox"):
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = "test"

            try:
                if form["method"] == "POST":
                    resp = session.post(form["action"], data=data, timeout=5)
                else:
                    resp = session.get(form["action"], params=data, timeout=5)

                body = resp.text.lower()
                for error in SQLI_ERRORS:
                    if error in body:
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "HIGH",
                            "detail": f"Payload '{payload}' triggered SQL error on {form['action']}",
                        })
                        break

            except Exception:
                pass

    return findings
