XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

def check_xss(forms, session):
    findings = []

    for form in forms:
        for payload in XSS_PAYLOADS:
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

                if payload in resp.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "HIGH",
                        "detail": f"Payload reflected on {form['action']} via input '{list(data.keys())[0]}'",
                    })
                    break

            except Exception:
                pass

    return findings
