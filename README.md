A Python-based web vulnerability scanner that automatically detects common security issues in web applications — built from scratch as a hands-on DevSecOps portfolio project.

---

## 🚀 What It Does

This tool crawls a target web application and tests for:

| Check | Type | Severity |
|---|---|---|
| Missing security headers (CSP, HSTS, X-Frame-Options, etc.) | Passive | MEDIUM |
| Server version disclosure | Passive | LOW |
| Sensitive file/path exposure (.env, phpinfo.php, .git, etc.) | Active | HIGH/MEDIUM |
| SQL Injection (error-based) | Active | HIGH |
| Reflected XSS | Active | HIGH |

Outputs a **colored terminal report** and a **downloadable HTML report** with severity breakdown.

---

## 📸 Sample Output
[HIGH]   SQL Injection — Payload "'" triggered SQL error on /vulnerabilities/sqli/
[HIGH]   Reflected XSS — Payload reflected on /vulnerabilities/xss_r/ via input 'name'
[HIGH]   Sensitive File/Path Exposed — /phpinfo.php returned HTTP 200
[MEDIUM] Missing Security Header — Content-Security-Policy
[LOW]    Server Header Leaking Info — Apache/2.4.25 (Debian)
Total issues: 23

---

## 🛠️ Tech Stack

- **Python 3** — core language
- **requests** — HTTP client
- **BeautifulSoup4** — HTML parsing and form discovery
- **colorama** — colored terminal output

---

## ⚙️ Installation
```bash
git clone https://github.com/halbeadi/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

---

## 💻 Usage

**Basic scan:**
```bash
python main.py --url http://target.com
```

**With custom page limit:**
```bash
python main.py --url http://target.com --max-pages 30
```

**With HTML report:**
```bash
python main.py --url http://target.com --html report.html
```

**Against DVWA (local lab):**
```bash
python main.py --url http://localhost:8080 --dvwa --max-pages 20
```

---

## 🏗️ Project Structure
web-vuln-scanner/
├── scanner/
│   ├── headers.py        # Security header checks
│   ├── fuzzer.py         # Sensitive file/path discovery
│   ├── crawler.py        # Link and form crawler
│   ├── sqli.py           # SQL injection detection
│   ├── xss.py            # Reflected XSS detection
│   └── html_reporter.py  # HTML report generator
├── main.py               # CLI entrypoint
├── requirements.txt
└── README.md

---

## 🧪 Testing

Tested against [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) running locally via Docker:
```bash
docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
python main.py --url http://localhost:8080 --dvwa --max-pages 20
```

**Results against DVWA:**
- 10 SQL Injection findings
- 3 Reflected XSS findings
- 1 Sensitive file exposure (phpinfo.php)
- 9 passive findings (headers, server info)
- **23 total issues detected**

---

## ⚠️ Legal Disclaimer

This tool is for **educational purposes only**. Only scan web applications you own or have **explicit written permission** to test. Unauthorized scanning is illegal.

---

## 👤 Author

**Aditya Halbe** — Cloud & DevSecOps Engineer  
CEH Certified  
[GitHub](https://github.com/halbeadi) · [LinkedIn](https://linkedin.com/in/halbeadi)
