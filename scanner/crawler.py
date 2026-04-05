import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(base_url, session, max_pages=20):
    visited = set()
    to_visit = [base_url]
    forms = []
    base_domain = urlparse(base_url).netloc

    print(f"  [*] Crawling {base_url} (max {max_pages} pages)...")

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)

        if url in visited:
            continue

        try:
            resp = session.get(url, timeout=5, allow_redirects=True)
            visited.add(url)
            print(f"      Found: {url}")
        except Exception:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Collect all links
        for tag in soup.find_all("a", href=True):
            full_url = urljoin(base_url, tag["href"])
            parsed = urlparse(full_url)
            # Stay on same domain, skip fragments and non-http
            if parsed.netloc == base_domain and parsed.scheme in ("http", "https"):
                if full_url not in visited:
                    to_visit.append(full_url)

        # Collect all forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            full_action = urljoin(url, action)
            inputs = []
            for inp in form.find_all(["input", "textarea"]):
                inp_name = inp.get("name")
                inp_type = inp.get("type", "text")
                if inp_name:
                    inputs.append({"name": inp_name, "type": inp_type})
            if inputs:
                forms.append({
                    "page": url,
                    "action": full_action,
                    "method": method,
                    "inputs": inputs,
                })

    print(f"\n  [*] Crawl complete — {len(visited)} pages, {len(forms)} forms found\n")
    return list(visited), forms
