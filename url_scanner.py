
---

## 🐍 url_scanner.py (Main Script)

```python
import re
import socket
from urllib.parse import urlparse

# List of suspicious TLDs
SUSPICIOUS_TLDS = ["tk", "gq", "ml", "ga", "cf"]
IP_URL_PATTERN = re.compile(r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}")

# Simple regex for URLs
URL_REGEX = re.compile(
    r"http[s]?://[^\s\"\'<>]+"
)

def is_ip_url(url):
    return bool(IP_URL_PATTERN.match(url))

def is_suspicious_tld(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split('.')[-1]
        return domain.lower() in SUSPICIOUS_TLDS
    except:
        return False

def contains_punycode(url):
    return "xn--" in url

def scan_urls(text):
    urls = URL_REGEX.findall(text)
    print(f"\nFound {len(urls)} URL(s):\n")

    for url in urls:
        flags = []
        if is_ip_url(url):
            flags.append("IP-based URL")
        if is_suspicious_tld(url):
            flags.append("Suspicious TLD")
        if contains_punycode(url):
            flags.append("Punycode (possible lookalike)")

        if flags:
            print(f"[!] {url} - Suspicious ({', '.join(flags)})")
        else:
            print(f"[✓] {url} - Looks okay")

if __name__ == "__main__":
    print("=== URL Scanner ===")
    input_text = input("Paste text containing URLs:\n")
    scan_urls(input_text)
