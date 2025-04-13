# 🕵️‍♂️ URL Scanner for Suspicious Links

This Python-based tool extracts and analyzes URLs from a block of text (e.g., emails, messages, comments) and flags links that may be potentially malicious or suspicious.

Great for awareness, education, and helping beginners understand common traits of phishing URLs.

---

## 🔍 Features

- Extracts all URLs from input text
- Detects:
  - IP-based URLs
  - Suspicious TLDs (e.g., `.tk`, `.gq`, `.ml`)
  - Obfuscated domains (punycode, long subdomains, uncommon characters)
- Compares against a sample blacklist (manually or from an API — coming soon)

---

## 🚀 How to Use

1. Clone the repo:

#```bash
git clone https://github.com/yourusername/url-malicious-scanner.git
cd url-malicious-scanner



2. Run the scanner:

python3 url_scanner.py



3. Paste or type the text containing links when prompted.




📌 Sample Suspicious Patterns
http://192.168.1.1/login.php — IP-based URL

http://paypal.account.verify-login.tk — Suspicious subdomain + TLD

http://xn--pple-43d.com — Punycode for lookalike domains



📸 Example Output

Found 3 URLs in the message.

[!] http://192.168.0.1/login.php - Suspicious (IP-based)
[!] http://secure-update.gq - Suspicious (TLD: .gq)
[✓] https://www.github.com - Safe



📚 Educational Value
This tool is a good exercise in:

Regex and URL parsing

Basic link threat detection

Building practical cybersecurity awareness tools



🛑 Disclaimer
This tool does NOT guarantee a URL is safe or unsafe — it performs basic static checks only. For real-world use, integrate threat intelligence APIs.


⭐ Show Support
Give the repo a ⭐ if you found it helpful and follow for more cybersecurity awareness tools.
