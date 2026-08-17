# 🔒 Cybersecurity Lab

Ethical hacking, penetration testing, and security research toolkit.

## 🎯 What We Do

- **Bug Bounty Hunting** — Find vulnerabilities in authorized systems
- **Penetration Testing** — Assess security of client systems
- **Security Audits** — Review code and configurations
- **AI Red Teaming** — Test AI systems for vulnerabilities

## 🛠️ Tools

### Core Tools

| Tool | Purpose | File |
|------|---------|------|
| **Recon** | Subdomain enumeration, port scanning | `tools/recon.py` |
| **Web Scanner** | SQLi, XSS, CSRF detection | `tools/web_scanner.py` |
| **API Tester** | API security testing | `tools/api_tester.py` |
| **Report Generator** | HTML/JSON/Markdown reports | `tools/report_generator.py` |

### Advanced Tools

| Tool | Purpose | File |
|------|---------|------|
| **Validator** | Eliminate false positives | `tools/validator.py` |
| **Exploiter** | Demonstrate vulnerability impact | `tools/exploiter.py` |
| **Hardening** | Generate security fixes | `tools/hardening.py` |

### Main Entry Points

| Command | Purpose | File |
|---------|---------|------|
| **CLI** | Unified interface | `cybersec.py` |
| **Full Pentest** | Complete workflow | `pentest_complete.py` |

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r tools/requirements.txt

# Run individual tools
python cybersec.py scan --target example.com --full-scan -f html

# Run complete pentest
python pentest_complete.py

# Generate fixes
python tools/hardening.py
```

## 📁 Project Structure

```
cybersecurity-lab/
├── cybersec.py              # Main CLI entry point
├── pentest_complete.py      # Complete pentest workflow
├── tools/
│   ├── recon.py            # Reconnaissance
│   ├── web_scanner.py      # Web vulnerability scanner
│   ├── api_tester.py       # API security tester
│   ├── report_generator.py # Report generation
│   ├── validator.py        # Finding validation
│   ├── exploiter.py        # Vulnerability exploitation
│   └── hardening.py        # Security hardening
├── poc/                    # Proof of concepts
├── reports/                # Generated reports
├── hardening/              # Security fix configurations
└── README.md
```

## 📊 What We Test

### Web Application Security

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Directory Traversal
- Security Headers
- SSL/TLS Configuration

### API Security

- Authentication bypass
- IDOR (Insecure Direct Object References)
- Rate limiting
- Input validation
- Mass assignment

### Infrastructure

- Subdomain enumeration
- Port scanning
- Technology fingerprinting
- Subdomain takeover

## 🔧 Generated Fixes

The `hardening/` directory contains:

- `nginx.conf` — Nginx security configuration
- `cloudflare_rules.txt` — Cloudflare WAF rules
- `fastapi_middleware.py` — FastAPI security middleware
- `react_security.js` — React security utilities

## 📈 Income Streams

1. **Bug Bounties** — ₹5K-₹25L per finding
2. **Pen Testing** — ₹50K-₹5L per engagement
3. **Consulting** — ₹10K-₹1L per hour
4. **Training** — Create courses, writeups

## ⚠️ Legal Disclaimer

**We only test systems we own or have written authorization to test.**

- Bug bounty programs with explicit scope
- Client engagements with signed agreements
- Our own infrastructure for practice

## 📚 Resources

- [HackerOne](https://hackerone.com) — Bug bounty platform
- [Bugcrowd](https://bugcrowd.com) — Bug bounty platform
- [Hack The Box](https://hackthebox.com) — Training platform
- [OWASP](https://owasp.org) — Security guidelines

---

*Built with ❤️ by Hermes AI Security Lab*
