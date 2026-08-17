# Recon Tool

Advanced domain reconnaissance tool with subdomain enumeration, port scanning, and technology fingerprinting.

## Features

- **Subdomain Enumeration** - DNS bruteforce + subfinder passive discovery
- **Port Scanning** - Nmap integration with raw socket fallback
- **Technology Fingerprinting** - HTTP headers, meta tags, body patterns, cookies
- **Async Operations** - Parallel execution for speed
- **JSON Output** - Machine-readable results

## Installation

```bash
pip install -r requirements.txt
```

External tools (optional):
- [subfinder](https://github.com/projectdiscovery/subfinder) - Passive subdomain enumeration
- [nmap](https://nmap.org/) - Advanced port scanning

## Usage

```bash
# Basic scan
python tools/recon.py example.com

# Custom port range
python tools/recon.py example.com -p 80,443,8080

# Verbose output with custom file
python tools/recon.py example.com -o results.json -v

# Skip fingerprinting
python tools/recon.py example.com --no-fingerprint

# Print JSON to stdout
python tools/recon.py example.com --json-stdout
```

## Output Format

```json
{
  "domain": "example.com",
  "timestamp": "2024-01-01T00:00:00Z",
  "subdomains": ["www.example.com", "api.example.com"],
  "ports": {
    "example.com": [
      {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
    ]
  },
  "fingerprinting": [
    {
      "url": "https://example.com",
      "technologies": ["Nginx", "React"],
      "status": 200
    }
  ],
  "summary": {
    "subdomains_found": 2,
    "hosts_with_open_ports": 1,
    "total_open_ports": 1,
    "technologies_detected": ["Nginx", "React"],
    "duration_seconds": 12.5
  }
}
```

## CLI Options

| Flag | Description |
|------|-------------|
| `-p, --ports` | Port range (default: 1-1000) |
| `-o, --output` | Output file path |
| `-v, --verbose` | Debug logging |
| `--no-subfinder` | Skip subfinder |
| `--no-fingerprint` | Skip fingerprinting |
| `--json-stdout` | Print JSON to stdout |

## License

For authorized security testing only.
