# JSExtractor

<p align="center">
  <b>Automated JavaScript Reconnaissance and Security Analysis Tool</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.6+-blue.svg" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Maintained-Yes-brightgreen.svg" alt="Maintained">
</p>

---

## Overview

**JSExtractor** is a powerful security reconnaissance tool designed for bug bounty hunters and penetration testers. It automatically:

- **Downloads** JavaScript files from a list of URLs (with concurrent downloads)
- **Scans** for secrets and credentials using 40+ built-in regex patterns
- **Extracts** URLs and relative paths from JS source code
- **Categorizes** findings (API routes, admin paths, auth endpoints)
- **Generates** a detailed REPORT.txt with all findings
- **Discovers** additional JS files for iterative reconnaissance

Perfect companion to [BurpJSCollector](https://github.com/yourusername/BurpJSCollector)!

## Key Features

### Complete URL Extraction
Extracts full URLs and relative paths from JavaScript source:

```
URLs:     https://api.example.com/v2/users
Paths:    /api/users, /admin/dashboard, /auth/login
```

### Iterative Reconnaissance
Automatically discovers new JS files referenced in code:
```bash
Round 1: 10 files -> discovers 15 more
Round 2: 25 files -> discovers 30 more
Round 3: 55 files -> keep going deeper!
```

### Smart Categorization
Automatically organizes findings:
- API Endpoints (`/api/`, `/v1/`, `/graphql`)
- Admin/Dashboard Paths (`/admin`, `/dashboard`)
- Authentication Paths (`/auth`, `/login`, `/signup`)
- User Profile Paths (`/user`, `/profile`, `/account`)
- Analytics/Tracking URLs
- CDN Resources

### Built-in Secret Scanning
Detects 145+ secret types with tuned regex patterns:
- AI/LLM keys (OpenAI, Anthropic, Groq, HuggingFace, Replicate, etc.)
- Cloud keys (AWS, Google, Azure, DigitalOcean, Vercel, Netlify)
- API keys and tokens (Stripe, Slack, GitHub, GitLab, etc.)
- Database URIs (MongoDB, PostgreSQL, MySQL, Redis, PlanetScale)
- Secrets management (Vault, Doppler, Pulumi, Terraform)
- Monitoring (Sentry, Datadog, New Relic, Grafana, Dynatrace)
- CI/CD tokens (Buildkite, npm, PyPI, Docker Hub)
- Private keys, JWTs, Bearer tokens
- Hardcoded credentials, S3 buckets, and more

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/JSExtractor.git
cd JSExtractor

# No dependencies required - uses Python standard library only
python js_recon.py -h
```

### Basic Usage

```bash
# 1. Create a file with JavaScript URLs (one per line)
cat > targets.txt << EOF
https://example.com/static/app.js
https://example.com/js/bundle.js
https://api.example.com/client.js
EOF

# 2. Run the scan
python js_recon.py targets.txt

# 3. Review findings
cat scans/targets_*/results/REPORT.txt
```

## Usage Examples

### Example 1: Basic Bug Bounty Workflow

```bash
# Collect JS URLs using BurpJSCollector or manually
python js_recon.py js_files.txt

# Review the main report
cat scans/js_files_*/results/REPORT.txt

# Check extracted URLs and paths separately
cat scans/js_files_*/results/urls.txt
cat scans/js_files_*/results/paths.txt
```

### Example 2: Domain-Prefixed Paths

```bash
# Prepend a domain to extracted paths for ready-to-test URLs
python js_recon.py js_files.txt --domain ads.tiktok.com
```

### Example 3: Iterative Deep Scan

```bash
# Round 1: Initial scan
python js_recon.py initial_urls.txt

# Round 2: Scan discovered JS files
python js_recon.py scans/initial_urls_*/results/js_files.txt

# Round 3: Go even deeper
python js_recon.py scans/js_files_*/results/js_files.txt
```

### Example 4: Keep Downloaded Files

```bash
# Keep JS files for manual inspection (deleted by default)
python js_recon.py urls.txt --keep

# Use more download threads for large lists
python js_recon.py urls.txt --workers 20
```

### Example 5: Integration with BurpJSCollector

```bash
# 1. Use BurpJSCollector to collect JS URLs from Burp Suite
# 2. Export as js_files.txt
# 3. Analyze with JSExtractor
python js_recon.py js_files.txt
```

## Output Structure

```
scans/
└── targets_2026-01-13_14-30-45/
    ├── downloaded/              # JS files by domain (deleted unless --keep)
    │   ├── example.com/
    │   └── cdn.example.com/
    └── results/
        ├── REPORT.txt           # <-- START HERE - Full scan report
        ├── urls.txt             # All extracted URLs
        ├── paths.txt            # All extracted paths
        └── js_files.txt         # All JS files (original + discovered)
```

## Command-Line Options

```
usage: js_recon.py [-h] [--domain DOMAIN] [--keep] [--workers WORKERS] urls_file

positional arguments:
  urls_file          Text file containing JS URLs (one per line)

options:
  --domain DOMAIN    Target domain to prepend to extracted paths
  --keep             Keep downloaded JS files instead of deleting after scan
  --workers WORKERS  Number of concurrent download threads (default: 10)
```

## Requirements

- Python 3.6 or higher (standard library only, no pip install needed)
- Internet connection for downloading JS files

## Use Cases

### Bug Bounty Hunting
- Discover hidden API endpoints
- Find admin panels and dashboards
- Identify authentication mechanisms
- Extract API keys and secrets
- Map application structure

### Penetration Testing
- Reconnaissance phase
- Asset discovery
- Endpoint enumeration
- Credential harvesting
- Attack surface mapping

### Security Research
- JavaScript analysis
- Application mapping
- Dependency discovery
- Version detection

## Sample Output

```
======================================================================
SCAN COMPLETE
======================================================================

Scan Directory: scans/targets_2026-01-13_14-30-45

Files Analyzed:  15
Secrets Found:   2
URLs Extracted:  127
Paths Extracted: 43
JS Files Total:  28
  - API Endpoints: 18
  - Admin Paths: 3
  - Auth Paths: 7

Output files (in scans/targets_2026-01-13_14-30-45/results):
  REPORT.txt   - Full scan report
  urls.txt     - All extracted URLs
  paths.txt    - All extracted paths
  js_files.txt - All JS files (original + discovered)
======================================================================
```

## Perfect Companion Tools

**[BurpJSCollector](https://github.com/yourusername/BurpJSCollector)** - Burp Suite extension to collect JS file URLs

Complete workflow:
1. Browse target with Burp + BurpJSCollector
2. Export JS file URLs
3. Analyze with JSExtractor
4. Review findings

## Security Notice

This tool is for **authorized security testing only**:
- Bug bounty programs
- Penetration testing with permission
- Your own applications

**You are responsible for ensuring you have permission before testing any systems.**

## Troubleshooting

### No URLs/Paths Extracted
- JS files may be heavily minified/obfuscated
- Try different JS files that are more readable

### Download Failures
- Check internet connection
- Some URLs may require authentication
- Verify URLs are correct

## License

This project is licensed under the MIT License with Attribution Requirement - see the [LICENSE](LICENSE) file for details.

### Attribution Requirements

If you use this tool commercially or create improvements/modifications:

**Required:**
- Provide clear attribution: "Based on JSExtractor by Shan Majeed"
- Include a link to this repository
- State if you've made modifications

**Example Attribution:**
```
This tool uses JSExtractor by Shan Majeed (https://github.com/yourusername/JSExtractor)
Modified to add [your changes]
```

### Give Credit

If you:
- Use this in a commercial product
- Create an improved version
- Fork and modify it
- Include it in another tool

**Please credit the original author!** It helps the community and supports open-source development.

## Acknowledgments

- Bug bounty and security research community

## Show Your Support

If you find JSExtractor useful, please consider:
- Starring the repository
- Sharing with the security community
- Contributing improvements
- Reporting bugs

---

<p align="center">
  Made with care for the security research community
</p>
