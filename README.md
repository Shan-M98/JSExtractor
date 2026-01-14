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

## 📋 Overview

**JSExtractor** is a powerful security reconnaissance tool designed for bug bounty hunters and penetration testers. It automatically:

- 🔍 **Downloads** JavaScript files from a list of URLs
- 🔐 **Scans** for secrets and credentials using TruffleHog
- 🌐 **Extracts** complete URLs and API endpoints (not relative paths!)
- 📊 **Categorizes** findings (API routes, admin paths, auth endpoints)
- 📝 **Generates** detailed security findings reports
- 🔄 **Discovers** additional JS files for iterative reconnaissance

Perfect companion to [BurpJSCollector](https://github.com/yourusername/BurpJSCollector)!

## ✨ Key Features

### Complete URL Extraction
Unlike other tools that show relative paths, JSExtractor provides **full, testable URLs**:

```
❌ Other tools: /api/users
✅ JSExtractor: https://example.com/api/users
```

### Iterative Reconnaissance
Automatically discovers new JS files referenced in code:
```bash
Round 1: 10 files → discovers 15 more
Round 2: 25 files → discovers 30 more
Round 3: 55 files → keep going deeper!
```

### Smart Categorization
Automatically organizes findings:
- 🔗 API Endpoints
- 🔒 Admin/Dashboard Paths
- 🔑 Authentication Paths
- 👤 User Profile Paths
- 📊 Analytics/Tracking URLs
- 🌐 CDN Resources

### Comprehensive Secret Scanning
Powered by TruffleHog, detects 700+ secret types:
- API Keys (AWS, GitHub, Slack, etc.)
- Database Credentials
- Private Keys
- Authentication Tokens
- And more...

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/JSExtractor.git
cd JSExtractor

# Install dependencies
pip install -r requirements.txt

# Verify installation
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
cat scans/targets_*/results/FINDINGS.txt
```

## 📖 Usage Examples

### Example 1: Basic Bug Bounty Workflow

```bash
# Collect JS URLs using BurpJSCollector or manually
python js_recon.py js_files.txt

# Review the main findings report
cat scans/js_files_*/results/FINDINGS.txt

# Check for API endpoints
cat scans/js_files_*/results/paths_api_routes.txt

# Check for admin paths
cat scans/js_files_*/results/paths_admin_paths.txt
```

### Example 2: Iterative Deep Scan

```bash
# Round 1: Initial scan
python js_recon.py initial_urls.txt

# Round 2: Scan discovered JS files
python js_recon.py scans/initial_urls_*/results/all_js_files.txt

# Round 3: Go even deeper
python js_recon.py scans/all_js_files_*/results/all_js_files.txt
```

### Example 3: Integration with BurpJSCollector

```bash
# 1. Use BurpJSCollector to collect JS URLs from Burp Suite
# 2. Export as js_files.txt
# 3. Analyze with JSExtractor
python js_recon.py js_files.txt
```

## 📂 Output Structure

```
scans/
└── targets_2026-01-13_14-30-45/
    ├── downloaded/                     # Downloaded JS files by domain
    │   ├── example.com/
    │   └── cdn.example.com/
    └── results/
        ├── FINDINGS.txt               # 👈 START HERE - Main report
        ├── all_js_files.txt           # Master list (original + discovered)
        ├── summary.txt                # Quick statistics
        ├── extracted_urls.txt         # All URLs found
        ├── extracted_paths.txt        # All endpoint URLs
        ├── trufflehog_results.json    # Secret scan results
        ├── urls_api_endpoints.txt     # Categorized URLs
        ├── urls_analytics.txt
        ├── urls_cdn_urls.txt
        ├── paths_api_routes.txt       # Categorized paths
        ├── paths_admin_paths.txt
        └── paths_auth_paths.txt
```

## 🔧 Requirements

- Python 3.6 or higher
- TruffleHog (installed via requirements.txt)
- Internet connection for downloading JS files

## 🎯 Use Cases

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

## 📊 Sample Output

```
======================================================================
SCAN COMPLETE - FINDINGS SUMMARY
======================================================================

Scan Directory: scans/targets_2026-01-13_14-30-45

Files Analyzed: 15
Secrets Found: 2
URLs Extracted: 127
Endpoint URLs Extracted: 43
Total JS Files (original + discovered): 28
  - API Endpoints: 18
  - Admin Paths: 3
  - Auth Paths: 7

[!] IMPORTANT: Review scans/targets_2026-01-13_14-30-45\results\FINDINGS.txt

[✓] All results saved to: scans/targets_2026-01-13_14-30-45
======================================================================
```

## 🤝 Perfect Companion Tools

**[BurpJSCollector](https://github.com/yourusername/BurpJSCollector)** - Burp Suite extension to collect JS file URLs

Complete workflow:
1. Browse target with Burp + BurpJSCollector
2. Export JS file URLs
3. Analyze with JSExtractor
4. Review findings

## 🛡️ Security Notice

This tool is for **authorized security testing only**:
- ✅ Bug bounty programs
- ✅ Penetration testing with permission
- ✅ Your own applications
- ❌ Unauthorized scanning
- ❌ Malicious use

**You are responsible for ensuring you have permission before testing any systems.**

## 🐛 Troubleshooting

### No URLs/Paths Extracted
- JS files may be heavily minified/obfuscated
- Try different JS files that are more readable

### Download Failures
- Check internet connection
- Some URLs may require authentication
- Verify URLs are correct

### TruffleHog Not Found
```bash
pip install trufflehog
```

## 📝 License

This project is licensed under the MIT License with Attribution Requirement - see the [LICENSE](LICENSE) file for details.

### 🏆 Attribution Requirements

If you use this tool commercially or create improvements/modifications:

✅ **Required:**
- Provide clear attribution: "Based on JSExtractor by Shan Majeed"
- Include a link to this repository
- State if you've made modifications

✅ **Example Attribution:**
```
This tool uses JSExtractor by Shan Majeed (https://github.com/yourusername/JSExtractor)
Modified to add [your changes]
```

### 📣 Give Credit

If you:
- Use this in a commercial product
- Create an improved version
- Fork and modify it
- Include it in another tool

**Please credit the original author!** It helps the community and supports open-source development.

## 🙏 Acknowledgments

- TruffleHog for secret scanning
- Bug bounty and security research community

## ⭐ Show Your Support

If you find JSExtractor useful, please consider:
- Starring the repository
- Sharing with the security community
- Contributing improvements
- Reporting bugs

---

<p align="center">
  Made with ❤️ for the security research community
</p>

<p align="center">
  <b>Happy Hunting! 🎯</b>
</p>
