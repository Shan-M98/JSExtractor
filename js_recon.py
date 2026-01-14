#!/usr/bin/env python3
"""
JS Recon Tool - Download, scan, and analyze JavaScript files for security research
"""

import os
import sys
import re
import subprocess
import argparse
import urllib.request
import json
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class JSReconTool:
    def __init__(self, urls_file):
        # Create scan directory based on input filename and timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        input_filename = Path(urls_file).stem  # Get filename without extension

        self.scans_dir = Path("scans")
        self.scans_dir.mkdir(exist_ok=True)

        self.scan_dir = self.scans_dir / f"{input_filename}_{timestamp}"
        self.downloaded_dir = self.scan_dir / "downloaded"
        self.results_dir = self.scan_dir / "results"

        self.downloaded_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def sanitize_filename(self, url):
        """Create a safe filename from URL"""
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        if not path or path.endswith('/'):
            filename = 'index.js'
        else:
            filename = path.split('/')[-1]
            if not filename.endswith('.js'):
                filename += '.js'

        # Sanitize filename
        filename = re.sub(r'[<>:"|?*]', '_', filename)
        return filename

    def get_domain_dir(self, url):
        """Get directory path for a domain"""
        parsed = urlparse(url)
        domain = parsed.netloc.replace(':', '_')
        domain_dir = self.downloaded_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        return domain_dir

    def download_js_files(self, urls_file):
        """Download all JS files from the URLs in the input file"""
        print(f"[*] Reading URLs from {urls_file}")

        with open(urls_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"[*] Found {len(urls)} URLs to download")

        downloaded_files = []
        for i, url in enumerate(urls, 1):
            print(f"[{i}/{len(urls)}] Downloading: {url}")

            domain_dir = self.get_domain_dir(url)
            filename = self.sanitize_filename(url)
            output_path = domain_dir / filename

            # Handle duplicate filenames
            counter = 1
            base_name = output_path.stem
            while output_path.exists():
                output_path = domain_dir / f"{base_name}_{counter}.js"
                counter += 1

            try:
                # Download using urllib
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                request = urllib.request.Request(url, headers=headers)

                with urllib.request.urlopen(request, timeout=30) as response:
                    content = response.read()

                # Write to file
                with open(output_path, 'wb') as f:
                    f.write(content)

                if output_path.exists() and output_path.stat().st_size > 0:
                    print(f"    [✓] Saved to: {output_path}")
                    downloaded_files.append({
                        'url': url,
                        'path': output_path,
                        'domain': domain_dir.name
                    })
                else:
                    print(f"    [✗] Failed to download")
            except urllib.error.URLError as e:
                print(f"    [✗] URL Error: {e.reason}")
            except TimeoutError:
                print(f"    [✗] Timeout")
            except Exception as e:
                print(f"    [✗] Error: {e}")

        print(f"\n[*] Successfully downloaded {len(downloaded_files)} files")
        return downloaded_files

    def run_trufflehog(self):
        """Run TruffleHog scan on downloaded files"""
        print(f"\n[*] Running TruffleHog scan on {self.downloaded_dir}")

        trufflehog_output = self.results_dir / "trufflehog_results.json"
        secrets_found = []

        try:
            # Check if trufflehog is installed
            subprocess.run(['trufflehog', '--version'],
                         capture_output=True, check=True)

            # Run trufflehog on the downloaded directory
            with open(trufflehog_output, 'w', encoding='utf-8') as f:
                result = subprocess.run(
                    ['trufflehog', 'filesystem', str(self.downloaded_dir), '--json'],
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )

            # Parse the results
            if trufflehog_output.stat().st_size > 0:
                with open(trufflehog_output, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                secret = json.loads(line)
                                secrets_found.append(secret)
                            except json.JSONDecodeError:
                                continue

                if secrets_found:
                    print(f"[!] Found {len(secrets_found)} potential secrets!")
                    print(f"[✓] TruffleHog results saved to: {trufflehog_output}")
                else:
                    print(f"[✓] TruffleHog scan complete - no secrets found")
            else:
                print(f"[✓] TruffleHog scan complete - no secrets found")

        except subprocess.CalledProcessError:
            print("[!] TruffleHog not found. Install it with:")
            print("    pip install trufflehog")
        except Exception as e:
            print(f"[✗] Error running TruffleHog: {e}")

        return secrets_found

    def categorize_urls(self, urls):
        """Categorize URLs by type"""
        categories = {
            'api_endpoints': [],
            'external_resources': [],
            'cdn_urls': [],
            'analytics': [],
            'other': []
        }

        for url in urls:
            url_lower = url.lower()
            if any(x in url_lower for x in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
                categories['api_endpoints'].append(url)
            elif any(x in url_lower for x in ['analytics', 'tracking', 'metrics', 'telemetry']):
                categories['analytics'].append(url)
            elif any(x in url_lower for x in ['cdn', 'static', 'assets']):
                categories['cdn_urls'].append(url)
            elif url.startswith('http'):
                categories['external_resources'].append(url)
            else:
                categories['other'].append(url)

        return categories

    def categorize_paths(self, paths):
        """Categorize paths by type (paths are now full URLs)"""
        categories = {
            'api_routes': [],
            'admin_paths': [],
            'auth_paths': [],
            'user_paths': [],
            'other': []
        }

        for path_url in paths:
            path_lower = path_url.lower()
            if any(x in path_lower for x in ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']):
                categories['api_routes'].append(path_url)
            elif any(x in path_lower for x in ['/admin', '/dashboard', '/panel']):
                categories['admin_paths'].append(path_url)
            elif any(x in path_lower for x in ['/auth', '/login', '/logout', '/register', '/signup']):
                categories['auth_paths'].append(path_url)
            elif any(x in path_lower for x in ['/user', '/profile', '/account']):
                categories['user_paths'].append(path_url)
            else:
                categories['other'].append(path_url)

        return categories

    def is_js_file_url(self, url):
        """Check if a URL points to a JavaScript file"""
        js_extensions = ['.js', '.jsx', '.mjs', '.ts', '.min.js', '.bundle.js']
        url_lower = url.lower()
        for ext in js_extensions:
            if ext in url_lower:
                # Make sure it's actually the extension
                if url_lower.endswith(ext) or (ext + '?') in url_lower or (ext + '#') in url_lower:
                    return True
        return False

    def extract_urls_and_paths(self, downloaded_files):
        """Extract URLs and paths from JS files"""
        print(f"\n[*] Extracting URLs and paths from JS files")

        all_urls = set()
        all_paths = set()
        discovered_js_files = set()

        # Add original JS files to the master list
        original_js_files = set()
        for file_info in downloaded_files:
            original_js_files.add(file_info['url'])

        # Regex patterns
        url_pattern = re.compile(
            r'https?://[^\s<>"\'`]+|'  # Full URLs
            r'//[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}[^\s<>"\'`]*'  # Protocol-relative URLs
        )

        path_pattern = re.compile(
            r'["\'](/[a-zA-Z0-9/_\-\.{}:]+)["\']|'  # Quoted absolute paths
            r'(?:route|path|endpoint|url|api)["\']?\s*[:=]\s*["\']([/a-zA-Z0-9/_\-\.{}:]+)["\']'  # API endpoints
        )

        for file_info in downloaded_files:
            try:
                # Get base URL from the source file
                source_url = file_info['url']
                parsed_url = urlparse(source_url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

                with open(file_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Extract URLs
                urls = url_pattern.findall(content)
                for url in urls:
                    url = url.rstrip('",\');')
                    if len(url) > 10:  # Filter out very short matches
                        all_urls.add(url)
                        # Check if this URL is a JS file
                        if self.is_js_file_url(url):
                            # Normalize protocol-relative URLs
                            if url.startswith('//'):
                                url = parsed_url.scheme + ':' + url
                            discovered_js_files.add(url)

                # Extract paths and convert to full URLs
                paths = path_pattern.findall(content)
                for match in paths:
                    path = match[0] if match[0] else match[1]
                    if path and len(path) > 1:
                        # Build full URL from path
                        full_url = base_url + path
                        all_paths.add(full_url)
                        # Check if this path is a JS file
                        if self.is_js_file_url(path):
                            discovered_js_files.add(full_url)

            except Exception as e:
                print(f"[!] Error processing {file_info['path']}: {e}")

        # Categorize findings
        url_categories = self.categorize_urls(all_urls)
        path_categories = self.categorize_paths(all_paths)

        # Write all URLs to file
        urls_output = self.results_dir / "extracted_urls.txt"
        with open(urls_output, 'w', encoding='utf-8') as f:
            for url in sorted(all_urls):
                f.write(f"{url}\n")

        # Write categorized URLs
        for category, urls in url_categories.items():
            if urls:
                category_file = self.results_dir / f"urls_{category}.txt"
                with open(category_file, 'w', encoding='utf-8') as f:
                    for url in sorted(urls):
                        f.write(f"{url}\n")

        # Write all paths to file (now full URLs)
        paths_output = self.results_dir / "extracted_paths.txt"
        with open(paths_output, 'w', encoding='utf-8') as f:
            for path in sorted(all_paths):
                f.write(f"{path}\n")

        # Write categorized paths (now full URLs)
        for category, paths in path_categories.items():
            if paths:
                category_file = self.results_dir / f"paths_{category}.txt"
                with open(category_file, 'w', encoding='utf-8') as f:
                    for path in sorted(paths):
                        f.write(f"{path}\n")

        # Create master JS files list (original + discovered)
        all_js_files = original_js_files.union(discovered_js_files)
        master_js_output = self.results_dir / "all_js_files.txt"
        with open(master_js_output, 'w', encoding='utf-8') as f:
            for js_url in sorted(all_js_files):
                f.write(f"{js_url}\n")

        print(f"[✓] Extracted {len(all_urls)} unique URLs -> {urls_output}")
        print(f"[✓] Extracted {len(all_paths)} unique endpoint URLs -> {paths_output}")
        print(f"[✓] Master JS files list ({len(all_js_files)} total: {len(original_js_files)} original + {len(discovered_js_files)} discovered) -> {master_js_output}")

        return all_urls, all_paths, url_categories, path_categories, all_js_files

    def generate_findings_report(self, secrets, url_categories, path_categories):
        """Generate a detailed findings report"""
        findings_file = self.results_dir / "FINDINGS.txt"

        with open(findings_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("JS RECON TOOL - SECURITY FINDINGS REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            # Secrets section
            f.write("=" * 80 + "\n")
            f.write("1. SECRETS & CREDENTIALS SCAN\n")
            f.write("=" * 80 + "\n\n")

            if secrets:
                f.write(f"[!] ALERT: Found {len(secrets)} potential secrets!\n\n")

                # Group secrets by detector type
                secrets_by_type = defaultdict(list)
                for secret in secrets:
                    detector = secret.get('DetectorName', 'Unknown')
                    secrets_by_type[detector].append(secret)

                for detector, detector_secrets in sorted(secrets_by_type.items()):
                    f.write(f"  {detector}: {len(detector_secrets)} finding(s)\n")
                    for secret in detector_secrets[:3]:  # Show first 3 of each type
                        source_file = secret.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'Unknown')
                        f.write(f"    - File: {source_file}\n")
                        raw = secret.get('Raw', '')
                        if len(raw) > 60:
                            raw = raw[:60] + "..."
                        f.write(f"      Preview: {raw}\n")
                    if len(detector_secrets) > 3:
                        f.write(f"    ... and {len(detector_secrets) - 3} more\n")
                    f.write("\n")

                f.write(f"\n[*] Full details in: trufflehog_results.json\n")
            else:
                f.write("[✓] No secrets or credentials detected\n")

            # URLs section
            f.write("\n" + "=" * 80 + "\n")
            f.write("2. EXTRACTED URLS ANALYSIS\n")
            f.write("=" * 80 + "\n\n")

            total_urls = sum(len(urls) for urls in url_categories.values())
            f.write(f"Total unique URLs found: {total_urls}\n\n")

            for category, urls in url_categories.items():
                if urls:
                    category_name = category.replace('_', ' ').upper()
                    f.write(f"  {category_name}: {len(urls)}\n")
                    # Show first 5 examples
                    for url in sorted(urls)[:5]:
                        f.write(f"    - {url}\n")
                    if len(urls) > 5:
                        f.write(f"    ... and {len(urls) - 5} more (see urls_{category}.txt)\n")
                    f.write("\n")

            # Paths section
            f.write("=" * 80 + "\n")
            f.write("3. EXTRACTED ENDPOINT URLS\n")
            f.write("=" * 80 + "\n\n")

            total_paths = sum(len(paths) for paths in path_categories.values())
            f.write(f"Total unique endpoint URLs found: {total_paths}\n\n")

            for category, paths in path_categories.items():
                if paths:
                    category_name = category.replace('_', ' ').upper()
                    f.write(f"  {category_name}: {len(paths)}\n")
                    # Show first 5 examples
                    for path in sorted(paths)[:5]:
                        f.write(f"    - {path}\n")
                    if len(paths) > 5:
                        f.write(f"    ... and {len(paths) - 5} more (see paths_{category}.txt)\n")
                    f.write("\n")

            # Interesting findings
            f.write("=" * 80 + "\n")
            f.write("4. NOTEWORTHY FINDINGS\n")
            f.write("=" * 80 + "\n\n")

            noteworthy = []
            if secrets:
                noteworthy.append(f"- {len(secrets)} potential secrets detected (REVIEW IMMEDIATELY)")
            if url_categories['api_endpoints']:
                noteworthy.append(f"- {len(url_categories['api_endpoints'])} API endpoints discovered")
            if path_categories['admin_paths']:
                noteworthy.append(f"- {len(path_categories['admin_paths'])} admin/dashboard paths found")
            if path_categories['auth_paths']:
                noteworthy.append(f"- {len(path_categories['auth_paths'])} authentication paths identified")
            if url_categories['analytics']:
                noteworthy.append(f"- {len(url_categories['analytics'])} analytics/tracking endpoints")

            if noteworthy:
                for note in noteworthy:
                    f.write(f"{note}\n")
            else:
                f.write("No significant security findings\n")

            # Master JS files note
            f.write("\n" + "=" * 80 + "\n")
            f.write("5. MASTER JS FILES LIST\n")
            f.write("=" * 80 + "\n\n")
            f.write("A complete list of all JavaScript files (original + discovered during scan)\n")
            f.write("has been saved to: all_js_files.txt\n\n")
            f.write("This list can be used for iterative scanning:\n")
            f.write("  python js_recon.py all_js_files.txt\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")

        return findings_file

    def generate_summary(self, downloaded_files, urls, paths, secrets, url_categories, path_categories, all_js_files):
        """Generate a summary report"""
        summary_file = self.results_dir / "summary.txt"

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("JS Recon Tool - Summary Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Total JS files downloaded: {len(downloaded_files)}\n")
            f.write(f"Total JS files (original + discovered): {len(all_js_files)}\n")
            f.write(f"Total unique URLs extracted: {len(urls)}\n")
            f.write(f"Total unique endpoint URLs extracted: {len(paths)}\n")
            f.write(f"Secrets found: {len(secrets)}\n\n")

            # Group by domain
            domains = {}
            for file_info in downloaded_files:
                domain = file_info['domain']
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append(file_info['url'])

            f.write("Files by domain:\n")
            f.write("-" * 70 + "\n")
            for domain, domain_urls in sorted(domains.items()):
                f.write(f"\n{domain} ({len(domain_urls)} files):\n")
                for url in domain_urls:
                    f.write(f"  - {url}\n")

        print(f"\n[✓] Summary report saved to: {summary_file}")


def main():
    parser = argparse.ArgumentParser(
        description='JS Recon Tool - Download, scan, and analyze JavaScript files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python js_recon.py urls.txt
  python js_recon.py my_targets.txt
        """
    )
    parser.add_argument('urls_file', help='Text file containing JS URLs (one per line)')

    args = parser.parse_args()

    if not os.path.exists(args.urls_file):
        print(f"[✗] Error: File not found: {args.urls_file}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("JS RECON TOOL - JavaScript Security Analysis")
    print("=" * 70 + "\n")

    tool = JSReconTool(urls_file=args.urls_file)

    # Download JS files
    downloaded_files = tool.download_js_files(args.urls_file)

    if not downloaded_files:
        print("\n[!] No files were downloaded. Exiting.")
        sys.exit(1)

    # Run TruffleHog scan
    secrets = tool.run_trufflehog()

    # Extract URLs and paths
    urls, paths, url_categories, path_categories, all_js_files = tool.extract_urls_and_paths(downloaded_files)

    # Generate detailed findings report
    print("\n[*] Generating findings report...")
    findings_file = tool.generate_findings_report(secrets, url_categories, path_categories)
    print(f"[✓] Detailed findings report: {findings_file}")

    # Generate summary
    tool.generate_summary(downloaded_files, urls, paths, secrets, url_categories, path_categories, all_js_files)

    # Console output summary
    print("\n" + "=" * 70)
    print("SCAN COMPLETE - FINDINGS SUMMARY")
    print("=" * 70)
    print(f"\nScan Directory: {tool.scan_dir}")
    print(f"\nFiles Analyzed: {len(downloaded_files)}")
    print(f"Secrets Found: {len(secrets)}")
    print(f"URLs Extracted: {len(urls)}")
    print(f"Endpoint URLs Extracted: {len(paths)}")
    print(f"Total JS Files (original + discovered): {len(all_js_files)}")

    if url_categories['api_endpoints']:
        print(f"  - API Endpoints: {len(url_categories['api_endpoints'])}")
    if path_categories['admin_paths']:
        print(f"  - Admin Paths: {len(path_categories['admin_paths'])}")
    if path_categories['auth_paths']:
        print(f"  - Auth Paths: {len(path_categories['auth_paths'])}")

    print(f"\n[!] IMPORTANT: Review {tool.scan_dir}\\results\\{findings_file.name}")
    print(f"\n[✓] All results saved to: {tool.scan_dir}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
