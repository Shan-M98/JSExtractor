#!/usr/bin/env python3
"""
JS Recon Tool - Download, scan, and analyze JavaScript files for security research
"""

import os
import sys
import re
import argparse
import urllib.request
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Comprehensive secret detection patterns
SECRET_PATTERNS = [
    # Cloud Provider Keys
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret Key", re.compile(r'(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*[\'"]?[A-Za-z0-9/+=]{40}')),
    ("AWS MWS Key", re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')),
    ("AWS ARN", re.compile(r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+')),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Google OAuth ID", re.compile(r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com')),
    ("Google OAuth Token", re.compile(r'ya29\.[0-9A-Za-z\-_]+')),
    ("Google Cloud SA Key", re.compile(r'"type"\s*:\s*"service_account"')),
    ("Azure Storage Key", re.compile(r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}')),
    ("Azure SAS Token", re.compile(r'(?i)[?&]sig=[A-Za-z0-9%+/=]{40,}')),
    ("Azure Client Secret", re.compile(r'(?i)(?:azure[_-]?client[_-]?secret|AZURE_SECRET)\s*[:=]\s*[\'"]?[A-Za-z0-9\-_.~]{30,}')),

    # API Keys & Tokens
    # (?<![a-zA-Z]) prevents matching inside compound identifiers like getApiKey, SetAuthToken
    ("Generic API Key", re.compile(r'(?i)(?<![a-zA-Z])(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*[\'"][A-Za-z0-9\-_.]{16,}[\'"]')),
    ("Generic Secret", re.compile(r'(?i)(?<![a-zA-Z])(?:secret[_-]?key|secret[_-]?token|client[_-]?secret|app[_-]?secret)\s*[:=]\s*[\'"][A-Za-z0-9\-_.]{16,}[\'"]')),
    ("Generic Access Token", re.compile(r'(?i)(?<![a-zA-Z])(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*[\'"][A-Za-z0-9\-_.]{16,}[\'"]')),
    # Password: lookbehind blocks ForgetPassword/ConfirmPwd; lookahead requires a digit in value (real passwords have digits; enum values don't)
    ("Generic Password", re.compile(r'(?i)(?<![a-zA-Z])(?:password|passwd|pwd)\s*[:=]\s*[\'"](?=[^\'"]*\d)[^\'"]{8,}[\'"]')),
    ("Authorization Header", re.compile(r'(?i)[\'"](?:Authorization|X-Api-Key|X-Auth-Token)[\'"]?\s*[:=]\s*[\'"][A-Za-z0-9\-_.+ /=]{16,}[\'"]')),
    ("Bearer Token", re.compile(r'(?i)[\'"]Bearer\s+[A-Za-z0-9\-_.]{20,}[\'"]')),
    # Basic Auth: min 20 chars and require at least one non-alpha char (digit/+/=//) to reject plain words like "Basic Information"
    ("Basic Auth", re.compile(r'(?i)[\'"]Basic\s+(?=[A-Za-z0-9+/=]*[0-9+/=])[A-Za-z0-9+/=]{20,}[\'"]')),

    # Crypto & Keys
    ("Private Key Block", re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----')),
    ("JWT Token", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+')),
    ("PGP Private Key", re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----')),

    # Third-Party Services
    ("Slack Token", re.compile(r'xox[bporas]-[0-9]{10,}-[a-zA-Z0-9-]+')),
    ("Slack Webhook", re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+')),
    ("GitHub Token", re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}')),
    # .{0,40} instead of .* to prevent matching across entire minified lines
    ("GitHub OAuth", re.compile(r'(?i)github.{0,40}[\'"][0-9a-fA-F]{40}[\'"]')),
    ("Heroku API Key", re.compile(r'(?i)heroku.{0,40}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')),
    ("Mailchimp API Key", re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}')),
    ("Mailgun API Key", re.compile(r'key-[0-9a-zA-Z]{32}')),
    ("Twilio API Key", re.compile(r'SK[0-9a-fA-F]{32}')),
    ("Twilio Account SID", re.compile(r'AC[a-z0-9]{32}')),
    ("SendGrid API Key", re.compile(r'SG\.[a-zA-Z0-9\-_.]{22}\.[a-zA-Z0-9\-_.]{43}')),
    ("Stripe API Key", re.compile(r'(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}')),
    ("Square Access Token", re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}')),
    ("Square OAuth Secret", re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}')),
    ("PayPal Braintree Token", re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')),
    ("Shopify Token", re.compile(r'shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}')),
    ("Telegram Bot Token", re.compile(r'(?i)(?:bot|telegram).{0,20}[0-9]{8,10}:[A-Za-z0-9_-]{35}')),
    ("Discord Bot Token", re.compile(r'(?:N|M|O)[A-Za-z0-9]{23,}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}')),
    ("Discord Webhook", re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_.]+')),

    # Database & Infrastructure
    ("MongoDB URI", re.compile(r'mongodb(?:\+srv)?://[^\s\'"]+')),
    ("PostgreSQL URI", re.compile(r'postgres(?:ql)?://[^\s\'"]+')),
    ("MySQL URI", re.compile(r'mysql://[^\s\'"]+')),
    ("Redis URI", re.compile(r'redis://[^\s\'"]+')),
    ("Firebase URL", re.compile(r'https://[a-z0-9-]+\.firebaseio\.com')),
    ("Firebase API Key", re.compile(r'(?i)(?:firebase|FIREBASE).{0,40}[\'"][A-Za-z0-9\-_]{30,}[\'"]')),
    ("Supabase Key", re.compile(r'(?i)(?:supabase[_-]?key|SUPABASE_KEY)\s*[:=]\s*[\'"]eyJ[A-Za-z0-9\-_.]+[\'"]')),

    # Social & OAuth
    ("Facebook Access Token", re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+')),
    ("Facebook OAuth", re.compile(r'(?i)facebook.{0,40}[\'"][0-9a-f]{32}[\'"]')),
    ("Twitter API Key", re.compile(r'(?i)twitter.{0,40}[\'"][0-9a-zA-Z]{25,}[\'"]')),
    ("LinkedIn Client ID", re.compile(r'(?i)linkedin.{0,40}[\'"][0-9a-z]{12,}[\'"]')),

    # ── AI / LLM Provider Keys ──
    ("OpenAI API Key", re.compile(r'sk-proj-[A-Za-z0-9\-_]{40,}')),
    ("OpenAI Admin Key", re.compile(r'sk-admin-[A-Za-z0-9\-_]{40,}')),
    ("OpenAI Service Account Key", re.compile(r'sk-svcacct-[A-Za-z0-9\-_]{40,}')),
    ("Anthropic API Key", re.compile(r'sk-ant-api03-[A-Za-z0-9\-_]{80,}')),
    ("Anthropic Admin Key", re.compile(r'sk-ant-admin01-[A-Za-z0-9\-_]{40,}')),
    ("Groq API Key", re.compile(r'gsk_[A-Za-z0-9]{30,}')),
    ("Perplexity API Key", re.compile(r'pplx-[A-Za-z0-9]{40,}')),
    ("xAI API Key", re.compile(r'xai-[A-Za-z0-9\-_]{30,}')),
    ("HuggingFace Access Token", re.compile(r'hf_[A-Za-z0-9]{30,}')),
    ("HuggingFace Org Token", re.compile(r'api_org_[A-Za-z0-9]{30,}')),
    ("Replicate API Token", re.compile(r'r8_[A-Za-z0-9]{36,}')),
    ("NVIDIA API Key", re.compile(r'nvapi-[A-Za-z0-9\-_]{30,}')),
    ("LangSmith API Key", re.compile(r'lsv2_(?:pt|sk)_[A-Za-z0-9]{30,}')),

    # ── GitLab Tokens ──
    ("GitLab Personal Access Token", re.compile(r'glpat-[A-Za-z0-9\-_]{20,}')),
    ("GitLab Pipeline Trigger Token", re.compile(r'glptt-[A-Za-z0-9\-_]{20,}')),
    ("GitLab Runner Registration Token", re.compile(r'GR1348941[A-Za-z0-9\-_]{20,}')),
    ("GitLab Runner Auth Token", re.compile(r'glrt-[A-Za-z0-9\-_]{20,}')),
    ("GitLab Deploy Token", re.compile(r'gldt-[A-Za-z0-9\-_]{20,}')),
    ("GitLab OAuth App Secret", re.compile(r'gloas-[A-Za-z0-9\-_]{20,}')),
    ("GitLab CI Job Token", re.compile(r'glcbt-[A-Za-z0-9\-_]{20,}')),
    ("GitLab Feed Token", re.compile(r'glft-[A-Za-z0-9\-_]{20,}')),
    ("GitLab SCIM Token", re.compile(r'glsoat-[A-Za-z0-9\-_]{20,}')),
    ("GitLab K8s Agent Token", re.compile(r'glagent-[A-Za-z0-9\-_]{20,}')),
    ("GitHub Fine-Grained PAT", re.compile(r'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}')),

    # ── Modern Cloud / Hosting Platforms ──
    ("Vercel Access Token", re.compile(r'vc[aprck]_[A-Za-z0-9\-_]{20,}')),
    ("Netlify Access Token", re.compile(r'nf[pt]_[A-Za-z0-9\-_]{20,}')),
    ("DigitalOcean Token", re.compile(r'do[por]_v1_[A-Za-z0-9]{40,}')),
    ("Fly.io Access Token", re.compile(r'FlyV1\s+fm2_[A-Za-z0-9+/=]{40,}')),
    ("Render API Key", re.compile(r'rnd_[A-Za-z0-9]{30,}')),
    ("Cloudflare Origin CA Key", re.compile(r'v1\.0-[A-Za-z0-9\-]{40,}')),
    ("Scalingo API Token", re.compile(r'tk-us-[A-Za-z0-9\-_]{40,}')),

    # ── Secrets Management & Infrastructure ──
    ("Vault Service Token", re.compile(r'hvs\.[A-Za-z0-9\-_]{24,}')),
    ("Vault Batch Token", re.compile(r'hvb\.[A-Za-z0-9\-_]{24,}')),
    ("Terraform Cloud Token", re.compile(r'[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{60,}')),
    ("Doppler Token", re.compile(r'dp\.(?:ct|pt|st|sa|scim|audit)\.[A-Za-z0-9\-_]{40,}')),
    ("Pulumi Access Token", re.compile(r'pul-[0-9a-f]{40}')),
    ("Infisical Service Token", re.compile(r'st\.[A-Za-z0-9\-_.]{30,}\.[A-Za-z0-9\-_.]{10,}')),
    ("Age Secret Key", re.compile(r'AGE-SECRET-KEY-1[A-Za-z0-9]{58}')),

    # ── Monitoring & Observability ──
    ("New Relic User API Key", re.compile(r'NRAK-[A-Za-z0-9]{27}')),
    ("New Relic Insights Key", re.compile(r'NRIQ-[A-Za-z0-9]{32}')),
    ("New Relic Insert Key", re.compile(r'NRII-[A-Za-z0-9\-_]{30,}')),
    ("New Relic Browser Key", re.compile(r'NRJS-[A-Za-z0-9]{19}')),
    ("Dynatrace API Token", re.compile(r'dt0[cs]01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}')),
    ("Grafana Cloud Token", re.compile(r'glc_[A-Za-z0-9\-_]{30,}')),
    ("Grafana Service Account Token", re.compile(r'glsa_[A-Za-z0-9\-_]{30,}')),
    ("Sentry Auth Token", re.compile(r'sntr[yuai]_[A-Za-z0-9\-_]{30,}')),
    ("Datadog API Key", re.compile(r'(?i)(?:datadog|dd).{0,40}[\'"][0-9a-f]{32}[\'"]')),

    # ── Package Registry Tokens ──
    ("npm Access Token", re.compile(r'npm_[A-Za-z0-9]{36,}')),
    ("PyPI Upload Token", re.compile(r'pypi-[A-Za-z0-9\-_]{50,}')),
    ("RubyGems API Token", re.compile(r'rubygems_[0-9a-f]{40,}')),
    ("NuGet API Key", re.compile(r'oy2[A-Za-z0-9]{40,}')),

    # ── CI/CD & Build Tools ──
    ("Buildkite API Token", re.compile(r'bkua_[A-Za-z0-9]{30,}')),
    ("Prefect API Key", re.compile(r'pn[ub]_[A-Za-z0-9]{30,}')),
    ("Octopus Deploy API Key", re.compile(r'API-[A-Za-z0-9]{30,}')),

    # ── Communication & Collaboration ──
    ("Slack App Token", re.compile(r'xapp-[0-9]+-[A-Za-z0-9\-]+')),
    ("Slack Config Token", re.compile(r'xoxe(?:\.xoxp)?-[0-9]+-[A-Za-z0-9\-]+')),
    ("Microsoft Teams Webhook", re.compile(r'https://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9\-@/]+')),

    # ── SaaS / Productivity ──
    ("Notion Integration Token", re.compile(r'ntn_[A-Za-z0-9]{40,}')),
    ("Notion Legacy Token", re.compile(r'secret_[A-Za-z0-9]{40,}')),
    ("Linear API Key", re.compile(r'lin_api_[A-Za-z0-9]{30,}')),
    ("Figma Access Token", re.compile(r'figd_[A-Za-z0-9\-_]{30,}')),
    ("Postman API Token", re.compile(r'PMAK-[A-Za-z0-9\-]{50,}')),
    ("Airtable PAT", re.compile(r'pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{50,}')),
    ("Sourcegraph Access Token", re.compile(r'sgp_[A-Za-z0-9\-_]{30,}')),
    ("Typeform API Token", re.compile(r'tfp_[A-Za-z0-9\-_]{30,}')),
    ("ReadMe API Token", re.compile(r'rdme_[A-Za-z0-9\-_]{30,}')),
    ("Asana PAT", re.compile(r'0/[0-9a-f]{32}')),

    # ── Payment & Financial ──
    ("Flutterwave Secret Key", re.compile(r'FLWSECK-[A-Za-z0-9\-]{30,}')),
    ("Flutterwave Public Key", re.compile(r'FLWPUBK-[A-Za-z0-9\-]{30,}')),
    ("Plaid Access Token", re.compile(r'access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')),
    ("Lob API Key", re.compile(r'(?:live|test)_pub_[A-Za-z0-9]{30,}')),
    ("EasyPost API Key", re.compile(r'EZ(?:AK|TEST)[A-Za-z0-9]{30,}')),
    ("Shippo API Token", re.compile(r'shippo_(?:live|test)_[A-Za-z0-9]{30,}')),
    ("Duffel API Token", re.compile(r'duffel_(?:live|test)_[A-Za-z0-9]{30,}')),

    # ── Database & Data Platforms ──
    ("Databricks API Token", re.compile(r'dapi[0-9a-f]{32,}')),
    ("PlanetScale Token", re.compile(r'pscale_(?:tkn|oauth|pw)_[A-Za-z0-9\-_]{30,}')),
    ("Confluent API Key", re.compile(r'(?i)confluent.{0,40}[\'"][A-Za-z0-9]{16}[\'"]')),
    ("AMQP URI", re.compile(r'amqps?://[^\s\'"]+')),
    ("Cloudinary URL", re.compile(r'cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[A-Za-z0-9\-_]+')),

    # ── Mapping & Media ──
    ("Mapbox Access Token", re.compile(r'(?:pk|sk|tk)\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{20,}')),
    ("Algolia API Key", re.compile(r'(?i)algolia.{0,40}[\'"][0-9a-f]{32}[\'"]')),
    ("Frame.io Token", re.compile(r'fio-u-[A-Za-z0-9\-_]{30,}')),

    # ── Feature Flags ──
    ("LaunchDarkly Access Token", re.compile(r'api-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')),

    # ── Email & Marketing ──
    ("Brevo API Token", re.compile(r'xkeysib-[0-9a-f]{64}')),
    ("Mailgun Pub Key", re.compile(r'pubkey-[0-9a-zA-Z]{32}')),

    # ── Misc SaaS ──
    ("1Password Service Account Token", re.compile(r'ops_[A-Za-z0-9\-_]{40,}')),
    ("Adafruit API Key", re.compile(r'aio_[A-Za-z0-9]{28}')),
    ("Yandex API Key", re.compile(r'AQVN[A-Za-z0-9\-_]{30,}')),
    ("Yandex Access Token", re.compile(r'(?:y0_|t1\.)[A-Za-z0-9\-_]{30,}')),
    ("OpenShift User Token", re.compile(r'sha256~[A-Za-z0-9\-_]{40,}')),
    ("Weights & Biases Key", re.compile(r'(?i)(?:wandb|WANDB).{0,40}[\'"][0-9a-f]{40}[\'"]')),
    ("Docker Hub PAT", re.compile(r'dckr_pat_[A-Za-z0-9\-_]{20,}')),
    ("Harness API Key", re.compile(r'(?:pat|sat)\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}')),

    # ── Other ──
    ("Private IP Address", re.compile(r'(?:^|\s|[\'"])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[\'"]|:\d+|\s|$)')),
    # Restrict user:pass to URL-safe chars only — prevents greedy matching across minified code
    ("Hardcoded Credentials in URL", re.compile(r'https?://[\w.~%+\-]+:[\w.~%+\-]+@[a-zA-Z0-9.-]+')),
    ("S3 Bucket URL", re.compile(r'(?:https?://)?[a-zA-Z0-9.-]+\.s3[.-](?:amazonaws\.com|[a-z]{2}-[a-z]+-\d\.amazonaws\.com)')),
    ("Generic High-Entropy Hex String", re.compile(r'(?i)(?<![a-zA-Z])(?:secret|token|key|password|credential|auth)\s*[:=]\s*[\'"][0-9a-f]{32,}[\'"]')),
]


def normalize_url(url):
    """Normalize a URL by stripping default ports (:443 for https, :80 for http)."""
    url = re.sub(r'(https://[^/:]+):443(?=/|$)', r'\1', url)
    url = re.sub(r'(http://[^/:]+):80(?=/|$)', r'\1', url)
    return url


class JSReconTool:
    def __init__(self, urls_file, domain=None):
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        input_filename = Path(urls_file).stem

        self.domain = domain
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
        filename = re.sub(r'[<>:"|?*]', '_', filename)
        return filename

    def get_domain_dir(self, url):
        """Get directory path for a domain (port-normalized)"""
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        port = parsed.port
        # Only include port in dir name if it's non-default
        if port and port not in (80, 443):
            domain = f"{hostname}_{port}"
        else:
            domain = hostname
        domain_dir = self.downloaded_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        return domain_dir

    def _download_single(self, url, index, total):
        """Download a single JS file. Returns a dict on success or None on failure."""
        domain_dir = self.get_domain_dir(url)
        filename = self.sanitize_filename(url)
        output_path = domain_dir / filename

        counter = 1
        base_name = output_path.stem
        while output_path.exists():
            output_path = domain_dir / f"{base_name}_{counter}.js"
            counter += 1

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            request = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read()

            with open(output_path, 'wb') as f:
                f.write(content)

            if output_path.exists() and output_path.stat().st_size > 0:
                print(f"[{index}/{total}] [+] {url}")
                return {
                    'url': url,
                    'path': output_path,
                    'domain': domain_dir.name
                }
            else:
                print(f"[{index}/{total}] [-] Empty response: {url}")
                return None
        except urllib.error.URLError as e:
            print(f"[{index}/{total}] [-] URL Error ({type(e).__name__}): {e.reason} - {url}")
        except TimeoutError:
            print(f"[{index}/{total}] [-] Timeout: {url}")
        except Exception as e:
            print(f"[{index}/{total}] [-] {type(e).__name__}: {e} - {url}")
        return None

    def download_js_files(self, urls_file, workers=10):
        """Download all JS files from the URLs in the input file"""
        print(f"[*] Reading URLs from {urls_file}")

        with open(urls_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        # Normalize and deduplicate URLs (strip :443/:80)
        seen = set()
        urls = []
        for url in raw_urls:
            normalized = normalize_url(url)
            if normalized not in seen:
                seen.add(normalized)
                urls.append(normalized)

        total = len(urls)
        print(f"[*] Found {total} unique URLs to download (from {len(raw_urls)} input lines)")
        print(f"[*] Downloading with {workers} concurrent workers...")

        downloaded_files = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._download_single, url, i, total): url
                for i, url in enumerate(urls, 1)
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    downloaded_files.append(result)

        print(f"\n[*] Successfully downloaded {len(downloaded_files)} files")
        return downloaded_files

    def scan_secrets(self, downloaded_files):
        """Scan downloaded JS files for secrets using regex patterns"""
        print(f"\n[*] Scanning {len(downloaded_files)} files for secrets...")

        findings = []
        for file_info in downloaded_files:
            try:
                with open(file_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for secret_type, pattern in SECRET_PATTERNS:
                            for match in pattern.finditer(line):
                                matched_value = match.group(0)
                                # Skip absurdly long matches — almost certainly false positives
                                if len(matched_value) > 500:
                                    continue
                                secret = matched_value if len(matched_value) <= 80 else matched_value[:80] + "..."
                                # Build context: ~40 chars before match + match (capped) + ~40 chars after
                                ctx_before_start = max(0, match.start() - 40)
                                ctx_after_end = min(len(line), match.end() + 40)
                                before = line[ctx_before_start:match.start()]
                                after = line[match.end():ctx_after_end]
                                # Cap the match portion shown in context to 80 chars
                                match_display = matched_value if len(matched_value) <= 80 else matched_value[:40] + " ... " + matched_value[-35:]
                                context = before + match_display + after
                                context = context.strip()
                                if ctx_before_start > 0:
                                    context = "..." + context
                                if ctx_after_end < len(line):
                                    context = context + "..."
                                findings.append({
                                    'type': secret_type,
                                    'secret': secret,
                                    'context': context,
                                    'source_url': normalize_url(file_info['url']),
                                    'file': str(file_info['path']),
                                    'line': line_num,
                                })
            except Exception as e:
                print(f"[!] {type(e).__name__} scanning {file_info['path']}: {e}")

        if findings:
            print(f"[!] Found {len(findings)} potential secrets!")
        else:
            print(f"[*] No secrets detected")

        return findings

    def categorize_urls(self, urls):
        """Categorize URLs by type"""
        categories = {
            'api_endpoints': [],
            'analytics': [],
            'cdn_urls': [],
            'external_resources': [],
        }

        for url in urls:
            url_lower = url.lower()
            if any(x in url_lower for x in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
                categories['api_endpoints'].append(url)
            elif any(x in url_lower for x in ['analytics', 'tracking', 'metrics', 'telemetry']):
                categories['analytics'].append(url)
            elif any(x in url_lower for x in ['cdn', 'static', 'assets']):
                categories['cdn_urls'].append(url)
            else:
                categories['external_resources'].append(url)

        return categories

    def categorize_paths(self, paths):
        """Categorize relative paths by type"""
        categories = {
            'api_routes': [],
            'auth_paths': [],
            'admin_paths': [],
            'user_paths': [],
            'other': []
        }

        for path in paths:
            path_lower = path.lower()
            if any(x in path_lower for x in ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']):
                categories['api_routes'].append(path)
            elif any(x in path_lower for x in ['/auth', '/login', '/logout', '/register', '/signup']):
                categories['auth_paths'].append(path)
            elif any(x in path_lower for x in ['/admin', '/dashboard', '/panel']):
                categories['admin_paths'].append(path)
            elif any(x in path_lower for x in ['/user', '/profile', '/account']):
                categories['user_paths'].append(path)
            else:
                categories['other'].append(path)

        return categories

    def is_js_file_url(self, url):
        """Check if a URL points to a JavaScript file"""
        # Strip query string and fragment before checking extension
        path = url.split('?')[0].split('#')[0].lower()
        js_extensions = ('.js', '.jsx', '.mjs', '.ts')
        if not path.endswith(js_extensions):
            return False
        # Guard against .ts matching non-JS paths like /timestamps
        if path.endswith('.ts') and not re.search(r'/[^/]+\.ts$', path):
            return False
        return True

    def extract_urls_and_paths(self, downloaded_files):
        """Extract URLs and paths from JS files"""
        print(f"\n[*] Extracting URLs and paths from JS files")

        all_urls = set()
        all_paths = set()
        discovered_js_files = set()

        original_js_files = set()
        for file_info in downloaded_files:
            original_js_files.add(normalize_url(file_info['url']))

        # Regex patterns
        url_pattern = re.compile(
            r'https?://[^\s<>"\'`]{10,2000}|'  # Full URLs (capped length for minified JS)
            r'//[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}[^\s<>"\'`]{0,2000}'  # Protocol-relative URLs
        )

        path_pattern = re.compile(
            r'["\'](/[a-zA-Z0-9/_\-\.{}:]+)["\']|'  # Quoted absolute paths
            r'(?:route|path|endpoint|url|api|href|src|action|redirect|callback)["\']?\s*[:=]\s*["\']([/a-zA-Z0-9/_\-\.{}:]+)["\']'  # API endpoints
        )

        for file_info in downloaded_files:
            try:
                source_url = file_info['url']
                parsed_url = urlparse(source_url)

                with open(file_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Extract full URLs
                urls = url_pattern.findall(content)
                for url in urls:
                    url = re.sub(r'["\',;)]+$', '', url)
                    if len(url) > 10:
                        normalized = normalize_url(url)
                        all_urls.add(normalized)
                        if self.is_js_file_url(normalized):
                            if normalized.startswith('//'):
                                normalized = parsed_url.scheme + ':' + normalized
                            discovered_js_files.add(normalize_url(normalized))

                # Extract paths as raw relative paths (NOT prepended with domain)
                paths = path_pattern.findall(content)
                for match in paths:
                    path = match[0] if match[0] else match[1]
                    if path and len(path) > 1:
                        all_paths.add(path)
                        if self.is_js_file_url(path):
                            # For JS file discovery, we need a full URL — use source domain
                            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                            discovered_js_files.add(normalize_url(base_url + path))

            except Exception as e:
                print(f"[!] {type(e).__name__} processing {file_info['path']}: {e}")

        # Categorize
        url_categories = self.categorize_urls(all_urls)
        path_categories = self.categorize_paths(all_paths)

        # Apply --domain to paths for output if specified
        output_paths = set()
        for path in all_paths:
            if self.domain:
                domain = self.domain.rstrip('/')
                if not domain.startswith('http'):
                    domain = 'https://' + domain
                output_paths.add(domain + path)
            else:
                output_paths.add(path)

        # Write urls.txt
        urls_output = self.results_dir / "urls.txt"
        with open(urls_output, 'w', encoding='utf-8') as f:
            for url in sorted(all_urls):
                f.write(f"{url}\n")

        # Write paths.txt
        paths_output = self.results_dir / "paths.txt"
        with open(paths_output, 'w', encoding='utf-8') as f:
            for path in sorted(output_paths):
                f.write(f"{path}\n")

        # Write js_files.txt (original + discovered)
        all_js_files = original_js_files.union(discovered_js_files)
        js_output = self.results_dir / "js_files.txt"
        with open(js_output, 'w', encoding='utf-8') as f:
            for js_url in sorted(all_js_files):
                f.write(f"{js_url}\n")

        print(f"[+] Extracted {len(all_urls)} unique URLs -> {urls_output}")
        print(f"[+] Extracted {len(all_paths)} unique paths -> {paths_output}")
        print(f"[+] JS files list ({len(all_js_files)} total: {len(original_js_files)} original + {len(discovered_js_files)} discovered) -> {js_output}")

        return all_urls, all_paths, url_categories, path_categories, all_js_files, output_paths

    def generate_report(self, downloaded_files, secrets, all_urls, all_paths, url_categories, path_categories, all_js_files, output_paths):
        """Generate a single comprehensive REPORT.txt"""
        report_file = self.results_dir / "REPORT.txt"

        with open(report_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("JS RECON TOOL - SCAN REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if self.domain:
                f.write(f"Target Domain: {self.domain}\n")
            f.write("=" * 80 + "\n\n")

            # ── SCAN SUMMARY ──
            f.write("-" * 80 + "\n")
            f.write("SCAN SUMMARY\n")
            f.write("-" * 80 + "\n\n")

            f.write(f"  Files downloaded:      {len(downloaded_files)}\n")
            f.write(f"  Secrets found:         {len(secrets)}\n")
            f.write(f"  Unique URLs extracted:  {len(all_urls)}\n")
            f.write(f"  Unique paths extracted: {len(all_paths)}\n")
            f.write(f"  JS files (total):      {len(all_js_files)}\n")

            # Domains scanned
            domains = defaultdict(int)
            for file_info in downloaded_files:
                domains[file_info['domain']] += 1
            f.write(f"\n  Domains scanned ({len(domains)}):\n")
            for domain, count in sorted(domains.items()):
                f.write(f"    {domain}: {count} files\n")

            # ── SECRETS ──
            f.write("\n" + "=" * 80 + "\n")
            f.write("SECRETS\n")
            f.write("=" * 80 + "\n\n")

            if secrets:
                f.write(f"  [!] {len(secrets)} potential secrets found\n\n")

                # Group by type
                secrets_by_type = defaultdict(list)
                for s in secrets:
                    secrets_by_type[s['type']].append(s)

                for secret_type, items in sorted(secrets_by_type.items()):
                    f.write(f"  {secret_type} ({len(items)})\n")
                    for item in items:
                        f.write(f"    Line {item['line']} | Secret: {item['secret']}\n")
                        f.write(f"    Context: {item['context']}\n")
                        f.write(f"    Source: {item['source_url']}\n\n")
            else:
                f.write("  No secrets or credentials detected.\n")

            # ── URLS BY CATEGORY ──
            f.write("\n" + "=" * 80 + "\n")
            f.write("URLS BY CATEGORY\n")
            f.write("=" * 80 + "\n\n")

            total_urls = sum(len(v) for v in url_categories.values())
            f.write(f"  Total: {total_urls}\n\n")

            category_display_order = ['api_endpoints', 'analytics', 'external_resources', 'cdn_urls']
            for category in category_display_order:
                urls = url_categories.get(category, [])
                if urls:
                    category_name = category.replace('_', ' ').upper()
                    f.write(f"  --- {category_name} ({len(urls)}) ---\n")
                    for url in sorted(urls):
                        f.write(f"    {url}\n")
                    f.write("\n")

            # ── PATHS BY CATEGORY ──
            f.write("=" * 80 + "\n")
            f.write("PATHS BY CATEGORY\n")
            f.write("=" * 80 + "\n\n")

            total_paths = sum(len(v) for v in path_categories.values())
            domain_note = f" (prepended with {self.domain})" if self.domain else ""
            f.write(f"  Total: {total_paths}{domain_note}\n\n")

            path_display_order = ['api_routes', 'auth_paths', 'admin_paths', 'user_paths', 'other']
            for category in path_display_order:
                paths = path_categories.get(category, [])
                if paths:
                    category_name = category.replace('_', ' ').upper()
                    f.write(f"  --- {category_name} ({len(paths)}) ---\n")
                    for path in sorted(paths):
                        if self.domain:
                            domain = self.domain.rstrip('/')
                            if not domain.startswith('http'):
                                domain = 'https://' + domain
                            f.write(f"    {domain}{path}\n")
                        else:
                            f.write(f"    {path}\n")
                    f.write("\n")

            # ── DISCOVERED JS FILES ──
            f.write("=" * 80 + "\n")
            f.write("DISCOVERED JS FILES\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"  Total: {len(all_js_files)}\n\n")
            for js_url in sorted(all_js_files):
                f.write(f"    {js_url}\n")

            f.write("\n  Tip: Re-run with this list for deeper scanning:\n")
            f.write(f"    python js_recon.py js_files.txt\n")

            # Footer
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")

        return report_file


def main():
    parser = argparse.ArgumentParser(
        description='JS Recon Tool - Download, scan, and analyze JavaScript files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python js_recon.py urls.txt
  python js_recon.py urls.txt --domain ads.tiktok.com
  python js_recon.py urls.txt --keep --workers 20
        """
    )
    parser.add_argument('urls_file', help='Text file containing JS URLs (one per line)')
    parser.add_argument('--domain', help='Target domain to prepend to extracted paths (e.g. ads.tiktok.com)')
    parser.add_argument('--keep', action='store_true', help='Keep downloaded JS files instead of deleting after scan')
    parser.add_argument('--workers', type=int, default=10, help='Number of concurrent download threads (default: 10)')

    args = parser.parse_args()

    if not os.path.exists(args.urls_file):
        print(f"[-] Error: File not found: {args.urls_file}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("JS RECON TOOL - JavaScript Security Analysis")
    print("=" * 70 + "\n")

    tool = JSReconTool(urls_file=args.urls_file, domain=args.domain)

    # Download JS files
    downloaded_files = tool.download_js_files(args.urls_file, workers=args.workers)

    if not downloaded_files:
        print("\n[!] No files were downloaded. Exiting.")
        sys.exit(1)

    # Scan for secrets (built-in regex scanner)
    secrets = tool.scan_secrets(downloaded_files)

    # Extract URLs and paths
    all_urls, all_paths, url_categories, path_categories, all_js_files, output_paths = tool.extract_urls_and_paths(downloaded_files)

    # Clean up downloaded JS files (unless --keep)
    if args.keep:
        print(f"\n[*] Keeping downloaded JS files in: {tool.downloaded_dir}")
    else:
        shutil.rmtree(tool.downloaded_dir, ignore_errors=True)
        print(f"\n[*] Cleaned up downloaded JS files (use --keep to preserve them)")

    # Generate single comprehensive report
    print("\n[*] Generating report...")
    report_file = tool.generate_report(downloaded_files, secrets, all_urls, all_paths, url_categories, path_categories, all_js_files, output_paths)
    print(f"[+] Report: {report_file}")

    # Console summary
    print("\n" + "=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print(f"\nScan Directory: {tool.scan_dir}")
    print(f"\nFiles Analyzed:  {len(downloaded_files)}")
    print(f"Secrets Found:   {len(secrets)}")
    print(f"URLs Extracted:  {len(all_urls)}")
    print(f"Paths Extracted: {len(all_paths)}")
    print(f"JS Files Total:  {len(all_js_files)}")

    if url_categories['api_endpoints']:
        print(f"  - API Endpoints: {len(url_categories['api_endpoints'])}")
    if path_categories['admin_paths']:
        print(f"  - Admin Paths: {len(path_categories['admin_paths'])}")
    if path_categories['auth_paths']:
        print(f"  - Auth Paths: {len(path_categories['auth_paths'])}")

    print(f"\nOutput files (in {tool.results_dir}):")
    print(f"  REPORT.txt   - Full scan report")
    print(f"  urls.txt     - All extracted URLs")
    print(f"  paths.txt    - All extracted paths")
    print(f"  js_files.txt - All JS files (original + discovered)")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
