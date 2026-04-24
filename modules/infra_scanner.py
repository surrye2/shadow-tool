#!/usr/bin/env python3
"""
Infrastructure Scanner - AlZill V6 Pro
Advanced multi-threaded infrastructure scanner with URL Fingerprinting
Features: ThreadPoolExecutor | Queue-based crawling | API discovery | Smart deduplication
"""

import re
import requests
import urllib3
import json
import time
import random
from collections import deque
from termcolor import cprint
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Set, List, Dict, Optional, Tuple
from difflib import SequenceMatcher

# إيقاف تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class UltimateSecurityScanner:
    def __init__(self, target_domain: str = None, verbose: bool = False, max_urls: int = 500):
        self.target_domain = target_domain
        self.verbose = verbose
        self.max_urls = max_urls
        self.scanned_urls = set()  # لمنع تكرار فحص نفس الرابط
        self.url_fingerprints = set()  # بصمات الروابط لمنع التكرار الذكي
        self.found_data = []
        self.api_endpoints = set()
        self.js_files = set()
        
        # User-Agent rotation لتجنب الحظر
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
        ]
        
        # ============================================================
        # URL FINGERPRINTING - لتجنب فحص الروابط المتشابهة
        # ============================================================
        self.ignored_url_patterns = [
            # صفحات الترقيم (Pagination)
            r'page=[0-9]+',
            r'offset=[0-9]+',
            r'limit=[0-9]+',
            r'start=[0-9]+',
            r'per_page=[0-9]+',
            
            # معاملات التاريخ والوقت
            r'timestamp=[0-9]+',
            r'date=[0-9-]+',
            r'time=[0-9:]+',
            r'cache=[0-9a-f]+',
            
            # معاملات عشوائية
            r'_=[0-9]+',
            r'rand=[0-9]+',
            r'random=[0-9a-f]+',
            r'nonce=[0-9a-f]+',
            r'callback=[a-zA-Z0-9_]+',
            
            # معاملات الجلسة
            r'session_id=[a-zA-Z0-9]+',
            r'sessid=[a-zA-Z0-9]+',
            r'sid=[a-zA-Z0-9]+',
            r'token=[a-zA-Z0-9]+',
            
            # معاملات المعرفات الرقمية (يمكن استثناؤها إذا أردت)
            r'id=[0-9]+',
            r'user_id=[0-9]+',
            r'product_id=[0-9]+',
            r'post_id=[0-9]+',
            r'article_id=[0-9]+',
        ]
        
        # ============================================================
        # IMPROVED PATTERNS WITH BETTER GROUP HANDLING
        # ============================================================
        self.critical_patterns = {
            "JWT/Bearer Token": [
                r'bearer\s+([a-zA-Z0-9\._\-]{20,})',
                r'Bearer\s+([a-zA-Z0-9\._\-]{20,})',
                r'Authorization:\s*Bearer\s+([a-zA-Z0-9\._\-]+)'
            ],
            "API Key": [
                r'(?i)(api[_-]?key|apikey|api_key)[\s"\']*[:=][\s"\']*([A-Za-z0-9\-_\.]{15,})',
                r'(?i)(secret|client_secret|private_key)[\s"\']*[:=][\s"\']*([A-Za-z0-9\-_\.]{15,})',
                r'(?i)(aws_access_key|aws_secret_key)[\s"\']*[:=][\s"\']*([A-Za-z0-9\-_\.]{15,})',
                r'(?i)(token|access_token)[\s"\']*[:=][\s"\']*([A-Za-z0-9\-_\.]{15,})',
            ],
            "Database Credentials": [
                r'(?i)(db_password|db_user|db_host|database_password)[\s"\']*[:=][\s"\']*([A-Za-z0-9]{5,})',
                r'(?i)(mysql|postgres|mongodb|redis)_(pass|user|host)[\s"\']*[:=][\s"\']*([A-Za-z0-9]{5,})',
                r'(?i)connection[\s"\']*[:=][\s"\']*[\'"]?(?:mysql|postgres|mongodb)://[^\s"\']+'
            ],
            "Email Addresses": [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            "IP Addresses": [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ],
            "Internal Paths": [
                r'/(?:admin|backup|config|database|dump|sql|backup|old|test|dev|staging)/[a-zA-Z0-9\-_./]*',
                r'/(?:wp-admin|wp-content|wp-includes)/',
                r'/(?:api|v1|v2|v3|rest|graphql)/[a-zA-Z0-9\-_./]*'
            ],
            "Sensitive Files": [
                r'\.(?:env|git/config|htaccess|htpasswd|ini|conf|config|yaml|yml|json|xml)["\'\s]',
                r'/(?:robots\.txt|sitemap\.xml|crossdomain\.xml|security\.txt)'
            ]
        }
        
        # ============================================================
        # LINK EXTRACTION PATTERNS
        # ============================================================
        self.link_patterns = [
            r'href=["\'](https?://[^"\']+|/[^"\']+|\.\.?/[^"\']+)["\']',
            r'src=["\'](https?://[^"\']+|/[^"\']+)["\']',
            r'action=["\'](https?://[^"\']+|/[^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
        ]
        
        # ============================================================
        # COMMON PATHS TO CHECK
        # ============================================================
        self.common_paths = [
            '/robots.txt', '/sitemap.xml', '/security.txt', '/humans.txt',
            '/.well-known/security.txt', '/.well-known/assetlinks.json',
            '/admin', '/administrator', '/wp-admin', '/cpanel', '/webmail',
            '/phpmyadmin', '/phpinfo.php', '/info.php', '/server-status',
            '/api', '/api/v1', '/api/v2', '/v1', '/v2', '/rest',
            '/graphql', '/swagger', '/swagger.json', '/openapi.json',
            '/config.php', '/.env', '/.git/config', '/backup.sql'
        ]

    # ============================================================
    # URL FINGERPRINTING FUNCTIONS
    # ============================================================
    
    def normalize_url(self, url: str) -> str:
        """
        تطبيع URL لإزالة المعاملات المتغيرة
        يحول product.php?id=123 إلى product.php
        """
        parsed = urlparse(url)
        
        # إزالة الـ fragment
        url_without_fragment = parsed._replace(fragment='').geturl()
        
        # استخراج المسار الأساسي بدون معاملات متغيرة
        path = parsed.path
        
        # إزالة الامتدادات الديناميكية
        path = re.sub(r'\.(php|asp|aspx|jsp|do|action)$', '', path)
        
        # إزالة الأرقام من نهاية المسار (مثل /product/123 -> /product)
        path = re.sub(r'/\d+$', '', path)
        path = re.sub(r'/\d+/', '/', path)
        
        # إزالة المعاملات الرقمية من الـ query
        query_params = parse_qs(parsed.query)
        normalized_params = {}
        
        for key, values in query_params.items():
            # تخطي المعاملات التي تحتوي على أرقام فقط أو قيم متغيرة
            if key in ['id', 'page', 'offset', 'limit', 'start', 'per_page', 'timestamp', 'rand', 'random', 'callback', '_']:
                continue
            
            # تخطي القيم الرقمية
            if values and values[0].isdigit():
                continue
            
            # تخطي القيم الطويلة جداً (tokens, hashes)
            if values and len(values[0]) > 32:
                continue
                
            normalized_params[key] = values
        
        # إعادة بناء الـ URL
        if normalized_params:
            new_query = urlencode(normalized_params, doseq=True)
            normalized_url = parsed._replace(path=path, query=new_query).geturl()
        else:
            normalized_url = parsed._replace(path=path, query='').geturl()
        
        return normalized_url.rstrip('/')

    def generate_fingerprint(self, url: str) -> str:
        """
        توليد بصمة فريدة للرابط
        البصمة تعتمد على المسار والمتغيرات (بدون القيم)
        """
        parsed = urlparse(url)
        
        # المسار الأساسي
        path = parsed.path
        
        # إزالة الأرقام من المسار
        path = re.sub(r'/\d+', '', path)
        path = re.sub(r'/[a-f0-9]{32,}', '', path)  # إزالة الـ hashes
        
        # استخراج أسماء المتغيرات فقط (بدون قيم)
        query_params = parse_qs(parsed.query)
        param_names = sorted(query_params.keys())
        
        # فلترة المعاملات المتغيرة
        filtered_params = []
        for param in param_names:
            if param not in ['id', 'page', 'offset', 'limit', 'start', 'per_page', 'timestamp', 'rand', 'random', 'callback', '_']:
                if not param.startswith('_'):
                    filtered_params.append(param)
        
        # بناء البصمة
        fingerprint = f"{path}|{','.join(filtered_params)}"
        
        return fingerprint.lower()

    def should_skip_url(self, url: str) -> bool:
        """
        تحديد ما إذا كان يجب تخطي الرابط لأنه مشابه لروابط تم فحصها سابقاً
        """
        # 1. فحص الأنماط المتجاهلة
        for pattern in self.ignored_url_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                if self.verbose:
                    cprint(f"    [*] Skipping paginated/duplicate URL: {url[:80]}...", INFO)
                return True
        
        # 2. فحص البصمة
        fingerprint = self.generate_fingerprint(url)
        
        if fingerprint in self.url_fingerprints:
            if self.verbose:
                cprint(f"    [*] Skipping duplicate fingerprint: {fingerprint}", INFO)
            return True
        
        # 3. فحص التشابه النصي (للروابط المتشابهة جداً)
        for existing_url in list(self.scanned_urls)[-100:]:  # آخر 100 رابط فقط للسرعة
            similarity = SequenceMatcher(None, url, existing_url).ratio()
            if similarity > 0.95:  # تشابه 95% أو أكثر
                if self.verbose:
                    cprint(f"    [*] Skipping similar URL (similarity: {similarity:.2f})", INFO)
                return True
        
        return False

    def add_url_fingerprint(self, url: str):
        """إضافة بصمة الرابط إلى المجموعة"""
        fingerprint = self.generate_fingerprint(url)
        self.url_fingerprints.add(fingerprint)

    def _get_random_user_agent(self) -> str:
        """Get random User-Agent"""
        return random.choice(self.user_agents)

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to target domain"""
        if not self.target_domain:
            return True
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            if self.target_domain.startswith('www.'):
                target = self.target_domain[4:]
            else:
                target = self.target_domain
            
            return domain == target or domain.endswith('.' + target)
        except:
            return False

    def extract_links(self, source_code: str, base_url: str) -> Set[str]:
        """Extract all links from source code"""
        links = set()
        
        for pattern in self.link_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            for match in matches:
                try:
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    full_url = urljoin(base_url, match)
                    
                    if self._is_same_domain(full_url):
                        parsed = urlparse(full_url)
                        clean_url = parsed._replace(fragment='').geturl()
                        
                        # تطبيق الـ fingerprinting قبل الإضافة
                        if not self.should_skip_url(clean_url):
                            links.add(clean_url)
                except:
                    continue
        
        return links

    def extract_api_endpoints(self, source_code: str, base_url: str) -> Set[str]:
        """Extract API endpoints specifically"""
        api_endpoints = set()
        
        api_patterns = [
            r'/api/[a-zA-Z0-9\-_/]+',
            r'/v[0-9]+/[a-zA-Z0-9\-_/]+',
            r'/rest/[a-zA-Z0-9\-_/]+',
            r'/graphql',
            r'/swagger',
            r'/openapi',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            for match in matches:
                try:
                    full_url = urljoin(base_url, match)
                    if self._is_same_domain(full_url):
                        api_endpoints.add(full_url)
                except:
                    continue
        
        return api_endpoints

    def extract_js_files(self, source_code: str, base_url: str) -> Set[str]:
        """Extract JavaScript file URLs"""
        js_files = set()
        
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'src=["\']([^"\']+\.js)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            for match in matches:
                try:
                    full_url = urljoin(base_url, match)
                    if self._is_same_domain(full_url):
                        js_files.add(full_url)
                except:
                    continue
        
        return js_files

    def search_sensitive_data(self, source_code: str, url: str):
        """Search for sensitive data in source code"""
        for category, patterns in self.critical_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, source_code, re.IGNORECASE)
                    for match in matches:
                        if match.groups():
                            value = next((g for g in match.groups() if g), match.group(0))
                        else:
                            value = match.group(0)
                        
                        if len(value) > 100:
                            value = value[:100] + "..."
                        
                        self.found_data.append({
                            'category': category,
                            'value': value,
                            'url': url,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        color = SUCCESS if category in ['JWT/Bearer Token', 'API Key', 'Database Credentials'] else INFO
                        cprint(f"    [+] Found {category}: {value[:50]}...", color)
                except Exception as e:
                    if self.verbose:
                        cprint(f"    [!] Regex error for {category}: {e}", WARNING)

    def check_common_paths(self, base_url: str) -> Set[str]:
        """Check common paths for exposed resources"""
        found_paths = set()
        
        for path in self.common_paths:
            try:
                test_url = urljoin(base_url, path)
                
                # تطبيق الـ fingerprinting
                if self.should_skip_url(test_url):
                    continue
                
                response = requests.get(
                    test_url, 
                    timeout=5, 
                    headers={'User-Agent': self._get_random_user_agent()},
                    verify=False
                )
                
                if response.status_code == 200:
                    cprint(f"    [+] Exposed path found: {test_url}", WARNING)
                    found_paths.add(test_url)
                    self.add_url_fingerprint(test_url)
                    self.search_sensitive_data(response.text, test_url)
                    
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Failed to check {path}: {e}", WARNING)
        
        return found_paths

    def scan_url(self, url: str) -> Set[str]:
        """Scan a single URL and extract new links"""
        if url in self.scanned_urls:
            return set()
        
        if len(self.scanned_urls) >= self.max_urls:
            return set()
        
        # تطبيق الـ fingerprinting
        if self.should_skip_url(url):
            return set()
        
        self.scanned_urls.add(url)
        self.add_url_fingerprint(url)
        new_links = set()
        
        try:
            headers = {
                'User-Agent': self._get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(url, timeout=8, headers=headers, verify=False)
            
            if self.verbose:
                cprint(f"    [*] Analyzing: {url[:80]}... | Status: {response.status_code}", INFO)
            
            if response.status_code == 200:
                # Search for sensitive data
                self.search_sensitive_data(response.text, url)
                
                # Extract API endpoints
                api_endpoints = self.extract_api_endpoints(response.text, url)
                self.api_endpoints.update(api_endpoints)
                
                # Extract JS files
                js_files = self.extract_js_files(response.text, url)
                self.js_files.update(js_files)
                
                # Extract new links for crawling (مع تطبيق الـ fingerprinting)
                new_links = self.extract_links(response.text, url)
                
            elif response.status_code == 403:
                cprint(f"    [!] Access forbidden: {url[:80]}...", WARNING)
                
        except requests.exceptions.Timeout:
            if self.verbose:
                cprint(f"    [!] Timeout: {url[:80]}...", WARNING)
        except requests.exceptions.ConnectionError:
            if self.verbose:
                cprint(f"    [!] Connection error: {url[:80]}...", WARNING)
        except Exception as e:
            if self.verbose:
                cprint(f"    [!] Error scanning {url[:80]}...: {e}", ERROR)
        
        return new_links

    def scan_js_files(self):
        """Scan JavaScript files for additional secrets"""
        cprint(f"\n[*] Scanning {len(self.js_files)} JavaScript files...", INFO)
        
        for js_url in list(self.js_files)[:50]:
            # تطبيق الـ fingerprinting
            if self.should_skip_url(js_url):
                continue
                
            try:
                response = requests.get(
                    js_url, 
                    timeout=8, 
                    headers={'User-Agent': self._get_random_user_agent()},
                    verify=False
                )
                
                if response.status_code == 200:
                    self.search_sensitive_data(response.text, js_url)
                    api_endpoints = self.extract_api_endpoints(response.text, js_url)
                    self.api_endpoints.update(api_endpoints)
                    self.add_url_fingerprint(js_url)
                    
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Error scanning JS {js_url[:80]}...: {e}", WARNING)

    def generate_report(self, target_url: str) -> Dict:
        """Generate comprehensive scan report"""
        report = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'urls_scanned': len(self.scanned_urls),
                'unique_fingerprints': len(self.url_fingerprints),
                'deduplication_rate': round((1 - len(self.scanned_urls) / max(1, len(self.scanned_urls) + len(self.url_fingerprints))) * 100, 2),
                'api_endpoints_found': len(self.api_endpoints),
                'js_files_found': len(self.js_files),
                'secrets_found': len(self.found_data)
            },
            'api_endpoints': list(self.api_endpoints)[:100],
            'secrets': self.found_data[:50],
            'js_files': list(self.js_files)[:50]
        }
        
        filename = f"infra_scan_{self.target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        cprint(f"\n[+] Report saved to: {filename}", SUCCESS)
        
        return report


def run_multi_scan(target_url: str, threads: int = 10, max_urls: int = 500, verbose: bool = False):
    """
    Multi-threaded infrastructure scanner with queue-based crawling and URL fingerprinting
    """
    parsed = urlparse(target_url)
    main_domain = parsed.netloc.lower().replace('www.', '')
    
    cprint("\n" + "="*70, HIGHLIGHT)
    cprint("[INFRASTRUCTURE SCANNER] AlZill V6 Pro - Smart Deduplication", HIGHLIGHT, attrs=['bold'])
    cprint("="*70, HIGHLIGHT)
    cprint(f"[*] Target: {main_domain}", INFO)
    cprint(f"[*] Threads: {threads}", INFO)
    cprint(f"[*] Max URLs: {max_urls}", INFO)
    cprint(f"[*] Features: URL Fingerprinting | Smart Deduplication | API Discovery", "yellow")
    
    scanner = UltimateSecurityScanner(target_domain=main_domain, verbose=verbose, max_urls=max_urls)
    
    # Initial URLs to scan
    urls_to_scan = deque()
    urls_to_scan.append(target_url)
    
    # Check common paths first
    cprint("\n[1] 📁 Phase: Common Paths Discovery", INFO)
    common_paths = scanner.check_common_paths(target_url)
    for path in common_paths:
        if path not in scanner.scanned_urls:
            urls_to_scan.append(path)
    
    cprint(f"\n[2] 🌐 Phase: Multi-threaded Crawling (with deduplication)", INFO)
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        while urls_to_scan and len(scanner.scanned_urls) < max_urls:
            # Process batch of URLs
            batch = []
            while urls_to_scan and len(batch) < threads * 2:
                url_to_process = urls_to_scan.popleft()
                batch.append(url_to_process)
            
            # Submit batch to executor
            futures = {executor.submit(scanner.scan_url, url): url for url in batch}
            
            # Collect results
            for future in as_completed(futures):
                url = futures[future]
                try:
                    new_links = future.result(timeout=30)
                    if new_links:
                        for link in new_links:
                            if link not in scanner.scanned_urls and link not in urls_to_scan:
                                if not scanner.should_skip_url(link):
                                    urls_to_scan.append(link)
                except Exception as e:
                    if verbose:
                        cprint(f"    [!] Error processing {url}: {e}", WARNING)
            
            # Display progress
            if verbose:
                cprint(f"    Progress: {len(scanner.scanned_urls)}/{max_urls} URLs, {len(urls_to_scan)} in queue, {len(scanner.url_fingerprints)} unique fingerprints", INFO)
    
    # Scan JavaScript files
    cprint("\n[3] 📜 Phase: JavaScript Files Analysis", INFO)
    scanner.scan_js_files()
    
    # Display API endpoints
    if scanner.api_endpoints:
        cprint(f"\n[4] 🔗 Phase: Discovered API Endpoints", INFO)
        for endpoint in list(scanner.api_endpoints)[:20]:
            cprint(f"    └─ {endpoint}", SUCCESS)
        if len(scanner.api_endpoints) > 20:
            cprint(f"    └─ ... and {len(scanner.api_endpoints) - 20} more", INFO)
    
    # Display secrets summary
    if scanner.found_data:
        cprint(f"\n[5] 🔑 Phase: Extracted Secrets Summary", INFO)
        secret_categories = {}
        for item in scanner.found_data:
            cat = item['category']
            secret_categories[cat] = secret_categories.get(cat, 0) + 1
        
        for cat, count in secret_categories.items():
            cprint(f"    └─ {cat}: {count}", WARNING)
    
    # Display deduplication stats
    cprint(f"\n[6] 📊 Phase: Deduplication Statistics", INFO)
    dedup_rate = scanner.generate_report(target_url)['statistics']['deduplication_rate']
    cprint(f"    └─ URLs skipped via fingerprinting: {len(scanner.url_fingerprints)}", SUCCESS)
    cprint(f"    └─ Deduplication rate: {dedup_rate}%", SUCCESS)
    
    # Generate final report
    cprint("\n[7] 📋 Phase: Generating Report", INFO)
    report = scanner.generate_report(target_url)
    
    # Final summary
    cprint("\n" + "="*70, HIGHLIGHT)
    cprint("📊 SCAN SUMMARY", HIGHLIGHT, attrs=['bold'])
    cprint("="*70, HIGHLIGHT)
    cprint(f"  URLs Scanned: {len(scanner.scanned_urls)}", INFO)
    cprint(f"  Unique Fingerprints: {len(scanner.url_fingerprints)}", SUCCESS)
    cprint(f"  Deduplication Rate: {report['statistics']['deduplication_rate']}%", SUCCESS)
    cprint(f"  API Endpoints: {len(scanner.api_endpoints)}", SUCCESS if scanner.api_endpoints else INFO)
    cprint(f"  JavaScript Files: {len(scanner.js_files)}", INFO)
    cprint(f"  Secrets Found: {len(scanner.found_data)}", ERROR if scanner.found_data else SUCCESS)
    cprint("="*70 + "\n", HIGHLIGHT)
    
    return report


# ============================================================
# Alias for backward compatibility (للتوافق مع الكود الرئيسي)
# ============================================================
auto_scan_infrastructure = run_multi_scan


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        threads = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        max_urls = int(sys.argv[3]) if len(sys.argv) > 3 else 500
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        run_multi_scan(target, threads=threads, max_urls=max_urls, verbose=verbose)
    else:
        print("Usage: python infra_scanner.py <target_url> [threads] [max_urls] [--verbose]")
        print("Examples:")
        print("  python infra_scanner.py https://example.com")
        print("  python infra_scanner.py https://example.com 20 1000")
        print("  python infra_scanner.py https://example.com --verbose")
