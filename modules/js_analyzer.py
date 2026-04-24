#!/usr/bin/env python3
"""
JavaScript Analyzer - AlZill V6 Pro
Advanced JS file analysis with smart link extraction, session management, WAF bypass
Features: Absolute/Relative URLs detection | Firebase/Cloudinary/Heroku patterns | Rate limiting
"""

import requests
import re
import json
import urllib3
import time
import random
from termcolor import cprint
from urllib.parse import urljoin, urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional

# تعطيل تحذيرات SSL المزعجة
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"

MAX_JS_FILE_SIZE = 2 * 1024 * 1024  # 2MB max
MAX_WORKERS = 10
REQUEST_DELAY = 0.3


# ============================================================
# ENHANCED SECRET PATTERNS (مع Firebase, Cloudinary, Heroku)
# ============================================================
SECRET_PATTERNS = [
    # Google / Firebase
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google/Firebase API Key', 95),
    (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Cloud Messaging Key', 98),
    (r'[A-Za-z0-9_-]{20,}\.firebaseapp\.com', 'Firebase App URL', 85),
    (r'[A-Za-z0-9_-]{20,}\.web\.app', 'Firebase Web App URL', 85),
    
    # GitHub
    (r'gh[ops]_[0-9a-zA-Z]{36}', 'GitHub Token', 98),
    (r'github_pat_[A-Za-z0-9_]{82}', 'GitHub Personal Access Token', 99),
    (r'[0-9a-f]{40}', 'GitHub Commit SHA (potential)', 60),
    
    # Slack
    (r'xox[baprs]-[0-9a-zA-Z]{10,}', 'Slack Token', 95),
    (r'xoxe\.xox[baprs]-[0-9a-zA-Z]{10,}', 'Slack Enterprise Token', 96),
    
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Secret Key (LIVE)', 99),
    (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Secret Key (TEST)', 95),
    (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Publishable Key (LIVE)', 85),
    
    # Square
    (r'sq0csp-[0-9A-Za-z\-_]{43}', 'Square Access Token', 95),
    (r'EAAA[A-Za-z0-9_-]{60,}', 'Square OAuth Token', 90),
    
    # AWS
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 98),
    (r'aws_access_key_id\s*[:=]\s*["\'][A-Z0-9]{16,}["\']', 'AWS Access Key (Config)', 95),
    (r'aws_secret_access_key\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']', 'AWS Secret Key (Config)', 99),
    
    # Heroku
    (r'HEROKU_API_KEY\s*[:=]\s*["\'][a-z0-9-]{36}["\']', 'Heroku API Key', 99),
    (r'[a-z0-9-]{36}\.herokuapp\.com', 'Heroku App URL', 85),
    (r'heroku\.com\/deploy\?template=https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+', 'Heroku Deploy URL', 70),
    
    # Mailgun
    (r'mailgun\s*[:=]\s*["\']key-[a-z0-9]{32}["\']', 'Mailgun API Key', 95),
    (r'pub-key-[a-z0-9]{32}', 'Mailgun Public Key', 85),
    
    # Cloudinary
    (r'cloudinary:\/\/[0-9]+:[0-9A-Za-z_-]+@[a-zA-Z0-9_-]+', 'Cloudinary URL', 90),
    (r'CLOUDINARY_URL\s*[:=]\s*["\'][^"\']+["\']', 'Cloudinary Config', 90),
    (r'cloud_name\s*[:=]\s*["\'][a-zA-Z0-9_-]+["\']', 'Cloudinary Cloud Name', 75),
    (r'api_key\s*[:=]\s*["\'][0-9]+["\']\s*,\s*api_secret\s*[:=]\s*["\'][A-Za-z0-9_-]+["\']', 'Cloudinary Credentials', 95),
    
    # Twilio
    (r'SK[0-9a-f]{32}', 'Twilio Secret Key', 95),
    (r'AC[0-9a-f]{32}', 'Twilio Account SID', 90),
    
    # SendGrid
    (r'SG\.[a-zA-Z0-9_-]{40,}', 'SendGrid API Key', 95),
    
    # Algolia
    (r'[a-f0-9]{32}\s*[:=]\s*["\'][a-f0-9]{32}["\']', 'Algolia Credentials', 90),
    
    # JWT Tokens
    (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT Token', 85),
    
    # Generic API Keys
    (r'api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']', 'Generic API Key', 75),
    (r'secret[_-]?key\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']', 'Generic Secret Key', 80),
    (r'token\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']', 'Generic Token', 70),
    
    # Sensitive file references
    (r'["\']/[.a-zA-Z0-9/_-]+\.(env|config|bak|sql|key|pem|crt)["\']', 'Sensitive File Reference', 70),
    (r'\.env\b', '.env File Reference', 75),
    (r'config\.(json|yml|yaml|xml)\b', 'Config File Reference', 70),
    
    # Database connection strings
    (r'(mongodb|mysql|postgresql|redis)://[a-zA-Z0-9:;?=@&%_.-]+', 'Database Connection String', 90),
    (r'jdbc:[a-zA-Z0-9]+://[a-zA-Z0-9:;?=@&%_.-]+', 'JDBC Connection String', 85),
    
    # Internal IPs / URLs
    (r'https?://(10|172|192)\.\d+\.\d+\.\d+:\d+', 'Internal URL (RFC1918)', 60),
    (r'https?://localhost(:\d+)?', 'Localhost URL', 50),
    
    # Email addresses
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email Address', 40),
]


class JSAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
        })
        self.session.verify = False  # Bypass SSL verification for pentesting
        self.request_count = 0
        self.found_secrets = []

    def _random_delay(self):
        """Random delay to avoid rate limiting"""
        time.sleep(random.uniform(0.1, 0.5))

    def _extract_js_links(self, url: str, html: str) -> Set[str]:
        """
        استخراج روابط JS بطريقة ذكية (Relative & Absolute & Protocol-relative)
        """
        links = set()
        
        # أنماط متعددة لاستخراج الروابط
        patterns = [
            # src attribute with various quote styles
            r'src=["\']([^"\']+\.js[^"\']*)["\']',
            r"src=['\"]([^'\"]+\.js[^'\"]*)['\"]",
            # href attribute (for some JS links)
            r'href=["\']([^"\']+\.js[^"\']*)["\']',
            # Absolute URLs with http/https
            r'https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]+\.js',
            # Protocol-relative URLs
            r'//[a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]+\.js',
            # Relative paths
            r'["\'](\.\.?/[a-zA-Z0-9/_-]+\.js)["\']',
            # JS imports (dynamic)
            r'import\(["\']([^"\']+\.js)["\']\)',
            r'require\(["\']([^"\']+\.js)["\']\)',
        ]
        
        for pattern in patterns:
            for match in re.findall(pattern, html, re.IGNORECASE):
                if isinstance(match, tuple):
                    match = match[0]
                
                # تنظيف الرابط من الـ Parameters مثل ?v=1.2
                clean_link = match.split('?')[0].split('#')[0]
                
                # بناء الرابط الكامل
                if clean_link.startswith('//'):
                    # Protocol-relative URL
                    parsed = urlparse(url)
                    full_url = f"{parsed.scheme}:{clean_link}"
                elif clean_link.startswith('http://') or clean_link.startswith('https://'):
                    # Absolute URL
                    full_url = clean_link
                else:
                    # Relative URL
                    full_url = urljoin(url, clean_link)
                
                # إزالة الـ fragments
                full_url = full_url.split('#')[0]
                links.add(full_url)
        
        return links

    def _check_js_file(self, full_url: str) -> List[Dict]:
        """
        فحص ملف JS واحد للبحث عن أسرار
        """
        findings = []
        
        try:
            # التحقق من الحجم قبل التحميل الكامل
            head = self.session.head(full_url, timeout=5)
            content_length = int(head.headers.get('Content-Length', 0))
            
            if content_length > MAX_JS_FILE_SIZE:
                if self.verbose:
                    cprint(f"    [!] Skipping large file: {full_url} ({content_length} bytes)", WARNING)
                return []
            
            # تحميل الملف
            self.request_count += 1
            self._random_delay()
            
            resp = self.session.get(full_url, timeout=10)
            content = resp.text
            
            if self.verbose:
                cprint(f"    [*] Analyzing: {full_url} ({len(content)} bytes)", INFO)
            
            # البحث عن الأنماط
            for pattern, name, confidence in SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                for match in set(matches):
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    # تجنب الإيجابيات الكاذبة (مثل روابط JavaScript العادية)
                    if self._is_false_positive(match, name):
                        continue
                    
                    findings.append({
                        'file': full_url,
                        'type': name,
                        'value': match[:80] + "..." if len(match) > 80 else match,
                        'confidence': confidence
                    })
                    
                    if self.verbose:
                        cprint(f"        [+] Found {name} (confidence: {confidence}%)", SUCCESS)
            
        except requests.exceptions.Timeout:
            if self.verbose:
                cprint(f"    [!] Timeout: {full_url}", WARNING)
        except requests.exceptions.TooManyRedirects:
            if self.verbose:
                cprint(f"    [!] Too many redirects: {full_url}", WARNING)
        except Exception as e:
            if self.verbose:
                cprint(f"    [!] Error checking {full_url}: {e}", WARNING)
        
        return findings

    def _is_false_positive(self, match: str, pattern_name: str) -> bool:
        """
        التحقق مما إذا كان النص المكتشف هو إيجابية كاذبة
        """
        # تجنب روابط JavaScript المضمنة
        if match.startswith('javascript:'):
            return True
        
        # تجنب النصوص القصيرة جداً
        if len(match) < 8:
            return True
        
        # تجنب الأمثلة التعليمية
        false_positive_keywords = ['example', 'test', 'demo', 'sample', 'your-', 'changeme', 'REPLACE_ME']
        for keyword in false_positive_keywords:
            if keyword in match.lower():
                return True
        
        return False

    def scan(self, url: str, verbose: bool = False) -> List[Dict]:
        """
        الوظيفة الرئيسية للمسح
        """
        self.verbose = verbose
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("[JS ANALYZER] AlZill V6 Pro - JavaScript Secrets Scanner", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        cprint(f"[*] Target: {url}", INFO)
        cprint("[*] Features: Absolute/Relative URLs | Firebase/Cloudinary/Heroku | Session reuse", "yellow")
        
        all_findings = []
        
        try:
            # جلب الصفحة الرئيسية
            cprint("[*] Fetching page and extracting JS links...", INFO)
            resp = self.session.get(url, timeout=10)
            js_files = self._extract_js_links(url, resp.text)
            
            if not js_files:
                cprint("[-] No JS files detected.", WARNING)
                return []
            
            cprint(f"[+] Found {len(js_files)} JS file(s). Analyzing...", SUCCESS)
            
            # فحص الملفات بالتوازي
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(self._check_js_file, js_url): js_url for js_url in js_files}
                
                for future in as_completed(futures):
                    js_url = futures[future]
                    try:
                        findings = future.result(timeout=30)
                        if findings:
                            all_findings.extend(findings)
                    except Exception as e:
                        if self.verbose:
                            cprint(f"    [!] Error processing {js_url}: {e}", WARNING)
            
            # عرض النتائج
            self._display_results(all_findings)
            
            return all_findings
            
        except Exception as e:
            cprint(f"[-] Scanner Error: {e}", ERROR)
            return []

    def _display_results(self, findings: List[Dict]):
        """
        عرض النتائج بشكل منظم
        """
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint(" JS SECURITY SCAN RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        
        if findings:
            # تجميع حسب الثقة
            high_confidence = [f for f in findings if f['confidence'] >= 90]
            medium_confidence = [f for f in findings if 70 <= f['confidence'] < 90]
            low_confidence = [f for f in findings if f['confidence'] < 70]
            
            cprint(f"\n[!!!] ALERT: {len(findings)} Potential Secret(s) Found!", ERROR, attrs=['bold'])
            cprint(f"    High Confidence (90%+): {len(high_confidence)}", ERROR)
            cprint(f"    Medium Confidence (70-89%): {len(medium_confidence)}", WARNING)
            cprint(f"    Low Confidence (<70%): {len(low_confidence)}", INFO)
            
            # عرض النتائج حسب الثقة
            if high_confidence:
                cprint(f"\n HIGH CONFIDENCE SECRETS:", ERROR)
                for f in high_confidence[:10]:
                    cprint(f"     {f['file']}", INFO)
                    cprint(f"        {f['type']} [{f['confidence']}%]", ERROR)
                    cprint(f"        {f['value']}", "yellow")
                    print()
            
            if medium_confidence:
                cprint(f"\n MEDIUM CONFIDENCE SECRETS:", WARNING)
                for f in medium_confidence[:10]:
                    cprint(f"     {f['file']}", INFO)
                    cprint(f"        {f['type']} [{f['confidence']}%]", WARNING)
                    cprint(f"        {f['value']}", "yellow")
                    print()
            
            if low_confidence and self.verbose:
                cprint(f"\n LOW CONFIDENCE SECRETS:", INFO)
                for f in low_confidence[:5]:
                    cprint(f"     {f['file']}", INFO)
                    cprint(f"        {f['type']} [{f['confidence']}%]", INFO)
                    cprint(f"        {f['value']}", "yellow")
                    print()
            
            if len(findings) > 25:
                cprint(f"\n... and {len(findings) - 25} more findings (use --verbose for details)", WARNING)
            
            # توصيات
            cprint(f"\n📝 RECOMMENDATIONS:", SUCCESS)
            cprint("   1. Revoke any exposed API keys/tokens immediately", INFO)
            cprint("   2. Remove secrets from client-side JavaScript files", INFO)
            cprint("   3. Use environment variables for sensitive data", INFO)
            cprint("   4. Implement CSP (Content Security Policy) to prevent data leakage", INFO)
            
        else:
            cprint(f"\n[✓] JS analysis clean. No common secrets found.", SUCCESS)
            cprint(f"    Total JS files analyzed: {self.request_count}", INFO)
        
        cprint(f"\n[*] Total requests: {self.request_count}", INFO)
        cprint("="*70 + "\n", HIGHLIGHT)


# ============================================================
# LEGACY FUNCTION
# ============================================================

def scan(url: str, verbose: bool = False) -> List[Dict]:
    """Legacy scan function"""
    analyzer = JSAnalyzer(verbose=verbose)
    return analyzer.scan(url, verbose)


if __name__ == "__main__":
    import sys

# ============================================================
# Proxy Support (Auto-injected)
# ============================================================
def get_session_with_proxy(proxy_session=None):
    """Get requests session with proxy support"""
    if proxy_session:
        return proxy_session
    return requests.Session()


def request_with_retry(url, method='GET', data=None, json=None, headers=None, 
                       proxy_session=None, max_retries=3, delay=2, **kwargs):
    """Send request with automatic retry and proxy support"""
    session = get_session_with_proxy(proxy_session)
    
    for attempt in range(max_retries):
        try:
            if method.upper() == 'GET':
                response = session.get(url, headers=headers, timeout=10, verify=False, **kwargs)
            elif method.upper() == 'POST':
                response = session.post(url, data=data, json=json, headers=headers, 
                                       timeout=10, verify=False, **kwargs)
            else:
                response = session.request(method, url, headers=headers, 
                                          timeout=10, verify=False, **kwargs)
            return response
        except (requests.exceptions.ConnectionError, ConnectionResetError) as e:
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise e
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise e
    return None

    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        scan(target, verbose=verbose)
    else:
        print("Usage: python js_analyzer.py <target_url> [--verbose]")
        print("Examples:")
        print("  python js_analyzer.py https://example.com")
        print("  python js_analyzer.py https://example.com --verbose")