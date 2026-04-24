#!/usr/bin/env python3
"""
JS Secret Scanner - AlZill V6 Pro
Advanced JavaScript secret detection with comment stripping, smart AWS detection, relative pathing
Features: Comment removal | High entropy check | Protocol-relative URL support
"""

import re
import requests
import urllib3
from termcolor import cprint
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class JSSecretScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings = []
        self.scanned_urls = set()  # لمنع تكرار فحص نفس الملف
        
        # ============================================================
        # ENHANCED SECRET PATTERNS (مع تحسين AWS Secret)
        # ============================================================
        self.secret_patterns = {
            # Google / Firebase
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'Firebase URL': r'https://[a-z0-9.-]+\.firebaseio\.com',
            'Firebase Config': r'firebaseConfig\s*=\s*{[^}]*apiKey:\s*["\'][^"\']+["\']',
            
            # AWS (محسن - البحث عن الكلمات المفتاحية أولاً)
            'Amazon AWS Access Key ID': r'(?:aws_access_key_id|AWS_ACCESS_KEY_ID|accessKeyId)\s*[:=]\s*["\'](AKIA[0-9A-Z]{16})["\']',
            'Amazon AWS Secret Access Key (w/ keyword)': r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
            'Amazon AWS Secret Access Key (raw)': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            
            # GitHub
            'GitHub Personal Access Token': r'ghp_[a-zA-Z0-9]{36}',
            'GitHub OAuth Access Token': r'gho_[a-zA-Z0-9]{36}',
            'GitHub App Token': r'ghu_[a-zA-Z0-9]{36}',
            'GitHub Refresh Token': r'ghr_[a-zA-Z0-9]{36}',
            
            # Slack
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+',
            
            # Stripe
            'Stripe Secret Key (Live)': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Secret Key (Test)': r'sk_test_[0-9a-zA-Z]{24}',
            'Stripe Publishable Key': r'pk_(live|test)_[0-9a-zA-Z]{24}',
            
            # Facebook
            'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Facebook App Secret': r'[0-9a-f]{32}',
            
            # Mailgun
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'Mailgun Public Key': r'pubkey-[0-9a-zA-Z]{32}',
            
            # Twilio
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'Twilio Account SID': r'AC[0-9a-fA-F]{32}',
            
            # SSH / Private Keys
            'SSH Private Key (RSA)': r'-----BEGIN RSA PRIVATE KEY-----',
            'SSH Private Key (DSA)': r'-----BEGIN DSA PRIVATE KEY-----',
            'SSH Private Key (EC)': r'-----BEGIN EC PRIVATE KEY-----',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            
            # Generic Secrets (مع كلمات مفتاحية)
            'Generic API Key': r'(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']([A-Za-z0-9-_]{16,})["\']',
            'Generic Secret': r'(?:secret|SECRET|client_secret)\s*[:=]\s*["\']([A-Za-z0-9-_]{16,})["\']',
            'Generic Password': r'(?:password|PASSWORD|passwd|db_password)\s*[:=]\s*["\']([^"\']{8,})["\']',
            'Generic Token': r'(?:token|TOKEN|access_token|auth_token)\s*[:=]\s*["\']([A-Za-z0-9-_]{16,})["\']',
            
            # JWT Tokens
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            
            # Cloud Services
            'Cloudinary URL': r'cloudinary://[0-9]{15}:[0-9a-zA-Z_-]+@[a-z]+',
            'Cloudinary Cloud Name': r'cloud_name\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
            
            # Email Services
            'SendGrid API Key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            
            # Database URLs
            'MongoDB URL': r'mongodb(?:\+srv)?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+\.[a-z]{3}/[a-zA-Z0-9]+',
            'MySQL URL': r'mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            'PostgreSQL URL': r'postgresql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9]+',
            'Redis URL': r'redis://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+',
            
            # Internal URLs
            'Internal IP (RFC1918)': r'https?://(10|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.\d+\.\d+:\d+',
            'Localhost URL': r'https?://localhost(:\d+)?',
            
            # Sensitive File References
            'Environment File': r'\.env\b',
            'Config File': r'config\.(json|yml|yaml|xml)\b',
            'Backup File': r'\.(bak|backup|old|swp)\b',
        }

    def _clean_code(self, content: str) -> str:
        """
        إزالة التعليقات من الكود لزيادة دقة الكشف
        (Comment Stripping) - حركة معلم
        """
        # إزالة التعليقات أحادية السطر (//)
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        # إزالة التعليقات متعددة الأسطر (/* ... */)
        content = re.sub(r'/\*[\s\S]*?\*/', '', content)
        # إزالة التعليقات بصيغة HTML (<!-- ... -->)
        content = re.sub(r'<!--[\s\S]*?-->', '', content)
        # إزالة الأسطر الفارغة
        content = re.sub(r'\n\s*\n', '\n', content)
        
        return content

    def _is_high_entropy(self, text: str, threshold: float = 0.45) -> bool:
        """
        التحقق من أن النص عشوائي بما يكفي ليكون مفتاحاً حقيقياً
        """
        if len(text) < 12:
            return False
        
        # حساب عدد الحروف الفريدة
        unique_chars = len(set(text))
        # حساب النسبة المئوية للحروف الفريدة
        entropy_ratio = unique_chars / len(text)
        
        # التحقق من وجود أحرف خاصة (زيادة العشوائية)
        special_chars = sum(1 for c in text if not c.isalnum())
        special_ratio = special_chars / len(text)
        
        # النص عشوائي إذا:
        # - نسبة الحروف الفريدة عالية (> 0.45)
        # - أو يحتوي على أحرف خاصة كثيرة (> 0.15)
        return entropy_ratio > threshold or special_ratio > 0.15

    def _is_false_positive(self, value: str, pattern_name: str) -> bool:
        """
        تجاهل الإيجابيات الكاذبة
        """
        # تجاهل النصوص القصيرة جداً
        if len(value) < 8:
            return True
        
        # تجاهل الأمثلة التعليمية
        false_positive_keywords = [
            'example', 'test', 'demo', 'sample', 'your-', 'changeme',
            'REPLACE_ME', 'YOUR_KEY', 'EXAMPLE_KEY', 'PLACEHOLDER'
        ]
        for keyword in false_positive_keywords:
            if keyword in value.lower():
                return True
        
        # تجاهل النصوص التي تحتوي على مسافات كثيرة
        if value.count(' ') > 3:
            return True
        
        return False

    def scan_content(self, content: str, source: str) -> bool:
        """
        فحص المحتوى بحثاً عن الأسرار
        """
        found_any = False
        
        # إزالة التعليقات قبل الفحص (Comment Stripping)
        clean_code = self._clean_code(content)
        
        if self.verbose:
            original_len = len(content)
            clean_len = len(clean_code)
            if original_len > clean_len:
                cprint(f"    [*] Comment stripping: {original_len - clean_len} bytes removed", INFO)
        
        for name, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, clean_code, re.IGNORECASE)
            
            for match in matches:
                # استخراج القيمة من المجموعة إذا وجدت
                if match.groups():
                    secret_value = match.group(1) if match.group(1) else match.group(0)
                else:
                    secret_value = match.group(0)
                
                # تجاهل الإيجابيات الكاذبة
                if self._is_false_positive(secret_value, name):
                    continue
                
                # التحقق من العشوائية للأنماط العامة
                if 'Generic' in name and not self._is_high_entropy(secret_value):
                    continue
                
                # تحقق إضافي لـ AWS Secret Key
                if 'AWS Secret' in name and len(secret_value) != 40:
                    continue
                
                finding = {
                    'type': name,
                    'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                    'full_value': secret_value,
                    'source': source,
                    'severity': 'CRITICAL' if any(k in name for k in ['Secret', 'Key', 'Token']) else 'HIGH'
                }
                self.findings.append(finding)
                found_any = True
                
                if self.verbose:
                    cprint(f"    [!] DISCOVERED: {name}", ERROR)
                    cprint(f"        Value: {secret_value[:30]}...", WARNING)
                    cprint(f"        Source: {source}", INFO)
        
        return found_any

    def extract_js_files(self, html: str, base_url: str) -> Set[str]:
        """
        استخراج روابط JS مع معالجة الروابط التي تبدأ بـ //
        """
        js_files = set()
        
        # أنماط متعددة لاستخراج الروابط
        patterns = [
            r'src=["\']([^"\']+\.js[^"\']*)["\']',
            r'src=([^\s>]+\.js)',
            r'data-src=["\']([^"\']+\.js[^"\']*)["\']',
            r'href=["\']([^"\']+\.js[^"\']*)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                # تنظيف الرابط
                clean_link = match.split('?')[0].split('#')[0]
                
                # معالجة الروابط التي تبدأ بـ // (Protocol-relative)
                if clean_link.startswith('//'):
                    # استخدام https كافتراضي
                    full_url = f"https:{clean_link}"
                elif clean_link.startswith('/'):
                    # رابط نسبي يبدأ بـ /
                    full_url = urljoin(base_url, clean_link)
                elif clean_link.startswith('http://') or clean_link.startswith('https://'):
                    # رابط مطلق
                    full_url = clean_link
                else:
                    # رابط نسبي
                    full_url = urljoin(base_url, clean_link)
                
                js_files.add(full_url)
        
        return js_files

    def scan_url(self, target_url: str):
        """
        فحص الموقع والملفات المرتبطة به
        """
        try:
            cprint(f"\n[*] Crawling for Secrets: {target_url}", INFO)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
            
            response = requests.get(target_url, timeout=10, verify=False, headers=headers)
            
            # فحص الصفحة الرئيسية
            cprint("[*] Scanning main page...", INFO)
            self.scan_content(response.text, target_url)
            
            # استخراج ملفات JS الخارجية (مع معالجة الروابط)
            cprint("[*] Extracting JavaScript files...", INFO)
            js_files = self.extract_js_files(response.text, target_url)
            cprint(f"[+] Found {len(js_files)} JavaScript file(s)", SUCCESS)
            
            # فحص كل ملف JS
            for js_url in js_files:
                if js_url in self.scanned_urls:
                    continue
                self.scanned_urls.add(js_url)
                
                if self.verbose:
                    cprint(f"    [*] Analyzing: {js_url}", INFO)
                
                try:
                    js_response = requests.get(js_url, timeout=5, verify=False, headers=headers)
                    if js_response.status_code == 200:
                        self.scan_content(js_response.text, js_url)
                    else:
                        if self.verbose:
                            cprint(f"    [!] Failed to fetch: HTTP {js_response.status_code}", WARNING)
                except requests.exceptions.Timeout:
                    if self.verbose:
                        cprint(f"    [!] Timeout: {js_url}", WARNING)
                except Exception as e:
                    if self.verbose:
                        cprint(f"    [!] Error: {e}", WARNING)
            
            # عرض التقرير
            self.report()
            
        except Exception as e:
            cprint(f"[-] Error: {e}", ERROR)

    def report(self):
        """
        عرض التقرير النهائي
        """
        if not self.findings:
            cprint("\n[✓] No hardcoded secrets found.", SUCCESS)
            return
        
        # تجميع حسب الخطورة
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        
        cprint(f"\n{'='*60}", ERROR)
        cprint(f"[!] SECRET SCAN REPORT", HIGHLIGHT, attrs=['bold'])
        cprint(f"{'='*60}", ERROR)
        cprint(f"Total Secrets Found: {len(self.findings)}", WARNING)
        cprint(f"Critical: {len(critical)} | High: {len(high)}", ERROR if critical else INFO)
        
        # عرض النتائج حسب الخطورة
        if critical:
            cprint(f"\n🔴 CRITICAL SECRETS:", ERROR)
            for f in critical[:10]:
                cprint(f"  📁 TYPE: {f['type']}", ERROR)
                cprint(f"     SOURCE: {f['source']}", INFO)
                cprint(f"     VALUE: {f['value']}", WARNING)
                print()
        
        if high and self.verbose:
            cprint(f"\n🟡 HIGH RISK SECRETS:", WARNING)
            for f in high[:10]:
                cprint(f"  📁 TYPE: {f['type']}", WARNING)
                cprint(f"     SOURCE: {f['source']}", INFO)
                cprint(f"     VALUE: {f['value']}", WARNING)
                print()
        
        if len(self.findings) > 20:
            cprint(f"\n... and {len(self.findings) - 20} more secrets", INFO)
        
        # توصيات
        cprint(f"\n📝 RECOMMENDATIONS:", SUCCESS)
        cprint("  1. Revoke any exposed API keys/tokens immediately", INFO)
        cprint("  2. Remove secrets from client-side JavaScript files", INFO)
        cprint("  3. Use environment variables for sensitive data", INFO)
        cprint("  4. Implement secret rotation policy", INFO)
        
        cprint(f"\n{'='*60}\n", ERROR)


# ============================================================
# LEGACY FUNCTION
# ============================================================

def scan(url: str, verbose: bool = True) -> bool:
    """
    الوظيفة المطلوبة للتشغيل
    """
    scanner = JSSecretScanner(verbose=verbose)
    scanner.scan_url(url)
    return len(scanner.findings) > 0


if __name__ == "__main__":
    import sys
import time

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
        print("Usage: python js_secret_scanner.py <target_url> [--verbose]")
        print("Examples:")
        print("  python js_secret_scanner.py https://example.com")
        print("  python js_secret_scanner.py https://example.com --verbose")