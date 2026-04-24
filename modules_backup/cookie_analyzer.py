#!/usr/bin/env python3
"""
Cookie Security Analyzer - AlZill V6 Edition
Advanced cookie security analysis with SameSite detection, Sensitive data discovery
Features: SameSite flags, JWT detection, Secure attribute validation, Fallback mechanisms
"""

import json
import time
import re
import requests
import urllib3
import os
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from termcolor import cprint

# تعطيل تحذيرات SSL المزعجة
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# محاولة استيراد Selenium مع معالجة غيابه
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    cprint("[!] Selenium not available. Install with: pip install selenium", "yellow")

# تعريف الألوان
INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class CookieAnalyzer:
    def __init__(self, timeout: int = 25, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0'
        })
        
        self.results = {
            'cookies': [],
            'summary': {'total': 0, 'secure': 0, 'insecure': 0},
            'network_info': {},
            'sensitive_data': [],
            'vulnerabilities': []
        }
        
        # ============================================================
        # أنماط الكشف عن البيانات الحساسة
        # ============================================================
        self.sensitive_patterns = [
            # JWT Tokens
            (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT Token'),
            # Email addresses
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email Address'),
            # IP Addresses
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP Address'),
            # Phone numbers
            (r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}', 'Phone Number'),
            # Credit Card numbers (basic)
            (r'\b(?:\d[ -]*?){13,16}\b', 'Credit Card Number (potential)'),
            # Session IDs (long strings)
            (r'[a-f0-9]{32,64}', 'Session ID (Hash)'),
            # Base64 encoded data
            (r'[A-Za-z0-9+/]{40,}={0,2}', 'Base64 Encoded Data'),
        ]
        
        # ============================================================
        # قائمة الأمان للكوكيز (Security Score)
        # ============================================================
        self.security_flags = {
            'secure': {'weight': 25, 'description': 'Secure flag - ensures cookie sent over HTTPS only'},
            'httpOnly': {'weight': 25, 'description': 'HttpOnly flag - prevents JavaScript access'},
            'sameSite': {'weight': 30, 'description': 'SameSite flag - protects against CSRF'},
            'expires': {'weight': 10, 'description': 'Expiration date - prevents session fixation'},
            'domain': {'weight': 10, 'description': 'Domain restriction - limits cookie scope'},
            'path': {'weight': 5, 'description': 'Path restriction - limits cookie scope'}
        }

    def _get_network_info(self):
        """جلب معلومات الشبكة والموقع مع معالجة أخطاء الاتصال"""
        try:
            res = requests.get('http://ip-api.com/json/', timeout=5).json()
            if res.get('status') == 'success':
                return res
        except:
            return None

    def _setup_chrome_options(self):
        """إعدادات المتصفح المثالية لبيئة Termux (بدون نوافذ وبدون أخطاء)"""
        chrome_options = Options()
        
        # الإعدادات السحرية لإخفاء الأخطاء
        chrome_options.add_argument("--headless")              # العمل في الخلفية
        chrome_options.add_argument("--no-sandbox")            # ضروري جداً لأندرويد
        chrome_options.add_argument("--disable-dev-shm-usage") # لمنع الانهيار (Crash)
        chrome_options.add_argument("--disable-gpu")           # تقليل استهلاك الموارد
        chrome_options.add_argument("--log-level=3")           # إخفاء رسائل الخطأ
        chrome_options.add_argument("--silent")                # التشغيل الصامت
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        
        # مسارات Termux الرسمية
        possible_paths = [
            "/data/data/com.termux/files/usr/bin/chromium-browser",
            "/data/data/com.termux/files/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                chrome_options.binary_location = path
                break
        
        return chrome_options

    def _extract_cookies_selenium(self, url: str) -> List[Dict]:
        """استخراج الكوكيز باستخدام المحرك المتطور"""
        if not SELENIUM_AVAILABLE:
            if self.verbose:
                cprint("[!] Selenium not installed. Skipping JS extraction.", WARNING)
            return []

        driver = None
        try:
            service = Service(executable_path="/data/data/com.termux/files/usr/bin/chromedriver")
            driver = webdriver.Chrome(service=service, options=self._setup_chrome_options())
            driver.set_page_load_timeout(self.timeout)
            
            driver.get(url)
            time.sleep(5)  # انتظار تنفيذ الـ JavaScript بالموقع
            
            cookies = driver.get_cookies()
            
            # إضافة معلومات إضافية عن SameSite
            for cookie in cookies:
                # محاولة الحصول على SameSite من JavaScript
                try:
                    same_site = driver.execute_script(f"""
                        return document.cookie.split(';').find(c => c.trim().startsWith('{cookie.get('name')}='));
                    """)
                    if same_site and 'SameSite' in same_site:
                        cookie['sameSite'] = re.search(r'SameSite=(\w+)', same_site).group(1) if re.search(r'SameSite=(\w+)', same_site) else 'None'
                except:
                    cookie['sameSite'] = cookie.get('sameSite', 'Not Set')
            
            return cookies
            
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Selenium Error: {e}", ERROR)
            return []
        finally:
            if driver:
                driver.quit()

    def _extract_cookies_requests(self, url: str) -> List[Dict]:
        """
        استخراج الكوكيز باستخدام requests (Fallback محسن)
        """
        cookies = []
        
        try:
            # طلب أولي للحصول على الكوكيز
            response = self.session.get(url, timeout=10, verify=False)
            
            # استخراج الكوكيز من الـ Response
            for name, value in response.cookies.items():
                cookie = {
                    'name': name,
                    'value': value[:50] + '...' if len(value) > 50 else value,
                    'secure': response.cookies._cookies.get(name, {}).get('secure', False),
                    'httpOnly': response.cookies._cookies.get(name, {}).get('httponly', False),
                    'sameSite': response.cookies._cookies.get(name, {}).get('samesite', 'Not Set'),
                    'domain': response.cookies._cookies.get(name, {}).get('domain', ''),
                    'path': response.cookies._cookies.get(name, {}).get('path', '/'),
                }
                cookies.append(cookie)
            
            # محاولة الحصول على الكوكيز من الـ Headers
            set_cookie_headers = response.headers.get('Set-Cookie', '')
            if set_cookie_headers:
                for header in set_cookie_headers.split(','):
                    cookie_info = self._parse_set_cookie_header(header)
                    if cookie_info:
                        # التحقق من عدم التكرار
                        if not any(c['name'] == cookie_info['name'] for c in cookies):
                            cookies.append(cookie_info)
            
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Requests cookie extraction error: {e}", WARNING)
        
        return cookies

    def _parse_set_cookie_header(self, header: str) -> Dict:
        """تحويل Set-Cookie header إلى قاموس"""
        try:
            parts = header.split(';')
            name_value = parts[0].split('=', 1)
            cookie = {
                'name': name_value[0].strip(),
                'value': name_value[1].strip()[:50] + '...' if len(name_value[1].strip()) > 50 else name_value[1].strip(),
                'secure': 'Secure' in header,
                'httpOnly': 'HttpOnly' in header,
                'sameSite': 'Not Set',
                'domain': '',
                'path': '/'
            }
            
            # استخراج SameSite
            samesite_match = re.search(r'SameSite=(\w+)', header, re.IGNORECASE)
            if samesite_match:
                cookie['sameSite'] = samesite_match.group(1)
            
            # استخراج Domain
            domain_match = re.search(r'Domain=([^;]+)', header, re.IGNORECASE)
            if domain_match:
                cookie['domain'] = domain_match.group(1).strip()
            
            # استخراج Path
            path_match = re.search(r'Path=([^;]+)', header, re.IGNORECASE)
            if path_match:
                cookie['path'] = path_match.group(1).strip()
            
            return cookie
        except:
            return None

    def _detect_sensitive_data(self, cookie: Dict) -> List[Dict]:
        """كشف البيانات الحساسة داخل قيمة الكوكي"""
        sensitive_found = []
        value = cookie.get('value', '')
        
        for pattern, data_type in self.sensitive_patterns:
            matches = re.findall(pattern, value)
            for match in matches:
                sensitive_found.append({
                    'cookie': cookie['name'],
                    'type': data_type,
                    'value': match[:50] + '...' if len(match) > 50 else match
                })
        
        return sensitive_found

    def _decode_jwt(self, token: str) -> Dict:
        """فك تشفير JWT token"""
        try:
            parts = token.split('.')
            if len(parts) == 3:
                header = base64.b64decode(parts[0] + '==').decode('utf-8')
                payload = base64.b64decode(parts[1] + '==').decode('utf-8')
                return {
                    'header': json.loads(header),
                    'payload': json.loads(payload)
                }
        except:
            pass
        return None

    def _analyze_samesite(self, cookie: Dict) -> Tuple[int, List[str]]:
        """
        تحليل SameSite flag
        SameSite=None requires Secure, otherwise browsers reject it
        """
        issues = []
        score = 0
        
        samesite = cookie.get('sameSite', 'Not Set')
        
        if samesite == 'Strict':
            score = 30
            issues.append("SameSite=Strict - Good CSRF protection")
        elif samesite == 'Lax':
            score = 20
            issues.append("SameSite=Lax - Moderate CSRF protection")
        elif samesite == 'None':
            score = 10
            issues.append("SameSite=None - No CSRF protection")
            # التحقق من Secure flag مع SameSite=None
            if not cookie.get('secure', False):
                issues.append("CRITICAL: SameSite=None requires Secure flag! Modern browsers will reject this cookie.")
        else:
            score = 0
            issues.append("SameSite not set - Vulnerable to CSRF attacks")
        
        return score, issues

    def _analyze_cookie(self, cookie: Dict) -> Dict:
        """تحليل أمان الكوكيز الفردي (محسن)"""
        name = cookie.get('name', 'Unknown')
        total_score = 0
        all_issues = []
        recommendations = []
        
        # 1. تحليل Secure flag
        if cookie.get('secure', False):
            total_score += self.security_flags['secure']['weight']
        else:
            all_issues.append("Secure flag missing - Cookie sent over HTTP (man-in-the-middle risk)")
            recommendations.append("Add Secure flag to ensure cookie only sent over HTTPS")
        
        # 2. تحليل HttpOnly flag
        if cookie.get('httpOnly', False):
            total_score += self.security_flags['httpOnly']['weight']
        else:
            all_issues.append("HttpOnly flag missing - Cookie accessible via JavaScript (XSS risk)")
            recommendations.append("Add HttpOnly flag to prevent XSS attacks")
        
        # 3. تحليل SameSite (محسن)
        samesite_score, samesite_issues = self._analyze_samesite(cookie)
        total_score += samesite_score
        all_issues.extend(samesite_issues)
        
        # 4. تحليل Expiration
        expires = cookie.get('expiry', cookie.get('expires', None))
        if expires:
            total_score += self.security_flags['expires']['weight']
        else:
            all_issues.append("No expiration set - Session cookie (persists until browser close)")
        
        # 5. تحليل Domain
        domain = cookie.get('domain', '')
        if domain:
            total_score += self.security_flags['domain']['weight']
        else:
            all_issues.append("No domain restriction - Cookie sent to all subdomains")
        
        # 6. تحليل Path
        path = cookie.get('path', '/')
        if path != '/':
            total_score += self.security_flags['path']['weight']
        
        # تحديد الحالة
        if total_score >= 80:
            status = 'SECURE'
            status_color = SUCCESS
        elif total_score >= 60:
            status = 'MODERATE'
            status_color = WARNING
        else:
            status = 'VULNERABLE'
            status_color = ERROR
        
        return {
            'name': name,
            'value': cookie.get('value', '')[:50],
            'score': total_score,
            'max_score': 100,
            'issues': all_issues,
            'recommendations': recommendations,
            'status': status,
            'status_color': status_color,
            'flags': {
                'secure': cookie.get('secure', False),
                'httpOnly': cookie.get('httpOnly', False),
                'sameSite': cookie.get('sameSite', 'Not Set'),
                'domain': domain,
                'path': path
            }
        }

    def scan(self, url: str):
        """دالة الفحص الرئيسية المتوافقة مع AlZill V6"""
        if not url.startswith('http'):
            url = 'https://' + url
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("[COOKIE ANALYZER] AlZill V6 - Advanced Cookie Security Scanner", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        cprint(f"[*] Target: {url}", INFO)
        cprint("[*] Features: SameSite Detection | JWT Analysis | Sensitive Data Discovery", "yellow")
        cprint("[*] CSRF Protection Analysis | Secure Flag Validation", "yellow")
        
        # 1. Network Data
        net = self._get_network_info()
        if net:
            cprint(f"\n[+] IP: {net['query']} | Country: {net['country']} | ISP: {net['isp']}", SUCCESS)

        # 2. Extracting Cookies (Selenium + Fallback)
        cprint("\n[*] Phase 1: Extracting cookies...", INFO)
        cookies = self._extract_cookies_selenium(url)
        
        # Fallback محسن باستخدام requests
        if not cookies:
            cprint("[*] Selenium failed, using requests fallback...", WARNING)
            cookies = self._extract_cookies_requests(url)
        
        if not cookies:
            cprint("[!] No cookies could be extracted.", ERROR)
            return False

        cprint(f"[+] Successfully extracted {len(cookies)} cookies.", SUCCESS)
        
        # 3. Analyze each cookie
        cprint("\n[*] Phase 2: Analyzing cookie security...", INFO)
        print("-" * 60)
        
        all_sensitive_data = []
        vulnerabilities = []
        
        for cookie in cookies:
            analysis = self._analyze_cookie(cookie)
            self.results['cookies'].append(analysis)
            
            # عرض النتائج
            status_color = analysis['status_color']
            cprint(f"\n  📍 Cookie: {analysis['name']}", HIGHLIGHT)
            cprint(f"     Value: {analysis['value']}...", INFO)
            cprint(f"     Score: {analysis['score']}/{analysis['max_score']} [{analysis['status']}]", status_color)
            
            # عرض الفلاغات
            flags = analysis['flags']
            cprint(f"     Flags:", INFO)
            cprint(f"       ├─ Secure: {flags['secure']}", SUCCESS if flags['secure'] else ERROR)
            cprint(f"       ├─ HttpOnly: {flags['httpOnly']}", SUCCESS if flags['httpOnly'] else ERROR)
            cprint(f"       ├─ SameSite: {flags['sameSite']}", 
                   SUCCESS if flags['sameSite'] in ['Strict', 'Lax'] else ERROR)
            cprint(f"       ├─ Domain: {flags['domain'] or 'Not set'}", INFO)
            cprint(f"       └─ Path: {flags['path']}", INFO)
            
            # عرض المشاكل
            if analysis['issues']:
                cprint(f"     Issues:", WARNING)
                for issue in analysis['issues']:
                    cprint(f"       └─ {issue}", WARNING)
            
            # عرض التوصيات
            if analysis['recommendations']:
                cprint(f"     Recommendations:", SUCCESS)
                for rec in analysis['recommendations']:
                    cprint(f"       └─ {rec}", SUCCESS)
            
            # كشف البيانات الحساسة
            sensitive = self._detect_sensitive_data(cookie)
            if sensitive:
                all_sensitive_data.extend(sensitive)
                cprint(f"     ⚠️ Sensitive Data Found:", ERROR)
                for data in sensitive:
                    cprint(f"       └─ {data['type']}: {data['value']}", ERROR)
            
            # تسجيل الثغرات
            if analysis['score'] < 60:
                vulnerabilities.append({
                    'cookie': analysis['name'],
                    'score': analysis['score'],
                    'issues': analysis['issues']
                })
        
        # 4. JWT Detection and Analysis
        cprint("\n[*] Phase 3: Analyzing for JWT tokens...", INFO)
        for cookie in cookies:
            if 'jwt' in cookie.get('name', '').lower() or 'token' in cookie.get('name', '').lower():
                jwt_data = self._decode_jwt(cookie.get('value', ''))
                if jwt_data:
                    cprint(f"\n  🔐 JWT Token Found in cookie: {cookie['name']}", HIGHLIGHT)
                    cprint(f"     Header: {json.dumps(jwt_data['header'], indent=6)}", INFO)
                    cprint(f"     Payload: {json.dumps(jwt_data['payload'], indent=6)}", INFO)
                    
                    # تحليل JWT
                    if jwt_data['payload'].get('exp'):
                        exp_time = datetime.fromtimestamp(jwt_data['payload']['exp'])
                        if exp_time < datetime.now():
                            cprint(f"     Status: EXPIRED", ERROR)
                        else:
                            cprint(f"     Status: VALID until {exp_time}", SUCCESS)
        
        # 5. Summary
        self.results['summary']['total'] = len(cookies)
        self.results['summary']['secure'] = len([c for c in self.results['cookies'] if c['status'] == 'SECURE'])
        self.results['summary']['insecure'] = len([c for c in self.results['cookies'] if c['status'] == 'VULNERABLE'])
        self.results['sensitive_data'] = all_sensitive_data
        self.results['vulnerabilities'] = vulnerabilities
        
        # عرض الملخص النهائي
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("📊 COOKIE SECURITY SUMMARY", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        cprint(f"  Total Cookies: {self.results['summary']['total']}", INFO)
        cprint(f"  Secure Cookies: {self.results['summary']['secure']}", SUCCESS)
        cprint(f"  Vulnerable Cookies: {self.results['summary']['insecure']}", ERROR)
        
        if all_sensitive_data:
            cprint(f"\n  ⚠️ Sensitive Data Exposed: {len(all_sensitive_data)} items", ERROR)
            for data in all_sensitive_data[:5]:
                cprint(f"     └─ {data['type']} in cookie '{data['cookie']}'", WARNING)
        
        if vulnerabilities:
            cprint(f"\n  🔴 CSRF Risk Assessment:", ERROR)
            for vuln in vulnerabilities:
                cprint(f"     └─ Cookie '{vuln['cookie']}' (Score: {vuln['score']}/100)", WARNING)
        
        cprint("\n" + "="*60, HIGHLIGHT)
        
        # توليد التقرير
        self._generate_report()
        
        return len(cookies) > 0
    
    def _generate_report(self):
        """توليد تقرير JSON"""
        try:
            filename = f"cookie_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            cprint(f"\n[+] Report saved to: {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save report: {e}", WARNING)


# ============================================================
# دالة التوافق مع المحرك الرئيسي
# ============================================================

def scan(url: str, verbose: bool = False):
    """دالة التوافق مع المحرك الرئيسي AlZill"""
    analyzer = CookieAnalyzer(verbose=verbose)
    return analyzer.scan(url)


def scan_cookies(url: str, verbose: bool = False):
    """Alias للدالة الرئيسية"""
    return scan(url, verbose)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
    scan(target, verbose=True)