#!/usr/bin/env python3
"""
CSRF Protection Checker - AlZill V6
Advanced CSRF detection with support for: Forms, Meta tags, Headers, Cookies, JavaScript
Features: Double Submit Cookie detection, AJAX CSRF, Multi-form analysis
"""

import requests
import re
import json
from termcolor import cprint
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class CSRFScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # ============================================================
        # قائمة أسماء التوكنات الموسعة
        # ============================================================
        self.token_names = [
            'csrf_token', '_token', 'csrfmiddlewaretoken', 'authenticity_token',
            'csrf', 'anti_csrf', 'xsrf-token', 'XSRF-TOKEN', 'csrf-token',
            '__RequestVerificationToken', 'CSRFToken', 'csrfKey', 'token',
            'x_csrf_token', 'csrf_name', 'csrf_value', 'csrf_hash',
            'antiCsrf', 'csrfToken', 'CSRF-Token', 'X-CSRF-TOKEN',
            'X-XSRF-TOKEN', 'csrf_prevention_token', 'security_token',
            'form_token', 'session_token', 'state', 'nonce'
        ]
        
        # ============================================================
        # قائمة الهيدرات المهمة للـ CSRF
        # ============================================================
        self.csrf_headers = [
            'X-CSRF-TOKEN', 'X-XSRF-TOKEN', 'CSRF-TOKEN', 'X-CSRFToken',
            'X-CSRF-Token', 'X-Csrf-Token', 'X-CSRF-Protection'
        ]
        
        # ============================================================
        # قائمة الكوكيز المهمة للـ CSRF (Double Submit Cookie)
        # ============================================================
        self.csrf_cookies = [
            'csrf_token', 'XSRF-TOKEN', 'CSRF-TOKEN', 'csrf', '_csrf',
            'X-CSRF-TOKEN', 'csrfToken', 'CSRFToken'
        ]
        
        self.results = {
            'forms': [],
            'has_protection': False,
            'protection_methods': [],
            'vulnerable_forms': []
        }

    def scan(self, url: str, verbose=False):
        """الوظيفة الرئيسية للمسح"""
        self.verbose = verbose
        
        cprint("\n" + "="*60, INFO)
        cprint("[CSRF SCAN] AlZill V6 - Advanced CSRF Protection Checker", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, INFO)
        cprint(f"[*] Target: {url}", INFO)
        cprint("[*] Techniques: Forms | Meta Tags | Headers | Cookies | JavaScript", "yellow")
        cprint("[*] Detection: Double Submit Cookie | AJAX CSRF | Multi-form Analysis", "yellow")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            if response.status_code != 200:
                cprint(f"[!] HTTP {response.status_code} - Cannot scan", WARNING)
                return
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # ============================================================
            # 1. فحص الفورمات (Forms)
            # ============================================================
            cprint("\n[*] Phase 1: Analyzing forms...", INFO)
            forms = soup.find_all("form")
            
            if not forms:
                cprint("    No forms found on page", WARNING)
            else:
                cprint(f"    Found {len(forms)} form(s)", INFO)
                
                for idx, form in enumerate(forms):
                    self._analyze_form(form, idx, url, response)
            
            # ============================================================
            # 2. فحص الميتا تاغز (Meta Tags)
            # ============================================================
            cprint("\n[*] Phase 2: Checking meta tags...", INFO)
            self._check_meta_tags(soup)
            
            # ============================================================
            # 3. فحص الهيدرات (Headers)
            # ============================================================
            cprint("\n[*] Phase 3: Checking response headers...", INFO)
            self._check_headers(response)
            
            # ============================================================
            # 4. فحص الكوكيز (Cookies - Double Submit Cookie)
            # ============================================================
            cprint("\n[*] Phase 4: Checking cookies (Double Submit)...", INFO)
            self._check_cookies(response)
            
            # ============================================================
            # 5. فحص الـ JavaScript (AJAX CSRF)
            # ============================================================
            cprint("\n[*] Phase 5: Analyzing JavaScript for CSRF tokens...", INFO)
            self._check_javascript(soup, response.text)
            
            # ============================================================
            # عرض النتائج النهائية
            # ============================================================
            self._display_results(url)
            
        except Exception as e:
            cprint(f"[!] CSRF scan error: {e}", ERROR)
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _analyze_form(self, form, idx: int, url: str, response):
        """تحليل فورم واحد بشكل متقدم"""
        form_info = {
            'index': idx + 1,
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'has_csrf': False,
            'csrf_location': None,
            'csrf_name': None,
            'inputs': []
        }
        
        if form_info['action']:
            form_info['action'] = urljoin(url, form_info['action'])
        else:
            form_info['action'] = url
        
        inputs = form.find_all("input")
        
        for inp in inputs:
            input_info = {
                'type': inp.get('type', 'text'),
                'name': inp.get('name', ''),
                'id': inp.get('id', ''),
                'value': inp.get('value', '')[:30]
            }
            form_info['inputs'].append(input_info)
            
            name = input_info['name'].lower()
            if name in self.token_names:
                form_info['has_csrf'] = True
                form_info['csrf_location'] = 'input name attribute'
                form_info['csrf_name'] = input_info['name']
            
            id_attr = input_info['id'].lower()
            if not form_info['has_csrf'] and id_attr in self.token_names:
                form_info['has_csrf'] = True
                form_info['csrf_location'] = 'input id attribute'
                form_info['csrf_name'] = input_info['id']
            
            if not form_info['has_csrf']:
                for attr in inp.attrs:
                    if attr.startswith('data-') and attr[5:] in self.token_names:
                        form_info['has_csrf'] = True
                        form_info['csrf_location'] = f'input {attr} attribute'
                        form_info['csrf_name'] = attr
        
        if not form_info['has_csrf']:
            for attr in form.attrs:
                if attr in self.token_names or (attr.startswith('data-') and attr[5:] in self.token_names):
                    form_info['has_csrf'] = True
                    form_info['csrf_location'] = f'form {attr} attribute'
                    form_info['csrf_name'] = attr
        
        self.results['forms'].append(form_info)
        
        if form_info['has_csrf']:
            if self.verbose:
                cprint(f"    Form #{form_info['index']}: CSRF token found ({form_info['csrf_location']})", SUCCESS)
        else:
            sensitive_keywords = ['password', 'email', 'profile', 'settings', 'delete', 'update', 'edit']
            is_sensitive = False
            
            for inp in form_info['inputs']:
                if any(keyword in inp['name'].lower() for keyword in sensitive_keywords):
                    is_sensitive = True
                    break
            
            if is_sensitive or form_info['method'] == 'POST':
                self.results['vulnerable_forms'].append(form_info)
                if self.verbose:
                    cprint(f"    Form #{form_info['index']}: ⚠️ NO CSRF protection (Sensitive form)", ERROR)

    def _check_meta_tags(self, soup):
        """فحص الميتا تاغز للبحث عن توكنات CSRF"""
        meta_tags = soup.find_all("meta")
        
        for meta in meta_tags:
            meta_name = meta.get('name', '').lower()
            meta_property = meta.get('property', '').lower()
            
            if meta_name in self.token_names or meta_property in self.token_names:
                self.results['has_protection'] = True
                self.results['protection_methods'].append(f'Meta tag: {meta_name or meta_property}')
                if self.verbose:
                    cprint(f"    [+] CSRF token in meta tag: {meta_name or meta_property}", SUCCESS)
                return
            
            for attr in meta.attrs:
                if attr.startswith('data-') and attr[5:] in self.token_names:
                    self.results['has_protection'] = True
                    self.results['protection_methods'].append(f'Meta tag attribute: {attr}')
                    if self.verbose:
                        cprint(f"    [+] CSRF token in meta tag attribute: {attr}", SUCCESS)
                    return

    def _check_headers(self, response):
        """فحص الهيدرات للبحث عن توكنات CSRF"""
        for header_name in self.csrf_headers:
            header_value = response.headers.get(header_name, '')
            if header_value:
                self.results['has_protection'] = True
                self.results['protection_methods'].append(f'Header: {header_name}')
                if self.verbose:
                    cprint(f"    [+] CSRF token in header: {header_name}", SUCCESS)
                return
        
        for header_name, header_value in response.headers.items():
            if header_name.lower() in [h.lower() for h in self.token_names]:
                self.results['has_protection'] = True
                self.results['protection_methods'].append(f'Header: {header_name}')
                if self.verbose:
                    cprint(f"    [+] CSRF token in header: {header_name}", SUCCESS)
                return

    def _check_cookies(self, response):
        """فحص الكوكيز للبحث عن Double Submit Cookie CSRF"""
        csrf_cookies_found = []
        
        # 1. البحث في الكوكيز المحددة مسبقاً
        for cookie_name in self.csrf_cookies:
            if cookie_name in response.cookies:
                csrf_cookies_found.append(cookie_name)
                self.results['has_protection'] = True
                self.results['protection_methods'].append(f'Cookie (Double Submit): {cookie_name}')
                if self.verbose:
                    cprint(f"    [+] CSRF cookie found: {cookie_name} (Double Submit Cookie pattern)", SUCCESS)
        
        # 2. فحص عام لجميع الكوكيز (الجزء المصحح)
        for cookie in response.cookies:
            name_str = cookie.name
            if name_str.lower() in [t.lower() for t in self.token_names]:
                if name_str not in csrf_cookies_found:
                    csrf_cookies_found.append(name_str)
                    self.results['has_protection'] = True
                    self.results['protection_methods'].append(f'Cookie: {name_str}')
                    if self.verbose:
                        cprint(f"    [+] CSRF cookie found: {name_str}", SUCCESS)

    def _check_javascript(self, soup, html_content):
        """فحص الـ JavaScript للبحث عن توكنات CSRF"""
        
        script_tags = soup.find_all("script")
        
        for script in script_tags:
            if script.string:
                script_content = script.string
                
                patterns = [
                    r'csrf[\s_\-]*token[\s:]*["\']([^"\']+)',
                    r'X-CSRF-TOKEN[\s:]*["\']([^"\']+)',
                    r'XSRF-TOKEN[\s:]*["\']([^"\']+)',
                    r'headers["\']?\s*:\s*{[^}]*X-CSRF-TOKEN',
                    r'headers["\']?\s*:\s*{[^}]*X-XSRF-TOKEN',
                    r'axios\.defaults\.headers\.common\[[\'"]X-CSRF-TOKEN[\'"]',
                    r'fetch\([^)]*,\s*{[^}]*headers[^}]*X-CSRF-TOKEN',
                ]
                
                for pattern in patterns:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        self.results['has_protection'] = True
                        self.results['protection_methods'].append('JavaScript (AJAX CSRF)')
                        if self.verbose:
                            cprint(f"    [+] CSRF protection detected in JavaScript (AJAX)", SUCCESS)
                        return
        
        external_scripts = soup.find_all("script", src=True)
        for script in external_scripts:
            src = script['src']
            if any(keyword in src.lower() for keyword in ['csrf', 'token', 'security']):
                if self.verbose:
                    cprint(f"    [*] Suspicious script found: {src}", INFO)

    def _display_results(self, url):
        """عرض النتائج النهائية"""
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("📊 CSRF PROTECTION SUMMARY", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        
        total_forms = len(self.results['forms'])
        protected_forms = len([f for f in self.results['forms'] if f['has_csrf']])
        vulnerable_forms = len(self.results['vulnerable_forms'])
        
        cprint(f"\n  Forms Analysis:", INFO)
        cprint(f"    ├─ Total forms found: {total_forms}", INFO)
        cprint(f"    ├─ Forms with CSRF protection: {protected_forms}", SUCCESS if protected_forms > 0 else WARNING)
        cprint(f"    └─ Vulnerable forms: {vulnerable_forms}", ERROR if vulnerable_forms > 0 else SUCCESS)
        
        if self.results['has_protection']:
            cprint(f"\n  ✅ CSRF Protection: ACTIVE", SUCCESS)
            cprint(f"     Detection methods:", SUCCESS)
            for method in self.results['protection_methods']:
                cprint(f"       └─ {method}", SUCCESS)
        else:
            cprint(f"\n  ❌ CSRF Protection: MISSING", ERROR)
            cprint(f"     No CSRF protection detected on this page", ERROR)
        
        if self.results['vulnerable_forms']:
            cprint(f"\n  ⚠️ VULNERABLE FORMS:", ERROR)
            for form in self.results['vulnerable_forms']:
                cprint(f"     Form #{form['index']}: {form['action']}", WARNING)
                cprint(f"        Method: {form['method']}", INFO)
                if form['inputs']:
                    sensitive_inputs = [i for i in form['inputs'] if any(k in i['name'].lower() for k in ['pass', 'email', 'user'])]
                    if sensitive_inputs:
                        cprint(f"        Contains sensitive fields: {', '.join([i['name'] for i in sensitive_inputs[:3]])}", WARNING)
        
        cprint(f"\n  📝 Recommendations:", INFO)
        if not self.results['has_protection']:
            cprint(f"     • Implement CSRF tokens for all state-changing requests", WARNING)
            cprint(f"     • Use SameSite cookies (Strict or Lax)", WARNING)
            cprint(f"     • Consider Double Submit Cookie pattern", WARNING)
        elif vulnerable_forms > 0:
            cprint(f"     • Add CSRF protection to the {vulnerable_forms} vulnerable form(s)", WARNING)
            cprint(f"     • Verify all POST/PUT/DELETE requests have CSRF tokens", WARNING)
        
        if any('Cookie' in m for m in self.results['protection_methods']):
            cprint(f"\n  ℹ️ Double Submit Cookie Pattern Detected:", INFO)
            cprint(f"     The application uses cookies for CSRF protection", INFO)
            cprint(f"     This is generally secure, but ensure the cookie is not accessible via JavaScript", INFO)
        
        cprint("\n" + "="*60, HIGHLIGHT)
        self._generate_report()

    def _generate_report(self):
        """توليد تقرير JSON"""
        try:
            from datetime import datetime
            filename = f"csrf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'has_protection': self.results['has_protection'],
                'protection_methods': self.results['protection_methods'],
                'total_forms': len(self.results['forms']),
                'protected_forms': len([f for f in self.results['forms'] if f['has_csrf']]),
                'vulnerable_forms': len(self.results['vulnerable_forms']),
                'vulnerable_forms_details': self.results['vulnerable_forms'],
                'all_forms': self.results['forms']
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            cprint(f"\n[+] Report saved to: {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save report: {e}", WARNING)


def scan(url, verbose=False):
    """دالة التوافق مع المحرك الرئيسي AlZill"""
    scanner = CSRFScanner(verbose=verbose)
    scanner.scan(url, verbose)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python csrf_checker.py <target_url>")
        print("Example: python csrf_checker.py https://example.com/login")
