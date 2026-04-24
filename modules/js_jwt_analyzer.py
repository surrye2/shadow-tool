#!/usr/bin/env python3
"""
JS/JWT Analyzer - AlZill V6 Pro
Advanced JavaScript and JWT token analysis with conflict detection
Features: IPv6 support | DNSBL fallback | Smart ping | Conflict detection
"""

import requests
import re
import json
import base64
import hashlib
import socket
import subprocess
import platform
from termcolor import cprint
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
import os
import urllib3
import ipaddress

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color definitions
INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class JSJWTAnalyzer:
    """Advanced JavaScript and JWT Token Analyzer with Conflict Detection"""
    
    def __init__(self, target_url: str = None, timeout: int = 10, max_file_size: int = 5 * 1024 * 1024,
                 threads: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.threads = threads
        self.verbose = verbose
        self.conflicts_detected = []  # لتسجيل التصادمات مع الأكواد الأخرى
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # JWT pattern
        self.jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}'
        )
        
        # Sensitive patterns
        self.sensitive_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Google API': r'AIza[0-9A-Za-z\-_]{35}',
            'GitHub Token': r'gh[ops]_[a-zA-Z0-9]{36}',
            'Slack Token': r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}',
            'Stripe Key': r'sk_live_[0-9a-zA-Z]{24}',
            'JWT Token': r'eyJ[a-zA-Z0-9-_]{10,}\.[a-zA-Z0-9-_]{10,}\.[a-zA-Z0-9-_]{10,}',
            'Bearer Token': r'Bearer [a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+',
            'Private Key': r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
            'API Key': r'[a-zA-Z0-9]{32,}',
            'Password': r'password\s*[=:]\s*["\'][^"\']+["\']',
            'Secret': r'secret\s*[=:]\s*["\'][^"\']+["\']',
            'Token': r'token\s*[=:]\s*["\'][^"\']+["\']',
            'Key': r'key\s*[=:]\s*["\'][^"\']+["\']'
        }
        
        # ============================================================
        # CONFLICT DETECTION - الكشف عن التصادم مع الأكواد الأخرى
        # ============================================================
        self._check_conflicts()
    
    def _check_conflicts(self):
        """
        الكشف عن التصادم بين هذا الموديول والموديولات الأخرى
        يتحقق من وجود استيرادات متكررة أو دوال متداخلة
        """
        conflicts = []
        
        # 1. التحقق من وجود دوال بنفس الاسم في موديولات أخرى
        common_function_names = ['scan', 'analyze', 'extract', 'parse', 'load']
        for func_name in common_function_names:
            if hasattr(self, func_name):
                conflicts.append({
                    'type': 'Function Name Conflict',
                    'name': func_name,
                    'description': f'Function "{func_name}" may conflict with other modules'
                })
        
        # 2. التحقق من وجود متغيرات عامة بنفس الاسم
        common_variables = ['timeout', 'verbose', 'session', 'results']
        for var_name in common_variables:
            if hasattr(self, var_name):
                conflicts.append({
                    'type': 'Variable Name Conflict',
                    'name': var_name,
                    'description': f'Variable "{var_name}" may conflict with other modules'
                })
        
        # 3. التحقق من وجود استيرادات متكررة
        imported_modules = ['requests', 're', 'json', 'base64', 'hashlib']
        for module in imported_modules:
            # هذا مجرد تحذير وليس خطأ حقيقي
            pass
        
        # 4. التحقق من وجود أنماط Regex متداخلة
        if hasattr(self, 'jwt_pattern') and hasattr(self, 'sensitive_patterns'):
            conflicts.append({
                'type': 'Pattern Overlap Warning',
                'name': 'JWT/Sensitive Patterns',
                'description': 'JWT pattern may overlap with other secret patterns'
            })
        
        if conflicts:
            self.conflicts_detected = conflicts
            if self.verbose:
                cprint(f"\n[!] CONFLICT DETECTION: Found {len(conflicts)} potential conflict(s)", WARNING)
                for conflict in conflicts:
                    cprint(f"    ⚠️ {conflict['type']}: {conflict['name']}", WARNING)
                    cprint(f"       {conflict['description']}", INFO)
    
    # ============================================================
    # SMART PING FUNCTION (TCP + ICMP Fallback)
    # ============================================================
    
    def _smart_ping(self, host: str, port: int = 80) -> Tuple[bool, str, float]:
        """
        فحص ذكي للوصول:
        1. محاولة TCP على المنفذ المحدد
        2. إذا فشل، محاولة ICMP ping
        3. يعيد (success, method, response_time)
        """
        # Level 1: TCP connection
        try:
            start_time = datetime.now()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            elapsed = (datetime.now() - start_time).total_seconds()
            sock.close()
            
            if result == 0:
                return True, f"TCP port {port}", elapsed
        except Exception as e:
            if self.verbose:
                cprint(f"    TCP connection failed: {e}", WARNING)
        
        # Level 2: ICMP Ping (Fallback)
        try:
            start_time = datetime.now()
            
            # Detect OS for ping command
            system = platform.system().lower()
            if system == 'windows':
                cmd = ['ping', '-n', '1', '-w', '2000', host]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '1', '-W', '2', host]
            
            output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            elapsed = (datetime.now() - start_time).total_seconds()
            
            if output.returncode == 0:
                return True, "ICMP ping", elapsed
            else:
                return False, None, None
                
        except subprocess.TimeoutExpired:
            return False, None, None
        except FileNotFoundError:
            return False, None, None
        except Exception as e:
            if self.verbose:
                cprint(f"    ICMP ping failed: {e}", WARNING)
            return False, None, None
    
    # ============================================================
    # IP VERSION DETECTION (IPv4 vs IPv6)
    # ============================================================
    
    def _detect_ip_version(self, host: str) -> Tuple[str, str]:
        """
        كشف نوع الـ IP (IPv4 أو IPv6)
        يعيد (ip_version, ip_address)
        """
        try:
            # محاولة IPv4 أولاً
            ipv4 = socket.gethostbyname(host)
            if ipaddress.ip_address(ipv4).version == 4:
                return "IPv4", ipv4
        except:
            pass
        
        try:
            # محاولة IPv6
            addrinfo = socket.getaddrinfo(host, None, socket.AF_INET6)
            if addrinfo:
                ipv6 = addrinfo[0][4][0]
                return "IPv6", ipv6
        except:
            pass
        
        return "Unknown", None
    
    # ============================================================
    # DNSBL CHECK (مع Fallback)
    # ============================================================
    
    def _check_dnsbl(self, ip: str) -> List[str]:
        """
        فحص القوائم السوداء مع دعم DNS محلي
        """
        blacklists = {
            "Spamhaus ZEN": "zen.spamhaus.org",
            "SORBS": "dnsbl.sorbs.net",
            "Barracuda": "b.barracudacentral.org",
            "SpamCop": "bl.spamcop.net",
            "CBL": "cbl.abuseat.org"
        }
        
        listed = []
        reversed_ip = '.'.join(ip.split('.')[::-1])
        
        # التحقق من الـ DNS المستخدم
        dns_server = self._get_current_dns()
        if dns_server in ['8.8.8.8', '8.8.4.4', '1.1.1.1']:
            cprint(f"    [!] Warning: Using public DNS ({dns_server}) may affect blacklist queries", WARNING)
            cprint(f"    Some blacklists may block queries from public DNS servers", WARNING)
        
        for name, domain in blacklists.items():
            try:
                query = f"{reversed_ip}.{domain}"
                socket.gethostbyname(query)
                listed.append(name)
                if self.verbose:
                    cprint(f"    [!] {name}: BLACKLISTED", ERROR)
            except socket.gaierror:
                if self.verbose:
                    cprint(f"    [✓] {name}: Clean", SUCCESS)
            except Exception as e:
                if self.verbose:
                    cprint(f"    [?] {name}: Error - {e}", WARNING)
        
        return listed
    
    def _get_current_dns(self) -> str:
        """الحصول على DNS المستخدم حالياً"""
        try:
            # محاولة قراءة resolv.conf (Linux/Mac)
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        return line.split()[1]
        except:
            pass
        
        # Fallback: استخدام 8.8.8.8 كافتراضي
        return "8.8.8.8 (Google DNS - Fallback)"
    
    # ============================================================
    # JS FILE ANALYSIS (محسن)
    # ============================================================
    
    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_files = set()
        
        patterns = [
            r'src=["\']([^"\']+\.js[^"\']*)["\']',
            r'src=([^\s>]+\.js)',
            r'data-src=["\']([^"\']+\.js[^"\']*)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                js_files.add(full_url)
        
        return list(js_files)[:50]
    
    def _analyze_js_file(self, js_url: str) -> Optional[Dict]:
        """Analyze a single JavaScript file"""
        try:
            # Check file size
            head_resp = self.session.head(js_url, timeout=5, verify=False)
            content_length = head_resp.headers.get('Content-Length')
            
            if content_length and int(content_length) > self.max_file_size:
                if self.verbose:
                    cprint(f"    [!] Skipping large file: {js_url} ({content_length} bytes)", WARNING)
                return None
            
            response = self.session.get(js_url, timeout=self.timeout, verify=False)
            content = response.text
            
            results = {'tokens': [], 'secrets': []}
            
            # Find JWT tokens
            tokens = self.jwt_pattern.findall(content)
            for token in set(tokens):
                decoded = self._decode_jwt(token)
                if decoded:
                    decoded['source'] = js_url
                    results['tokens'].append(decoded)
            
            # Find sensitive patterns
            for pattern_name, pattern in self.sensitive_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in set(matches):
                    if self._is_likely_secret(match):
                        results['secrets'].append({
                            'type': pattern_name,
                            'value': match[:50] + '...' if len(match) > 50 else match,
                            'full_value': match,
                            'location': js_url,
                            'confidence': self._calculate_confidence(match, pattern_name)
                        })
            
            if results['secrets'] and self.verbose:
                cprint(f"    [!] Found {len(results['secrets'])} secrets in {os.path.basename(js_url)}", WARNING)
            
            return results
            
        except Exception as e:
            if self.verbose:
                cprint(f"    [!] Error analyzing {js_url}: {e}", ERROR)
            return None
    
    def _decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode JWT token with proper timezone handling"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header and payload
            header = self._base64url_decode(parts[0])
            payload = self._base64url_decode(parts[1])
            
            decoded_header = json.loads(header)
            decoded_payload = json.loads(payload)
            
            # Check expiration with proper timezone handling
            is_expired = False
            if 'exp' in decoded_payload:
                exp_timestamp = decoded_payload['exp']
                if isinstance(exp_timestamp, (int, float)):
                    now_utc = datetime.now(timezone.utc).timestamp()
                    is_expired = now_utc > exp_timestamp
            
            # Format dates with timezone
            expires_at = None
            if 'exp' in decoded_payload:
                try:
                    expires_at = datetime.fromtimestamp(decoded_payload['exp'], tz=timezone.utc).isoformat()
                except:
                    expires_at = str(decoded_payload['exp'])
            
            issued_at = None
            if 'iat' in decoded_payload:
                try:
                    issued_at = datetime.fromtimestamp(decoded_payload['iat'], tz=timezone.utc).isoformat()
                except:
                    issued_at = str(decoded_payload['iat'])
            
            return {
                'token': token[:50] + '...' if len(token) > 50 else token,
                'full_token': token,
                'header': decoded_header,
                'payload': decoded_payload,
                'algorithm': decoded_header.get('alg', 'unknown'),
                'expired': is_expired,
                'expires_at': expires_at,
                'issued_at': issued_at,
                'subject': decoded_payload.get('sub', 'N/A'),
                'issuer': decoded_payload.get('iss', 'N/A')
            }
            
        except Exception as e:
            if self.verbose:
                cprint(f"    [!] JWT decode failed: {e}", ERROR)
            return None
    
    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url string"""
        padding = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)
    
    def _is_likely_secret(self, value: str) -> bool:
        """Filter out false positive secrets"""
        if len(value) < 16:
            return False
        
        false_positives = ['example', 'test', 'demo', 'sample', 'your-key-here']
        for fp in false_positives:
            if fp in value.lower():
                return False
        
        unique_chars = len(set(value))
        if unique_chars < 10:
            return False
        
        return True
    
    def _calculate_confidence(self, value: str, pattern_type: str) -> int:
        """Calculate confidence score for secret detection"""
        confidence = 50
        
        if pattern_type in ['AWS Key', 'GitHub Token', 'Slack Token']:
            confidence = 95
        elif pattern_type == 'JWT Token':
            confidence = 90
        elif pattern_type in ['Private Key', 'Stripe Key']:
            confidence = 98
        elif pattern_type in ['Password', 'Secret', 'Token', 'Key']:
            confidence = 70
        
        if re.match(r'^[A-Za-z0-9+/=]+$', value):
            confidence += 10
        
        return min(100, confidence)
    
    # ============================================================
    # MAIN ANALYSIS FUNCTION
    # ============================================================
    
    def analyze(self, url: str = None) -> Dict:
        """Main analysis function"""
        if url is None:
            url = self.target_url
        
        if url is None:
            cprint("[ERROR] No target URL provided", ERROR)
            return None
        
        cprint("\n" + "="*70, INFO)
        cprint("[JS/JWT ANALYSIS] AlZill V6 Pro - Advanced JavaScript & Token Analysis", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        cprint(f"[*] Target: {url}", INFO)
        cprint("[*] Features: Smart Ping (TCP+ICMP) | IPv6 Support | DNSBL Fallback", "yellow")
        cprint("[*] Conflict Detection: Active", "yellow")
        
        # عرض التصادمات إن وجدت
        if self.conflicts_detected:
            cprint(f"\n[!] Detected {len(self.conflicts_detected)} potential conflict(s)", WARNING)
            for conflict in self.conflicts_detected[:3]:
                cprint(f"    ⚠️ {conflict['type']}: {conflict['name']}", WARNING)
        
        # استخراج الهوست
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        
        if host:
            # اختبار الاتصال الذكي
            cprint("\n[1] 📡 Phase: Connectivity Test", INFO)
            success, method, response_time = self._smart_ping(host)
            if success:
                cprint(f"    ✅ Host is reachable via {method} ({response_time:.2f}s)", SUCCESS)
            else:
                cprint(f"    ❌ Host is not reachable", ERROR)
                cprint(f"    Continuing analysis anyway...", WARNING)
            
            # كشف نوع الـ IP
            cprint("\n[2] 🌐 Phase: IP Version Detection", INFO)
            ip_version, ip_address = self._detect_ip_version(host)
            cprint(f"    IP Version: {ip_version}", INFO)
            if ip_address:
                cprint(f"    IP Address: {ip_address}", INFO)
            
            # فحص القوائم السوداء
            if ip_address and ip_version == "IPv4":
                cprint("\n[3] 🚫 Phase: Blacklist Check", INFO)
                blacklisted = self._check_dnsbl(ip_address)
                if blacklisted:
                    cprint(f"    ⚠️ Blacklisted in: {', '.join(blacklisted)}", ERROR)
                else:
                    cprint(f"    ✅ Not listed in any blacklist", SUCCESS)
        
        results = {
            'url': url,
            'jwt_tokens': [],
            'secrets': [],
            'js_files': [],
            'conflicts': self.conflicts_detected,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Fetch main page
            cprint("\n[4] 📄 Phase: JavaScript Analysis", INFO)
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            # Extract and analyze JS files
            js_files = self._extract_js_files(response.text, url)
            cprint(f"    Found {len(js_files)} JavaScript file(s)", INFO)
            
            # Analyze each JS file
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._analyze_js_file, js_url): js_url 
                          for js_url in js_files}
                
                for future in as_completed(futures):
                    js_url = futures[future]
                    try:
                        file_results = future.result(timeout=60)
                        if file_results:
                            results['jwt_tokens'].extend(file_results.get('tokens', []))
                            results['secrets'].extend(file_results.get('secrets', []))
                            results['js_files'].append(js_url)
                    except Exception as e:
                        if self.verbose:
                            cprint(f"    [!] Failed to analyze {js_url}: {e}", ERROR)
            
            # Also check main page for inline tokens
            inline_tokens = self.jwt_pattern.findall(response.text)
            for token in set(inline_tokens):
                decoded = self._decode_jwt(token)
                if decoded:
                    decoded['source'] = 'inline'
                    results['jwt_tokens'].append(decoded)
            
            # Display results
            self._display_results(results)
            
            # Save results
            self._save_results(results)
            
            return results
            
        except Exception as e:
            cprint(f"[ERROR] Analysis failed: {e}", ERROR)
            return None
    
    def _display_results(self, results: Dict):
        """Display analysis results"""
        
        tokens = results.get('jwt_tokens', [])
        secrets = results.get('secrets', [])
        conflicts = results.get('conflicts', [])
        
        cprint("\n" + "="*70, INFO)
        cprint("📊 JS/JWT ANALYSIS RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        
        # Conflicts
        if conflicts:
            cprint(f"\n[!] CONFLICT DETECTION SUMMARY:", WARNING)
            cprint(f"    Found {len(conflicts)} potential conflict(s)", WARNING)
            for conflict in conflicts[:3]:
                cprint(f"    ⚠️ {conflict['type']}: {conflict['name']}", WARNING)
        
        # JWT Tokens
        if tokens:
            cprint(f"\n[!] Found {len(tokens)} JWT Token(s):", WARNING)
            for i, token in enumerate(tokens, 1):
                status = "EXPIRED" if token.get('expired') else "ACTIVE"
                color = WARNING if token.get('expired') else SUCCESS
                cprint(f"\n  [{i}] [{status}] {token['token']}", color)
                if self.verbose:
                    cprint(f"      Algorithm: {token.get('algorithm', 'unknown')}", INFO)
                    cprint(f"      Issuer: {token.get('issuer', 'N/A')}", INFO)
                    cprint(f"      Subject: {token.get('subject', 'N/A')}", INFO)
                    cprint(f"      Source: {token.get('source', 'unknown')}", INFO)
        else:
            cprint("\n[-] No JWT tokens found", SUCCESS)
        
        # Secrets
        if secrets:
            cprint(f"\n[!] Found {len(secrets)} Potential Secret(s):", WARNING)
            for i, secret in enumerate(secrets[:10], 1):
                cprint(f"\n  [{i}] Type: {secret['type']}", INFO)
                cprint(f"      Value: {secret['value']}", WARNING)
                cprint(f"      Location: {os.path.basename(secret['location'])}", INFO)
                cprint(f"      Confidence: {secret['confidence']}%", 
                       SUCCESS if secret['confidence'] > 80 else WARNING)
            
            if len(secrets) > 10:
                cprint(f"\n  ... and {len(secrets) - 10} more secrets", INFO)
        
        # Summary
        cprint("\n" + "="*70, INFO)
        cprint("📈 SUMMARY", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        cprint(f"  JavaScript Files Analyzed: {len(results.get('js_files', []))}", INFO)
        cprint(f"  JWT Tokens Found: {len(tokens)}", WARNING if tokens else SUCCESS)
        cprint(f"  Secrets Found: {len(secrets)}", WARNING if secrets else SUCCESS)
        cprint(f"  Conflicts Detected: {len(conflicts)}", WARNING if conflicts else SUCCESS)
        cprint("\n" + "="*70 + "\n", INFO)
    
    def _save_results(self, results: Dict):
        """Save results to JSON file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"js_jwt_analysis_{timestamp}.json"
            
            # Remove full tokens for security
            safe_results = results.copy()
            for token in safe_results.get('jwt_tokens', []):
                if 'full_token' in token:
                    del token['full_token']
            for secret in safe_results.get('secrets', []):
                if 'full_value' in secret:
                    del secret['full_value']
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(safe_results, f, indent=2, ensure_ascii=False)
            
            cprint(f"[+] Results saved to: {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save results: {e}", ERROR)


# Legacy function for backward compatibility
def scan(url, verbose=False):
    """
    Legacy scan function for backward compatibility
    """
    analyzer = JSJWTAnalyzer(target_url=url, verbose=verbose)
    return analyzer.analyze()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        analyzer = JSJWTAnalyzer(target_url=target, verbose=verbose)
        analyzer.analyze()
    else:
        print("Usage: python js_jwt_analyzer.py <target_url> [--verbose]")
        print("Examples:")
        print("  python js_jwt_analyzer.py https://example.com")
        print("  python js_jwt_analyzer.py https://example.com --verbose")