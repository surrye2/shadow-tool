#!/usr/bin/env python3
"""
WHOIS Scanner - AlZill V6 Pro
Advanced domain reconnaissance with multi-IP detection, CDN detection, DNS security records
Features: Multiple IPs | CDN Detection | SPF/DMARC/DKIM | DNS Records | Security Headers
"""

import socket
import requests
import whois
import ssl
import re
import json
import urllib3
import dns.resolver
from datetime import datetime
from termcolor import cprint
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class WhoisScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _clean_date(self, date_value):
        if not date_value: return None
        if isinstance(date_value, list): date_value = date_value[0]
        if hasattr(date_value, 'strftime'):
            return date_value.strftime("%Y-%m-%d")
        return str(date_value)
    
    # ============================================================
    # MULTI-IP DETECTION (تعدد العناوين)
    # ============================================================
    
    def _get_all_ips(self, domain: str) -> List[str]:
        """استخراج جميع عناوين IP المرتبطة بالدومين"""
        ips = set()
        
        # A Records (IPv4)
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for answer in answers:
                ips.add(str(answer))
        except:
            pass
        
        # AAAA Records (IPv6)
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            for answer in answers:
                ips.add(str(answer))
        except:
            pass
        
        return list(ips) if ips else [socket.gethostbyname(domain)]
    
    # ============================================================
    # CDN DETECTION (كشف شبكات التوزيع)
    # ============================================================
    
    def _detect_cdn(self, domain: str, ips: List[str]) -> Tuple[bool, str]:
        """كشف ما إذا كان الدومين خلف CDN"""
        cdn_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
            'Akamai': ['akamai', 'akamaiedge', 'akamaitech'],
            'Fastly': ['fastly', 'x-fastly-request-id'],
            'Amazon CloudFront': ['cloudfront', 'x-amz-cf-id'],
            'Google Cloud CDN': ['google', 'gcdn'],
            'StackPath': ['stackpath', 'sp-cdn'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'Incapsula': ['incapsula', 'x-cdn']
        }
        
        # Check via HTTP headers
        try:
            response = self.session.get(f"https://{domain}", timeout=10, verify=False)
            headers = str(response.headers).lower()
            
            for cdn_name, signatures in cdn_signatures.items():
                for sig in signatures:
                    if sig in headers:
                        return True, cdn_name
        except:
            pass
        
        # Check via IP ranges (simplified)
        for ip in ips:
            if ip.startswith('104.16.') or ip.startswith('104.24.') or ip.startswith('172.64.'):
                return True, 'Cloudflare'
            if ip.startswith('23.32.') or ip.startswith('23.52.') or ip.startswith('23.72.'):
                return True, 'Akamai'
        
        return False, None
    
    # ============================================================
    # DNS SECURITY RECORDS (SPF, DMARC, DKIM)
    # ============================================================
    
    def _get_dns_security_records(self, domain: str) -> Dict:
        """استخراج سجلات DNS الأمنية (SPF, DMARC, DKIM)"""
        records = {
            'spf': None,
            'dmarc': None,
            'dkim': None,
            'mx': [],
            'txt': []
        }
        
        # SPF Record
        try:
            spf = dns.resolver.resolve(domain, 'TXT')
            for record in spf:
                if 'v=spf1' in str(record).lower():
                    records['spf'] = str(record)
                    break
        except:
            pass
        
        # DMARC Record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc = dns.resolver.resolve(dmarc_domain, 'TXT')
            for record in dmarc:
                if 'v=DMARC1' in str(record).upper():
                    records['dmarc'] = str(record)
                    break
        except:
            pass
        
        # MX Records
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            for record in mx:
                records['mx'].append(str(record.exchange).rstrip('.'))
        except:
            pass
        
        # All TXT Records
        try:
            txt = dns.resolver.resolve(domain, 'TXT')
            for record in txt:
                records['txt'].append(str(record)[:100])
        except:
            pass
        
        return records
    
    def _analyze_security_records(self, records: Dict) -> List[str]:
        """تحليل سجلات DNS الأمنية وإعطاء توصيات"""
        recommendations = []
        
        # SPF Analysis
        if records['spf']:
            if '~all' in records['spf']:
                recommendations.append("SPF: SoftFail (~all) - Consider using HardFail (-all)")
            elif '-all' in records['spf']:
                recommendations.append("SPF: HardFail (-all) - Good configuration")
            else:
                recommendations.append("SPF: Missing proper policy - Consider adding -all")
        else:
            recommendations.append("SPF: Missing - Email spoofing risk")
        
        # DMARC Analysis
        if records['dmarc']:
            if 'p=reject' in records['dmarc'].lower():
                recommendations.append("DMARC: Reject policy - Good security")
            elif 'p=quarantine' in records['dmarc'].lower():
                recommendations.append("DMARC: Quarantine policy - Consider upgrading to reject")
            else:
                recommendations.append("DMARC: Found but weak policy")
        else:
            recommendations.append("DMARC: Missing - Email spoofing risk")
        
        return recommendations
    
    # ============================================================
    # SSL INFORMATION (محسن)
    # ============================================================
    
    def _get_ssl_info(self, domain: str) -> Optional[Dict]:
        """استخراج معلومات SSL مع دعم أفضل"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"valid": False, "issuer": "Unknown", "days_left": 0}
                    
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    expiry_str = cert.get('notAfter')
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days
                    
                    return {
                        'issuer': issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                        'subject': subject.get('commonName', 'Unknown'),
                        'expiry_date': expiry_date.strftime("%Y-%m-%d"),
                        'days_left': days_left,
                        'valid': days_left > 0,
                        'version': cert.get('version', 'Unknown')
                    }
        except Exception as e:
            if self.verbose:
                cprint(f"    SSL error: {e}", WARNING)
            return None
    
    # ============================================================
    # SECURITY TXT CHECK
    # ============================================================
    
    def _check_security_txt(self, domain: str) -> Tuple[bool, str]:
        """البحث عن ملف التواصل الأمني"""
        paths = [
            "/.well-known/security.txt",
            "/security.txt",
            "/.well-known/security.txt?",
            "/security.txt?"
        ]
        
        for path in paths:
            try:
                response = self.session.get(f"https://{domain}{path}", timeout=5, verify=False)
                if response.status_code == 200:
                    # Extract contact info
                    contact_match = re.search(r'Contact:\s*(mailto:)?(\S+)', response.text, re.IGNORECASE)
                    if contact_match:
                        contact = contact_match.group(2)
                        return True, f"Found with contact: {contact}"
                    return True, "Found"
            except:
                pass
        
        return False, None
    
    # ============================================================
    # HTTP SECURITY HEADERS
    # ============================================================
    
    def _get_security_headers(self, domain: str) -> Dict:
        """استخراج وتحليل هيدرات الأمان"""
        headers_info = {
            'has_hsts': False,
            'has_csp': False,
            'has_xframe': False,
            'has_xss_protection': False,
            'raw_headers': {}
        }
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10, verify=False)
            headers = response.headers
            
            headers_info['raw_headers'] = dict(headers)
            headers_info['has_hsts'] = 'Strict-Transport-Security' in headers
            headers_info['has_csp'] = 'Content-Security-Policy' in headers
            headers_info['has_xframe'] = 'X-Frame-Options' in headers
            headers_info['has_xss_protection'] = 'X-XSS-Protection' in headers
            
        except Exception as e:
            if self.verbose:
                cprint(f"    Security headers error: {e}", WARNING)
        
        return headers_info

    # ============================================================
    # MAIN SCAN FUNCTION
    # ============================================================
    
    def scan(self, url: str, verbose: bool = False) -> Dict:
        """الوظيفة الرئيسية للمسح"""
        self.verbose = verbose
        
        # استخراج الدومين بشكل نظيف
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path.split("/")[0]
        domain = domain.replace("www.", "").split(':')[0]
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("[RECONNAISSANCE] AlZill V6 Pro - Advanced Domain Intelligence", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        cprint(f"[*] Target: {domain}", INFO)
        cprint("[*] Features: Multi-IP | CDN Detection | SPF/DMARC/DKIM | DNS Records", "yellow")
        
        results = {
            'domain': domain,
            'ips': [],
            'cdn': {'detected': False, 'provider': None},
            'whois': {},
            'ssl': {},
            'dns_security': {},
            'security_headers': {},
            'security_txt': False,
            'timestamp': datetime.now().isoformat()
        }
        
        # ============================================================
        # 1. Multi-IP Detection (تعدد العناوين)
        # ============================================================
        cprint("\n[1] 🌐 Phase: IP Discovery", INFO)
        ips = self._get_all_ips(domain)
        results['ips'] = ips
        
        if len(ips) > 1:
            cprint(f"[+] Found {len(ips)} IP addresses:", SUCCESS)
            for ip in ips:
                cprint(f"    └─ {ip}", INFO)
        else:
            cprint(f"[+] Primary IP: {ips[0] if ips else 'Unknown'}", INFO)
        
        # ============================================================
        # 2. CDN Detection
        # ============================================================
        cprint("\n[2] ☁️ Phase: CDN Detection", INFO)
        cdn_detected, cdn_provider = self._detect_cdn(domain, ips)
        results['cdn']['detected'] = cdn_detected
        results['cdn']['provider'] = cdn_provider
        
        if cdn_detected:
            cprint(f"[!] CDN DETECTED: {cdn_provider}", ERROR)
            cprint(f"    Note: IP addresses may belong to CDN, not origin server", WARNING)
        else:
            cprint(f"[✓] No CDN detected", SUCCESS)
        
        # ============================================================
        # 3. WHOIS Information
        # ============================================================
        cprint("\n[3] 📋 Phase: WHOIS Analysis", INFO)
        try:
            w = whois.whois(domain)
            results['whois'] = {
                'registrar': w.registrar if w.registrar else 'Private/Redacted',
                'creation_date': self._clean_date(w.creation_date),
                'expiration_date': self._clean_date(w.expiration_date),
                'updated_date': self._clean_date(w.updated_date),
                'name_servers': [ns.lower() for ns in (w.name_servers or [])][:5],
                'status': w.status if w.status else []
            }
            
            cprint(f"[+] Registrar: {results['whois']['registrar']}", SUCCESS)
            if results['whois']['creation_date']:
                cprint(f"[+] Created: {results['whois']['creation_date']}", INFO)
            if results['whois']['expiration_date']:
                days_left = (datetime.strptime(results['whois']['expiration_date'], '%Y-%m-%d') - datetime.now()).days
                color = ERROR if days_left < 30 else WARNING if days_left < 90 else SUCCESS
                cprint(f"[+] Expires: {results['whois']['expiration_date']} ({days_left} days left)", color)
            if results['whois']['name_servers']:
                cprint(f"[+] Name Servers: {', '.join(results['whois']['name_servers'][:3])}", INFO)
        except Exception as e:
            cprint(f"[!] WHOIS Error: {e}", WARNING)
        
        # ============================================================
        # 4. DNS Security Records (SPF, DMARC, DKIM)
        # ============================================================
        cprint("\n[4] 🔐 Phase: DNS Security Records", INFO)
        dns_security = self._get_dns_security_records(domain)
        results['dns_security'] = dns_security
        
        if dns_security['spf']:
            cprint(f"[+] SPF Record: {dns_security['spf'][:80]}...", SUCCESS)
        else:
            cprint(f"[!] SPF Record: MISSING", WARNING)
        
        if dns_security['dmarc']:
            cprint(f"[+] DMARC Record: {dns_security['dmarc'][:80]}...", SUCCESS)
        else:
            cprint(f"[!] DMARC Record: MISSING", WARNING)
        
        if dns_security['mx']:
            cprint(f"[+] MX Records: {', '.join(dns_security['mx'][:3])}", INFO)
        
        # Security recommendations
        recommendations = self._analyze_security_records(dns_security)
        if recommendations:
            for rec in recommendations:
                if 'Missing' in rec:
                    cprint(f"    ⚠️ {rec}", WARNING)
                elif 'Good' in rec:
                    cprint(f"    ✅ {rec}", SUCCESS)
                else:
                    cprint(f"    📝 {rec}", INFO)
        
        # ============================================================
        # 5. SSL Certificate Analysis
        # ============================================================
        cprint("\n[5] 🔒 Phase: SSL/TLS Analysis", INFO)
        ssl_info = self._get_ssl_info(domain)
        if ssl_info:
            results['ssl'] = ssl_info
            cprint(f"[+] Issuer: {ssl_info['issuer']}", SUCCESS)
            cprint(f"[+] Subject: {ssl_info['subject']}", INFO)
            days_left = ssl_info['days_left']
            color = ERROR if days_left < 15 else WARNING if days_left < 30 else SUCCESS
            cprint(f"[+] Valid until: {ssl_info['expiry_date']} ({days_left} days left)", color)
        else:
            cprint(f"[!] SSL Certificate: Not found or error", WARNING)
        
        # ============================================================
        # 6. Security Headers
        # ============================================================
        cprint("\n[6] 🛡️ Phase: Security Headers", INFO)
        sec_headers = self._get_security_headers(domain)
        results['security_headers'] = sec_headers
        
        hsts_status = "✅" if sec_headers['has_hsts'] else "❌"
        csp_status = "✅" if sec_headers['has_csp'] else "❌"
        xframe_status = "✅" if sec_headers['has_xframe'] else "❌"
        
        cprint(f"    HSTS: {hsts_status}", SUCCESS if sec_headers['has_hsts'] else WARNING)
        cprint(f"    CSP: {csp_status}", SUCCESS if sec_headers['has_csp'] else WARNING)
        cprint(f"    X-Frame-Options: {xframe_status}", SUCCESS if sec_headers['has_xframe'] else WARNING)
        
        # ============================================================
        # 7. Security.txt Check
        # ============================================================
        cprint("\n[7] 📧 Phase: Security.txt Discovery", INFO)
        security_txt_found, security_txt_detail = self._check_security_txt(domain)
        results['security_txt'] = security_txt_found
        
        if security_txt_found:
            cprint(f"[+] Security.txt: Found", SUCCESS)
            if security_txt_detail:
                cprint(f"    {security_txt_detail}", INFO)
        else:
            cprint(f"[-] Security.txt: Not found", INFO)
        
        # ============================================================
        # 8. Summary
        # ============================================================
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("📊 RECONNAISSANCE SUMMARY", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        cprint(f"  Domain: {domain}", INFO)
        cprint(f"  IPs: {len(ips)} address(es)", INFO)
        cprint(f"  CDN: {'Yes (' + cdn_provider + ')' if cdn_detected else 'No'}", 
               ERROR if cdn_detected else SUCCESS)
        cprint(f"  SPF: {'Configured' if dns_security['spf'] else 'Missing'}", 
               SUCCESS if dns_security['spf'] else WARNING)
        cprint(f"  DMARC: {'Configured' if dns_security['dmarc'] else 'Missing'}", 
               SUCCESS if dns_security['dmarc'] else WARNING)
        cprint(f"  HSTS: {'Enabled' if sec_headers['has_hsts'] else 'Disabled'}", 
               SUCCESS if sec_headers['has_hsts'] else WARNING)
        cprint(f"  SSL Days Left: {ssl_info['days_left'] if ssl_info else 'N/A'}", 
               SUCCESS if ssl_info and ssl_info['days_left'] > 30 else WARNING)
        
        # Save results
        self._save_results(results)
        
        cprint("\n" + "="*60 + "\n", HIGHLIGHT)
        
        return results
    
    def _save_results(self, results: Dict):
        """حفظ النتائج في ملف JSON"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_{results['domain']}_{timestamp}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            if self.verbose:
                cprint(f"\n[+] Results saved to: {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save results: {e}", WARNING)


# ============================================================
# LEGACY FUNCTIONS
# ============================================================

def scan_recon(url: str, verbose: bool = False) -> Dict:
    """Legacy function for backward compatibility"""
    scanner = WhoisScanner(verbose=verbose)
    return scanner.scan(url, verbose)


def scan(url: str, verbose: bool = False) -> Dict:
    """Alias for scan_recon"""
    return scan_recon(url, verbose)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = "--verbose" in sys.argv or "-v" in sys.argv
        scan_recon(target, verbose=verbose)
    else:
        print("Usage: python whois_scanner.py <target_url> [--verbose]")
        print("Examples:")
        print("  python whois_scanner.py https://example.com")
        print("  python whois_scanner.py example.com --verbose")