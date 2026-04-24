#!/usr/bin/env python3
"""
Header Analyzer - AlZill V6 Pro
Advanced HTTP Security Headers Analysis with CSP deep inspection, Cookie flags, Fingerprinting
Features: CSP unsafe-inline/eval detection, Cookie flags (HttpOnly/Secure/SameSite), Technology fingerprinting
"""

import requests
from termcolor import cprint
import re
from urllib.parse import urlparse
import json
from datetime import datetime
import urllib3
from typing import Dict, List, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class HeaderAnalyzer:
    """Advanced HTTP Security Headers Analyzer - CSP Deep Analysis + Cookie Flags + Fingerprinting"""
    
    def __init__(self, timeout: int = 15, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # ============================================================
        # Critical security headers with descriptions
        # ============================================================
        self.critical_headers = {
            "Strict-Transport-Security": {
                "name": "HSTS",
                "risk": "SSL Stripping",
                "recommendation": "Add HSTS header with max-age=31536000; includeSubDomains"
            },
            "Content-Security-Policy": {
                "name": "CSP",
                "risk": "XSS, Code Injection",
                "recommendation": "Implement strict CSP with nonce or hash"
            },
            "X-Frame-Options": {
                "name": "Clickjacking",
                "risk": "Clickjacking",
                "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "name": "MIME Sniffing",
                "risk": "MIME Sniffing Attacks",
                "recommendation": "Add X-Content-Type-Options: nosniff"
            },
            "Referrer-Policy": {
                "name": "Referrer Leak",
                "risk": "Information Leak",
                "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin"
            },
            "Permissions-Policy": {
                "name": "Feature Control",
                "risk": "Browser Feature Abuse",
                "recommendation": "Restrict geolocation, camera, microphone, etc."
            }
        }
        
        # ============================================================
        # Technology fingerprinting headers
        # ============================================================
        self.tech_headers = {
            "Server": "Web Server",
            "X-Powered-By": "Backend Framework",
            "X-AspNet-Version": "ASP.NET Version",
            "X-AspNetMvc-Version": "ASP.NET MVC Version",
            "X-Runtime": "Ruby on Rails Runtime",
            "X-Generator": "CMS/Generator",
            "X-Drupal-Cache": "Drupal CMS",
            "X-Drupal-Dynamic-Cache": "Drupal CMS",
            "X-Varnish": "Varnish Cache",
            "X-Cache": "Cache Server",
            "X-Cache-Hits": "Cache Server",
            "CF-Ray": "Cloudflare",
            "CF-Cache-Status": "Cloudflare",
            "X-Sucuri-ID": "Sucuri WAF",
            "X-Akamai-Transformed": "Akamai CDN",
            "X-Request-ID": "Request Tracking",
            "X-Runtime": "Ruby/Rails",
            "X-Version": "Version Info",
            "X-Powered-By-Plesk": "Plesk Control Panel",
            "X-OWA-Version": "Outlook Web Access",
            "X-Backend-Server": "Backend Server"
        }
        
        # ============================================================
        # HTTP methods to test
        # ============================================================
        self.methods = ['GET', 'HEAD', 'POST', 'OPTIONS', 'TRACE']
        
        # ============================================================
        # CSP dangerous directives
        # ============================================================
        self.csp_dangerous = {
            "'unsafe-inline'": "Allows inline scripts (XSS risk)",
            "'unsafe-eval'": "Allows eval() (code injection risk)",
            "'unsafe-hashes'": "Allows unsafe hashes",
            "'unsafe-dynamic'": "Allows dynamic script loading",
            "data:": "Allows data: URIs (XSS risk)",
            "http://": "Allows insecure HTTP sources",
            "*": "Wildcard allows any source"
        }
        
        self.csp_missing = {
            "default-src": "No default fallback policy",
            "script-src": "No script source restriction",
            "style-src": "No style source restriction",
            "object-src": "No plugin/object restriction",
            "frame-ancestors": "No clickjacking protection"
        }
    
    def scan(self, url: str) -> Dict:
        """Main scanning function"""
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("[HEADER ANALYSIS] AlZill V6 Pro - Advanced Security Headers Scanner", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        cprint("[*] Features: CSP Deep Analysis | Cookie Flags | Technology Fingerprinting", "yellow")
        cprint("[*] Detection: unsafe-inline/eval | HttpOnly/Secure/SameSite | Server/Powered-By", "yellow")
        
        url = self._normalize_url(url)
        domain = urlparse(url).netloc
        
        # Send multiple requests to check consistency
        responses = {}
        for method in self.methods:
            try:
                if method == 'GET':
                    resp = self.session.get(url, timeout=self.timeout, verify=False)
                elif method == 'HEAD':
                    resp = self.session.head(url, timeout=self.timeout, verify=False)
                elif method == 'POST':
                    resp = self.session.post(url, timeout=self.timeout, verify=False)
                elif method == 'OPTIONS':
                    resp = self.session.options(url, timeout=self.timeout, verify=False)
                elif method == 'TRACE':
                    resp = self.session.request('TRACE', url, timeout=self.timeout, verify=False)
                else:
                    continue
                
                responses[method] = resp
                if self.verbose:
                    cprint(f"[*] {method} request: {resp.status_code}", INFO)
                    
            except Exception as e:
                if self.verbose:
                    cprint(f"[!] {method} failed: {e}", WARNING)
                responses[method] = None
        
        # Analyze headers from GET request (primary)
        if not responses.get('GET'):
            cprint("[!] Failed to fetch page", ERROR)
            return None
        
        headers = responses['GET'].headers
        cookies = responses['GET'].cookies
        
        # ============================================================
        # 1. Basic Security Headers Check
        # ============================================================
        cprint("\n[1] 🔐 Phase: Security Headers Analysis", INFO)
        self._analyze_security_headers(headers, responses)
        
        # ============================================================
        # 2. CSP Deep Analysis (مهم جداً)
        # ============================================================
        cprint("\n[2] 🛡️ Phase: CSP (Content Security Policy) Deep Analysis", INFO)
        self._analyze_csp(headers)
        
        # ============================================================
        # 3. Cookie Security Flags (HttpOnly, Secure, SameSite)
        # ============================================================
        cprint("\n[3] 🍪 Phase: Cookie Security Analysis", INFO)
        self._analyze_cookies(cookies, headers)
        
        # ============================================================
        # 4. Technology Fingerprinting (Server, X-Powered-By, etc.)
        # ============================================================
        cprint("\n[4] 🔬 Phase: Technology Fingerprinting", INFO)
        self._analyze_technology(headers, url, domain)
        
        # ============================================================
        # 5. Permissions-Policy (Feature-Policy)
        # ============================================================
        cprint("\n[5] 📱 Phase: Permissions-Policy Analysis", INFO)
        self._analyze_permissions_policy(headers)
        
        # ============================================================
        # 6. Inconsistent Headers Check
        # ============================================================
        self._check_inconsistent_headers(headers, responses)
        
        # Calculate score and grade
        score, grade = self._calculate_score(headers, cookies)
        
        # Save results
        self._save_results(url, headers, cookies, score, grade)
        
        return {
            'score': score,
            'grade': grade,
            'headers': dict(headers),
            'cookies': list(cookies.keys()) if cookies else []
        }
    
    def _analyze_security_headers(self, headers: Dict, responses: Dict):
        """تحليل الهيدرات الأمنية الأساسية"""
        
        for header, info in self.critical_headers.items():
            if header in headers:
                value = headers[header][:80]
                cprint(f"    ✅ {info['name']}: Present", SUCCESS)
                if self.verbose:
                    cprint(f"        Value: {value}", INFO)
            else:
                cprint(f"    ❌ {info['name']}: MISSING - {info['risk']}", ERROR)
                cprint(f"        Recommendation: {info['recommendation']}", "yellow")
    
    def _analyze_csp(self, headers: Dict):
        """تحليل عميق لـ Content Security Policy"""
        
        csp = headers.get('Content-Security-Policy', '')
        if not csp:
            csp = headers.get('Content-Security-Policy-Report-Only', '')
            if csp:
                cprint(f"    ⚠️ CSP Report-Only mode (not enforcing)", WARNING)
            else:
                cprint(f"    ❌ CSP: NOT IMPLEMENTED", ERROR)
                cprint(f"        Risk: High risk of XSS and code injection", ERROR)
                return
        
        cprint(f"    ✅ CSP: Implemented", SUCCESS)
        
        # Check for dangerous directives
        dangerous_found = []
        for directive, risk in self.csp_dangerous.items():
            if directive in csp:
                dangerous_found.append((directive, risk))
                cprint(f"    ⚠️ Dangerous directive: {directive}", ERROR)
                cprint(f"        Risk: {risk}", WARNING)
        
        # Check for missing critical directives
        missing_directives = []
        for directive, risk in self.csp_missing.items():
            if directive not in csp:
                missing_directives.append((directive, risk))
                cprint(f"    ⚠️ Missing: {directive}", WARNING)
                cprint(f"        Risk: {risk}", WARNING)
        
        # Check for nonce/hash (good practice)
        if "'nonce-" in csp or "'sha256-" in csp or "'sha384-" in csp or "'sha512-" in csp:
            cprint(f"    ✅ CSP uses nonce/sha (Good practice)", SUCCESS)
        
        if not dangerous_found and not missing_directives:
            cprint(f"    ✅ CSP configuration looks good", SUCCESS)
    
    def _analyze_cookies(self, cookies, headers: Dict):
        """تحليل أمان الكوكيز (HttpOnly, Secure, SameSite)"""
        
        set_cookie = headers.get('Set-Cookie', '')
        
        if not set_cookie and len(cookies) == 0:
            cprint(f"    ℹ️ No cookies found", INFO)
            return
        
        cookie_issues = []
        
        # Parse Set-Cookie header
        cookie_strings = set_cookie.split(',') if set_cookie else []
        
        for cookie_str in cookie_strings:
            cookie_name = cookie_str.split('=')[0].strip()
            
            # Check flags
            has_httponly = 'HttpOnly' in cookie_str
            has_secure = 'Secure' in cookie_str
            has_samesite = 'SameSite' in cookie_str
            
            status = []
            if not has_httponly:
                cookie_issues.append(f"Cookie '{cookie_name}' missing HttpOnly (XSS risk)")
            if not has_secure:
                cookie_issues.append(f"Cookie '{cookie_name}' missing Secure (MITM risk)")
            if not has_samesite:
                cookie_issues.append(f"Cookie '{cookie_name}' missing SameSite (CSRF risk)")
            
            # Display cookie status
            flags = []
            if has_httponly:
                flags.append("HttpOnly")
            if has_secure:
                flags.append("Secure")
            if has_samesite:
                samesite_val = re.search(r'SameSite=(\w+)', cookie_str)
                flags.append(f"SameSite={samesite_val.group(1) if samesite_val else 'Present'}")
            
            if flags:
                cprint(f"    ✅ Cookie '{cookie_name}': {', '.join(flags)}", SUCCESS)
            else:
                cprint(f"    ❌ Cookie '{cookie_name}': No security flags", ERROR)
        
        # Check cookies from response.cookies
        for cookie in cookies:
            cookie_name = cookie.name
            has_httponly = cookie.has_nonstandard_attr('httponly') or getattr(cookie, 'httponly', False)
            has_secure = cookie.secure
            has_samesite = getattr(cookie, 'samesite', None) is not None
            
            if not has_httponly and not has_secure and not has_samesite:
                if cookie_name not in [c.split('=')[0] for c in cookie_strings]:
                    cookie_issues.append(f"Cookie '{cookie_name}' has no security flags")
        
        # Display issues summary
        if cookie_issues:
            cprint(f"\n    ⚠️ Cookie Security Issues:", WARNING)
            for issue in cookie_issues[:5]:
                cprint(f"        └─ {issue}", WARNING)
    
    def _analyze_technology(self, headers: Dict, url: str, domain: str):
        """تحليل التقنيات المستخدمة (Fingerprinting)"""
        
        technologies = []
        
        for header, description in self.tech_headers.items():
            if header in headers:
                value = headers[header][:50]
                technologies.append(f"{description}: {value}")
                cprint(f"    📌 {description}: {value}", INFO)
        
        # Try to detect additional technologies from URL/domain
        if 'wp-content' in url or 'wp-json' in url:
            technologies.append("WordPress detected (URL pattern)")
            cprint(f"    📌 WordPress: Detected (URL pattern)", INFO)
        
        if '.php' in url:
            technologies.append("PHP detected (URL extension)")
            cprint(f"    📌 PHP: Detected (URL extension)", INFO)
        
        if '.aspx' in url:
            technologies.append("ASP.NET detected (URL extension)")
            cprint(f"    📌 ASP.NET: Detected (URL extension)", INFO)
        
        if technologies:
            cprint(f"\n    Total technologies identified: {len(technologies)}", SUCCESS)
        else:
            cprint(f"    ℹ️ No obvious technology headers found", INFO)
    
    def _analyze_permissions_policy(self, headers: Dict):
        """تحليل Permissions-Policy (Feature-Policy)"""
        
        policy = headers.get('Permissions-Policy', '')
        if not policy:
            policy = headers.get('Feature-Policy', '')
            if policy:
                cprint(f"    ⚠️ Feature-Policy (deprecated, use Permissions-Policy)", WARNING)
            else:
                cprint(f"    ❌ Permissions-Policy: NOT IMPLEMENTED", WARNING)
                cprint(f"        Risk: Browser features (camera, mic, geolocation) unrestricted", WARNING)
                return
        
        cprint(f"    ✅ Permissions-Policy: Implemented", SUCCESS)
        
        # Check for restricted features
        restricted = []
        unrestricted = []
        
        features = ['geolocation', 'camera', 'microphone', 'usb', 'payment', 'autoplay']
        for feature in features:
            if f"{feature}=()" in policy or f"{feature}=none" in policy.lower():
                restricted.append(feature)
            elif feature in policy:
                unrestricted.append(feature)
        
        if restricted:
            cprint(f"    ✅ Restricted features: {', '.join(restricted)}", SUCCESS)
        if unrestricted:
            cprint(f"    ⚠️ Unrestricted features: {', '.join(unrestricted)}", WARNING)
    
    def _check_inconsistent_headers(self, headers: Dict, responses: Dict):
        """فحص التناقضات بين الطلبات المختلفة"""
        
        inconsistent = []
        for method, resp in responses.items():
            if resp and resp.headers:
                for header in self.critical_headers:
                    if header in resp.headers and header not in headers:
                        inconsistent.append(f"{header} appears only in {method}")
        
        if inconsistent:
            cprint(f"\n[!] Inconsistent headers detected:", WARNING)
            for issue in inconsistent[:3]:
                cprint(f"    └─ {issue}", WARNING)
    
    def _calculate_score(self, headers: Dict, cookies) -> Tuple[float, str]:
        """حساب النتيجة والتقدير"""
        
        score = 0
        max_score = 0
        
        # Security headers (50 points)
        for header in self.critical_headers:
            max_score += 10
            if header in headers:
                score += 10
                # Bonus for CSP without dangerous directives
                if header == 'Content-Security-Policy':
                    csp = headers[header]
                    if "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp:
                        score += 5
                        max_score += 5
        
        # Cookie security (30 points)
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            max_score += 30
            if 'HttpOnly' in set_cookie:
                score += 10
            if 'Secure' in set_cookie:
                score += 10
            if 'SameSite' in set_cookie:
                score += 10
        
        # Permissions-Policy (20 points)
        if headers.get('Permissions-Policy') or headers.get('Feature-Policy'):
            max_score += 20
            score += 20
        
        # Calculate percentage
        if max_score > 0:
            final_score = (score / max_score) * 100
        else:
            final_score = 0
        
        # Determine grade
        if final_score >= 80:
            grade = "A"
            color = SUCCESS
        elif final_score >= 60:
            grade = "C"
            color = WARNING
        elif final_score >= 40:
            grade = "D"
            color = WARNING
        else:
            grade = "F"
            color = ERROR
        
        cprint(f"\n" + "="*70, HIGHLIGHT)
        cprint(f"📊 FINAL SECURITY SCORE: {final_score:.1f}/100 ({grade})", color, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        
        return final_score, grade
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _save_results(self, url: str, headers: Dict, cookies, score: float, grade: str):
        """Save results to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(url).netloc.replace('.', '_')
            filename = f"header_analysis_{domain}_{timestamp}.json"
            
            output = {
                "url": url,
                "timestamp": timestamp,
                "score": score,
                "grade": grade,
                "headers": dict(headers),
                "cookies": [{"name": c.name, "secure": c.secure, "httponly": c.has_nonstandard_attr('httponly')} for c in cookies],
                "server": headers.get('Server', 'Unknown'),
                "powered_by": headers.get('X-Powered-By', 'Unknown')
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            
            if self.verbose:
                cprint(f"\n[+] Results saved to: {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save results: {e}", ERROR)


# ============================================================
# Legacy function for backward compatibility
# ============================================================

def scan(url: str, verbose: bool = False) -> Dict:
    """Legacy scan function"""
    analyzer = HeaderAnalyzer(verbose=verbose)
    return analyzer.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        scan(target, verbose=verbose)
    else:
        print("Usage: python header_analyzer.py <target_url> [--verbose]")
        print("Examples:")
        print("  python header_analyzer.py https://example.com")
        print("  python header_analyzer.py https://example.com --verbose")