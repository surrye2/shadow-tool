#!/usr/bin/env python3
"""
Domain Intelligence Module - AlZill V6 Pro
Deep analysis: IP, Geo, WHOIS, WAF Detection, Security Headers, Stack Fingerprinting
Features: Advanced WAF detection, Security headers analyzer, Technology stack discovery
"""

import socket
import requests
import whois
import json
import urllib3
import re
import ssl
import OpenSSL
from termcolor import cprint
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class DomainIntelligence:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.session.timeout = 10
        
        # ============================================================
        # قواعد كشف الـ WAF المتقدمة
        # ============================================================
        self.waf_signatures = {
            'Cloudflare': [
                'cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-ray',
                'Cloudflare', '__cfduid', '__cflb'
            ],
            'Sucuri': [
                'x-sucuri-id', 'x-sucuri-cache', 'sucuri', 'Sucuri-Cloudproxy'
            ],
            'Akamai': [
                'akamai', 'X-Akamai-Transformed', 'X-Akamai-Request-ID'
            ],
            'AWS WAF': [
                'x-amzn-requestid', 'x-amzn-trace-id', 'AWSALB'
            ],
            'Imperva': [
                'x-iinfo', 'X-CDN', 'Incapsula', 'x-application-context'
            ],
            'F5 BIG-IP': [
                'X-WA-Info', 'X-WA-Request-ID', 'BIG-IP'
            ],
            'ModSecurity': [
                'Mod_Security', 'NOYB', 'X-Mod-Security'
            ],
            'WordFence': [
                'wordfence', 'wf_log', 'wf_scan'
            ],
            'Barracuda': [
                'barracuda', 'x-barracuda', 'cuda'
            ],
            'Fortinet': [
                'fortigate', 'fortiweb', 'forticlient'
            ],
            'StackPath': [
                'x-stackpath', 'SP'
            ],
            'Fastly': [
                'x-fastly', 'fastly', 'x-served-by'
            ],
            'Varnish': [
                'x-varnish', 'varnish', 'X-Varnish-Age'
            ]
        }
        
        # ============================================================
        # بصمات التقنيات المتقدمة (Technology Fingerprinting)
        # ============================================================
        self.tech_signatures = {
            'CMS': {
                'WordPress': [r'wp-content', r'wp-includes', r'wordpress', r'wp-json', r'wp-admin'],
                'Drupal': [r'drupal', r'sites/default/files', r'Drupal.settings'],
                'Joomla': [r'joomla', r'com_content', r'/media/jui/'],
                'Magento': [r'magento', r'skin/frontend', r'Mage.Cookies'],
                'Shopify': [r'shopify', r'myshopify.com', r'cdn.shopify'],
                'WooCommerce': [r'woocommerce', r'wc-ajax', r'/product/']
            },
            'Backend': {
                'PHP': [r'php', r'phpsessid', r'.php', r'X-Powered-By: PHP'],
                'Python': [r'python', r'django', r'flask', r'fastapi', r'wsgi', r'asgi'],
                'Node.js': [r'node', r'express', r'x-powered-by: express'],
                'Ruby': [r'ruby', r'rails', r'rack', r'x-powered-by: phusion'],
                'Java': [r'java', r'spring', r'jsp', r'jsf', r'x-powered-by: jsp'],
                'ASP.NET': [r'asp.net', r'x-aspnet-version', r'aspx', r'__requestverificationtoken']
            },
            'Frontend': {
                'React': [r'react', r'reactdom', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                'Vue.js': [r'vue', r'vuejs', r'__VUE__', r'data-v-'],
                'Angular': [r'angular', r'ng-version', r'ng-app'],
                'jQuery': [r'jquery', r'jquery-', r'$\.'],
                'Bootstrap': [r'bootstrap', r'bs-modal', r'data-bs-']
            },
            'Database': {
                'MySQL': [r'mysql', r'mariadb'],
                'PostgreSQL': [r'postgresql', r'pgsql'],
                'MongoDB': [r'mongodb', r'mongoose'],
                'Redis': [r'redis']
            },
            'Server': {
                'Apache': [r'apache', r'apache/'],
                'Nginx': [r'nginx', r'nginx/'],
                'IIS': [r'iis', r'microsoft-iis'],
                'LiteSpeed': [r'litespeed', r'lsws'],
                'Caddy': [r'caddy']
            },
            'CDN': {
                'Cloudflare': [r'cloudflare', r'cf-'],
                'Akamai': [r'akamai', r'akamaiedge'],
                'Fastly': [r'fastly'],
                'Amazon CloudFront': [r'cloudfront', r'x-amz-cf'],
                'Google Cloud CDN': [r'google', r'gcdn']
            }
        }
        
        # ============================================================
        # قائمة الهيدرات الأمنية للتحليل
        # ============================================================
        self.security_headers = {
            'X-Frame-Options': {'risk': 'Clickjacking', 'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'},
            'Content-Security-Policy': {'risk': 'XSS, Code Injection', 'recommendation': 'Implement strict CSP policy'},
            'X-Content-Type-Options': {'risk': 'MIME Sniffing', 'recommendation': 'Add X-Content-Type-Options: nosniff'},
            'X-XSS-Protection': {'risk': 'XSS', 'recommendation': 'Add X-XSS-Protection: 1; mode=block'},
            'Strict-Transport-Security': {'risk': 'SSL Stripping', 'recommendation': 'Enable HSTS'},
            'Referrer-Policy': {'risk': 'Information Leak', 'recommendation': 'Set Referrer-Policy: strict-origin-when-cross-origin'},
            'Permissions-Policy': {'risk': 'Browser Feature Abuse', 'recommendation': 'Restrict browser features'},
            'Cross-Origin-Embedder-Policy': {'risk': 'Cross-origin attacks', 'recommendation': 'Set COEP: require-corp'},
            'Cross-Origin-Opener-Policy': {'risk': 'Cross-origin attacks', 'recommendation': 'Set COOP: same-origin'},
            'Cross-Origin-Resource-Policy': {'risk': 'Cross-origin attacks', 'recommendation': 'Set CORP: same-origin'}
        }

    def scan(self, url: str, verbose: bool = False):
        """الوظيفة الرئيسية للمسح"""
        self.verbose = verbose
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("[DOMAIN INTELLIGENCE] AlZill V6 Pro - Deep Domain Analysis", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        
        # استخراج الدومين
        parsed = urlparse(url)
        domain = parsed.netloc or url.split('/')[0]
        domain = domain.split(':')[0]
        
        cprint(f"[*] Target: {domain}", INFO)
        
        data = {
            'domain': domain,
            'ip': None,
            'geo': {},
            'waf': 'None/Undetected',
            'technologies': {'cms': [], 'backend': [], 'frontend': [], 'server': [], 'cdn': [], 'database': []},
            'security_headers': {},
            'security_risks': [],
            'ssl_info': {},
            'whois': {},
            'dns_records': {}
        }
        
        # ============================================================
        # 1. تحليل الـ IP والـ Geo
        # ============================================================
        cprint("\n[1] 📍 Phase: IP & Geolocation Analysis", INFO)
        try:
            data['ip'] = socket.gethostbyname(domain)
            cprint(f"    IP Address: {data['ip']}", SUCCESS)
            
            geo = self._get_geo(data['ip'])
            if geo:
                data['geo'] = geo
                cprint(f"    Location: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}", INFO)
                cprint(f"    ISP: {geo.get('isp', 'N/A')}", INFO)
                cprint(f"    Organization: {geo.get('org', 'N/A')}", INFO)
        except Exception as e:
            cprint(f"    Resolution Error: {e}", ERROR)
            return data
        
        # ============================================================
        # 2. كشف الـ WAF المتقدم
        # ============================================================
        cprint("\n[2] 🛡️ Phase: WAF Detection", INFO)
        data['waf'] = self._detect_waf_advanced(domain)
        waf_color = ERROR if data['waf'] != 'None/Undetected' else SUCCESS
        cprint(f"    WAF: {data['waf']}", waf_color, attrs=['bold'] if data['waf'] != 'None/Undetected' else [])
        
        # ============================================================
        # 3. تحليل الـ HTTP Headers والأمان
        # ============================================================
        cprint("\n[3] 🔐 Phase: Security Headers Analysis", INFO)
        headers_info = self._analyze_headers_advanced(domain)
        data.update(headers_info)
        
        # عرض مخاطر الأمان
        if data.get('security_risks'):
            cprint(f"    Security Risks Found: {len(data['security_risks'])}", ERROR)
            for risk in data['security_risks'][:5]:
                cprint(f"      └─ {risk}", WARNING)
        
        # ============================================================
        # 4. كشف التقنيات المتقدم (Stack Fingerprinting)
        # ============================================================
        cprint("\n[4] 💻 Phase: Technology Stack Discovery", INFO)
        data['technologies'] = self._fingerprint_advanced(domain, headers_info.get('raw_headers', {}))
        
        # عرض التقنيات المكتشفة
        tech_count = sum(len(v) for v in data['technologies'].values())
        if tech_count > 0:
            cprint(f"    Technologies Found: {tech_count}", SUCCESS)
            for category, techs in data['technologies'].items():
                if techs:
                    cprint(f"      ├─ {category.title()}: {', '.join(techs)}", INFO)
        else:
            cprint(f"    No technologies detected", WARNING)
        
        # ============================================================
        # 5. تحليل SSL/TLS
        # ============================================================
        cprint("\n[5] 🔒 Phase: SSL/TLS Analysis", INFO)
        ssl_info = self._analyze_ssl(domain)
        if ssl_info:
            data['ssl_info'] = ssl_info
            cprint(f"    Certificate Issuer: {ssl_info.get('issuer', 'N/A')}", INFO)
            cprint(f"    Valid Until: {ssl_info.get('expiry', 'N/A')}", INFO)
            if ssl_info.get('days_left', 0) < 30:
                cprint(f"    ⚠️ Certificate expires in {ssl_info.get('days_left', 0)} days!", ERROR)
            else:
                cprint(f"    Days Left: {ssl_info.get('days_left', 'N/A')}", SUCCESS)
        
        # ============================================================
        # 6. تحليل WHOIS (محسن)
        # ============================================================
        cprint("\n[6] 📋 Phase: WHOIS Analysis", INFO)
        whois_info = self._get_whois_advanced(domain)
        if whois_info:
            data['whois'] = whois_info
            if whois_info.get('registrar'):
                cprint(f"    Registrar: {whois_info['registrar']}", INFO)
            if whois_info.get('creation_date'):
                cprint(f"    Created: {whois_info['creation_date']}", INFO)
            if whois_info.get('expiration_date'):
                cprint(f"    Expires: {whois_info['expiration_date']}", INFO)
            if whois_info.get('name_servers'):
                cprint(f"    Name Servers: {', '.join(whois_info['name_servers'][:3])}", INFO)
        
        # ============================================================
        # 7. تحليل DNS Records
        # ============================================================
        cprint("\n[7] 🌐 Phase: DNS Records Analysis", INFO)
        dns_records = self._analyze_dns(domain)
        if dns_records:
            data['dns_records'] = dns_records
            for record_type, records in dns_records.items():
                if records:
                    cprint(f"    {record_type}: {', '.join(records[:3])}", INFO)
        
        # ============================================================
        # 8. عرض الملخص النهائي
        # ============================================================
        self._display_summary(data)
        
        # حفظ النتائج
        self._save_results(domain, data)
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("[✓] Intelligence Gathering Completed", SUCCESS)
        cprint("="*60, HIGHLIGHT)
        
        return data

    def _detect_waf_advanced(self, domain: str) -> str:
        """كشف متقدم لوجود جدران حماية"""
        detected_wafs = []
        
        try:
            # محاولة HTTP و HTTPS
            for protocol in ['https', 'http']:
                try:
                    response = self.session.get(f"{protocol}://{domain}", timeout=10, verify=False)
                    headers = response.headers
                    
                    # فحص الهيدرات
                    for waf_name, signatures in self.waf_signatures.items():
                        for sig in signatures:
                            if sig.lower() in str(headers).lower():
                                detected_wafs.append(waf_name)
                                break
                    
                    # فحص الكوكيز
                    for cookie in response.cookies:
                        cookie_name = cookie.name.lower()
                        for waf_name, signatures in self.waf_signatures.items():
                            for sig in signatures:
                                if sig.lower() in cookie_name:
                                    detected_wafs.append(waf_name)
                                    break
                    
                    # فحص نص الاستجابة
                    if 'cloudflare' in response.text.lower():
                        detected_wafs.append('Cloudflare')
                    if 'sucuri' in response.text.lower():
                        detected_wafs.append('Sucuri')
                    
                except:
                    continue
                    
        except Exception as e:
            if self.verbose:
                cprint(f"    WAF detection error: {e}", WARNING)
        
        if detected_wafs:
            return ', '.join(set(detected_wafs))
        return "None/Undetected"

    def _analyze_headers_advanced(self, domain: str) -> dict:
        """تحليل متقدم للهيدرات الأمنية"""
        result = {
            'server': 'Unknown',
            'raw_headers': {},
            'security_headers': {},
            'security_risks': []
        }
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10, verify=False)
            headers = response.headers
            
            result['raw_headers'] = dict(headers)
            result['server'] = headers.get('Server', 'Unknown')
            result['powered_by'] = headers.get('X-Powered-By', 'Unknown')
            
            cprint(f"    Web Server: {result['server']}", INFO)
            if result['powered_by'] != 'Unknown':
                cprint(f"    Powered By: {result['powered_by']}", INFO)
            
            # فحص كل هيدر أمني
            for header_name, info in self.security_headers.items():
                if header_name in headers:
                    result['security_headers'][header_name] = headers[header_name]
                    cprint(f"    ✅ {header_name}: Present", SUCCESS)
                else:
                    result['security_risks'].append(f"Missing {header_name} - {info['risk']}")
                    cprint(f"    ❌ {header_name}: MISSING - {info['risk']}", ERROR)
            
            # فحص إضافي: وجود CORS misconfiguration
            if 'Access-Control-Allow-Origin' in headers:
                if headers['Access-Control-Allow-Origin'] == '*':
                    result['security_risks'].append("CORS misconfiguration: Access-Control-Allow-Origin: *")
                    cprint(f"    ⚠️ CORS: Wildcard origin allowed", ERROR)
            
        except Exception as e:
            if self.verbose:
                cprint(f"    Header analysis error: {e}", WARNING)
        
        return result

    def _fingerprint_advanced(self, domain: str, headers: dict) -> dict:
        """كشف متقدم للتقنيات المستخدمة"""
        technologies = {'cms': [], 'backend': [], 'frontend': [], 'server': [], 'cdn': [], 'database': []}
        
        # تحويل الهيدرات إلى نص للبحث
        headers_text = str(headers).lower()
        
        try:
            # محاولة جلب الصفحة الرئيسية
            response = self.session.get(f"https://{domain}", timeout=10, verify=False)
            body = response.text.lower()
            
            # فحص كل فئة
            for category, techs in self.tech_signatures.items():
                for tech_name, patterns in techs.items():
                    for pattern in patterns:
                        if re.search(pattern, headers_text, re.IGNORECASE) or re.search(pattern, body, re.IGNORECASE):
                            if tech_name not in technologies[category]:
                                technologies[category].append(tech_name)
                            break
            
            # كشف إضافي من الـ cookies
            for cookie in response.cookies:
                cookie_name = cookie.name.lower()
                if 'wordpress' in cookie_name:
                    technologies['cms'].append('WordPress')
                if 'laravel' in cookie_name:
                    technologies['backend'].append('Laravel')
                if 'django' in cookie_name:
                    technologies['backend'].append('Django')
                if 'session' in cookie_name and 'php' in cookie_name:
                    technologies['backend'].append('PHP')
            
        except Exception as e:
            if self.verbose:
                cprint(f"    Fingerprinting error: {e}", WARNING)
        
        return technologies

    def _analyze_ssl(self, domain: str) -> dict:
        """تحليل شهادة SSL/TLS"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # استخراج المعلومات
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    expiry_str = cert['notAfter']
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days
                    
                    return {
                        'issuer': issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                        'subject': subject.get('commonName', 'Unknown'),
                        'expiry': expiry_str,
                        'days_left': days_left,
                        'version': cert.get('version', 'Unknown'),
                        'serial': cert.get('serialNumber', 'Unknown')[:16]
                    }
        except Exception as e:
            if self.verbose:
                cprint(f"    SSL analysis error: {e}", WARNING)
            return None

    def _get_whois_advanced(self, domain: str) -> dict:
        """الحصول على معلومات WHOIS مع معالجة الخصوصية"""
        result = {}
        try:
            w = whois.whois(domain)
            
            if w:
                result['registrar'] = w.registrar if w.registrar else 'Private/Redacted'
                result['creation_date'] = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date) if w.creation_date else 'N/A'
                result['expiration_date'] = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date) if w.expiration_date else 'N/A'
                result['name_servers'] = w.name_servers if w.name_servers else []
                result['status'] = w.status if w.status else []
                result['emails'] = w.emails if w.emails else []
                
                # معالجة الخصوصية
                if 'Private' in str(result['registrar']) or 'Redacted' in str(result['registrar']):
                    cprint(f"    ⚠️ WHOIS data is privacy protected", WARNING)
                
        except Exception as e:
            if self.verbose:
                cprint(f"    WHOIS lookup error: {e}", WARNING)
        
        return result

    def _analyze_dns(self, domain: str) -> dict:
        """تحليل سجلات DNS"""
        dns_records = {'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'NS': [], 'CNAME': []}
        
        try:
            # A record
            dns_records['A'] = [socket.gethostbyname(domain)]
        except:
            pass
        
        # استخدام dns.resolver إذا كان متاحاً
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            
            for record_type in ['AAAA', 'MX', 'TXT', 'NS', 'CNAME']:
                try:
                    answers = resolver.resolve(domain, record_type, lifetime=3)
                    for answer in answers:
                        if record_type == 'MX':
                            dns_records[record_type].append(str(answer.exchange))
                        else:
                            dns_records[record_type].append(str(answer))
                except:
                    pass
        except ImportError:
            if self.verbose:
                cprint("    dnspython not installed for advanced DNS records", WARNING)
        
        return dns_records

    def _get_geo(self, ip: str) -> dict:
        """الحصول على معلومات جغرافية"""
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }
        except Exception as e:
            if self.verbose:
                cprint(f"    Geo lookup error: {e}", WARNING)
        return None

    def _display_summary(self, data: dict):
        """عرض الملخص النهائي"""
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("📊 INTELLIGENCE SUMMARY", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        
        cprint(f"  Domain: {data['domain']}", INFO)
        cprint(f"  IP: {data['ip']}", INFO)
        cprint(f"  Location: {data['geo'].get('city', 'N/A')}, {data['geo'].get('country', 'N/A')}", INFO)
        cprint(f"  WAF: {data['waf']}", ERROR if data['waf'] != 'None/Undetected' else SUCCESS)
        cprint(f"  Server: {data.get('server', 'Unknown')}", INFO)
        
        # التقنيات المكتشفة
        techs = []
        for category, items in data['technologies'].items():
            techs.extend(items)
        if techs:
            cprint(f"  Technologies: {', '.join(techs)}", SUCCESS)
        
        # المخاطر الأمنية
        if data.get('security_risks'):
            cprint(f"  Security Risks: {len(data['security_risks'])}", ERROR)
        
        # SSL Status
        if data.get('ssl_info'):
            ssl = data['ssl_info']
            if ssl.get('days_left', 0) < 30:
                cprint(f"  SSL Status: Expires in {ssl.get('days_left', 0)} days", ERROR)
            else:
                cprint(f"  SSL Status: Valid ({ssl.get('days_left', 0)} days left)", SUCCESS)

    def _save_results(self, domain: str, data: dict):
        """حفظ النتائج في ملف JSON"""
        try:
            filename = f"intel_{domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            if self.verbose:
                cprint(f"\n[+] Results saved to {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save results: {e}", WARNING)


# ============================================================
# دالة التوافق مع المحرك الرئيسي
# ============================================================

def scan(url: str, verbose: bool = False):
    """دالة التوافق مع المحرك الرئيسي AlZill"""
    scanner = DomainIntelligence(verbose=verbose)
    return scanner.scan(url, verbose)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python domain_intel.py <target>")
        print("Examples:")
        print("  python domain_intel.py https://example.com")
        print("  python domain_intel.py example.com")