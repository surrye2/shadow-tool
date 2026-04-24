#!/usr/bin/env python3
"""
DNS Security Scanner - AlZill V6 Pro
Advanced DNS security analysis targeting REAL Name Servers
Features: Multi-NS scanning, Amplification factor, Zone transfer, DDoS risk assessment
"""

import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.flags
import dns.zone
import socket
import ipaddress
import time
import json
from termcolor import cprint
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class DNSProScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.results = {
            'target': '',
            'domain': '',
            'nameservers': [],
            'vulnerable_ns': [],
            'overall_risk': 'SECURE'
        }
        
        # قائمة الـ Resolvers الاحتياطية لتجاوز قيود Android/Termux
        self.fallback_resolvers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '9.9.9.9',      # Quad9
            '208.67.222.222', # OpenDNS
            '8.8.4.4'       # Google Secondary
        ]

    def get_custom_resolver(self):
        """
        إنشاء Resolver مخصص لتجاوز مشاكل resolv.conf في Android/Termux
        """
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.fallback_resolvers
        resolver.timeout = 5
        resolver.lifetime = 5
        return resolver

    def get_clean_domain(self, target: str) -> str:
        """استخراج الدومين النظيف من الـ URL"""
        if "://" in target:
            domain = urlparse(target).netloc
        else:
            domain = target
        
        # إزالة البورت إذا كان موجوداً
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain

    def get_name_servers(self, domain: str) -> List[Dict]:
        """
        جلب سيرفرات الـ NS الحقيقية للهدف
        يعيد قائمة من القواميس تحتوي على اسم السيرفر و IP
        """
        nameservers = []
        resolver = self.get_custom_resolver()
        
        try:
            cprint(f"    Looking up NS records for {domain}...", INFO)
            ns_records = resolver.resolve(domain, 'NS', lifetime=5)
            
            for ns in ns_records:
                ns_name = str(ns.target).rstrip('.')
                cprint(f"    Found NS: {ns_name}", SUCCESS)
                
                # محاولة الحصول على IP لكل NS
                try:
                    ns_ip = resolver.resolve(ns_name, 'A', lifetime=5)[0].to_text()
                    nameservers.append({
                        'name': ns_name,
                        'ip': ns_ip,
                        'type': 'IPv4'
                    })
                except:
                    # محاولة IPv6
                    try:
                        ns_ip = resolver.resolve(ns_name, 'AAAA', lifetime=5)[0].to_text()
                        nameservers.append({
                            'name': ns_name,
                            'ip': ns_ip,
                            'type': 'IPv6'
                        })
                    except Exception as e:
                        if self.verbose:
                            cprint(f"    Could not resolve {ns_name}: {e}", WARNING)
                        nameservers.append({
                            'name': ns_name,
                            'ip': 'unknown',
                            'type': 'unknown'
                        })
                        
        except dns.resolver.NXDOMAIN:
            cprint(f"    Domain {domain} does not exist", ERROR)
        except dns.resolver.NoAnswer:
            cprint(f"    No NS records found for {domain}", WARNING)
        except Exception as e:
            if self.verbose:
                cprint(f"    NS lookup error: {e}", WARNING)
        
        return nameservers

    def analyze_dns_vulnerability(self, ns_ip: str, domain: str) -> Dict:
        """
        فحص شامل للسيرفر: Open Resolver + Recursion + Amplification
        يعيد قاموس بالنتائج
        """
        results = {
            'open': False,
            'recursion': False,
            'recursion_enabled': False,
            'amp_factor': 0,
            'max_amp_factor': 0,
            'record_types': {},
            'response_time': 0,
            'vulnerabilities': []
        }
        
        # أنواع السجلات المختلفة لقياس التضخيم
        record_tests = [
            (dns.rdatatype.ANY, 'ANY'),
            (dns.rdatatype.TXT, 'TXT'),
            (dns.rdatatype.DNSKEY, 'DNSKEY'),
            (dns.rdatatype.RRSIG, 'RRSIG'),
            (dns.rdatatype.NSEC, 'NSEC'),
            (dns.rdatatype.MX, 'MX'),
            (dns.rdatatype.SOA, 'SOA')
        ]
        
        for rtype, rtype_name in record_tests:
            try:
                # بناء الطلب
                query = dns.message.make_query(domain, rtype)
                query.flags |= dns.flags.RD  # Recursion Desired
                
                # قياس حجم الطلب
                start_size = len(query.to_wire())
                start_time = time.time()
                
                # إرسال الطلب
                response = dns.query.udp(query, ns_ip, timeout=3)
                elapsed = time.time() - start_time
                
                # قياس حجم الاستجابة
                end_size = len(response.to_wire())
                
                if end_size > 0 and start_size > 0:
                    amp_factor = round(end_size / start_size, 2)
                    results['record_types'][rtype_name] = {
                        'send_bytes': start_size,
                        'recv_bytes': end_size,
                        'factor': amp_factor
                    }
                    
                    # تحديث الحد الأقصى
                    if amp_factor > results['max_amp_factor']:
                        results['max_amp_factor'] = amp_factor
                    
                    # تحديث وقت الاستجابة
                    if results['response_time'] == 0 or elapsed < results['response_time']:
                        results['response_time'] = round(elapsed, 3)
                
                # فحص Recursion
                if response.flags & dns.flags.RA:
                    results['recursion'] = True
                    results['recursion_enabled'] = True
                
                results['open'] = (response.rcode() == 0)
                
            except dns.query.Timeout:
                if self.verbose:
                    cprint(f"    {rtype_name} test timeout", WARNING)
            except Exception as e:
                if self.verbose:
                    cprint(f"    {rtype_name} test failed: {e}", WARNING)
        
        # حساب متوسط عامل التضخيم
        if results['record_types']:
            factors = [f['factor'] for f in results['record_types'].values()]
            results['amp_factor'] = round(sum(factors) / len(factors), 2)
        else:
            results['amp_factor'] = 0
        
        # تحديد الثغرات
        if results['recursion_enabled']:
            results['vulnerabilities'].append('Open Recursion - Can be used in DDoS attacks')
        
        if results['max_amp_factor'] > 50:
            results['vulnerabilities'].append(f'CRITICAL Amplification (x{results["max_amp_factor"]}) - Severe DDoS risk')
        elif results['max_amp_factor'] > 20:
            results['vulnerabilities'].append(f'HIGH Amplification (x{results["max_amp_factor"]}) - DDoS risk')
        elif results['max_amp_factor'] > 10:
            results['vulnerabilities'].append(f'MEDIUM Amplification (x{results["max_amp_factor"]})')
        elif results['max_amp_factor'] > 5:
            results['vulnerabilities'].append(f'LOW Amplification (x{results["max_amp_factor"]})')
        
        return results

    def try_zone_transfer(self, domain: str, ns_ip: str) -> Optional[Dict]:
        """
        محاولة Zone Transfer (AXFR)
        يعيد قاموس بالسجلات إذا نجح
        """
        try:
            if self.verbose:
                cprint(f"    Attempting zone transfer (AXFR) from {ns_ip}...", INFO)
            
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            
            if zone:
                records = []
                for node in zone.nodes.keys():
                    records.append(str(node))
                
                return {
                    'success': True,
                    'record_count': len(records),
                    'records': records[:50]  # حد أقصى 50 سجل للعرض
                }
        except dns.query.TransferError:
            if self.verbose:
                cprint(f"    Zone transfer refused (AXFR not allowed)", INFO)
        except Exception as e:
            if self.verbose:
                cprint(f"    Zone transfer failed: {e}", WARNING)
        
        return None

    def calculate_ddos_risk(self, results: Dict) -> Tuple[str, str]:
        """
        تقييم خطورة DDoS بناءً على نتائج الفحص
        """
        max_amp = results.get('max_amp_factor', 0)
        recursion = results.get('recursion_enabled', False)
        
        if max_amp > 50:
            return "CRITICAL", f"Extreme DDoS risk - x{max_amp} amplification + {'recursion' if recursion else ''}"
        elif max_amp > 20:
            return "HIGH", f"High DDoS risk - x{max_amp} amplification + {'recursion' if recursion else ''}"
        elif max_amp > 10:
            return "MEDIUM", f"Moderate DDoS risk - x{max_amp} amplification"
        elif recursion:
            return "MEDIUM", f"Open recursion - Can be used in DDoS attacks"
        elif max_amp > 5:
            return "LOW", f"Low amplification - x{max_amp}"
        
        return "SECURE", "No significant DDoS risk detected"

    def scan_nameserver(self, ns: Dict, domain: str) -> Dict:
        """فحص سيرفر Nameserver واحد بشكل كامل"""
        ns_name = ns['name']
        ns_ip = ns['ip']
        ns_type = ns.get('type', 'unknown')
        
        if self.verbose:
            cprint(f"\n  [→] Testing Name Server: {ns_name} ({ns_ip})", HIGHLIGHT)
        
        result = {
            'name': ns_name,
            'ip': ns_ip,
            'type': ns_type,
            'vulnerabilities': [],
            'zone_transfer': False,
            'zone_records': 0,
            'analysis': {}
        }
        
        if ns_ip == 'unknown':
            result['vulnerabilities'].append('Could not resolve NS IP')
            return result
        
        # 1. تحليل الثغرات الأساسية
        analysis = self.analyze_dns_vulnerability(ns_ip, domain)
        result['analysis'] = analysis
        
        # إضافة الثغرات المكتشفة
        result['vulnerabilities'].extend(analysis['vulnerabilities'])
        
        # 2. محاولة Zone Transfer
        zone_result = self.try_zone_transfer(domain, ns_ip)
        if zone_result:
            result['zone_transfer'] = True
            result['zone_records'] = zone_result['record_count']
            result['vulnerabilities'].append(f'Zone Transfer allowed! {zone_result["record_count"]} records leaked')
        
        # 3. تقييم DDoS
        ddos_risk, ddos_desc = self.calculate_ddos_risk(analysis)
        result['ddos_risk'] = ddos_risk
        result['ddos_description'] = ddos_desc
        
        if ddos_risk in ['CRITICAL', 'HIGH']:
            result['vulnerabilities'].append(ddos_desc)
        
        return result

    def scan(self, target: str, verbose: bool = False) -> bool:
        """الوظيفة الرئيسية للمسح"""
        self.verbose = verbose
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint("[DNS SCANNER] AlZill V6 Pro - Advanced DNS Security Audit", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        
        # استخراج الدومين
        domain = self.get_clean_domain(target)
        self.results['target'] = target
        self.results['domain'] = domain
        
        cprint(f"[*] Target Domain: {domain}", INFO)
        
        # ============================================================
        # 1. جلب سيرفرات الأسماء (Targeting the real DNS servers)
        # ============================================================
        cprint("\n[1]  Phase: Nameserver Discovery", INFO)
        
        nameservers = self.get_name_servers(domain)
        
        if not nameservers:
            cprint("[!] Could not find Name Servers. Trying direct IP lookup...", WARNING)
            try:
                # محاولة الحصول على IP مباشر للدومين
                resolver = self.get_custom_resolver()
                ip = resolver.resolve(domain, 'A', lifetime=5)[0].to_text()
                nameservers = [{
                    'name': domain,
                    'ip': ip,
                    'type': 'IPv4 (Direct)'
                }]
                cprint(f"    Using direct IP: {ip}", INFO)
            except Exception as e:
                cprint(f"[!] DNS audit failed: {e}", ERROR)
                return False
        else:
            cprint(f"[+] Found {len(nameservers)} Name Server(s)", SUCCESS)
        
        self.results['nameservers'] = nameservers
        
        # ============================================================
        # 2. فحص كل سيرفر NS على حدة (بشكل متوازي)
        # ============================================================
        cprint("\n[2]  Phase: Nameserver Security Analysis", INFO)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.scan_nameserver, ns, domain): ns for ns in nameservers}
            
            for future in as_completed(futures):
                result = future.result()
                self.results['vulnerable_ns'].append(result)
                
                if result['vulnerabilities']:
                    self.results['overall_risk'] = 'VULNERABLE'
        
        # ============================================================
        # 3. عرض النتائج
        # ============================================================
        self._display_results()
        
        # ============================================================
        # 4. حفظ النتائج
        # ============================================================
        self._save_results()
        
        cprint("\n" + "="*60, HIGHLIGHT)
        return self.results['overall_risk'] == 'VULNERABLE'

    def _display_results(self):
        """عرض النتائج بشكل منظم واحترافي"""
        
        cprint("\n" + "="*60, HIGHLIGHT)
        cprint(" DNS SECURITY AUDIT RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, HIGHLIGHT)
        
        total_ns = len(self.results['vulnerable_ns'])
        vulnerable_ns = [ns for ns in self.results['vulnerable_ns'] if ns['vulnerabilities']]
        
        # إحصائيات عامة
        cprint(f"\n  Target: {self.results['domain']}", INFO)
        cprint(f"  Nameservers tested: {total_ns}", INFO)
        cprint(f"  Vulnerable nameservers: {len(vulnerable_ns)}", ERROR if vulnerable_ns else SUCCESS)
        
        # تفاصيل كل NS
        for ns in self.results['vulnerable_ns']:
            cprint(f"\n   Nameserver: {ns['name']} ({ns['ip']})", HIGHLIGHT)
            
            # عرض تحليل الثغرات
            if ns['vulnerabilities']:
                cprint(f"     ⚠️ VULNERABILITIES:", ERROR)
                for vuln in ns['vulnerabilities']:
                    cprint(f"        └─ {vuln}", ERROR)
            else:
                cprint(f"      No vulnerabilities found", SUCCESS)
            
            # عرض تفاصيل التضخيم
            if ns['analysis'] and ns['analysis'].get('max_amp_factor', 0) > 1:
                cprint(f"      Amplification Analysis:", INFO)
                cprint(f"        ├─ Max factor: x{ns['analysis']['max_amp_factor']}", 
                       ERROR if ns['analysis']['max_amp_factor'] > 10 else WARNING)
                cprint(f"        ├─ Average factor: x{ns['analysis']['amp_factor']}", INFO)
                cprint(f"        └─ Response time: {ns['analysis']['response_time']}s", INFO)
                
                # أفضل نوع للتضخيم
                if ns['analysis']['record_types']:
                    best_type = max(ns['analysis']['record_types'].items(), 
                                   key=lambda x: x[1]['factor'])
                    cprint(f"        └─ Best amplification: {best_type[0]} (x{best_type[1]['factor']})", INFO)
            
            # عرض Recursion
            if ns['analysis'] and ns['analysis'].get('recursion_enabled'):
                cprint(f"      Recursion: ENABLED (DDoS risk)", ERROR)
            
            # عرض Zone Transfer
            if ns['zone_transfer']:
                cprint(f"      Zone Transfer: ALLOWED - {ns['zone_records']} records leaked!", ERROR)
            
            # DDoS Risk Assessment
            if ns.get('ddos_risk') and ns['ddos_risk'] != 'SECURE':
                risk_color = ERROR if ns['ddos_risk'] in ['CRITICAL', 'HIGH'] else WARNING
                cprint(f"      DDoS Risk: {ns['ddos_risk']}", risk_color)
                cprint(f"        └─ {ns.get('ddos_description', '')}", risk_color)
        
        # الخلاصة النهائية
        cprint(f"\n   FINAL VERDICT:", HIGHLIGHT)
        if self.results['overall_risk'] == 'VULNERABLE':
            cprint(f"     DNS Configuration: INSECURE", ERROR, attrs=['bold'])
            cprint(f"     {len(vulnerable_ns)} out of {total_ns} nameservers have security issues", ERROR)
            cprint(f"     Recommendation: Contact your DNS provider immediately", WARNING)
        else:
            cprint(f"     DNS Configuration: SECURE", SUCCESS, attrs=['bold'])
            cprint(f"     No major security issues detected", SUCCESS)

    def _save_results(self):
        """حفظ النتائج في ملف JSON"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dns_audit_{self.results['domain']}_{timestamp}.json"
            
            # تحضير البيانات للحفظ
            save_data = {
                'timestamp': timestamp,
                'target': self.results['target'],
                'domain': self.results['domain'],
                'total_nameservers': len(self.results['vulnerable_ns']),
                'vulnerable_count': len([ns for ns in self.results['vulnerable_ns'] if ns['vulnerabilities']]),
                'overall_risk': self.results['overall_risk'],
                'nameservers': [
                    {
                        'name': ns['name'],
                        'ip': ns['ip'],
                        'type': ns.get('type', 'unknown'),
                        'vulnerabilities': ns['vulnerabilities'],
                        'zone_transfer': ns['zone_transfer'],
                        'zone_records': ns['zone_records'],
                        'recursion': ns['analysis'].get('recursion_enabled', False) if ns['analysis'] else False,
                        'max_amplification': ns['analysis'].get('max_amp_factor', 0) if ns['analysis'] else 0,
                        'avg_amplification': ns['analysis'].get('amp_factor', 0) if ns['analysis'] else 0,
                        'ddos_risk': ns.get('ddos_risk', 'UNKNOWN')
                    }
                    for ns in self.results['vulnerable_ns']
                ]
            }
            
            with open(filename, 'w') as f:
                json.dump(save_data, f, indent=4)
            
            if self.verbose:
                cprint(f"\n[+] Results saved to {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save results: {e}", WARNING)


# ============================================================
# دالة التوافق مع المحرك الرئيسي
# ============================================================

def scan(target, verbose=False):
    """دالة التوافق مع المحرك الرئيسي AlZill"""
    scanner = DNSProScanner(verbose=verbose)
    return scanner.scan(target, verbose)


def exploit(target, verbose=False):
    """Alias للدالة الرئيسية"""
    return scan(target, verbose)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python dns_pro_scanner.py <target>")
        print("Examples:")
        print("  python dns_pro_scanner.py https://example.com")
        print("  python dns_pro_scanner.py example.com")
        print("  python dns_pro_scanner.py 8.8.8.8")