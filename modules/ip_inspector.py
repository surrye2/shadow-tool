#!/usr/bin/env python3
"""
IP Inspector - AlZill V6 Pro
IP Intelligence with Smart Fallback (TCP → ICMP → ARP)
Features: Multi-protocol reachability | Smart fallback | Parallel blacklist checking
"""

import socket
import subprocess
import json
import requests
import time
import random
import re
from termcolor import cprint
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class IPInspector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.ports_to_check = [80, 443, 22, 21, 25, 53, 3306, 5432, 6379, 27017]
        
        # قائمة بالأخطاء التي تستدعي الـ Fallback
        self.retry_errors = [
            "Connection refused",
            "Connection reset",
            "Network is unreachable",
            "No route to host",
            "Operation timed out",
            "Timeout"
        ]

    def scan_ip(self, ip, verbose=False, save_to_file=False):
        """Main IP inspection function with smart fallback"""
        show_details = verbose or self.verbose

        results = {
            'ip': ip,
            'reachable': False,
            'reachable_via': None,
            'response_time': None,
            'ports_open': [],
            'info': {},
            'blacklisted': []
        }

        cprint(f"\n[*] Inspecting IP: {ip}", HIGHLIGHT)

        # ============================================================
        # 1. SMART REACHABILITY CHECK (TCP → ICMP → ARP)
        # ============================================================
        reachable, method, response_time, open_ports = self._smart_reachability_check(ip, show_details)
        
        results['reachable'] = reachable
        results['reachable_via'] = method
        results['response_time'] = response_time
        results['ports_open'] = open_ports
        
        if reachable:
            status_color = SUCCESS
            status_text = f"✅ Reachable via {method} ({response_time:.2f}s)"
            if open_ports:
                status_text += f" | Open ports: {', '.join(map(str, open_ports[:5]))}"
        else:
            status_color = ERROR
            status_text = "❌ Not reachable (all methods failed)"
        
        cprint(f"    {status_text}", status_color)

        # ============================================================
        # 2. IP Information (Geo, ASN, etc.)
        # ============================================================
        ip_info, geo_error = self._get_ip_info(ip)
        results['info'] = ip_info
        if show_details and geo_error:
            cprint(f"    [!] GeoIP lookup: {geo_error}", WARNING)
        elif show_details and ip_info.get('country') != 'N/A':
            cprint(f"    📍 Location: {ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}", INFO)
            if ip_info.get('org') != 'N/A':
                cprint(f"    🏢 Organization: {ip_info.get('org', 'N/A')}", INFO)

        # ============================================================
        # 3. Blacklist check (موازي)
        # ============================================================
        blacklisted = self._check_blacklist_parallel(ip, show_details)
        results['blacklisted'] = blacklisted
        
        if blacklisted:
            cprint(f"    ⚠️ Blacklisted in: {', '.join(blacklisted)}", ERROR)
        else:
            cprint(f"    ✅ Not listed in any blacklist", SUCCESS)

        # حفظ النتائج إذا طلب
        if save_to_file:
            self._save_results(ip, results)

        return results

    # ============================================================
    # SMART REACHABILITY CHECK (مع Fallback ذكي)
    # ============================================================
    
    def _smart_reachability_check(self, ip, show_details=False):
        """
        فحص ذكي للوصول:
        1. TCP على المنافذ الشائعة
        2. ICMP Ping
        3. ARP (للمحلي)
        """
        response_time = None
        open_ports = []
        
        # ============================================================
        # LEVEL 1: TCP Port Scan (المنافذ الشائعة)
        # ============================================================
        if show_details:
            cprint(f"    [*] Level 1: TCP port scan...", INFO)
        
        for port in self.ports_to_check[:5]:  # أول 5 منافذ للسرعة
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                elapsed = time.time() - start
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    response_time = elapsed
                    if show_details:
                        cprint(f"        [+] Port {port} open ({elapsed:.2f}s)", SUCCESS)
                    
                    # إذا وجدنا منفذ مفتوح، نعتبر الهدف متاحاً
                    return True, f"TCP port {port}", response_time, open_ports
                    
            except socket.gaierror:
                if show_details:
                    cprint(f"        [!] DNS resolution failed", WARNING)
            except socket.timeout:
                if show_details:
                    cprint(f"        [!] Port {port} timeout", WARNING)
            except Exception as e:
                if show_details:
                    cprint(f"        [!] Port {port} error: {e}", WARNING)
        
        # ============================================================
        # LEVEL 2: ICMP Ping (إذا فشل TCP)
        # ============================================================
        if show_details:
            cprint(f"    [*] Level 2: ICMP ping...", INFO)
        
        ping_success, ping_time, ping_error = self._ping_ip_advanced(ip)
        
        if ping_success:
            response_time = ping_time
            if show_details:
                cprint(f"        [+] ICMP ping successful ({ping_time:.2f}s)", SUCCESS)
            return True, "ICMP ping", response_time, open_ports
        else:
            if show_details and ping_error:
                cprint(f"        [!] ICMP ping failed: {ping_error}", WARNING)
        
        # ============================================================
        # LEVEL 3: ARP (للمحلي فقط)
        # ============================================================
        # التحقق إذا كان الـ IP محلياً
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                          '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                          '172.30.', '172.31.', '192.168.')):
            if show_details:
                cprint(f"    [*] Level 3: ARP check (local network)...", INFO)
            
            arp_success, arp_time = self._arp_check(ip)
            if arp_success:
                response_time = arp_time
                if show_details:
                    cprint(f"        [+] ARP response received ({arp_time:.2f}s)", SUCCESS)
                return True, "ARP", response_time, open_ports
            elif show_details:
                cprint(f"        [!] No ARP response", WARNING)
        
        return False, None, None, open_ports

    def _ping_ip_advanced(self, ip):
        """
        Ping متقدم مع قياس الوقت الدقيق
        يعيد (success, response_time, error_message)
        """
        # محاولة ping مع خيارات مختلفة حسب النظام
        ping_commands = [
            ['ping', '-c', '1', '-W', '2', ip],           # Linux/Mac
            ['ping', '-n', '1', '-w', '2', ip],           # Windows
            ['ping', '-c', '1', '-t', '2', ip],           # BusyBox
        ]
        
        for cmd in ping_commands:
            try:
                start = time.time()
                output = subprocess.run(cmd, stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE, timeout=3)
                elapsed = time.time() - start
                
                if output.returncode == 0:
                    # استخراج وقت الاستجابة من المخرجات
                    output_text = output.stdout.decode()
                    time_match = re.search(r'time[=<](\d+(?:\.\d+)?)\s*ms', output_text, re.IGNORECASE)
                    if time_match:
                        response_time = float(time_match.group(1)) / 1000  # تحويل إلى ثواني
                    else:
                        response_time = elapsed
                    return True, response_time, None
                    
            except subprocess.TimeoutExpired:
                continue
            except FileNotFoundError:
                continue
            except Exception as e:
                continue
        
        return False, 0, "All ping methods failed"

    def _arp_check(self, ip):
        """
        فحص ARP للشبكة المحلية
        """
        try:
            # محاولة ARPing
            cmd = ['arping', '-c', '1', '-w', '1', ip]
            start = time.time()
            output = subprocess.run(cmd, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, timeout=2)
            elapsed = time.time() - start
            
            if output.returncode == 0:
                output_text = output.stdout.decode()
                if '1 received' in output_text or '1 reply' in output_text:
                    return True, elapsed
                    
        except FileNotFoundError:
            # arping غير متاح، نحاول قراءة جدول ARP
            try:
                cmd = ['arp', '-n', ip]
                output = subprocess.run(cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, timeout=2)
                if output.returncode == 0 and ip in output.stdout.decode():
                    return True, 0.01
            except:
                pass
        except:
            pass
        
        return False, 0

    # ============================================================
    # TCP RETRY WITH FALLBACK (للمواقع التي تقفل البورتات)
    # ============================================================
    
    def _tcp_with_retry(self, ip, port=80, max_retries=2, timeout=3):
        """
        TCP connection with automatic retry and fallback
        """
        for attempt in range(max_retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                start = time.time()
                result = sock.connect_ex((ip, port))
                elapsed = time.time() - start
                sock.close()
                
                if result == 0:
                    return True, elapsed, None
                else:
                    error_msg = f"Connection refused (errno {result})"
                    
            except socket.gaierror as e:
                error_msg = f"DNS resolution failed: {e}"
            except socket.timeout:
                error_msg = "Connection timeout"
            except Exception as e:
                error_msg = str(e)
            
            # زيادة المهلة في كل محاولة
            timeout += 1
            if attempt < max_retries:
                time.sleep(0.5)
        
        return False, 0, error_msg

    # ============================================================
    # IP INFORMATION (محسن)
    # ============================================================
    
    def _get_ip_info(self, ip):
        """Get IP geolocation and ASN information (multiple sources) with error logging"""
        info = {
            'asn': 'N/A', 'asn_description': 'N/A', 'network_name': 'N/A',
            'city': 'N/A', 'region': 'N/A', 'country': 'N/A', 'loc': 'N/A',
            'org': 'N/A', 'timezone': 'N/A', 'isp': 'N/A'
        }
        error_msg = None
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

        # Source 1: ip-api.com
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    info['city'] = data.get('city', 'N/A')
                    info['region'] = data.get('regionName', 'N/A')
                    info['country'] = data.get('country', 'N/A')
                    info['loc'] = f"{data.get('lat', 0)},{data.get('lon', 0)}"
                    info['org'] = data.get('org', 'N/A')
                    info['isp'] = data.get('isp', 'N/A')
                    info['asn'] = data.get('as', 'N/A').split()[0] if data.get('as') else 'N/A'
                    info['timezone'] = data.get('timezone', 'N/A')
                    return info, None
        except Exception as e:
            error_msg = str(e)

        # Source 2: ipinfo.io
        try:
            response = requests.get(f'https://ipinfo.io/{ip}/json', headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                info['city'] = data.get('city', 'N/A')
                info['region'] = data.get('region', 'N/A')
                info['country'] = data.get('country', 'N/A')
                info['loc'] = data.get('loc', 'N/A')
                info['org'] = data.get('org', 'N/A')
                if 'org' in data and 'AS' in data['org']:
                    info['asn'] = data['org'].split()[0].replace('AS', '')
                return info, None
        except Exception as e:
            if error_msg:
                error_msg += f"; ipinfo.io: {e}"
            else:
                error_msg = str(e)

        return info, error_msg

    # ============================================================
    # BLACKLIST CHECK (موازي)
    # ============================================================
    
    def _check_blacklist_parallel(self, ip, show_details=False):
        """Check multiple blacklists in parallel using threading"""
        blacklists = {
            "Spamhaus ZEN": "zen.spamhaus.org",
            "SORBS": "dnsbl.sorbs.net",
            "Barracuda": "b.barracudacentral.org",
            "SpamCop": "bl.spamcop.net",
            "CBL": "cbl.abuseat.org"
        }
        reversed_ip = '.'.join(ip.split('.')[::-1])
        listed = []

        def check_one(name, domain):
            query = f"{reversed_ip}.{domain}"
            try:
                socket.gethostbyname(query)
                return name
            except socket.gaierror:
                return None
            except Exception as e:
                if show_details:
                    cprint(f"    [!] Error checking {name}: {e}", WARNING)
                return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(check_one, name, domain): name for name, domain in blacklists.items()}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    listed.append(result)

        return listed

    # ============================================================
    # SAVE RESULTS
    # ============================================================
    
    def _save_results(self, ip, results):
        """Save results to JSON file"""
        try:
            filename = f"ip_inspector_{ip.replace('.', '_')}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
            if self.verbose:
                cprint(f"[+] Results saved to {filename}", SUCCESS)
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Failed to save results: {e}", WARNING)


# ============================================================
# LEGACY FUNCTIONS
# ============================================================

def scan_ip(ip, verbose=False, save_to_file=False):
    """Legacy function for backward compatibility"""
    inspector = IPInspector(verbose=verbose)
    return inspector.scan_ip(ip, verbose, save_to_file)


def scan(url, verbose=False):
    """Scan IP from URL"""
    parsed = urlparse(url)
    host = parsed.hostname or url.split('/')[0]
    try:
        ip = socket.gethostbyname(host)
        return scan_ip(ip, verbose)
    except Exception as e:
        cprint(f"[!] Failed to resolve {host}: {e}", ERROR)
        return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python ip_inspector.py <IP_ADDRESS or URL>")
        print("Examples:")
        print("  python ip_inspector.py 8.8.8.8")
        print("  python ip_inspector.py https://google.com")
        sys.exit(1)
    
    target = sys.argv[1]
    if target.startswith('http'):
        scan(target, verbose=True)
    else:
        scan_ip(target, verbose=True, save_to_file=True)