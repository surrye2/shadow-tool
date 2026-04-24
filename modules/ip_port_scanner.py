#!/usr/bin/env python3
"""
Port Scanner Module - AlZill V6 Pro
Advanced port scanner with banner grabbing, Cloudflare detection, Smart fallback
Features: Famous ports only | Banner grabbing | Service detection | IPv6 support
"""

import socket
import concurrent.futures
import re
import select
import time
import sys
from tqdm import tqdm
from colorama import init, Fore, Style
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple

# محاولة استيراد ipaddress مع معالجة الأخطاء
try:
    import ipaddress
    IPADDRESS_AVAILABLE = True
except ImportError:
    IPADDRESS_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] ipaddress module not available. Cloudflare detection disabled.{Style.RESET_ALL}")

init(autoreset=True)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"

# ============================================================
# FAMOUS PORTS (غير تسلسلي لتجنب الاكتشاف)
# ============================================================
FAMOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5222: "XMPP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "PHP-FPM",
    9200: "Elasticsearch",
    11211: "Memcached",
    15672: "RabbitMQ",
    27017: "MongoDB",
    50000: "SAP"
}

# منافذ قد تكون إيجابيات كاذبة مع Cloudflare
CLOUDFLARE_FALSE_POSITIVES = {80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096}

# Cloudflare IP ranges (محدثة)
CLOUDFLARE_IP_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
    '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
    '2c0f:f248::/32'
]

# Service-specific probe payloads
SERVICE_PROBES = {
    'HTTP': [b"HEAD / HTTP/1.0\r\n\r\n", b"GET / HTTP/1.0\r\n\r\n"],
    'FTP': [b"USER anonymous\r\n", b"HELP\r\n"],
    'SMTP': [b"HELO test.com\r\n", b"EHLO test.com\r\n"],
    'SSH': [],  # SSH sends banner on connect
    'MySQL': [b"\x00\x00\x00\x01\x85\xa2\x03\x00\x00\x00\x00\x00"],
    'Redis': [b"PING\r\n"],
    'Memcached': [b"stats\r\n"],
    'MongoDB': [b"\x41\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"],
}


def is_valid_ip(ip: str) -> bool:
    """Validate IP address format (IPv4 and IPv6)"""
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    # IPv6 pattern (basic)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    if re.match(ipv6_pattern, ip):
        return True
    
    return False


def is_cloudflare_ip(ip: str) -> bool:
    """
    Check if IP belongs to Cloudflare
    مع معالجة استثناءات شاملة
    """
    if not IPADDRESS_AVAILABLE:
        return False
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in CLOUDFLARE_IP_RANGES:
            try:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        return False
    except Exception:
        return False


def get_service_name(port: int) -> str:
    """Get service name for famous ports"""
    return FAMOUS_PORTS.get(port, "Unknown")


def grab_banner_advanced(ip: str, port: int, service: str, timeout: int = 3) -> Optional[str]:
    """
    Advanced banner grabbing - tries to receive before sending
    """
    banner = None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # ============================================================
        # STEP 1: Try to receive banner first (SSH, FTP, SMTP send banners)
        # ============================================================
        try:
            # استخدام select للتحقق من وجود بيانات للقراءة
            readable, _, _ = select.select([sock], [], [], 1)
            if readable:
                data = sock.recv(512)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    if banner:
                        sock.close()
                        return banner[:200]
        except (socket.timeout, select.error):
            pass
        except Exception:
            pass
        
        # ============================================================
        # STEP 2: Send service-specific probes
        # ============================================================
        probes = SERVICE_PROBES.get(service, [b"\r\n", b"HEAD / HTTP/1.0\r\n\r\n"])
        
        for probe in probes[:3]:  # حد أقصى 3 محاولات
            try:
                sock.send(probe)
                data = sock.recv(512)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    if banner:
                        sock.close()
                        return banner[:200]
            except (socket.timeout, ConnectionResetError):
                continue
            except Exception:
                continue
        
        sock.close()
        
    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        if False:  # verbose mode
            print(f"{Fore.YELLOW}[!] Banner grab error on port {port}: {e}{Style.RESET_ALL}")
    
    return banner


def scan_tcp_port_advanced(ip: str, port: int, timeout: float = 2, retries: int = 2) -> Optional[Dict]:
    """
    Advanced TCP port scan with retries and service detection
    """
    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout + (attempt * 0.5))
                
                start_time = time.time()
                result = s.connect_ex((ip, port))
                elapsed = time.time() - start_time
                
                if result == 0:
                    service = get_service_name(port)
                    banner = grab_banner_advanced(ip, port, service, timeout)
                    
                    return {
                        'port': port,
                        'service': service,
                        'response_time': round(elapsed, 3),
                        'banner': banner
                    }
        except socket.gaierror:
            # DNS resolution error - لا نعيد المحاولة
            return None
        except Exception:
            if attempt == retries - 1:
                return None
            time.sleep(0.2)
    
    return None


def scan_ports(ip: str, verbose: bool = False, max_workers: int = 50) -> List[Dict]:
    """
    Scan famous ports only (non-sequential to avoid detection)
    
    Args:
        ip: Target IP address
        verbose: Show detailed output
        max_workers: Number of concurrent threads
    """
    if not is_valid_ip(ip):
        print(f"{Fore.RED}[-] Invalid IP address: {ip}{Style.RESET_ALL}")
        return []

    # Check if behind Cloudflare
    behind_cf = is_cloudflare_ip(ip)
    if behind_cf and verbose:
        print(f"{Fore.YELLOW}[!] IP is behind Cloudflare - some ports may be false positives{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] TCP Port Scan: {ip}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Scanning {len(FAMOUS_PORTS)} famous ports...{Style.RESET_ALL}")
    if verbose:
        print(f"{Fore.CYAN}[*] Threads: {max_workers} | Timeout: 2s | Retries: 2{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    open_ports = []

    # Scan ports from famous list only (non-sequential)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_tcp_port_advanced, ip, port): port for port in FAMOUS_PORTS.keys()}
        
        with tqdm(total=len(futures), desc="Port Scan", ncols=70, colour="cyan") as pbar:
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                result = future.result()
                pbar.update(1)
                
                if result:
                    # Filter out false positives from Cloudflare
                    if behind_cf and port in CLOUDFLARE_FALSE_POSITIVES:
                        if verbose:
                            print(f"{Fore.YELLOW}[!] Port {port} may be Cloudflare false positive{Style.RESET_ALL}")
                        continue
                    open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: x['port'])

    # Display results
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[✓] SCAN RESULTS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    if open_ports:
        print(f"{Fore.GREEN}[+] Found {len(open_ports)} open port(s):{Style.RESET_ALL}\n")
        for result in open_ports:
            port = result['port']
            service = result['service']
            response_time = result['response_time']
            banner = result.get('banner')
            
            if banner:
                print(f"{Fore.GREEN}    → Port {port} ({service}) - Response: {response_time}s{Style.RESET_ALL}")
                # Clean banner for display
                clean_banner = banner.replace('\n', ' ').replace('\r', ' ').strip()
                if len(clean_banner) > 80:
                    clean_banner = clean_banner[:80] + "..."
                print(f"{Fore.CYAN}      Banner: {clean_banner}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}    → Port {port} ({service}) - Response: {response_time}s{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] No open ports found.{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    return open_ports


def scan(url: str, verbose: bool = False, max_workers: int = 50) -> List[Dict]:
    """
    Main entry point for port scanning
    
    Args:
        url: Target URL or IP
        verbose: Show detailed output
        max_workers: Number of concurrent threads
    """
    # Extract hostname
    parsed_url = urlparse(url)
    host = parsed_url.hostname if parsed_url.hostname else url.split('/')[0]

    if not host:
        print(f"{Fore.RED}[-] Invalid URL: Cannot extract hostname.{Style.RESET_ALL}")
        return []

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"{Fore.RED}[-] Could not resolve host {host}: {e}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[-] Resolution error: {e}{Style.RESET_ALL}")
        return []

    if verbose:
        print(f"{Fore.CYAN}[~] Target: {host} ({ip}){Style.RESET_ALL}")
        if is_cloudflare_ip(ip):
            print(f"{Fore.YELLOW}[!] IP is behind Cloudflare WAF{Style.RESET_ALL}")

    return scan_ports(ip, verbose=verbose, max_workers=max_workers)


def quick_scan(url: str, verbose: bool = False) -> List[Dict]:
    """
    Quick scan of famous ports only (lightning fast)
    """
    print(f"{Fore.CYAN}[*] Running quick scan on famous ports...{Style.RESET_ALL}")
    return scan(url, verbose=verbose, max_workers=50)


def detailed_scan(url: str, verbose: bool = False) -> List[Dict]:
    """
    Detailed scan with more threads and banner grabbing
    """
    print(f"{Fore.CYAN}[*] Running detailed scan with banner grabbing...{Style.RESET_ALL}")
    return scan(url, verbose=verbose, max_workers=100)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scan_type = sys.argv[2] if len(sys.argv) > 2 else "quick"
        
        print(f"{Fore.CYAN}Testing port scanner on: {target}{Style.RESET_ALL}")
        
        if scan_type == "detailed":
            detailed_scan(target, verbose=True)
        else:
            quick_scan(target, verbose=True)
    else:
        print(f"{Fore.YELLOW}Usage: python ip_port_scanner.py <target_url> [quick|detailed]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Examples:{Style.RESET_ALL}")
        print(f"  python ip_port_scanner.py https://example.com")
        print(f"  python ip_port_scanner.py 192.168.1.1")
        print(f"  python ip_port_scanner.py example.com detailed")