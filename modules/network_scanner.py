#!/usr/bin/env python3
"""
Network Scanner - Advanced Port Discovery with Stealth
Concise output, customizable scan types, random delays
"""

import socket
import random
import time
from termcolor import cprint

class NetworkScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.start_time = 0

    def scan(self, target_ip, scan_type="common", stealth=True, retries=2, timeout=1.0):
        """
        Perform network port scan.
        
        Args:
            target_ip: Target IP address
            scan_type: 'common' (only common ports), 'all' (1-1024), 'random' (random 100 ports)
            stealth: Enable random delays
            retries: Number of attempts per port
            timeout: Socket timeout
        """
        cprint(f"\n[PORT SCAN] Target: {target_ip} | Type: {scan_type} | Stealth: {'ON' if stealth else 'OFF'}", "cyan")
        self.start_time = time.time()
        
        # Define port lists
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 5900: "VNC", 6379: "Redis",
            27017: "MongoDB", 3389: "RDP"
        }
        
        if scan_type == "common":
            ports_to_scan = common_ports
        elif scan_type == "all":
            # Generate ports 1-1024
            ports_to_scan = {p: "Unknown" for p in range(1, 1025)}
        elif scan_type == "random":
            # Generate 100 random ports between 1 and 65535
            random_ports = random.sample(range(1, 65536), 100)
            ports_to_scan = {p: "Unknown" for p in random_ports}
        else:
            cprint("[!] Invalid scan type. Using 'common'.", "yellow")
            ports_to_scan = common_ports
        
        found = []
        total = len(ports_to_scan)
        tested = 0
        
        for port, service in ports_to_scan.items():
            tested += 1
            if stealth:
                # Wider random delay range (0.2 - 1.2 sec) to avoid detection
                time.sleep(random.uniform(0.2, 1.2))
            
            port_open = False
            for attempt in range(retries):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                try:
                    if sock.connect_ex((target_ip, port)) == 0:
                        port_open = True
                        break
                except:
                    pass
                finally:
                    sock.close()
                time.sleep(0.1)
            
            if port_open:
                found.append((port, service))
                if self.verbose:
                    cprint(f"    [+] Port {port} ({service})", "green")
        
        # Concise output
        if found:
            cprint(f"\n[✓] Open ports ({len(found)}):", "green")
            for port, service in found[:10]:
                cprint(f"    {port} ({service})", "green")
            if len(found) > 10:
                cprint(f"    ... and {len(found)-10} more", "yellow")
        else:
            cprint("[!] No open ports detected", "yellow")
        
        if self.verbose:
            elapsed = time.time() - self.start_time
            cprint(f"[*] Scanned {tested} ports in {elapsed:.1f}s", "cyan")
        
        return [p[0] for p in found]


# Legacy function for backward compatibility
def scan(ip, retries=3, timeout=1.0, stealth_mode=True):
    scanner = NetworkScanner(verbose=True)
    return scanner.scan(ip, scan_type="common", stealth=stealth_mode, retries=retries, timeout=timeout)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scan(target, stealth_mode=True)
    else:
        print("Usage: python network_scanner.py <target_ip>")


