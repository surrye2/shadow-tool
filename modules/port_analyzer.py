import subprocess
from termcolor import cprint
import time

COMMON_PORTS = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web)",
    110: "POP3 (Mail)",
    123: "NTP (Time)",
    143: "IMAP (Mail)",
    161: "SNMP",
    443: "HTTPS (Secure Web)",
    3306: "MySQL Database",
    3389: "Remote Desktop (RDP)",
    8080: "HTTP Proxy/Alt",
}

def reliable_nmap_scan(ip, ports, retries=3, delay=2):
    for attempt in range(1, retries+1):
        try:
            cprint(f"[PORT ANALYZER] Running Nmap scan attempt {attempt}...", "cyan")
            ports_str = ",".join(str(p) for p in ports)
            result = subprocess.check_output(
                ["nmap", "-p", ports_str, "-sV", ip],
                stderr=subprocess.DEVNULL
            ).decode()
            return result
        except Exception as e:
            cprint(f"[!] Nmap scan attempt {attempt} failed: {e}", "red")
            time.sleep(delay)
    return None

def analyze_ports(ip, open_ports):
    cprint("\n[PORT ANALYZER] Analyzing open ports...\n", "cyan")

    for port in open_ports:
        service = COMMON_PORTS.get(port, "Unknown Service")
        cprint(f"[+] Port {port}: {service}", "green")

    # Use reliable nmap scan with retries
    nmap_result = reliable_nmap_scan(ip, open_ports)
    if nmap_result:
        print(nmap_result)
    else:
        cprint("[!] Nmap scan failed after multiple attempts.", "red")
