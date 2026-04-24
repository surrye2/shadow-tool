#!/usr/bin/env python3
"""
Auto Proxy Support Injector - AlZill V6 Pro
Automatically adds proxy support to all scanner modules
Run this script once to patch all modules
"""

import os
import re
import sys
from datetime import datetime

# ============================================================
# Configuration
# ============================================================
MODULES_DIR = "modules"
BACKUP_DIR = "modules_backup"

# List of modules to patch
MODULES_TO_PATCH = [
    "lfi_scanner.py",
    "xss_scanner.py",
    "xss_post_scanner.py",
    "sqli_scanner.py",
    "sqli_post_scanner.py",
    "cmdi_scanner.py",
    "ssrf_scanner.py",
    "exploit_cmdi.py",
    "exploit_lfi.py",
    "exploit_sqli.py",
    "exploit_xss.py",
    "js_analyzer.py",
    "js_scanner.py",
    "open_redirect_scanner.py",
    "header_analyzer.py",
    "cookie_analyzer.py",
    "waf_detector.py",
    "input_monitor.py"
]

# Proxy support code to inject
PROXY_SUPPORT_CODE = '''
# ============================================================
# Proxy Support (Auto-injected)
# ============================================================
def get_session_with_proxy(proxy_session=None):
    """Get requests session with proxy support"""
    if proxy_session:
        return proxy_session
    return requests.Session()


def request_with_retry(url, method='GET', data=None, json=None, headers=None, 
                       proxy_session=None, max_retries=3, delay=2, **kwargs):
    """Send request with automatic retry and proxy support"""
    session = get_session_with_proxy(proxy_session)
    
    for attempt in range(max_retries):
        try:
            if method.upper() == 'GET':
                response = session.get(url, headers=headers, timeout=10, verify=False, **kwargs)
            elif method.upper() == 'POST':
                response = session.post(url, data=data, json=json, headers=headers, 
                                       timeout=10, verify=False, **kwargs)
            else:
                response = session.request(method, url, headers=headers, 
                                          timeout=10, verify=False, **kwargs)
            return response
        except (requests.exceptions.ConnectionError, ConnectionResetError) as e:
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise e
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise e
    return None

'''

# Function to add proxy parameter to scan functions
SCAN_FUNCTION_PATCH = '''
def scan(url, verbose=False, delay=1.0, payloads_file="payloads.txt", proxy_session=None):
'''

EXPLOIT_FUNCTION_PATCH = '''
def exploit(url, verbose=False, payloads_file="payloads.txt", proxy_session=None):
'''


def backup_file(filepath):
    """Create backup of original file"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    backup_path = os.path.join(BACKUP_DIR, os.path.basename(filepath))
    if not os.path.exists(backup_path):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"    Backup created: {backup_path}")
        return True
    return False


def patch_module(filepath):
    """Patch a single module with proxy support"""
    print(f"\n[*] Processing: {filepath}")
    
    if not os.path.exists(filepath):
        print(f"    [!] File not found: {filepath}")
        return False
    
    # Create backup
    backup_file(filepath)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # ============================================================
    # 1. Add proxy support code after imports
    # ============================================================
    if 'get_session_with_proxy' not in content:
        # Find where to insert (after imports)
        import_pattern = r'(import .+?\n|from .+?\n)+'
        import_matches = list(re.finditer(import_pattern, content))
        
        if import_matches:
            last_import = import_matches[-1]
            insert_pos = last_import.end()
            content = content[:insert_pos] + PROXY_SUPPORT_CODE + content[insert_pos:]
            print(f"    [+] Added proxy support functions")
        else:
            # If no imports found, add at beginning
            content = PROXY_SUPPORT_CODE + content
            print(f"    [+] Added proxy support functions (at top)")
    
    # ============================================================
    # 2. Add proxy_session parameter to scan function
    # ============================================================
    # Pattern for scan function definition
    scan_patterns = [
        r'def scan\(url,\s*verbose=False(?:,\s*delay=[\d.]+)?(?:,\s*payloads_file="[^"]+")?\):',
        r'def scan\(url,\s*verbose=False(?:,\s*delay=[\d.]+)?\):',
        r'def scan\(url,\s*verbose=False\):',
        r'def scan\(self,\s*url,\s*verbose=False\):',
    ]
    
    for pattern in scan_patterns:
        if re.search(pattern, content):
            # Replace with proxy version
            new_def = re.sub(
                r'def scan\(([^)]+)\):',
                r'def scan(\1, proxy_session=None):',
                content
            )
            if new_def != content:
                content = new_def
                print(f"    [+] Added proxy_session to scan() function")
                break
    
    # ============================================================
    # 3. Add proxy_session parameter to exploit function
    # ============================================================
    exploit_patterns = [
        r'def exploit\(url,\s*verbose=False\):',
        r'def exploit\(url,\s*path=None,\s*param=None,\s*verbose=False\):',
        r'def exploit\(url,\s*param_name=None,\s*verbose=False\):',
    ]
    
    for pattern in exploit_patterns:
        if re.search(pattern, content):
            new_def = re.sub(
                r'def exploit\(([^)]+)\):',
                r'def exploit(\1, proxy_session=None):',
                content
            )
            if new_def != content:
                content = new_def
                print(f"    [+] Added proxy_session to exploit() function")
                break
    
    # ============================================================
    # 4. Replace requests.get with session.get using proxy
    # ============================================================
    # Pattern for requests.get (but not inside strings)
    get_pattern = r'requests\.get\s*\(\s*([^,)]+)\s*(?:,\s*([^)]+))?\s*\)'
    
    def replace_get(match):
        url_param = match.group(1)
        other_params = match.group(2) if match.group(2) else ''
        
        # Create session call
        if other_params:
            return f'session.get({url_param}, {other_params})'
        else:
            return f'session.get({url_param})'
    
    # First, ensure we have a session variable
    if 'session = get_session_with_proxy(proxy_session)' not in content:
        # Add session initialization after function start
        function_start_pattern = r'(def (?:scan|exploit)\([^)]+\):\n)(\s+)(?:.*?)(?=\n\s+for|\n\s+if|\n\s+try|\n\s+while)'
        
        def add_session_init(match):
            func_def = match.group(1)
            indent = match.group(2)
            return func_def + f'{indent}# Initialize session with proxy\n{indent}session = get_session_with_proxy(proxy_session)\n\n'
        
        content = re.sub(function_start_pattern, add_session_init, content, flags=re.DOTALL)
        print(f"    [+] Added session initialization")
    
    # Replace requests.get with session.get
    if 'requests.get' in content and 'session.get' not in content:
        content = re.sub(r'requests\.get', 'session.get', content)
        print(f"    [+] Replaced requests.get with session.get")
    
    # Replace requests.post with session.post
    if 'requests.post' in content and 'session.post' not in content:
        content = re.sub(r'requests\.post', 'session.post', content)
        print(f"    [+] Replaced requests.post with session.post")
    
    # ============================================================
    # 5. Add import time if missing
    # ============================================================
    if 'import time' not in content and 'time.' in content:
        # Add import time after other imports
        import_pattern = r'(import .+?\n|from .+?\n)+'
        import_matches = list(re.finditer(import_pattern, content))
        if import_matches:
            last_import = import_matches[-1]
            insert_pos = last_import.end()
            content = content[:insert_pos] + 'import time\n' + content[insert_pos:]
            print(f"    [+] Added missing import time")
    
    # ============================================================
    # 6. Save changes if modified
    # ============================================================
    if content != original_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"    ✅ Successfully patched: {os.path.basename(filepath)}")
        return True
    else:
        print(f"    ⚠️ No changes needed: {os.path.basename(filepath)}")
        return False


def patch_main_script():
    """Patch the main script (abdh or azil)"""
    main_scripts = ['abdh', 'azil', 'abdh.py', 'azil.py', 'main.py']
    
    for script in main_scripts:
        if os.path.exists(script):
            print(f"\n[*] Patching main script: {script}")
            return patch_module(script)
    
    print(f"\n[!] Main script not found")
    return False


def create_proxy_manager():
    """Create the proxy_manager.py file if it doesn't exist"""
    proxy_manager_path = os.path.join(MODULES_DIR, "proxy_manager.py")
    
    if os.path.exists(proxy_manager_path):
        print(f"\n[*] Proxy manager already exists: {proxy_manager_path}")
        return True
    
    print(f"\n[*] Creating proxy manager: {proxy_manager_path}")
    
    proxy_manager_code = '''#!/usr/bin/env python3
# modules/proxy_manager.py
# AlZill V6 Pro - Smart Proxy Rotation Manager

import requests
import random
import time
import threading
from termcolor import cprint
from concurrent.futures import ThreadPoolExecutor, as_completed

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class ProxyManager:
    """Smart Proxy Manager with Auto-Rotation"""
    
    def __init__(self, verbose=False, max_retries=3):
        self.verbose = verbose
        self.max_retries = max_retries
        self.proxies = []
        self.current_index = 0
        self.failed_proxies = set()
        self.lock = threading.Lock()
        self.last_rotation_time = time.time()
        self.rotation_interval = 30
        self.requests_per_proxy = 15
        self.request_count_per_proxy = {}
        
        self.proxy_sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        ]
        
        self.test_urls = [
            "http://httpbin.org/ip",
            "http://ip-api.com/json/",
        ]
    
    def fetch_free_proxies(self, max_proxies=50, timeout=10):
        """Fetch free proxies from multiple sources"""
        all_proxies = []
        
        cprint(f"\\n[*] Fetching free proxies...", INFO)
        
        for source in self.proxy_sources:
            try:
                if self.verbose:
                    cprint(f"    Fetching from: {source[:60]}...", INFO)
                
                response = requests.get(source, timeout=timeout)
                
                if response.status_code == 200:
                    for line in response.text.split('\\n'):
                        line = line.strip()
                        if line and self._is_valid_proxy_format(line):
                            all_proxies.append(line)
                            
                            if len(all_proxies) >= max_proxies * 2:
                                break
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Failed: {str(e)[:50]}", WARNING)
                continue
            
            if len(all_proxies) >= max_proxies * 2:
                break
        
        all_proxies = list(set(all_proxies))
        
        if all_proxies:
            cprint(f"[+] Fetched {len(all_proxies)} proxies, testing...", SUCCESS)
            return self._test_proxies(all_proxies[:max_proxies * 2], max_proxies)
        else:
            cprint("[!] No proxies fetched, using fallback", WARNING)
            return self._get_fallback_proxies()
    
    def _is_valid_proxy_format(self, proxy_str):
        """Validate proxy format (ip:port)"""
        parts = proxy_str.split(':')
        if len(parts) == 2:
            ip, port = parts
            if ip.replace('.', '').isdigit() and port.isdigit():
                return True
        return False
    
    def _test_proxies(self, proxies, max_working=20, timeout=5):
        """Test multiple proxies in parallel"""
        working_proxies = []
        
        def test_single_proxy(proxy):
            try:
                proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
                
                for test_url in self.test_urls[:1]:
                    start_time = time.time()
                    response = requests.get(test_url, proxies=proxy_dict, timeout=timeout)
                    elapsed = time.time() - start_time
                    
                    if response.status_code == 200:
                        if self.verbose:
                            cprint(f"    [+] Working: {proxy} ({elapsed:.2f}s)", SUCCESS)
                        return proxy
                    break
            except:
                pass
            return None
        
        cprint(f"[*] Testing {len(proxies)} proxies...", INFO)
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_single_proxy, proxy): proxy for proxy in proxies}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    working_proxies.append(result)
                    if len(working_proxies) >= max_working:
                        break
        
        if working_proxies:
            cprint(f"[+] Found {len(working_proxies)} working proxies", SUCCESS)
        else:
            cprint("[!] No working proxies found, using fallback", WARNING)
            working_proxies = self._get_fallback_proxies()
        
        return working_proxies
    
    def _get_fallback_proxies(self):
        """Fallback proxies"""
        return [
            "104.16.0.1:80",
            "104.24.0.1:80",
            "172.64.0.1:80",
        ]
    
    def get_next_proxy(self):
        """Get next proxy with auto-rotation"""
        with self.lock:
            if not self.proxies:
                return None
            
            current_time = time.time()
            current_proxy = self.proxies[self.current_index]
            request_count = self.request_count_per_proxy.get(current_proxy, 0)
            
            should_rotate = (
                current_time - self.last_rotation_time > self.rotation_interval or
                request_count >= self.requests_per_proxy
            )
            
            if should_rotate:
                self.current_index = (self.current_index + 1) % len(self.proxies)
                self.last_rotation_time = current_time
                
                if self.verbose:
                    cprint(f"    [*] Rotating proxy...", INFO)
            
            proxy = self.proxies[self.current_index]
            self.request_count_per_proxy[proxy] = self.request_count_per_proxy.get(proxy, 0) + 1
            
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    
    def mark_failed(self, proxy):
        """Mark a proxy as failed"""
        if proxy:
            proxy_str = proxy.get('http', '').replace('http://', '')
            with self.lock:
                if proxy_str in self.proxies:
                    self.proxies.remove(proxy_str)
                    self.failed_proxies.add(proxy_str)
            
            if len(self.proxies) < 5:
                threading.Thread(target=self.update_proxies, daemon=True).start()
    
    def update_proxies(self, max_proxies=30):
        """Update proxy list"""
        cprint(f"\\n[*] Updating proxy list...", INFO)
        new_proxies = self.fetch_free_proxies(max_proxies)
        
        with self.lock:
            self.proxies = new_proxies
            self.current_index = 0
            self.request_count_per_proxy = {}
        
        return len(self.proxies)
    
    def get_proxy_count(self):
        """Get number of available proxies"""
        with self.lock:
            return len(self.proxies)


class ProxySession:
    """Session wrapper with automatic proxy rotation"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.proxy_manager = ProxyManager(verbose=verbose)
        self.proxy_manager.proxies = self.proxy_manager.fetch_free_proxies(max_proxies=20)
        self.request_count = 0
        
        if self.proxy_manager.proxies:
            cprint(f"[+] Proxy Session initialized with {len(self.proxy_manager.proxies)} proxies", SUCCESS)
        else:
            cprint("[!] No proxies available, running without proxy", WARNING)
    
    def get(self, url, **kwargs):
        """Send GET request with proxy rotation"""
        max_retries = 3
        
        for attempt in range(max_retries):
            proxy = self.proxy_manager.get_next_proxy()
            
            if proxy:
                kwargs['proxies'] = proxy
                if self.verbose:
                    cprint(f"    [*] Using proxy: {proxy.get('http', 'unknown')}", INFO)
            
            try:
                response = requests.get(url, timeout=10, verify=False, **kwargs)
                self.request_count += 1
                return response
                
            except (requests.exceptions.ConnectionError, ConnectionResetError) as e:
                if proxy:
                    self.proxy_manager.mark_failed(proxy)
                    if self.verbose:
                        cprint(f"    [!] Proxy failed, retrying... ({attempt+1}/{max_retries})", WARNING)
                time.sleep(1)
                
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Request error: {e}", WARNING)
                time.sleep(1)
        
        raise Exception("Max retries exceeded")
    
    def post(self, url, data=None, json=None, **kwargs):
        """Send POST request with proxy rotation"""
        max_retries = 3
        
        for attempt in range(max_retries):
            proxy = self.proxy_manager.get_next_proxy()
            
            if proxy:
                kwargs['proxies'] = proxy
                if self.verbose:
                    cprint(f"    [*] Using proxy: {proxy.get('http', 'unknown')}", INFO)
            
            try:
                response = requests.post(url, data=data, json=json, timeout=10, verify=False, **kwargs)
                self.request_count += 1
                return response
                
            except (requests.exceptions.ConnectionError, ConnectionResetError) as e:
                if proxy:
                    self.proxy_manager.mark_failed(proxy)
                    if self.verbose:
                        cprint(f"    [!] Proxy failed, retrying... ({attempt+1}/{max_retries})", WARNING)
                time.sleep(1)
                
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] Request error: {e}", WARNING)
                time.sleep(1)
        
        raise Exception("Max retries exceeded")
    
    def get_stats(self):
        """Get proxy statistics"""
        return {
            'total_proxies': self.proxy_manager.get_proxy_count(),
            'requests_sent': self.request_count
        }
'''
    
    os.makedirs(MODULES_DIR, exist_ok=True)
    
    with open(proxy_manager_path, 'w', encoding='utf-8') as f:
        f.write(proxy_manager_code)
    
    print(f"    ✅ Created proxy_manager.py")
    return True


def main():
    print("="*60)
    print(" AlZill V6 Pro - Proxy Support Injector")
    print("="*60)
    print(f"[*] Modules directory: {MODULES_DIR}")
    print(f"[*] Backup directory: {BACKUP_DIR}")
    print(f"[*] Modules to patch: {len(MODULES_TO_PATCH)}")
    print("="*60)
    
    # Create proxy manager
    create_proxy_manager()
    
    # Patch main script
    patch_main_script()
    
    # Patch all modules
    patched_count = 0
    for module in MODULES_TO_PATCH:
        module_path = os.path.join(MODULES_DIR, module)
        if patch_module(module_path):
            patched_count += 1
    
    print("\n" + "="*60)
    print(f" SUMMARY")
    print("="*60)
    print(f"[*] Modules patched: {patched_count}/{len(MODULES_TO_PATCH)}")
    print(f"[*] Backup saved to: {BACKUP_DIR}/")
    print("\n[!] To use proxy mode, add --proxy flag when running the tool")
    print("[!] Example: ./abdh -u https://target.com --proxy")
    print("="*60)


if __name__ == "__main__":
    main()
