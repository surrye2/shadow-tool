#!/usr/bin/env python3
"""
AlZill Vulnerability Scanner - Full Fixed Version
"""

import requests
import concurrent.futures
import json
import time
import re
import os
from collections import deque
from bs4 import BeautifulSoup, Comment
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from termcolor import colored
from typing import List, Dict, Optional, Tuple, Any

# ============================================================
# MODULE IMPORTS WITH ERROR HANDLING
# ============================================================
try:
    from modules import (
        xploit_xss,
        xploit_sqli,
        xploit_lfi,
        xploit_cmdi,
        xploit_csrf,
        xploit_redirect,
        xploit_ssrf
    )
    MODULES_AVAILABLE = True
except ImportError as e:
    print(colored(f"[!] Could not import exploitation modules: {e}", 'yellow'))
    print(colored("[!] Continuing with scanning only (exploitation disabled)", 'yellow'))
    MODULES_AVAILABLE = False
    # Create dummy modules to avoid NameError
    class DummyModule:
        @staticmethod
        def exploit(url):
            print(colored(f"    [!] Exploitation not available (module missing)", 'yellow'))
    
    xploit_xss = xploit_sqli = xploit_lfi = xploit_cmdi = xploit_csrf = xploit_redirect = xploit_ssrf = DummyModule()

# === Configuration ===
HEADERS = {'User-Agent': 'VulnHunterPlus/1.0'}
TIMEOUT = 10
DELAY = 0.3
MAX_DEPTH = 3
MAX_WORKERS = 10
SEPARATOR = colored("=" * 60, 'blue')

visited_urls = set()
vulnerabilities_found = []
suspected_issues = []
interesting_payloads = []
extracted_data = []

TARGET_DOMAIN = None

STATIC_PAYLOADS = {
    'xss': '<script>alert(1)</script>',
    'sqli': "' OR '1'='1",
    'lfi': '../../etc/passwd',
    'cmdi': ';id',
    'csrf': '',
    'open_redirect': 'https://evil.com',
    'ssrf': 'http://localhost:80'
}

COMMON_PATHS = [
    '/admin', '/backup', '/.git', '/debug', '/old',
    '/test', '/phpinfo.php', '/db.sql'
]

# ============================================================
# HTML RESERVED WORDS BLACKLIST (للفلترة)
# ============================================================
HTML_RESERVED_WORDS = {
    'meta', 'title', 'head', 'body', 'html', 'div', 'span', 'p', 'a',
    'script', 'style', 'link', 'img', 'br', 'hr', 'table', 'tr', 'td',
    'th', 'form', 'input', 'button', 'select', 'option', 'textarea',
    'footer', 'header', 'nav', 'section', 'article', 'aside', 'main',
    'DOCTYPE', 'xml', 'DOCTYPE html', 'HTTP/1.1', 'HTTP/2', 'Content-Type',
    'charset', 'utf-8', 'viewport', 'X-UA-Compatible', 'IE=edge'
}


def print_status(msg, color='green'):
    """Print colored status message"""
    print(colored(msg, color))


def generate_fuzz_payloads():
    """Generate fuzzing payloads - FIXED: removed broken JSON string"""
    return ["'", '"', '<>', '><', 'A' * 500, '', '{{7*7}}', '[]]', '|id', 'cat /etc/passwd', '{"json":"broken"}', '']


def is_same_domain(url, target_domain):
    """Check if URL belongs to target domain"""
    if not target_domain:
        return True
    try:
        parsed = urlparse(url)
        link_domain = parsed.netloc.lower()
        if link_domain.startswith('www.'):
            link_domain = link_domain[4:]
        if target_domain.startswith('www.'):
            target_domain = target_domain[4:]
        return link_domain == target_domain or link_domain.endswith('.' + target_domain)
    except:
        return False


def fetch_url(url):
    """Fetch URL content"""
    if not is_same_domain(url, TARGET_DOMAIN):
        return None, None, None
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        return resp.text, resp.status_code, resp.elapsed.total_seconds()
    except Exception as e:
        if "NameResolutionError" not in str(e) and "timeout" not in str(e).lower():
            print_status(f"[X] Failed to fetch {url}: {e}", 'red')
        return None, None, None


def extract_links(base_url, html):
    """
    Extracts all valid internal links from <a> and <form> tags.
    FIXED: Added html validation and improved error handling
    """
    # FIX: Check if html is valid
    if not html or not isinstance(html, str):
        return set()
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return set()
    
    links = set()
    
    # Scanning both 'a' tags and 'form' tags for potential entry points
    for tag in soup.find_all(['a', 'form']):
        href = tag.get('href')
        if not href:
            continue
            
        try:
            # Joining relative paths with the base URL
            full_link = urljoin(base_url, href)
            parsed_url = urlparse(full_link)
            
            # Filter: Only crawl links belonging to the TARGET_DOMAIN
            if parsed_url.scheme in ['http', 'https'] and is_same_domain(full_link, TARGET_DOMAIN):
                links.add(full_link)
        except Exception:
            # Silently skip malformed URLs to prevent script crashes
            continue
            
    return links


# ============================================================
# SQLi DETECTION - Boolean-based comparison (بدون False Positives)
# ============================================================
def test_sqli_boolean_based(url, param, original_html, original_length, session=None):
    """
    اختبار SQLi باستخدام تقنية Boolean-based
    يقارن استجابة الصفحة الأصلية مع استجابة الـ Payload
    """
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    if param not in query:
        return False
    
    # Payloads للاختبار: واحد true وواحد false
    true_payload = "' AND '1'='1"
    false_payload = "' AND '1'='2"
    
    try:
        # اختبار true payload
        query[param] = [true_payload]
        new_query = urlencode(query, doseq=True)
        true_url = parsed._replace(query=new_query).geturl()
        
        resp_true = requests.get(true_url, headers=HEADERS, timeout=TIMEOUT) if not session else session.get(true_url, timeout=TIMEOUT)
        
        # اختبار false payload
        query[param] = [false_payload]
        new_query = urlencode(query, doseq=True)
        false_url = parsed._replace(query=new_query).geturl()
        
        resp_false = requests.get(false_url, headers=HEADERS, timeout=TIMEOUT) if not session else session.get(false_url, timeout=TIMEOUT)
        
        # مقارنة الاستجابات
        # إذا اختلفت استجابة true عن false، فالثغرة موجودة
        if abs(len(resp_true.text) - len(resp_false.text)) > 50:
            return True
        
        # إذا كانت استجابة true مشابهة للأصل واستجابة false مختلفة
        if original_length is not None:
            if abs(len(resp_true.text) - original_length) < 100 and abs(len(resp_false.text) - original_length) > 100:
                return True
            
    except Exception:
        pass
    
    return False


def test_sqli_time_based(url, param, session=None):
    """
    اختبار SQLi باستخدام Time-based technique
    """
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    if param not in query:
        return False
    
    time_payloads = [
        "' OR SLEEP(5)-- -",
        "'; WAITFOR DELAY '00:00:05'-- -",
        "' AND pg_sleep(5)-- -",
        "' OR BENCHMARK(5000000, MD5('test'))-- -"
    ]
    
    for payload in time_payloads:
        try:
            query[param] = [payload]
            new_query = urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            start_time = time.time()
            resp = requests.get(test_url, headers=HEADERS, timeout=15) if not session else session.get(test_url, timeout=15)
            elapsed = time.time() - start_time
            
            if elapsed >= 4.5:  # إذا تأخر الرد أكثر من 4.5 ثانية
                return True
        except Exception:
            pass
    
    return False


# ============================================================
# XSS DETECTION - التحقق من الـ Encoding
# ============================================================
def is_html_encoded(text):
    """
    التحقق مما إذا كان النص مشفراً HTML Entities
    """
    if not text:
        return False
    html_entities = ['&lt;', '&gt;', '&amp;', '&quot;', '&#39;', '&apos;']
    for entity in html_entities:
        if entity in text:
            return True
    return False


def test_xss(url, param, payload):
    """
    اختبار XSS مع التحقق من Encoding
    """
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    if param not in query:
        return False
    
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    target_url = parsed._replace(query=new_query).geturl()
    
    try:
        resp = requests.get(target_url, headers=HEADERS, timeout=TIMEOUT)
        if not resp.text:
            return False
            
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # إزالة التعليقات والوسوم غير الضرورية
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
        
        # البحث عن الـ Payload في الـ HTML
        raw_text = resp.text
        
        # التحقق من ظهور الرموز الخطر بدون Encoding
        dangerous_chars = ['<', '>', '"', "'", '(', ')']
        
        # الحالة 1: الـ Payload ظهر بدون أي تغيير
        if payload in raw_text:
            # التحقق من عدم وجود Encoding
            if not is_html_encoded(raw_text):
                # التحقق الإضافي: هل الرموز الخطر موجودة؟
                for char in dangerous_chars:
                    if char in payload and char in raw_text:
                        return True
        
        # الحالة 2: البحث في السياق - هل ظهرت وسوم script؟
        if '<script' in raw_text.lower() and 'alert' in raw_text.lower():
            return True
        
        # الحالة 3: التحقق من وجود event handlers مهددة
        dangerous_events = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus']
        for event in dangerous_events:
            if event in raw_text.lower() and '=' in raw_text.lower():
                return True
                
    except Exception:
        pass
    
    return False


# ============================================================
# EXTRACTION MATRIX - Advanced Secrets Detection (مع فلترة HTML)
# ============================================================
def is_html_reserved(content):
    """
    التحقق مما إذا كان المحتوى من الكلمات المحجوزة في HTML
    """
    if not content:
        return False
    content_lower = content.lower().strip()
    for reserved in HTML_RESERVED_WORDS:
        if content_lower == reserved or content_lower.startswith(reserved):
            return True
    return False


def extract_secrets(html, url):
    """Extract emails, API keys, passwords, JWT tokens with quality filtering"""
    
    if not html:
        return
    
    # 1. Extract real emails (مع فلترة العناوين الوهمية)
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
    ignore_emails = {'test@example.com', 'admin@test.com', 'user@example.com', 'test@test.com', 'example@example.com', 'email@example.com'}
    for email in set(emails):
        if email.lower() not in ignore_emails and len(email) > 10:
            # تجنب استخراج البريد إذا كان ضمن كود HTML
            if not is_html_reserved(email.split('@')[0]):
                extracted_data.append(("Email", email, url))
                print_status(f"    📧 Found email: {email}", 'cyan')
    
    # 2. Extract API Keys (مع فلترة القيم الوهمية)
    api_key_patterns = [
        r'(?:api[_-]?key|apikey|api_key|secret|token|access_token|auth_token)(?:[\s=:\'"]+)([a-zA-Z0-9_\-]{16,64})',
        r'(AKIA[0-9A-Z]{16})',
        r'(AIza[0-9A-Za-z\-_]{35})',
        r'(gh[ops]_[0-9a-zA-Z]{36})',
        r'(sk_live_[0-9a-zA-Z]{24})',
        r'(pk_live_[0-9a-zA-Z]{24})',
        r'(xox[baprs]-[0-9a-zA-Z]{10,})',
    ]
    
    fake_keys = {'YOUR_API_KEY', 'API_KEY_HERE', 'SECRET_KEY', 'CHANGE_ME', 'REPLACE_ME'}
    
    for pattern in api_key_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in set(matches):
            if len(match) >= 16 and match not in fake_keys:
                if not is_html_reserved(match[:20]):
                    extracted_data.append(("API_KEY_FOUND", match, url))
                    print_status(f"    🔑 Found API Key: {match[:30]}...", 'yellow')
    
    # 3. Extract Passwords (مع فلترة القيم الوهمية)
    password_patterns = [
        r'(?:password|passwd|pwd|db_pass|db_password|db_user|mysql_pass)(?:[\s=:\'"]+)([a-zA-Z0-9@#$%^&*()_+!]{6,64})',
        r'(?:PASSWORD|PASSWD|DB_PASS)(?:[\s=:\'"]+)([a-zA-Z0-9@#$%^&*()_+!]{6,64})',
    ]
    
    fake_passwords = {'password', '123456', 'admin123', 'root', 'changeme', 'P@ssw0rd', '******'}
    
    for pattern in password_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in set(matches):
            if len(match) >= 6 and not match.isdigit() and match.lower() not in fake_passwords:
                if not is_html_reserved(match):
                    extracted_data.append(("LEAKED_PASSWORD", match, url))
                    print_status(f"    🔓 Found Password: {match[:30]}...", 'red')
    
    # 4. Extract JWT Tokens (مع فلترة الطول)
    jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    jwt_tokens = re.findall(jwt_pattern, html)
    for jwt in set(jwt_tokens):
        if len(jwt) > 50:
            if not is_html_reserved(jwt[:30]):
                extracted_data.append(("JWT_TOKEN", jwt[:50] + "...", url))
                print_status(f"    🎫 Found JWT Token: {jwt[:40]}...", 'magenta')
    
    # 5. Extract Database connection strings
    db_patterns = [
        r'(?:mongodb(?:\+srv)?|mysql|postgresql|redis|sqlite)://[a-zA-Z0-9@:/\-_.]+',
    ]
    
    for pattern in db_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in set(matches):
            if not is_html_reserved(match[:30]):
                extracted_data.append(("DATABASE_URI", match, url))
                print_status(f"    🗄️ Found DB URI: {match[:50]}...", 'yellow')
    
    # 6. Extract Private Keys
    private_key_pattern = r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----'
    if re.search(private_key_pattern, html):
        extracted_data.append(("PRIVATE_KEY", "Private key detected", url))
        print_status(f"    🔐 Found Private Key!", 'red')


def extract_interesting_data(html, url):
    """Extract interesting data from HTML"""
    if not is_same_domain(url, TARGET_DOMAIN):
        return
    if not html:
        return
        
    extract_secrets(html, url)
    
    # فلترة الأرقام - تجنب استخراج الأرقام العادية كأرقام هواتف
    phones = re.findall(r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}", html)
    file_links = re.findall(r'href=["\'](.*?)["\']', html)
    usernames = re.findall(r"(user(name)?|id)=\w+", url)

    for phone in set(phones):
        if len(phone) > 8:  # فلترة الأرقام القصيرة
            extracted_data.append(("Phone", phone, url))
    for file_link in set(file_links):
        if not is_html_reserved(file_link):
            extracted_data.append(("FileLink", file_link, url))
    for user in set(usernames):
        extracted_data.append(("Username", user[0], url))


# ============================================================
# IMPROVED TEST PAYLOAD - مع تقليل False Positives
# ============================================================
def test_payload(url, param, payload, vuln_type, original_html=None, original_length=None):
    """Test a specific payload for vulnerabilities"""
    if not is_same_domain(url, TARGET_DOMAIN):
        return False
    
    # معالجة خاصة لـ SQLi
    if vuln_type == 'sqli':
        # FIX: Use 'is not None' instead of truthiness for original_length
        if original_html is not None and original_length is not None:
            if test_sqli_boolean_based(url, param, original_html, original_length):
                return True
        if test_sqli_time_based(url, param):
            return True
        return False
    
    # معالجة خاصة لـ XSS
    if vuln_type == 'xss':
        return test_xss(url, param, payload)
    
    # باقي أنواع الثغرات
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if param not in query:
        return False

    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    target_url = parsed._replace(query=new_query).geturl()

    try:
        resp = requests.get(target_url, headers=HEADERS, timeout=TIMEOUT)
        if not resp.text:
            return False
            
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # إزالة التعليقات لتجنب الـ False Positives
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        if resp.status_code == 500:
            suspected_issues.append(("ServerError", target_url, param, payload))
            return True

        # للثغرات الأخرى: البحث عن الـ Payload في النص
        for text in soup.stripped_strings:
            if payload.lower() in text.lower():
                # تجنب الكلمات المحجوزة في HTML
                if not is_html_reserved(text[:50]):
                    vulnerabilities_found.append((vuln_type, target_url, param))
                    return True
    except:
        return False
    return False


def scan_url(url, original_html=None, original_length=None):
    """Scan a single URL for vulnerabilities"""
    if not is_same_domain(url, TARGET_DOMAIN):
        return
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for param in query_params:
        for vuln_type, payload in STATIC_PAYLOADS.items():
            if test_payload(url, param, payload, vuln_type, original_html, original_length):
                print(SEPARATOR)
                print_status(f'[!] {vuln_type.upper()} found at {url} param="{param}"', 'red')
                print(SEPARATOR)

        for fuzz in generate_fuzz_payloads():
            if test_payload(url, param, fuzz, 'fuzz'):
                print(SEPARATOR)
                print_status(f'[?] Fuzz hit at {url} param="{param}"', 'cyan')
                print(SEPARATOR)
                suspected_issues.append(("FuzzingHit", url, param, fuzz))
                interesting_payloads.append(fuzz)


# ============================================================
# QUEUE-BASED CRAWLING (No recursion, memory efficient)
# ============================================================
def crawl_with_queue(start_url):
    """Non-recursive crawling using a queue to prevent memory overflow"""
    queue = deque()
    queue.append((start_url, 0))  # (url, depth)
    
    while queue:
        url, depth = queue.popleft()
        
        if depth > MAX_DEPTH or url in visited_urls:
            continue
        if not is_same_domain(url, TARGET_DOMAIN):
            continue
        
        visited_urls.add(url)
        html, status, elapsed = fetch_url(url)
        if not html:
            continue
        
        # حفظ HTML الأصلي وطوله للمقارنة في اختبار SQLi
        original_length = len(html)
        
        extract_interesting_data(html, url)
        
        if status == 500:
            suspected_issues.append(("ServerCrash", url, None, None))
        elif elapsed and elapsed > 5:
            suspected_issues.append(("SlowResponse", url, None, None))
        
        # تمرير HTML الأصلي لاختبار SQLi
        scan_url(url, html, original_length)
        
        links = extract_links(url, html)
        for link in links:
            if link not in visited_urls:
                queue.append((link, depth + 1))
        
        time.sleep(DELAY)


def scan_common_paths(base_url):
    """Scan common sensitive paths"""
    if not is_same_domain(base_url, TARGET_DOMAIN):
        return
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in COMMON_PATHS:
        full_url = base + path
        if not is_same_domain(full_url, TARGET_DOMAIN):
            continue
        html, status, _ = fetch_url(full_url)
        if status == 200:
            print(SEPARATOR)
            print_status(f'[+] Found accessible path: {full_url}', 'magenta')
            print(SEPARATOR)
            suspected_issues.append(("CommonPath", full_url, None, None))


def save_results():
    """Save all results to JSON files"""
    os.makedirs("results", exist_ok=True)

    with open("results/results_vulns.json", "w") as f:
        json.dump(vulnerabilities_found, f, indent=4)

    with open("results/results_suspected.json", "w") as f:
        json.dump(suspected_issues, f, indent=4)

    with open("results/interesting_payloads.json", "w") as f:
        json.dump(interesting_payloads, f, indent=4)

    with open("results/results_extracted_data.json", "w") as f:
        json.dump(extracted_data, f, indent=4)


def run_exploitation_modules(url, found_types):
    """Run exploitation modules with proper error handling"""
    if not MODULES_AVAILABLE:
        print_status("[!] Exploitation modules not available, skipping...", 'yellow')
        return
    
    exploitation_map = {
        'xss': ('xploit_xss', xploit_xss),
        'sqli': ('xploit_sqli', xploit_sqli),
        'lfi': ('xploit_lfi', xploit_lfi),
        'cmdi': ('xploit_cmdi', xploit_cmdi),
        'csrf': ('xploit_csrf', xploit_csrf),
        'open_redirect': ('xploit_redirect', xploit_redirect),
        'ssrf': ('xploit_ssrf', xploit_ssrf),
    }
    
    for vuln_type, (module_name, module) in exploitation_map.items():
        if vuln_type in found_types:
            try:
                print_status(f"[*] Running {module_name}...", 'blue')
                module.exploit(url)
            except Exception as e:
                print_status(f"[!] {module_name} failed: {e}", 'red')


def run_deep_scan(url, target_domain=None):
    """Main scanning function"""
    global TARGET_DOMAIN
    TARGET_DOMAIN = target_domain
    
    if not TARGET_DOMAIN:
        parsed = urlparse(url)
        TARGET_DOMAIN = parsed.netloc.lower()
        if TARGET_DOMAIN.startswith('www.'):
            TARGET_DOMAIN = TARGET_DOMAIN[4:]
    
    print_status(f"[+] Target domain: {TARGET_DOMAIN}", 'cyan')
    print_status("[+] Starting advanced deep scan (using queue, non-recursive)...", 'cyan')
    scan_common_paths(url)
    crawl_with_queue(url)

    print(SEPARATOR)
    print_status("\n[✓] Scan complete.", 'green')
    
    if extracted_data:
        print_status("\n[📋 EXTRACTED SECRETS SUMMARY:]", 'cyan')
        secret_types = {}
        for item in extracted_data:
            secret_type = item[0]
            secret_types[secret_type] = secret_types.get(secret_type, 0) + 1
        
        for stype, count in secret_types.items():
            print_status(f"    - {stype}: {count}", 'yellow')
    
    print_status("[*] Running exploitation modules...", 'blue')

    found_types = {v[0] for v in vulnerabilities_found}
    
    # Run exploitation modules with error handling
    run_exploitation_modules(url, found_types)

    save_results()

    print(SEPARATOR)
    print_status("[✓] Exploitation complete. Results saved.", 'green')
    print(SEPARATOR)

    found_types_list = sorted({v[0] for v in vulnerabilities_found})
    print(colored("\n[=] Summary:", 'cyan'))
    print(colored(f" ├── Total Vulnerabilities Found : {len(vulnerabilities_found)}", 'yellow'))
    print(colored(f" ├── Types Detected             : {', '.join(found_types_list).upper() if found_types_list else 'None'}", 'yellow'))
    print(colored(f" ├── Secrets Extracted          : {len(extracted_data)}", 'yellow'))

    if found_types_list:
        print(colored(" └── Exploitation Modules Used  :", 'yellow'))
        for vtype in found_types_list:
            print(colored(f"      - exploit_{vtype.lower()}", 'green'))
    else:
        print(colored(" └── No exploitation modules triggered.", 'yellow'))


import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AlZill Vulnerability Scanner - Full Fixed Version")
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-d', '--domain', help='Target domain (optional, extracted from URL if not provided)')
    args = parser.parse_args()

    run_deep_scan(args.url, args.domain)