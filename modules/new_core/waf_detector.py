import requests
import urllib3

# Disable insecure request warnings for proxy/WAF scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WAFDetector:
    def __init__(self, url):
        if not url.startswith('http'):
            self.url = f"http://{url}"
        else:
            self.url = url
            
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AlZill-Scanner/3.0',
            'Accept': 'text/html,application/xhtml+xml,xml;q=0.9,*/*;q=0.8'
        }
        
        # Enhanced Signatures Database
        self.signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'cf_clearance', 'cf-cache-status'],
            'Akamai': ['akamai', 'ak_bmsc', 'X-Akamai-Transformed', 'akamai-ghost'],
            'Sucuri': ['sucuri', 'x-sucuri-id', 'x-sucuri-cache', 'cloudproxy'],
            'ModSecurity': ['mod_security', 'NOYB', 'x-has-modsecurity'],
            'F5 BIG-IP': ['TS', 'BigIP', 'F5', 'x-wa-info'],
            'AWS WAF': ['awswaf', 'x-amz-waf', 'aws-waf-logs'],
            'Imperva/Incapsula': ['incap_ses', 'visid_incap', 'X-Iinfo', 'incapsula'],
            'FortiWeb': ['fortiwafsid', 'fortigate'],
            'Barracuda': ['barra_counter_session', 'barracuda_waf']
        }

    def run(self):
        """Main entry point for scanner_engine.py to identify WAF"""
        print(f"\n[*] [WAF Detector] Analyzing: {self.url}")
        
        try:
            # 1. Passive Analysis (Headers & Cookies)
            response = requests.get(self.url, headers=self.headers, timeout=12, verify=False, allow_redirects=True)
            
            for waf_name, keys in self.signatures.items():
                # Check Headers
                for header, value in response.headers.items():
                    if any(key.lower() in header.lower() or key.lower() in value.lower() for key in keys):
                        print(f"[!] [WAF] IDENTIFIED: {waf_name} (Fingerprint in Headers)")
                        return waf_name
                
                # Check Cookies
                for cookie_name in response.cookies.get_dict():
                    if any(key.lower() in cookie_name.lower() for key in keys):
                        print(f"[!] [WAF] IDENTIFIED: {waf_name} (Fingerprint in Cookies)")
                        return waf_name

            # 2. Active Behavioral Probe (Simulated Attack)
            # Using a sensitive payload to trigger a reaction
            malicious_payloads = [
                "/?id=<script>alert(1)</script>",
                "/?file=/etc/passwd",
                "/?query=' OR '1'='1"
            ]
            
            for payload in malicious_payloads:
                attack_url = f"{self.url}{payload}"
                try:
                    attack_res = requests.get(attack_url, headers=self.headers, timeout=10, verify=False)
                    
                    # Common WAF Block codes: 403, 406, 429, 501
                    if attack_res.status_code in [403, 406, 501, 429]:
                        waf_info = "Generic/Unknown WAF (Active Blocking Detected)"
                        print(f"[!] [WAF] DETECTED: {waf_info} - Status Code: {attack_res.status_code}")
                        return waf_info
                except:
                    continue

            print("[+] [WAF] Analysis complete: No active WAF found.")
            return None

        except Exception as e:
            print(f"[X] [WAF Error] Connection failed: {str(e)}")
            return None
