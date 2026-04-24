import re
import requests
import json
import os
import sys
from bs4 import BeautifulSoup
from termcolor import cprint
from datetime import datetime

class FacebookOSINT:
    def __init__(self, profile_url, verbose=False, local_check=False):
        self.profile_url = profile_url.strip()
        self.verbose = verbose
        self.local_check = local_check
        self.session = requests.Session()
        # Header to mimic a mobile device for better crawling
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.91 Mobile Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9'
        })

    def run(self):
        cprint("\n" + "="*60, "cyan")
        cprint("[ALZILL ENGINE] Starting Advanced Intelligence Gathering", "magenta", attrs=['bold'])
        cprint(f"[*] Target: {self.profile_url}", "white")
        
        try:
            # 1. Web OSINT Phase
            m_url = self.profile_url.replace("www.facebook.com", "mbasic.facebook.com")
            if "mbasic" not in m_url:
                m_url = m_url.replace("facebook.com", "mbasic.facebook.com")

            response = self.session.get(m_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                uid = self._extract_uid(response.text)
                self._extract_name(soup)
                self._analyze_metadata(response.text, uid)
                if uid:
                    self._extract_likes(uid)
            else:
                cprint("[!] Web Profile is private or unreachable.", "yellow")

            # 2. Local Forensic Phase (The Crawler you requested)
            if self.local_check:
                self._crawl_local_session()

            cprint("\n" + "="*60, "cyan")
            cprint("[✓] Scan Completed Successfully", "green", attrs=['bold'])

        except Exception as e:
            cprint(f"[!] Critical Error: {e}", "red")

    def _extract_uid(self, text):
        patterns = [r'target=(\d+)', r'fb://profile/(\d+)', r'"userID":"(\d+)"', r'/composer/context/\?id=(\d+)']
        for p in patterns:
            match = re.search(p, text)
            if match:
                uid = match.group(1)
                cprint(f"[+] Unique UID Found: {uid}", "green")
                return uid
        return None

    def _extract_name(self, soup):
        title = soup.find('title').text if soup.find('title') else "N/A"
        name = title.replace(' | Facebook', '').replace(' - Facebook', '').strip()
        cprint(f"[+] Display Name: {name}", "green")

    def _analyze_metadata(self, text, uid):
        # Estimate Account Era
        if uid and uid.isdigit():
            u = int(uid)
            era = "Modern (Post-2018)"
            if u < 50000000: era = "Legacy (2004-2005)"
            elif u < 1000000000: era = "Early (2006-2010)"
            elif u < 1000000000000: era = "Growth Era (2011-2017)"
            cprint(f"[+] Account Age Estimate: {era}", "yellow")

        # Device Detection from source
        if "fbsource=android" in text or "android" in text.lower():
            cprint("[+] Primary Device: Android", "cyan")
        elif "fbsource=iphone" in text or "iphone" in text.lower():
            cprint("[+] Primary Device: iPhone/iOS", "cyan")
        else:
            cprint("[+] Primary Device: Desktop Browser", "cyan")

    def _extract_likes(self, uid):
        likes_url = f"https://mbasic.facebook.com/profile.php?id={uid}&v=likes"
        try:
            res = self.session.get(likes_url, timeout=7)
            soup = BeautifulSoup(res.text, 'html.parser')
            cprint("\n[*] Public Liked Pages:", "magenta")
            links = soup.find_all('a', href=True)
            for link in links:
                if '/pages/' in link['href'] or 'category' in link['href']:
                    if link.text.strip() and link.text.strip() != "More":
                        cprint(f"    → {link.text.strip()}", "white")
        except: pass

    def _crawl_local_session(self):
        """
        [DEEP CRAWLER] Extracts session data, emails, and tokens from Android Root.
        This targets the storage area that bypasses password entry.
        """
        cprint("\n[!] INITIATING LOCAL SYSTEM CRAWL...", "red", attrs=['bold'])
        
        # Core paths for Facebook App Data
        base_path = "/data/data/com.facebook.katana/"
        artifacts = {
            "Active Session": "databases/active_session_info",
            "Authentication DB": "databases/auth_db",
            "User Settings (XML)": "shared_prefs/com.facebook.katana_preferences.xml",
            "Login History": "databases/login_history_db"
        }

        if not os.path.exists(base_path):
            cprint("[-] Path /data/data/com.facebook.katana/ not found.", "yellow")
            cprint("    Make sure you have ROOT and are running in 'tsu' environment.", "yellow")
            return

        for name, subpath in artifacts.items():
            full_path = os.path.join(base_path, subpath)
            if os.path.exists(full_path):
                cprint(f"[+] Found Secure Artifact: {name}", "green")
                
                # Attempt to extract emails from XML preferences
                if full_path.endswith(".xml"):
                    try:
                        with open(full_path, 'r', errors='ignore') as f:
                            content = f.read()
                            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                            for email in set(emails):
                                cprint(f"    [FOUND STORED EMAIL]: {email}", "cyan", attrs=['bold'])
                            
                            # Searching for potential Session Tokens
                            tokens = re.findall(r'EAA[a-zA-Z0-9]+', content)
                            for token in set(tokens):
                                cprint(f"    [FOUND ACCESS TOKEN]: {token[:15]}...", "magenta")
                    except PermissionError:
                        cprint(f"    [!] Permission Denied to read {name}. Use Root.", "red")
            else:
                cprint(f"[-] Artifact {name} not found.", "white")

def scan(url, verbose=False, local_check=False):
    engine = FacebookOSINT(url, verbose, local_check)
    engine.run()

