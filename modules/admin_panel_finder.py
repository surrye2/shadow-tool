#!/usr/bin/env python3
"""
Admin Panel Finder - AlZill V6 Scanner Module
Advanced admin panel detection with Soft 404 detection, Smart fingerprinting, Redirect handling
"""

import requests
from bs4 import BeautifulSoup
from termcolor import cprint
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import re
import time
import random

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class AdminPanelFinder:
    def __init__(self, timeout=8, threads=15, verbose=False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
        ]
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        self.admin_indicators = [
            'password', 'login', 'username', 'signin', 'csrf', 'autofocus',
            'session', 'authenticate', 'authorization', 'auth', 'credential',
            'admin', 'dashboard', 'control panel', 'administration',
            'manage users', 'user management', 'system settings',
            'logout', 'signout', 'forgot password', 'reset password',
            'two-factor', '2fa', 'mfa', 'captcha', 'recaptcha'
        ]
        
        self.soft_404_indicators = [
            '404', 'not found', 'page not found', 'does not exist',
            'صفحة غير موجودة', 'الصفحة غير موجودة', '404 error',
            'sorry', 'oops', 'something went wrong', 'error occurred',
            'the requested url was not found', 'no results found',
            'return to home', 'go back', 'page not exist'
        ]
        
        self.common_paths = {
            "admin": "Standard Admin Panel",
            "administrator": "Standard Admin Panel",
            "admin/": "Standard Admin Panel",
            "administrator/": "Standard Admin Panel",
            "admin/login": "Admin Login Page",
            "admin/login.php": "PHP Admin Login",
            "admin/login.aspx": "ASP.NET Admin Login",
            "admin/index.php": "PHP Admin Index",
            "admin/index.html": "HTML Admin Index",
            "admin/dashboard": "Admin Dashboard",
            "admin/panel": "Admin Panel",
            "admin/controlpanel": "Admin Control Panel",
            "login": "Login Page",
            "login/": "Login Page",
            "login.php": "PHP Login",
            "login.aspx": "ASP.NET Login",
            "login.html": "HTML Login",
            "signin": "Sign In Page",
            "signin/": "Sign In Page",
            "signin.php": "PHP Sign In",
            "auth": "Authentication Page",
            "auth/": "Authentication Page",
            "authenticate": "Authentication Page",
            "wp-admin": "WordPress Admin",
            "wp-login.php": "WordPress Login",
            "administrator/index.php": "Joomla Admin",
            "cpanel": "cPanel Control Panel",
            "cpanel/": "cPanel Control Panel",
            "webmail": "Webmail Interface",
            "webmail/": "Webmail Interface",
            "dashboard": "Dashboard",
            "dashboard/": "Dashboard",
            "dashboard.php": "PHP Dashboard",
            "phpmyadmin": "phpMyAdmin Database",
            "phpmyadmin/": "phpMyAdmin Database",
            "pma": "phpMyAdmin Short",
            "mysql": "MySQL Admin",
            "mysql/": "MySQL Admin",
            "adminer": "Adminer Database",
            "manage": "Management Panel",
            "manage/": "Management Panel",
            "management": "Management Panel",
            "backoffice": "Back Office",
            "backoffice/": "Back Office",
            "backend": "Backend Panel",
            "backend/": "Backend Panel",
            "panel": "Control Panel",
            "panel/": "Control Panel",
            "cp": "Control Panel",
            "cp/": "Control Panel",
            "secure": "Secure Area",
            "secure/": "Secure Area",
            "protected": "Protected Area",
            "protected/": "Protected Area",
            "private": "Private Area",
            "private/": "Private Area",
            "restricted": "Restricted Area",
            "restricted/": "Restricted Area",
            "server-status": "Apache Server Status",
            "server-info": "Apache Server Info",
            "phpinfo.php": "PHP Info Page",
            "info.php": "PHP Info Page",
        }
        
        self.smart_patterns = [
            'admin', 'login', 'dashboard', 'cpanel', 'administrator', 
            'wp-admin', 'phpmyadmin', 'panel', 'control', 'manage',
            'backend', 'backoffice', 'staff', 'operator', 'secure',
            'private', 'protected', 'restricted', 'auth', 'signin'
        ]

    def _rotate_user_agent(self):
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents)
        })

    def scan(self, url: str) -> List[Dict]:
        cprint("\n" + "="*60, INFO)
        cprint("[ADMIN PANEL SCAN] AlZill V6 - Smart Discovery Engine", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, INFO)
        cprint("[*] Features: Soft 404 Detection | Smart Fingerprinting | Redirect Handling", "yellow")
        cprint("[*] Anti-False-Positive: Content Analysis | Keyword Matching", "yellow")

        url = self._normalize_url(url)

        cprint("[*] Phase 1: Scanning common admin paths...", INFO)
        common_results = self._scan_common_paths(url)

        cprint("[*] Phase 2: Discovering admin links from homepage...", INFO)
        link_results = self._discover_from_links(url)

        cprint("[*] Phase 3: Smart pattern-based discovery...", INFO)
        pattern_results = self._smart_pattern_scan(url)

        cprint("[*] Phase 4: Analyzing robots.txt...", INFO)
        robots_results = self._analyze_robots_txt(url)

        cprint("[*] Phase 5: Analyzing HTML source...", INFO)
        source_results = self._analyze_html_source(url)

        all_results = common_results + link_results + pattern_results + robots_results + source_results
        all_results = self._merge_results(all_results)
        all_results = self._filter_false_positives(all_results)

        self._display_results(all_results)
        return all_results

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def _is_soft_404(self, response) -> bool:
        try:
            content = response.text.lower()
            indicator_count = 0
            for indicator in self.soft_404_indicators:
                if indicator in content:
                    indicator_count += 1
            if indicator_count >= 3:
                return True
            if len(content) < 500 and indicator_count >= 1:
                return True
        except Exception:
            pass
        return False

    def _scan_common_paths(self, url: str) -> List[Dict]:
        results = []
        
        def check_path(path):
            self._rotate_user_agent()
            full_url = urljoin(url + '/', path)
            try:
                resp = self.session.get(full_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 401, 403]:
                    return {
                        'url': full_url,
                        'type': self.common_paths.get(path, "Detected Panel"),
                        'status': resp.status_code,
                        'method': 'common_path'
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(check_path, p): p for p in self.common_paths}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)
        return results

    def _discover_from_links(self, url: str) -> List[Dict]:
        results = []
        admin_keywords = ['admin', 'login', 'signin', 'dashboard', 'panel', 'manage', 'control', 'backend']
        
        try:
            self._rotate_user_agent()
            resp = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link.get('href', '').lower()
                text = link.get_text().lower()
                if any(k in href for k in admin_keywords) or any(k in text for k in admin_keywords):
                    full_url = urljoin(url, link['href'])
                    results.append({
                        'url': full_url,
                        'type': 'Discovered from homepage link',
                        'status': 'Checking...',
                        'method': 'link_discovery'
                    })
        except Exception as e:
            if self.verbose:
                cprint(f"    Link discovery error: {e}", WARNING)
        
        return list({r['url']: r for r in results}.values())[:30]

    def _smart_pattern_scan(self, url: str) -> List[Dict]:
        results = []
        
        def check_pattern(pattern):
            full_url = urljoin(url + '/', pattern)
            try:
                resp = self.session.get(full_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 401, 403]:
                    return {
                        'url': full_url,
                        'type': f'Smart pattern: {pattern}',
                        'status': resp.status_code,
                        'method': 'smart_pattern'
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(check_pattern, p): p for p in self.smart_patterns}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)
        return results

    def _analyze_robots_txt(self, url: str) -> List[Dict]:
        results = []
        robots_url = urljoin(url + '/', 'robots.txt')
        
        try:
            self._rotate_user_agent()
            resp = self.session.get(robots_url, timeout=self.timeout)
            if resp.status_code == 200:
                paths = re.findall(r'(?:Disallow|Allow):\s*(.*)', resp.text, re.IGNORECASE)
                for path in paths:
                    path = path.strip()
                    if path and path != '/':
                        full_url = urljoin(url + '/', path.lstrip('/'))
                        results.append({
                            'url': full_url,
                            'type': 'Discovered in robots.txt',
                            'status': 'Checking...',
                            'method': 'robots_analysis'
                        })
        except Exception:
            pass
        return results

    def _analyze_html_source(self, url: str) -> List[Dict]:
        results = []
        admin_keywords = ['admin', 'login', 'panel', 'manage', 'config', 'dashboard']
        
        try:
            self._rotate_user_agent()
            resp = self.session.get(url, timeout=self.timeout)
            content = resp.text
            
            comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            for comment in comments:
                if any(k in comment.lower() for k in admin_keywords):
                    potential_paths = re.findall(r'/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*', comment)
                    for p in potential_paths:
                        full_url = urljoin(url + '/', p.lstrip('/'))
                        results.append({
                            'url': full_url,
                            'type': 'Hidden in HTML comment',
                            'status': 'Checking...',
                            'method': 'source_analysis'
                        })
        except Exception:
            pass
        return results

    def _filter_false_positives(self, results: List[Dict]) -> List[Dict]:
        final_verified = []
        seen_urls = set()

        for res in results:
            url = res['url'].rstrip('/')
            if url in seen_urls:
                continue
            
            try:
                self._rotate_user_agent()
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if resp.status_code in [401, 403]:
                    res['status'] = resp.status_code
                    final_verified.append(res)
                    seen_urls.add(url)
                elif resp.status_code == 200 and not self._is_soft_404(resp):
                    content = resp.text.lower()
                    if any(ind in content for ind in self.admin_indicators):
                        res['status'] = resp.status_code
                        final_verified.append(res)
                        seen_urls.add(url)
                elif resp.status_code in [301, 302]:
                    location = resp.headers.get('Location', '')
                    if 'login' in location.lower() or 'admin' in location.lower():
                        res['status'] = resp.status_code
                        final_verified.append(res)
                        seen_urls.add(url)
            except Exception:
                pass
        
        return final_verified

    def _merge_results(self, results: List[Dict]) -> List[Dict]:
        seen = set()
        merged = []
        for r in results:
            url = r['url'].rstrip('/')
            if url not in seen:
                seen.add(url)
                merged.append(r)
        return merged

    def _display_results(self, results: List[Dict]):
        print()
        if results:
            cprint("="*55, SUCCESS)
            cprint(f"[✓] Found {len(results)} potential admin panel(s)!", SUCCESS, attrs=['bold'])
            cprint("="*55, SUCCESS)
            for i, panel in enumerate(results, 1):
                cprint(f"\n[{i}]  {panel['url']}", SUCCESS)
                cprint(f"    Type: {panel['type']}", INFO)
                cprint(f"    Status: {panel['status']}", INFO)
                cprint(f"    Discovered via: {panel['method']}", INFO)
        else:
            cprint("="*55, WARNING)
            cprint("[-] No admin panels detected", WARNING)
            cprint("="*55, WARNING)
        print()


def scan(url, verbose=False):
    finder = AdminPanelFinder(verbose=verbose)
    return finder.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python admin_panel_finder.py <target_url>")
