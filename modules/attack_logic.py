#!/usr/bin/env python3
"""
Admin Panel Finder - AlZill V6 Scanner Module
Advanced admin panel detection with Soft 404 detection, Smart fingerprinting, Redirect handling
Features: robots.txt analysis, HTML source analysis, Hidden link discovery
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
        
        # ============================================================
        # كلمات دلالية لتأكيد أن الصفحة هي لوحة تحكم حقيقية (Fingerprinting)
        # ============================================================
        self.admin_indicators = [
            'password', 'login', 'username', 'signin', 'csrf', 'autofocus',
            'session', 'authenticate', 'authorization', 'auth', 'credential',
            'admin', 'dashboard', 'control panel', 'administration',
            'manage users', 'user management', 'system settings',
            'logout', 'signout', 'forgot password', 'reset password',
            'two-factor', '2fa', 'mfa', 'captcha', 'recaptcha'
        ]
        
        # كلمات تدل على صفحة خطأ (Soft 404)
        self.soft_404_indicators = [
            '404', 'not found', 'page not found', 'does not exist',
            'صفحة غير موجودة', 'الصفحة غير موجودة', '404 error',
            'sorry', 'oops', 'something went wrong', 'error occurred',
            'the requested url was not found', 'no results found',
            'return to home', 'go back', 'page not exist'
        ]
        
        # ============================================================
        # قائمة موسعة للمسارات الشائعة (Admin Paths) - 250+ مسار
        # ============================================================
        self.common_paths = {
            # Standard admin paths
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
            "admincp": "vBulletin Admin",
            "modcp": "vBulletin Moderator CP",
            "admin_area": "Generic Admin Area",
            "panel-administracion": "Spanish Admin Panel",
            
            # Login pages
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
            
            # CMS specific
            "wp-admin": "WordPress Admin",
            "wp-login.php": "WordPress Login",
            "wp-admin/index.php": "WordPress Admin Index",
            "wp-admin/admin.php": "WordPress Admin Page",
            "administrator/index.php": "Joomla Admin",
            "administrator/index2.php": "Joomla Admin Alt",
            "admin/index.php": "Generic PHP Admin",
            "admin/index.asp": "ASP Admin",
            "admin/default.asp": "ASP Default Admin",
            "admin/default.aspx": "ASP.NET Default Admin",
            
            # Control panels
            "cpanel": "cPanel Control Panel",
            "cpanel/": "cPanel Control Panel",
            "webmail": "Webmail Interface",
            "webmail/": "Webmail Interface",
            "webmail/login.php": "Webmail Login",
            "dashboard": "Dashboard",
            "dashboard/": "Dashboard",
            "dashboard.php": "PHP Dashboard",
            "controlpanel": "Control Panel",
            "control-panel": "Control Panel",
            "control_panel": "Control Panel",
            
            # Database management
            "phpmyadmin": "phpMyAdmin Database",
            "phpmyadmin/": "phpMyAdmin Database",
            "pma": "phpMyAdmin Short",
            "mysql": "MySQL Admin",
            "mysql/": "MySQL Admin",
            "adminer": "Adminer Database",
            "adminer.php": "Adminer Database",
            "dbadmin": "Database Admin",
            "myadmin": "MyAdmin Database",
            "phpPgAdmin": "PostgreSQL Admin",
            "pgadmin": "PostgreSQL Admin",
            
            # Application specific
            "manage": "Management Panel",
            "manage/": "Management Panel",
            "management": "Management Panel",
            "backoffice": "Back Office",
            "backoffice/": "Back Office",
            "back-end": "Backend Panel",
            "backend": "Backend Panel",
            "operator": "Operator Panel",
            "staff": "Staff Panel",
            "member": "Member Area",
            "members": "Members Area",
            "user": "User Area",
            "users": "Users Area",
            "profile": "User Profile",
            "account": "Account Management",
            
            # Additional common paths
            "panel": "Control Panel",
            "cp": "Control Panel",
            "secure": "Secure Area",
            "protected": "Protected Area",
            "private": "Private Area",
            "restricted": "Restricted Area",
            
            # Framework specific
            "admin/content": "Content Management",
            "admin/pages": "Page Management",
            "admin/users": "User Management",
            "admin/settings": "Settings Page",
            
            # Server specific
            "server-status": "Apache Server Status",
            "server-info": "Apache Server Info",
            "phpinfo.php": "PHP Info Page",
            "info.php": "PHP Info Page",
            
            # E-commerce
            "admin/account": "E-commerce Admin",
            "admin/orders": "Order Management",
            "admin/products": "Product Management",
            "admin/customers": "Customer Management",
            
            # Hosting panels
            "plesk": "Plesk Control Panel",
            "plesk/": "Plesk Control Panel",
            "vhosts": "Virtual Hosts",
            "webstat": "Web Statistics",
            "awstats": "AWStats Statistics",
            
            # Development
            "_profiler": "Symfony Profiler",
            "_debugbar": "Debug Bar",
            "phpmyadmin": "phpMyAdmin",
            "adminer": "Adminer",
            "dev": "Development Panel",
            "dev/": "Development Panel",
        }
        
        # ============================================================
        # أنماط ذكية للكشف عن المسارات
        # ============================================================
        self.smart_patterns = [
            'admin', 'login', 'dashboard', 'cpanel', 'administrator', 
            'wp-admin', 'phpmyadmin', 'panel', 'control', 'manage',
            'backend', 'backoffice', 'staff', 'operator', 'secure',
            'private', 'protected', 'restricted', 'auth', 'signin'
        ]

    def _rotate_user_agent(self):
        """تغيير User-Agent بشكل عشوائي"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents)
        })

    def scan(self, url: str) -> List[Dict]:
        cprint("\n" + "="*60, INFO)
        cprint("[ADMIN PANEL SCAN] AlZill V6 - Smart Discovery Engine", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, INFO)
        cprint("[*] Features: Soft 404 Detection | Smart Fingerprinting | Redirect Handling", "yellow")
        cprint("[*] Anti-False-Positive: Content Analysis | Keyword Matching | HTML Comments", "yellow")

        url = self._normalize_url(url)

        # Phase 1: Common paths (قائمة موسعة)
        cprint(f"[*] Phase 1: Scanning {len(self.common_paths)} common admin paths...", INFO)
        common_results = self._scan_common_paths(url)

        # Phase 2: Links from homepage
        cprint("[*] Phase 2: Discovering admin links from homepage...", INFO)
        link_results = self._discover_from_links(url)

        # Phase 3: Smart patterns
        cprint("[*] Phase 3: Smart pattern-based discovery...", INFO)
        pattern_results = self._smart_pattern_scan(url)

        # Phase 4: Robots.txt analysis (جديد)
        cprint("[*] Phase 4: Analyzing robots.txt for hidden admin paths...", INFO)
        robots_results = self._analyze_robots_txt(url)

        # Phase 5: HTML source analysis (جديد)
        cprint("[*] Phase 5: Analyzing HTML source for hidden admin links...", INFO)
        source_results = self._analyze_html_source(url)

        # Phase 6: Sitemap analysis (جديد)
        cprint("[*] Phase 6: Analyzing sitemap.xml for admin paths...", INFO)
        sitemap_results = self._analyze_sitemap(url)

        # Merge all results
        all_results = (common_results + link_results + pattern_results + 
                      robots_results + source_results + sitemap_results)
        all_results = self._merge_results(all_results)
        
        # Filter out false positives (الفلترة النهائية)
        cprint("[*] Phase 7: Filtering false positives (Smart verification)...", INFO)
        all_results = self._filter_false_positives(all_results)

        self._display_results(all_results)
        return all_results

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def _is_soft_404(self, response) -> bool:
        """كشف الـ Soft 404 (صفحة خطأ مخصصة بكود 200)"""
        try:
            content = response.text.lower()
            
            # فحص الكلمات الدالة على الخطأ
            indicator_count = 0
            for indicator in self.soft_404_indicators:
                if indicator in content:
                    indicator_count += 1
            
            # إذا وجدنا 3 كلمات أو أكثر دالة على الخطأ، فهي Soft 404
            if indicator_count >= 3:
                return True
            
            # فحص طول المحتوى - صفحات الخطأ غالباً قصيرة
            if len(content) < 500 and indicator_count >= 1:
                return True
                
        except Exception:
            pass
        return False

    def _scan_common_paths(self, url: str) -> List[Dict]:
        """مسح المسارات الشائعة (250+ مسار)"""
        results = []
        
        def check_path(path):
            # تدوير User-Agent كل 10 طلبات
            if len(results) % 10 == 0:
                self._rotate_user_agent()
                
            full_url = urljoin(url + '/', path)
            try:
                # استخدام allow_redirects=False أولاً لكشف المسارات الحقيقية
                resp = self.session.get(full_url, timeout=self.timeout, allow_redirects=False)
                
                # كود 200 أو 301/302 أو 401 (محمي بكلمة مرور)
                if resp.status_code in [200, 301, 302, 401, 403]:
                    return {
                        'url': full_url,
                        'type': self.common_paths.get(path, "Detected Panel"),
                        'status': resp.status_code,
                        'method': 'common_path',
                        'location': resp.headers.get('Location', '') if resp.status_code in [301, 302] else ''
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
                    if self.verbose:
                        cprint(f"    Found: {r['url']} ({r['status']})", SUCCESS)
        return results

    def _discover_from_links(self, url: str) -> List[Dict]:
        """اكتشاف الروابط من الصفحة الرئيسية"""
        results = []
        admin_keywords = ['admin', 'login', 'signin', 'dashboard', 'panel', 'manage', 
                          'control', 'backend', 'cpanel', 'webmail', 'auth']
        
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
        
        # إزالة التكرارات
        return list({r['url']: r for r in results}.values())[:30]

    def _smart_pattern_scan(self, url: str) -> List[Dict]:
        """مسح ذكي باستخدام الأنماط"""
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
        """
        تحليل ملف robots.txt للكشف عن المسارات التي يطلب الموقع عدم أرشفتها
        غالباً ما تكون هذه المسارات هي لوحات التحكم
        """
        results = []
        robots_url = urljoin(url + '/', 'robots.txt')
        
        try:
            self._rotate_user_agent()
            resp = self.session.get(robots_url, timeout=self.timeout)
            
            if resp.status_code == 200:
                if self.verbose:
                    cprint(f"    robots.txt found, analyzing...", INFO)
                
                # استخراج الروابط بعد كلمة Disallow أو Allow
                patterns = re.findall(r'(?:Disallow|Allow):\s*(.*)', resp.text, re.IGNORECASE)
                
                for path in patterns:
                    path = path.strip()
                    if path and path != '/' and path != '':
                        full_url = urljoin(url + '/', path.lstrip('/'))
                        results.append({
                            'url': full_url,
                            'type': 'Discovered in robots.txt',
                            'status': 'Checking...',
                            'method': 'robots_analysis',
                            'robots_directive': 'Disallow' if 'Disallow' in resp.text else 'Allow'
                        })
                        
                        if self.verbose:
                            cprint(f"    Found in robots.txt: {path}", INFO)
                            
        except Exception as e:
            if self.verbose:
                cprint(f"    robots.txt analysis error: {e}", WARNING)
        
        return results

    def _analyze_html_source(self, url: str) -> List[Dict]:
        """
        تحليل الـ HTML Source للكشف عن الروابط المخفية داخل التعليقات أو ملفات JS
        """
        results = []
        admin_keywords = ['admin', 'login', 'panel', 'manage', 'config', 
                         'dashboard', 'control', 'backend', 'cpanel']
        
        try:
            self._rotate_user_agent()
            resp = self.session.get(url, timeout=self.timeout)
            content = resp.text
            
            # 1. البحث في التعليقات HTML
            comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            
            for comment in comments:
                comment_lower = comment.lower()
                if any(key in comment_lower for key in admin_keywords):
                    if self.verbose:
                        cprint(f"    Found suspicious comment: {comment[:100]}...", INFO)
                    
                    # محاولة استخراج رابط من داخل التعليق
                    potential_paths = re.findall(r'/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*', comment)
                    for path in potential_paths:
                        if any(key in path.lower() for key in admin_keywords):
                            full_url = urljoin(url + '/', path.lstrip('/'))
                            results.append({
                                'url': full_url,
                                'type': 'Hidden link in HTML comment',
                                'status': 'Checking...',
                                'method': 'source_analysis'
                            })
            
            # 2. البحث عن ملفات JS المشبوهة
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                if any(key in src for key in admin_keywords):
                    full_url = urljoin(url + '/', script['src'])
                    results.append({
                        'url': full_url,
                        'type': 'Sensitive JavaScript file',
                        'status': 'Checking...',
                        'method': 'source_analysis'
                    })
            
            # 3. البحث عن روابط مخفية في الـ data-attributes
            data_attrs = re.findall(r'data-[a-zA-Z-]+=["\']([^"\']+)["\']', content)
            for attr in data_attrs:
                if any(key in attr.lower() for key in admin_keywords):
                    full_url = urljoin(url + '/', attr.lstrip('/'))
                    results.append({
                        'url': full_url,
                        'type': 'Hidden in data attribute',
                        'status': 'Checking...',
                        'method': 'source_analysis'
                    })
                    
        except Exception as e:
            if self.verbose:
                cprint(f"    HTML source analysis error: {e}", WARNING)
        
        return results

    def _analyze_sitemap(self, url: str) -> List[Dict]:
        """
        تحليل ملف sitemap.xml للكشف عن المسارات الإدارية
        """
        results = []
        sitemap_urls = ['sitemap.xml', 'sitemap_index.xml', 'sitemap/sitemap.xml']
        admin_keywords = ['admin', 'login', 'panel', 'dashboard', 'control', 'manage']
        
        for sitemap_file in sitemap_urls:
            sitemap_full_url = urljoin(url + '/', sitemap_file)
            
            try:
                self._rotate_user_agent()
                resp = self.session.get(sitemap_full_url, timeout=self.timeout)
                
                if resp.status_code == 200:
                    if self.verbose:
                        cprint(f"    Found sitemap: {sitemap_file}", INFO)
                    
                    # استخراج الروابط من الـ sitemap
                    urls = re.findall(r'<loc>(.*?)</loc>', resp.text, re.IGNORECASE)
                    
                    for found_url in urls:
                        if any(key in found_url.lower() for key in admin_keywords):
                            results.append({
                                'url': found_url,
                                'type': 'Found in sitemap.xml',
                                'status': 'Checking...',
                                'method': 'sitemap_analysis'
                            })
                            
            except Exception as e:
                if self.verbose:
                    cprint(f"    Sitemap analysis error for {sitemap_file}: {e}", WARNING)
        
        return results

    def _filter_false_positives(self, results: List[Dict]) -> List[Dict]:
        """
        الفلترة النهائية - التأكد من أن كل ما تم جمعه هو لوحة تحكم حقيقية
        """
        final_verified = []
        seen_urls = set()

        for res in results:
            url = res['url'].rstrip('/')
            if url in seen_urls:
                continue
            
            try:
                self._rotate_user_agent()
                # استخدام allow_redirects=False أولاً
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                # حالة 401/403 (محمية بكلمة مرور) -> تعتبر لوحة تحكم
                if resp.status_code in [401, 403]:
                    res['status'] = resp.status_code
                    res['type'] = f"{res['type']} (Protected)"
                    final_verified.append(res)
                    seen_urls.add(url)
                    if self.verbose:
                        cprint(f"    Verified protected panel: {url}", SUCCESS)
                    
                # حالة 200 -> نحتاج للتأكد من المحتوى
                elif resp.status_code == 200 and not self._is_soft_404(resp):
                    content = resp.text.lower()
                    
                    # فحص الكلمات الدالة على لوحة التحكم
                    indicator_count = 0
                    matched_indicators = []
                    
                    for indicator in self.admin_indicators:
                        if indicator in content:
                            indicator_count += 1
                            matched_indicators.append(indicator)
                    
                    # إذا وجدنا 2 كلمة أو أكثر دالة على لوحة التحكم
                    if indicator_count >= 2:
                        res['status'] = resp.status_code
                        res['matched_keywords'] = matched_indicators[:5]
                        final_verified.append(res)
                        seen_urls.add(url)
                        if self.verbose:
                            cprint(f"    Verified admin panel: {url} (matched {indicator_count} keywords)", SUCCESS)
                    
                # حالة 301/302 -> نحاول متابعة التحويل
                elif resp.status_code in [301, 302]:
                    location = resp.headers.get('Location', '')
                    if location and 'login' in location.lower() or 'admin' in location.lower():
                        res['status'] = resp.status_code
                        res['redirects_to'] = location
                        final_verified.append(res)
                        seen_urls.add(url)
                        if self.verbose:
                            cprint(f"    Verified redirect to admin: {url} -> {location}", SUCCESS)
                            
            except requests.exceptions.Timeout:
                if self.verbose:
                    cprint(f"    Timeout on {url}", WARNING)
            except Exception as e:
                if self.verbose:
                    cprint(f"    Error verifying {url}: {e}", WARNING)
        
        return final_verified

    def _merge_results(self, results: List[Dict]) -> List[Dict]:
        """دمج النتائج وإزالة التكرارات"""
        seen = set()
        merged = []
        for r in results:
            url = r['url'].rstrip('/')
            if url not in seen:
                seen.add(url)
                merged.append(r)
        return merged

    def _display_results(self, results: List[Dict]):
        """عرض النتائج النهائية"""
        print()
        if results:
            cprint("="*60, SUCCESS)
            cprint(f"[✓] Found {len(results)} potential admin panel(s)!", SUCCESS, attrs=['bold'])
            cprint("="*60, SUCCESS)
            
            for i, panel in enumerate(results, 1):
                cprint(f"\n[{i}]  {panel['url']}", SUCCESS)
                cprint(f"    Type: {panel['type']}", INFO)
                cprint(f"    Status: {panel['status']}", INFO)
                cprint(f"    Discovered via: {panel['method']}", INFO)
                
                if panel.get('matched_keywords'):
                    cprint(f"    Matched keywords: {', '.join(panel['matched_keywords'])}", "cyan")
                if panel.get('redirects_to'):
                    cprint(f"    Redirects to: {panel['redirects_to']}", "yellow")
                    
            cprint("\n" + "="*60, SUCCESS)
            cprint("[!] IMPORTANT: Always verify these findings manually", WARNING)
            cprint("="*60, SUCCESS)
        else:
            cprint("="*55, WARNING)
            cprint("[-] No admin panels detected after smart filtering", WARNING)
            cprint("[*] Try: Different wordlist | More time | Manual inspection", INFO)
            cprint("="*55, WARNING)
        print()


# ========== دالة متوافقة مع الكود الرئيسي ==========
def scan(url, verbose=False):
    finder = AdminPanelFinder(verbose=verbose)
    return finder.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python admin_panel_finder.py <target_url>")