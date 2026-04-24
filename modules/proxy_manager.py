#!/usr/bin/env python3
"""
Proxy Manager - AlZill V6 Pro (Extended Version)
Features: 20+ Proxy Sources | Auto Testing | Auto Rotation | Redis Fallback
Sources: 66ip, data5u, fatezero, zdaye, yqie, xiladaili, xicidaili, xsdaili, ip3366, 89ip, goubanjia, 
         proxyscrape, geonode, pubproxy, spys, hidemy, proxyhub, sslproxies, proxylist, free-proxy
"""

import requests
import re
import random
import time
import threading
import json
from termcolor import cprint
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

try:
    from pyquery import PyQuery as pq
    PYQUERY_AVAILABLE = True
except ImportError:
    PYQUERY_AVAILABLE = False

try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class ProxyManager:
    """Extended Proxy Manager - 20+ Sources + Auto Testing + Rotation"""
    
    def __init__(self, verbose=False, max_proxies=50, auto_refresh=True, test_proxies=True):
        self.verbose = verbose
        self.max_proxies = max_proxies
        self.auto_refresh = auto_refresh
        self.test_proxies = test_proxies
        self.proxies = []
        self.working_proxies = []
        self.current_index = 0
        self.failed_proxies = set()
        self.lock = threading.Lock()
        self.last_refresh_time = time.time()
        self.refresh_interval = 300
        self.request_count = 0
        self.rotation_interval = 30
        self.requests_per_proxy = 15
        self.last_rotation_time = time.time()
        self.request_count_per_proxy = {}
        
        self._init_sources()
        self.refresh_proxies()
        
        if auto_refresh:
            self._start_refresh_thread()
    
    def _init_sources(self):
        """Initialize all proxy source URLs - 20+ sources"""
        self.sources = [
            # المصادر المحلية (مواقع HTML)
            {
                'name': '66ip',
                'urls': [f'http://www.66ip.cn/{page}.html' for page in range(1, 4)],
                'parser': self._parse_66ip,
                'enabled': True
            },
            {
                'name': 'data5u',
                'urls': ['http://www.data5u.com'],
                'parser': self._parse_data5u,
                'enabled': True
            },
            {
                'name': 'fatezero',
                'urls': ['http://proxylist.fatezero.org/proxy.list'],
                'parser': self._parse_fatezero,
                'enabled': True
            },
            {
                'name': 'zdaye',
                'urls': self._get_zdaye_urls(),
                'parser': self._parse_zdaye,
                'enabled': PYQUERY_AVAILABLE
            },
            {
                'name': 'yqie',
                'urls': ['http://ip.yqie.com/ipproxy.htm'],
                'parser': self._parse_yqie,
                'enabled': PYQUERY_AVAILABLE
            },
            {
                'name': 'xiladaili',
                'urls': ['http://www.xiladaili.com/'],
                'parser': self._parse_xiladaili,
                'enabled': LXML_AVAILABLE
            },
            {
                'name': 'xicidaili',
                'urls': ['https://www.xicidaili.com/'],
                'parser': self._parse_xicidaili,
                'enabled': PYQUERY_AVAILABLE
            },
            {
                'name': 'xiaoshu',
                'urls': self._get_xiaoshu_urls(),
                'parser': self._parse_xiaoshu,
                'enabled': PYQUERY_AVAILABLE
            },
            {
                'name': 'ip3366',
                'urls': [f'http://www.ip3366.net/free/?stype={stype}&page={page}' 
                        for stype in range(1, 3) for page in range(1, 8)],
                'parser': self._parse_ip3366,
                'enabled': True
            },
            {
                'name': '89ip',
                'urls': ['http://api.89ip.cn/tqdl.html?api=1&num=9999&port=&address=&isp='],
                'parser': self._parse_89ip,
                'enabled': True
            },
            {
                'name': 'goubanjia',
                'urls': ['http://www.goubanjia.com/'],
                'parser': self._parse_goubanjia,
                'enabled': PYQUERY_AVAILABLE
            },
            # مصادر API جديدة
            {
                'name': 'proxyscrape',
                'urls': [
                    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all',
                    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=5000&country=all&ssl=all&anonymity=all',
                    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=all&ssl=all&anonymity=all',
                    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all',
                ],
                'parser': self._parse_raw_text,
                'enabled': True
            },
            {
                'name': 'geonode',
                'urls': [
                    'https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps',
                    'https://proxylist.geonode.com/api/proxy-list?limit=500&page=2&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps',
                ],
                'parser': self._parse_geonode_json,
                'enabled': True
            },
            {
                'name': 'pubproxy',
                'urls': [
                    'http://pubproxy.com/api/proxy?limit=50&format=txt&http=true&https=true',
                    'http://pubproxy.com/api/proxy?limit=50&format=txt&http=true&https=true&level=anonymous',
                ],
                'parser': self._parse_raw_text,
                'enabled': True
            },
            {
                'name': 'spys',
                'urls': ['https://spys.one/en/'],
                'parser': self._parse_spys,
                'enabled': LXML_AVAILABLE
            },
            {
                'name': 'hidemy',
                'urls': ['https://hidemy.name/en/proxy-list/'],
                'parser': self._parse_hidemy,
                'enabled': LXML_AVAILABLE
            },
            {
                'name': 'proxyhub',
                'urls': ['https://proxyhub.me/'],
                'parser': self._parse_proxyhub,
                'enabled': PYQUERY_AVAILABLE
            },
            {
                'name': 'sslproxies',
                'urls': ['https://www.sslproxies.org/'],
                'parser': self._parse_sslproxies,
                'enabled': PYQUERY_AVAILABLE
            },
            {
                'name': 'proxylist',
                'urls': ['https://www.proxy-list.download/api/v1/get?type=http'],
                'parser': self._parse_raw_text,
                'enabled': True
            },
            {
                'name': 'free-proxy',
                'urls': ['https://free-proxy-list.net/'],
                'parser': self._parse_free_proxy,
                'enabled': PYQUERY_AVAILABLE
            },
            # مصادر GitHub
            {
                'name': 'github_proxies',
                'urls': [
                    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt',
                    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
                    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
                    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
                    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
                    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt',
                    'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt',
                    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt',
                    'https://raw.githubusercontent.com/almroot/proxylist/master/list.txt',
                ],
                'parser': self._parse_raw_text,
                'enabled': True
            },
        ]
    
    def _get_zdaye_urls(self):
        urls = []
        try:
            response = requests.get('https://www.zdaye.com/dayProxy/', timeout=10)
            if response.status_code == 200:
                doc = pq(response.text)
                for item in doc('#J_posts_list .thread_item div div p a').items():
                    url = 'https://www.zdaye.com' + item.attr('href')
                    urls.append(url)
        except:
            pass
        return urls[:10]
    
    def _get_xiaoshu_urls(self):
        urls = []
        try:
            response = requests.get('http://www.xsdaili.cn/', timeout=10)
            if response.status_code == 200:
                doc = pq(response.text)
                for t in doc(".title:eq(0) a").items():
                    match = re.search(r"/(\d+)\.html", t.attr("href"))
                    if match:
                        latest_page = int(match.group(1))
                        for page in range(max(1, latest_page - 3), latest_page):
                            urls.append(f'http://www.xsdaili.cn/dayProxy/ip/{page}.html')
        except:
            pass
        return urls
    
    # ============================================================
    # PARSERS
    # ============================================================
    
    def _parse_raw_text(self, text):
        """Parse raw text format (one proxy per line)"""
        proxies = []
        for line in text.split('\n'):
            line = line.strip()
            if line and self._is_valid_proxy_format(line):
                proxies.append(line)
        return proxies
    
    def _parse_geonode_json(self, text):
        """Parse GeoNode JSON API response"""
        proxies = []
        try:
            data = json.loads(text)
            for item in data.get('data', []):
                ip = item.get('ip')
                port = item.get('port')
                if ip and port:
                    proxies.append(f"{ip}:{port}")
        except:
            pass
        return proxies
    
    def _is_valid_proxy_format(self, proxy_str):
        parts = proxy_str.split(':')
        if len(parts) == 2:
            ip, port = parts
            if ip.replace('.', '').replace(':', '').isdigit() and port.isdigit():
                return True
        return False
    
    def _parse_66ip(self, html):
        proxies = []
        pattern = r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)'
        matches = re.findall(pattern, html)
        for ip, port in matches:
            proxies.append(f"{ip}:{port}")
        return proxies
    
    def _parse_data5u(self, html):
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            items = doc('.wlist ul.l2').items()
            for item in items:
                host = item.find('span:first-child').text()
                port = item.find('span:nth-child(2)').text()
                if host and port:
                    proxies.append(f"{host}:{port}")
        return proxies
    
    def _parse_fatezero(self, html):
        proxies = []
        for line in html.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    host = data.get('host')
                    port = data.get('port')
                    if host and port:
                        proxies.append(f"{host}:{port}")
                except:
                    pass
        return proxies
    
    def _parse_zdaye(self, html):
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            for tr in doc('.cont br').items():
                line = tr[0].tail if tr[0].tail else ''
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if match:
                    proxies.append(f"{match.group(1)}:{match.group(2)}")
        return proxies
    
    def _parse_yqie(self, html):
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            trs = doc('#GridViewOrder tr:gt(0)').items()
            for tr in trs:
                host = tr.find('td:nth-child(1)').text()
                port = tr.find('td:nth-child(2)').text()
                if host and port:
                    proxies.append(f"{host}:{port}")
        return proxies
    
    def _parse_xiladaili(self, html):
        proxies = []
        if LXML_AVAILABLE:
            try:
                etree_html = etree.HTML(html)
                ip_ports = etree_html.xpath("//tbody/tr/td[1]/text()")
                for ip_port in ip_ports:
                    parts = ip_port.partition(":")
                    host = parts[0]
                    port = parts[2]
                    if host and port:
                        proxies.append(f"{host}:{port}")
            except:
                pass
        return proxies
    
    def _parse_xicidaili(self, html):
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            items = doc('#ip_list tr:contains(高匿)').items()
            for item in items:
                host = item.find('td:nth-child(2)').text()
                port = item.find('td:nth-child(3)').text()
                if host and port:
                    proxies.append(f"{host}:{port}")
        return proxies
    
    def _parse_xiaoshu(self, html):
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            content = doc('.cont').text()
            for line in content.split('\n'):
                if '@' in line:
                    c = line[:line.find("@")]
                    if ':' in c:
                        host, port = c.split(':')
                        proxies.append(f"{host}:{port}")
        return proxies
    
    def _parse_ip3366(self, html):
        proxies = []
        pattern = r'<td>(\d+\.\d+\.\d+\.\d+)</td>\s*<td>(\d+)</td>'
        matches = re.findall(pattern, html, re.DOTALL)
        for host, port in matches:
            proxies.append(f"{host}:{port}")
        return proxies
    
    def _parse_89ip(self, html):
        proxies = []
        pattern = r'([\d:\.]*)<br>'
        matches = re.findall(pattern, html)
        for addr in matches:
            parts = addr.split(':')
            if len(parts) == 2:
                proxies.append(f"{parts[0]}:{parts[1]}")
        return proxies
    
    def _parse_goubanjia(self, html):
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            for td in doc('.ip').items():
                ip_str = ''
                for tr in td.children():
                    attrib = tr.attrib
                    if 'style' in attrib and 'none' in attrib['style']:
                        continue
                    ip_str += tr.text or ''
                if ':' in ip_str:
                    parts = ip_str.split(':')
                    if len(parts) == 2:
                        proxies.append(f"{parts[0]}:{parts[1]}")
        return proxies
    
    def _parse_spys(self, html):
        """Parse spys.one"""
        proxies = []
        if LXML_AVAILABLE:
            try:
                etree_html = etree.HTML(html)
                rows = etree_html.xpath("//tr[@class='spy1x']")
                for row in rows:
                    cells = row.xpath(".//td")
                    if len(cells) >= 2:
                        ip_port = cells[0].text_content().strip()
                        if ':' in ip_port:
                            proxies.append(ip_port)
            except:
                pass
        return proxies
    
    def _parse_hidemy(self, html):
        """Parse hidemy.name"""
        proxies = []
        if LXML_AVAILABLE:
            try:
                etree_html = etree.HTML(html)
                rows = etree_html.xpath("//table[@class='proxy__t']/tbody/tr")
                for row in rows:
                    cells = row.xpath(".//td")
                    if len(cells) >= 2:
                        ip = cells[0].text_content().strip()
                        port = cells[1].text_content().strip()
                        if ip and port:
                            proxies.append(f"{ip}:{port}")
            except:
                pass
        return proxies
    
    def _parse_proxyhub(self, html):
        """Parse proxyhub.me"""
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            for row in doc('table tbody tr').items():
                cells = row.find('td')
                if len(cells) >= 2:
                    ip = cells.eq(0).text()
                    port = cells.eq(1).text()
                    if ip and port:
                        proxies.append(f"{ip}:{port}")
        return proxies
    
    def _parse_sslproxies(self, html):
        """Parse sslproxies.org"""
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            for row in doc('#proxylisttable tbody tr').items():
                cells = row.find('td')
                if len(cells) >= 2:
                    ip = cells.eq(0).text()
                    port = cells.eq(1).text()
                    if ip and port:
                        proxies.append(f"{ip}:{port}")
        return proxies
    
    def _parse_free_proxy(self, html):
        """Parse free-proxy-list.net"""
        proxies = []
        if PYQUERY_AVAILABLE:
            doc = pq(html)
            for row in doc('#proxylisttable tbody tr').items():
                cells = row.find('td')
                if len(cells) >= 2:
                    ip = cells.eq(0).text()
                    port = cells.eq(1).text()
                    if ip and port:
                        proxies.append(f"{ip}:{port}")
        return proxies
    
    # ============================================================
    # CRAWLER METHODS
    # ============================================================
    
    def fetch_from_source(self, source: Dict) -> List[str]:
        proxies = []
        name = source['name']
        
        if not source['enabled']:
            return proxies
        
        for url in source['urls']:
            try:
                if self.verbose:
                    cprint(f"    [*] {name}: fetching from {url[:60]}...", INFO)
                
                response = requests.get(url, timeout=15, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response.status_code == 200:
                    new_proxies = source['parser'](response.text)
                    proxies.extend(new_proxies)
                    if self.verbose and new_proxies:
                        cprint(f"    [+] {name}: {len(new_proxies)} proxies", SUCCESS)
                
                time.sleep(0.3)
                
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] {name}: error - {str(e)[:50]}", WARNING)
        
        return proxies
    
    def fetch_all_proxies(self) -> List[str]:
        all_proxies = []
        
        cprint(f"\n[*] Fetching proxies from {len(self.sources)} sources...", INFO)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.fetch_from_source, source): source for source in self.sources}
            
            for future in as_completed(futures):
                source = futures[future]
                try:
                    proxies = future.result(timeout=60)
                    all_proxies.extend(proxies)
                except Exception as e:
                    if self.verbose:
                        cprint(f"    [!] {source['name']}: timeout", WARNING)
        
        all_proxies = list(set(all_proxies))
        cprint(f"[+] Total proxies fetched: {len(all_proxies)}", SUCCESS)
        return all_proxies
    
    def test_proxy(self, proxy: str, test_url="http://httpbin.org/ip", timeout=5) -> Tuple[bool, float]:
        try:
            proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
            start_time = time.time()
            response = requests.get(test_url, proxies=proxy_dict, timeout=timeout)
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                return True, elapsed
        except:
            pass
        return False, 0
    
    def test_proxies_batch(self, proxies: List[str], max_workers=30) -> List[str]:
        working = []
        
        if not self.test_proxies:
            return proxies[:self.max_proxies]
        
        cprint(f"[*] Testing {len(proxies)} proxies...", INFO)
        
        def test_one(proxy):
            success, _ = self.test_proxy(proxy)
            return proxy if success else None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(test_one, proxy): proxy for proxy in proxies[:300]}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    working.append(result)
                    if len(working) >= self.max_proxies:
                        break
        
        cprint(f"[+] Working proxies: {len(working)}", SUCCESS)
        return working
    
    def refresh_proxies(self):
        cprint(f"\n[*] Refreshing proxy list...", INFO)
        
        all_proxies = self.fetch_all_proxies()
        
        if not all_proxies:
            cprint("[!] No proxies fetched, using fallback", WARNING)
            all_proxies = [
                "104.16.0.1:80", "104.24.0.1:80", "172.64.0.1:80",
                "188.114.96.1:80", "190.93.240.1:80"
            ]
        
        with self.lock:
            self.proxies = all_proxies
            self.working_proxies = self.test_proxies_batch(all_proxies)
            self.current_index = 0
            self.request_count_per_proxy = {}
            self.last_refresh_time = time.time()
        
        return len(self.working_proxies)
    
    def get_next_proxy(self) -> Optional[Dict]:
        with self.lock:
            if not self.working_proxies:
                return None
            
            current_time = time.time()
            current_proxy = self.working_proxies[self.current_index % len(self.working_proxies)]
            request_count = self.request_count_per_proxy.get(current_proxy, 0)
            
            should_rotate = (
                current_time - self.last_rotation_time > self.rotation_interval or
                request_count >= self.requests_per_proxy
            )
            
            if should_rotate:
                self.current_index = (self.current_index + 1) % len(self.working_proxies)
                self.last_rotation_time = current_time
                if self.verbose:
                    cprint(f"    [*] Rotating proxy...", INFO)
            
            proxy = self.working_proxies[self.current_index % len(self.working_proxies)]
            self.request_count_per_proxy[proxy] = self.request_count_per_proxy.get(proxy, 0) + 1
            self.request_count += 1
            
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    
    def get_random_proxy(self) -> Optional[Dict]:
        with self.lock:
            if not self.working_proxies:
                return None
            proxy = random.choice(self.working_proxies)
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    
    def mark_failed(self, proxy: Optional[Dict]):
        if proxy:
            proxy_str = proxy.get('http', '').replace('http://', '')
            with self.lock:
                if proxy_str in self.working_proxies:
                    self.working_proxies.remove(proxy_str)
                    self.failed_proxies.add(proxy_str)
                    if self.verbose:
                        cprint(f"    [!] Removed failed proxy: {proxy_str}", WARNING)
            
            if len(self.working_proxies) < 5:
                threading.Thread(target=self.refresh_proxies, daemon=True).start()
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'total_fetched': len(self.proxies),
                'working_proxies': len(self.working_proxies),
                'failed_proxies': len(self.failed_proxies),
                'requests_sent': self.request_count,
                'auto_rotate': True
            }
    
    def get_proxy_count(self):
        with self.lock:
            return len(self.working_proxies)
    
    def _start_refresh_thread(self):
        def refresh_loop():
            while True:
                time.sleep(self.refresh_interval)
                if len(self.working_proxies) < 10:
                    self.refresh_proxies()
        
        thread = threading.Thread(target=refresh_loop, daemon=True)
        thread.start()


class ProxySession:
    def __init__(self, verbose=False, max_proxies=30):
        self.verbose = verbose
        self.proxy_manager = ProxyManager(verbose=verbose, max_proxies=max_proxies, test_proxies=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.request_count = 0
        
        cprint(f"[+] Proxy Session initialized with {len(self.proxy_manager.working_proxies)} working proxies", SUCCESS)
    
    def get(self, url, **kwargs):
        max_retries = 3
        
        for attempt in range(max_retries):
            proxy = self.proxy_manager.get_next_proxy()
            
            if proxy:
                kwargs['proxies'] = proxy
                if self.verbose:
                    cprint(f"    [*] Using proxy: {proxy.get('http', 'unknown')}", INFO)
            
            try:
                response = self.session.get(url, timeout=15, verify=False, **kwargs)
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
        
        if self.verbose:
            cprint(f"    [!] All proxies failed, using direct request", WARNING)
        return self.session.get(url, timeout=15, verify=False, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        max_retries = 3
        
        for attempt in range(max_retries):
            proxy = self.proxy_manager.get_next_proxy()
            
            if proxy:
                kwargs['proxies'] = proxy
                if self.verbose:
                    cprint(f"    [*] Using proxy: {proxy.get('http', 'unknown')}", INFO)
            
            try:
                response = self.session.post(url, data=data, json=json, timeout=15, verify=False, **kwargs)
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
        
        if self.verbose:
            cprint(f"    [!] All proxies failed, using direct request", WARNING)
        return self.session.post(url, data=data, json=json, timeout=15, verify=False, **kwargs)
    
    def refresh(self):
        return self.proxy_manager.refresh_proxies()
    
    def get_stats(self):
        return self.proxy_manager.get_stats()
    
    def get_proxy_count(self):
        return self.proxy_manager.get_proxy_count()


def get_proxy_session(verbose=False, max_proxies=30):
    return ProxySession(verbose=verbose, max_proxies=max_proxies)


if __name__ == "__main__":
    cprint("\n" + "="*60, "cyan")
    cprint("Testing Proxy Manager...", "magenta", attrs=['bold'])
    cprint("="*60, "cyan")
    
    session = ProxySession(verbose=True, max_proxies=20)
    
    try:
        response = session.get("http://httpbin.org/ip")
        cprint(f"\n[+] Response: {response.text}", SUCCESS)
    except Exception as e:
        cprint(f"\n[!] Error: {e}", ERROR)
    
    cprint(f"\n[*] Stats: {session.get_stats()}", INFO)

