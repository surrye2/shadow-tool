# modules/new_core/session_manager.py

import requests
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from termcolor import cprint
from typing import Optional, Dict, Any, List
from datetime import datetime

class SessionManager:
    
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/119.0.0.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
    ]
    
    def __init__(self, timeout: int = 10, delay: float = 0, max_retries: int = 3,
                 retry_backoff: float = 1.0, use_rotation: bool = False,
                 verbose: bool = False):
        
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.use_rotation = use_rotation
        self.verbose = verbose
        self.request_count = 0
        self.failure_count = 0
        
        self.session = requests.Session()
        self._setup_retry_strategy()
        self._setup_default_headers()
        self.proxies = None
        
        self.stats = {
            'requests': 0,
            'success': 0,
            'failures': 0,
            'start_time': datetime.now()
        }
    
    def _setup_retry_strategy(self):
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=50,
            pool_maxsize=50
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def _setup_default_headers(self):
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'DNT': '1'
        })
        self._rotate_user_agent()
    
    def _rotate_user_agent(self):
        if self.use_rotation:
            user_agent = random.choice(self.USER_AGENTS)
        else:
            user_agent = self.USER_AGENTS[0]
        
        self.session.headers.update({'User-Agent': user_agent})
        
        if self.verbose:
            cprint(f"[*] User-Agent set", "blue")
    
    def _throttle(self):
        if self.delay > 0:
            actual_delay = self.delay + random.uniform(0, self.delay * 0.3)
            time.sleep(actual_delay)
    
    def _update_stats(self, success: bool):
        self.stats['requests'] += 1
        if success:
            self.stats['success'] += 1
        else:
            self.stats['failures'] += 1
    
    def set_proxy(self, proxy_url: str):
        self.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        if self.verbose:
            cprint(f"[*] Proxy set: {proxy_url}", "blue")
    
    def clear_proxy(self):
        self.proxies = None
        if self.verbose:
            cprint(f"[*] Proxy cleared", "blue")
    
    def get(self, url: str, **kwargs) -> requests.Response:
        self._throttle()
        
        if self.use_rotation and self.request_count % 10 == 0:
            self._rotate_user_agent()
        
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('verify', True)
        
        if self.proxies:
            kwargs.setdefault('proxies', self.proxies)
        
        self.request_count += 1
        
        try:
            response = self.session.get(url, **kwargs)
            self._update_stats(True)
            return response
        except requests.RequestException as e:
            self._update_stats(False)
            if self.verbose:
                cprint(f"[!] GET failed: {e}", "red")
            raise
    
    def post(self, url: str, data=None, json=None, files=None, **kwargs) -> requests.Response:
        self._throttle()
        
        if self.use_rotation and self.request_count % 10 == 0:
            self._rotate_user_agent()
        
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('verify', True)
        
        if self.proxies:
            kwargs.setdefault('proxies', self.proxies)
        
        self.request_count += 1
        
        try:
            response = self.session.post(url, data=data, json=json, files=files, **kwargs)
            self._update_stats(True)
            return response
        except requests.RequestException as e:
            self._update_stats(False)
            if self.verbose:
                cprint(f"[!] POST failed: {e}", "red")
            raise
    
    def update_header(self, key: str, value: str):
        self.session.headers.update({key: value})
    
    def get_cookies(self):
        return self.session.cookies
    
    def get_headers(self):
        return self.session.headers
    
    def get_stats(self) -> Dict:
        elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
        success_rate = (self.stats['success'] / self.stats['requests'] * 100) if self.stats['requests'] > 0 else 0
        
        return {
            'total_requests': self.stats['requests'],
            'successful': self.stats['success'],
            'failed': self.stats['failures'],
            'success_rate': f"{success_rate:.1f}%",
            'elapsed_seconds': elapsed
        }
    
    def close(self):
        self.session.close()
