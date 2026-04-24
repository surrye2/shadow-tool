import requests
import urllib3
import time
import random

# Suppress insecure request warnings for Termux environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ProxyHandler:
    def __init__(self, *args, **kwargs):
        # Multiple sources to ensure the tool never stops
        self.sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://www.proxy-list.download/api/v1/get?type=https",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"
        ]
        self.working_proxies = []
        self.test_url = "http://httpbin.org/ip"  # URL آمن لاختبار الـ proxy

    def get_free_proxies(self, verify=True, max_proxies=50):
        """
        Fetches fresh proxies from multiple backup sources.
        Optional: verify=True to test proxies before returning
        """
        print("[*] AlZill Proxy Engine: Fetching fresh proxies...")

        all_proxies = []
        
        for url in self.sources:
            try:
                # verify=False bypasses local issuer certificate errors in Termux
                response = requests.get(url, timeout=12, verify=False)
                if response.status_code == 200 and len(response.text) > 20:
                    proxy_list = response.text.strip().splitlines()
                    # تنظيف الـ proxies (إزالة المسافات الفارغة)
                    proxy_list = [p.strip() for p in proxy_list if p.strip()]
                    print(f"[✓] Successfully fetched {len(proxy_list)} proxies from {url.split('/')[2]}")
                    all_proxies.extend(proxy_list)
            except Exception as e:
                print(f"[!] Source failed ({url.split('/')[2]}): Connection Error")
                continue
        
        # إزالة التكرارات
        all_proxies = list(set(all_proxies))
        
        if not all_proxies:
            print("[!] Fatal: All proxy sources are unreachable. Check your DNS/Internet.")
            return []
        
        print(f"[*] Total unique proxies collected: {len(all_proxies)}")
        
        # فحص صحة الـ proxies (اختياري)
        if verify:
            print("[*] Verifying proxies (this may take a moment)...")
            self.working_proxies = self._verify_proxies(all_proxies, max_proxies)
            print(f"[✓] Found {len(self.working_proxies)} working proxies")
            return self.working_proxies
        
        return all_proxies[:max_proxies]
    
    def _verify_proxies(self, proxies, max_working=50):
        """
        فحص الـ proxies الصالحة فقط
        """
        working = []
        
        for proxy in proxies[:200]:  # فحص أول 200 proxy فقط للسرعة
            try:
                proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
                response = requests.get(
                    self.test_url, 
                    proxies=proxy_dict, 
                    timeout=5, 
                    verify=False
                )
                if response.status_code == 200:
                    working.append(proxy)
                    if len(working) >= max_working:
                        break
            except Exception:
                continue
        
        return working
    
    def get_random_proxy(self):
        """
        إرجاع Proxy عشوائي من القائمة العاملة
        """
        if not self.working_proxies:
            self.get_free_proxies(verify=True)
        
        if self.working_proxies:
            return random.choice(self.working_proxies)
        return None
    
    def rotate_proxy(self):
        """
        تدوير الـ proxies (تغيير الـ proxy مع كل طلب)
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                proxy = self.get_random_proxy()
                if proxy:
                    kwargs['proxy'] = proxy
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def save_proxies(self, proxies, filename="proxies.txt"):
        """
        Saves the fetched proxies to a local file.
        """
        try:
            with open(filename, "w") as f:
                for proxy in proxies:
                    f.write(proxy.strip() + "\n")
            print(f"[*] Saved {len(proxies)} proxies to {filename}")
        except IOError as e:
            print(f"[!] File Error: Could not save proxies: {e}")
    
    def load_proxies_from_file(self, filename="proxies.txt"):
        """
        تحميل proxies من ملف محلي
        """
        try:
            with open(filename, "r") as f:
                proxies = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(proxies)} proxies from {filename}")
            return proxies
        except Exception as e:
            print(f"[!] Could not load proxies from file: {e}")
            return []


# دالة مساعدة للاستخدام السريع
def get_free_proxies(verify=True, max_proxies=50):
    """
    دالة سريعة لجلب proxies عاملة
    """
    handler = ProxyHandler()
    return handler.get_free_proxies(verify=verify, max_proxies=max_proxies)


if __name__ == "__main__":
    engine = ProxyHandler()
    print("[*] Testing proxy handler...")
    
    # جلب proxies بدون فحص (سريع)
    live_proxies = engine.get_free_proxies(verify=False, max_proxies=20)
    
    if live_proxies:
        print(f"\n[✓] Got {len(live_proxies)} proxies (unverified)")
        engine.save_proxies(live_proxies[:10], "proxies_sample.txt")
    
    # جلب proxies مع الفحص (أبطأ لكن أدق)
    print("\n[*] Fetching verified proxies...")
    verified = engine.get_free_proxies(verify=True, max_proxies=10)
    
    if verified:
        print(f"\n[✓] Verified working proxies:")
        for p in verified[:5]:
            print(f"    → {p}")
