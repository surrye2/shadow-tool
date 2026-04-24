import re
import requests
from termcolor import cprint
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run(target_url=None):
    cprint(f"[*] Analyzing target: {target_url}", "cyan")
    session = requests.Session()

    try:
        resp = session.get(target_url, timeout=10, verify=False)
    except Exception as e:
        cprint(f"[!] Request failed: {e}", "red")
        return {"error": str(e)}

    text = resp.text
    cookies = session.cookies.get_dict()

    suspicious = {
        "emails": [],
        "tokens": [],
        "passwords": [],
        "possible_encrypted": [],
        "js_suspicious": [],
        "cookies": cookies
    }

    # Extract emails
    suspicious["emails"] = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)

    # Extract possible passwords or API keys
    suspicious["passwords"] = re.findall(r"(?i)(password|pwd|pass|secret)[\"'=:\s>]+([^\s\"'<>{}]{4,})", text)
    suspicious["tokens"] = re.findall(r"(?i)(token|access_token|auth_token|key)[\"'=:\s>]+([A-Za-z0-9\-_\.]{10,})", text)

    # Find Base64 / HEX / ROT / suspicious strings
    suspicious["possible_encrypted"] = re.findall(
        r"(?:[A-Za-z0-9+/]{20,}={0,2}|[0-9A-Fa-f]{16,})", text
    )

    # Detect suspicious JS functions
    suspicious["js_suspicious"] = re.findall(r"(?i)(eval|atob|btoa|decodeURIComponent)\(", text)

    total_found = sum(len(v) for v in suspicious.values() if isinstance(v, list))
    cprint(f"[+] Extracted {total_found} potentially sensitive or encrypted items", "green")

    return suspicious
