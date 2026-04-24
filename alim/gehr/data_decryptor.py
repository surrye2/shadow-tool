import base64
import codecs
import urllib.parse
from termcolor import cprint

def run(data=None):
    if not data:
        return {"error": "no input data"}

    cprint("[*] Attempting to decrypt extracted data...", "cyan")
    results = {"decoded": []}

    for key, items in data.items():
        if not isinstance(items, list):
            continue
        for entry in items:
            # Handle (label, value) tuples (like passwords)
            if isinstance(entry, tuple):
                entry = entry[-1]

            for method in (try_base64, try_hex, try_rot13, try_url_decode):
                decoded = method(entry)
                if decoded and decoded != entry:
                    results["decoded"].append({
                        "original": entry,
                        "decoded": decoded,
                        "method": method.__name__
                    })

    cprint(f"[✓] {len(results['decoded'])} items successfully decoded", "green")
    return results


def try_base64(s):
    try:
        return base64.b64decode(s).decode("utf-8")
    except Exception:
        return None

def try_hex(s):
    try:
        return bytes.fromhex(s).decode("utf-8")
    except Exception:
        return None

def try_rot13(s):
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return None

def try_url_decode(s):
    try:
        decoded = urllib.parse.unquote(s)
        return decoded if decoded != s else None
    except Exception:
        return None
