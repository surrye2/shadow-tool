# modules/new_core/sqli_utils.py
import time
from termcolor import cprint

def check_sqli_by_comparison(session_manager, url, verbose=False, delay=1.0):
    """
    Advanced SQLi detection using Boolean-based comparison and Error analysis.
    """
    try:
        # 1. Respect the delay between tests
        if delay > 0:
            time.sleep(delay)

        # Ensure correct URL parameter joining
        separator = '&' if '?' in url else '?'
        
        # 2. Perform Normal Request
        normal_resp = session_manager.get(f"{url}{separator}id=1", timeout=10)
        normal_text = normal_resp.text.strip()

        if delay > 0:
            time.sleep(delay)

        # 3. Perform Boolean Injection Request (OR 1=1)
        # If the page content changes significantly, it indicates vulnerability
        boolean_url = f"{url}{separator}id=1%20OR%201=1"
        payload_resp = session_manager.get(boolean_url, timeout=10)
        payload_text = payload_resp.text.strip()

        if normal_text != payload_text:
            # Check if the difference is substantial, not just a timestamp change
            if abs(len(normal_text) - len(payload_text)) > 20:
                return True, f"Boolean-based: Response differs for OR 1=1 (Size delta: {len(payload_text) - len(normal_text)})"

        if delay > 0:
            time.sleep(delay)

        # 4. Perform Error-based Request
        error_url = f"{url}{separator}id='"
        error_resp = session_manager.get(error_url, timeout=10)
        error_text = error_resp.text.lower()

        error_signatures = [
            "sql syntax", "mysql", "syntax error", "unclosed quotation mark",
            "db error", "postgresql", "sqlite", "oracle"
        ]

        if any(sig in error_text for sig in error_signatures):
            return True, "Error-based: Database error signature observed in response"

    except Exception as e:
        if verbose:
            cprint(f"[X] check_sqli_by_comparison error: {e}", "red")
            
    return False, "No SQLi signs detected"
