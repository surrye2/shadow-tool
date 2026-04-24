# modules/new_core/csrf_utils.py
from urllib.parse import urljoin
import time
from termcolor import cprint
import re

def is_random_looking(value):
    """
    Heuristic check to see if a string looks like a random token.
    Checks for length > 16 and a mix of alphanumeric characters.
    """
    if not value or len(value) < 16:
        return False
    # Check for high entropy (mix of lowercase, uppercase, and numbers)
    if re.search(r'[a-z]', value) and re.search(r'[A-Z]', value) and re.search(r'[0-9]', value):
        return True
    # Also consider long hex strings or base64-like strings as potential tokens
    if re.fullmatch(r'[a-fA-F0-9]{32,}', value) or re.fullmatch(r'[a-zA-Z0-9+/=]{20,}', value):
        return True
    return False

def has_csrf_token(form, verbose=False):
    """
    Advanced check for CSRF tokens in a form.
    Looks for common names and suspicious hidden inputs.
    """
    # Common Anti-CSRF token names (case-insensitive)
    known_token_names = [
        "csrf", "xsrf", "token", "__requestverificationtoken", 
        "authenticity_token", "synching_token", "anti-forgery", "state"
    ]
    
    inputs = form.get('inputs', [])
    if verbose and not inputs:
        cprint(f"[!] No inputs found in form action: {form.get('action')}", "yellow")

    for i in inputs:
        # 1. Check if the input is hidden
        if i.get('type') == 'hidden':
            input_name = i.get('name', '').lower()
            input_value = i.get('value', '')

            # 2. Check for known token names
            if any(known_name in input_name for known_name in known_token_names):
                if verbose:
                    cprint(f"[*] Found potential CSRF token by name: '{input_name}'", "blue")
                return True
            
            # 3. Heuristic check: Look for random-looking values in hidden inputs
            # even if the name is generic (e.g., name="s", name="id", name="v")
            if is_random_looking(input_value):
                if verbose:
                    cprint(f"[*] Found potential CSRF token by value entropy in input: '{input_name}'", "blue")
                return True
                
    return False

def attempt_csrf_change(session_manager, base_url, form, test_payload, delay=1.0, verbose=False):
    """
    Attempts to submit a form without a valid CSRF token to check vulnerability.
    Includes a delay to prevent rate limiting.
    """
    action = urljoin(base_url, form.get('action', ''))
    
    # Respect the delay before making the request
    if delay > 0:
        time.sleep(delay)
        
    try:
        if verbose:
            cprint(f"[*] Attempting CSRF state change on: {action}", "blue")
            
        # Submit the form using the session manager (which handles cookies)
        # We assume 'test_payload' contains the parameters to change state
        r = session_manager.post(action, data=test_payload, timeout=10)
        
        return r
    except Exception as e:
        if verbose:
            cprint(f"[X] attempt_csrf_change error: {e}", "red")
    return None
