# modules/new_core/xss_utils.py
from urllib.parse import urljoin
import html
import time
from termcolor import cprint

# Expanded payloads for better detection/bypass
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '\"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<svg/onload=alert(1)>'
]

def check_reflected(session_manager, url, verbose=False, delay=1.0):
    """
    Checks for Reflected XSS in common URL parameters.
    """
    found = []
    # Test 'q', 'id', 'search', 'query' as common entry points
    test_params = ['q', 'search', 'query', 'id']
    
    for p in XSS_PAYLOADS:
        for param in test_params:
            if delay > 0:
                time.sleep(delay)

            # Determine correct URL structure
            sep = '&' if '?' in url else '?'
            test_url = f"{url}{sep}{param}={p}"
            
            try:
                r = session_manager.get(test_url, timeout=10)
                body = r.text or ''
                
                # Critical check: is the payload reflected exactly as is?
                if p in body:
                    found.append((param, p, 'reflected', test_url))
                    if verbose:
                        cprint(f"[!] XSS Reflection found in param: {param}", "red")
                
                # Security check: is the payload safely escaped?
                elif html.escape(p) in body:
                    if verbose:
                        cprint(f"[*] Payload escaped in param: {param} (Filtered)", "blue")
                        
            except Exception as e:
                if verbose:
                    cprint(f"[X] check_reflected error: {e}", "red")
    return found

def fuzz_form_and_check(session_manager, base_url, form, payload, verbose=False, delay=1.0):
    """
    Fuzzes all form inputs with XSS payloads.
    """
    if delay > 0:
        time.sleep(delay)
        
    action_url = urljoin(base_url, form.get('action', ''))
    method = form.get('method', 'get').lower()
    data = {}
    
    # Fill all inputs with the payload
    for inp in form.get('inputs', []):
        name = inp.get('name', '')
        if not name: continue
        
        # Handle password fields differently to avoid logical errors
        if 'password' in name.lower():
            data[name] = 'TestPass123!'
        else:
            data[name] = payload
            
    try:
        if verbose:
            cprint(f"[*] Fuzzing form at: {action_url} via {method.upper()}", "blue")
            
        if method == 'post':
            r = session_manager.post(action_url, data=data, timeout=10)
        else:
            r = session_manager.get(action_url, params=data, timeout=10)
            
        return (r, data)
    except Exception as e:
        if verbose:
            cprint(f"[X] fuzz_form_and_check error: {e}", "red")
        return (None, data)
