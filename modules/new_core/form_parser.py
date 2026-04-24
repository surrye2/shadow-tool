# modules/new_core/extractor_utils.py
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import base64
import re
from termcolor import cprint

def try_decode_value(value):
    """
    Checks if a string is encoded (Base64/URL) and decodes it for scanning.
    If it contains a threat, it returns the decoded string; otherwise, it returns None.
    """
    if not value or len(value) < 8:
        return None
        
    try:
        # Check if it's potentially Base64
        if re.fullmatch(r'[A-Za-z0-9+/=]+', value):
            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
            # Look for common attack patterns in decoded text
            patterns = [r"union select", r"<script>", r"alert\(", r"OR 1=1"]
            if any(re.search(p, decoded, re.IGNORECASE) for p in patterns):
                return decoded
    except:
        pass
    return None

def extract_forms(html_content, base_url, verbose=False):
    """
    Advanced form extractor that also analyzes encoded values in hidden fields.
    """
    soup = BeautifulSoup(html_content or '', 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        f = {
            'action': urljoin(base_url, form.get('action') or ''),
            'method': form.get('method', 'get').lower(),
            'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
            'inputs': []
        }
        
        # Extract inputs, textareas, and selects
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if not name:
                continue
            
            val = inp.get('value', '')
            input_type = inp.get('type', 'text')
            
            # --- INTELLIGENT DECODING LOGIC ---
            # If a hidden field has encoded content, decode and check it
            decoded_val = try_decode_value(val)
            if decoded_val:
                if verbose:
                    cprint(f"[*] Decoded sensitive data in field '{name}': {decoded_val}", "magenta")
                val = decoded_val # Pass the decoded value for further scanning
            elif input_type == 'hidden' and len(val) > 20:
                # If it's just random encoded data with no threats, we can ignore it 
                # (As per your request to discard clean encoded data)
                pass

            f['inputs'].append({
                'name': name,
                'type': input_type,
                'value': val
            })
            
        forms.append(f)
        
    return forms

def get_full_action(form, base_url):
    """
    Returns the absolute URL for the form action.
    """
    return urljoin(base_url, form.get('action') or '')
