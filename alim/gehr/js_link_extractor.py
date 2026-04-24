#!/usr/bin/env python3
import re
import requests
from termcolor import cprint

def run(url):
    """
    Extracts URLs and useful data from remote JS files or text-based assets.
    """

    cprint(f"[JS_LINK_EXTRACTOR] Fetching: {url}", "blue")
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        cprint(f"[JS_LINK_EXTRACTOR] Failed to fetch {url}: {e}", "red")
        return

    content = resp.text

    # Regex patterns for different types of data
    url_pattern = re.compile(r'https?://[^\s\'"<>]+')
    path_pattern = re.compile(r'/(?:[A-Za-z0-9_\-./]+)\.(?:php|asp|aspx|jsp|html|json|xml|js|css|svg|txt)')
    email_pattern = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
    api_pattern = re.compile(r'["\'](/api/[A-Za-z0-9_\-./]+)["\']')

    found_urls = set(url_pattern.findall(content))
    found_paths = set(path_pattern.findall(content))
    found_emails = set(email_pattern.findall(content))
    found_api = set(api_pattern.findall(content))

    cprint("\n[+] Extracted Data Summary:", "cyan")
    if found_urls:
        cprint(f" - URLs ({len(found_urls)}):", "green")
        for u in found_urls:
            print("   ", u)
    if found_paths:
        cprint(f" - Paths ({len(found_paths)}):", "green")
        for p in found_paths:
            print("   ", p)
    if found_emails:
        cprint(f" - Emails ({len(found_emails)}):", "green")
        for e in found_emails:
            print("   ", e)
    if found_api:
        cprint(f" - API Endpoints ({len(found_api)}):", "green")
        for a in found_api:
            print("   ", a)

    if not any([found_urls, found_paths, found_emails, found_api]):
        cprint("[-] No useful data found in the file.", "yellow")
